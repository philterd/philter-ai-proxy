/*
 *     Copyright 2026 Philterd, LLC @ https://www.philterd.ai
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ai.philterd.aiproxy;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;

/**
 * An OpenAI-shaped provider for tests. It records the last request it received and answers with {@link #reply},
 * as one JSON response or, when the request asks to stream, as server-sent events of {@link #chunkSize}
 * characters each.
 */
public final class StubProvider implements AutoCloseable {

    public final AtomicReference<JsonObject> lastBody = new AtomicReference<>();
    public final AtomicReference<Headers> lastHeaders = new AtomicReference<>();
    public final AtomicInteger requests = new AtomicInteger();
    public volatile String reply = "Your SSN is 123-45-6789 and email is jane.doe@example.com, noted.";
    public volatile int chunkSize = 5;
    public volatile int status = 200;
    /** Adds logprobs whose tokens spell out the reply. */
    public volatile boolean logprobs;
    /** When set, the reply also makes a tool call with these arguments. */
    public volatile String toolArguments;
    /** Sends the buffered reply's content as an array of text parts. */
    public volatile boolean contentParts;
    /** Compresses the response with gzip, although the request did not ask for it. */
    public volatile boolean gzip;
    /** Adds a data line to the stream that is not JSON. */
    public volatile boolean junkEvent;

    private final HttpServer server;

    public StubProvider() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    public String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public void reset() {
        lastBody.set(null);
        lastHeaders.set(null);
        requests.set(0);
        reply = "Your SSN is 123-45-6789 and email is jane.doe@example.com, noted.";
        chunkSize = 5;
        status = 200;
        logprobs = false;
        toolArguments = null;
        contentParts = false;
        gzip = false;
        junkEvent = false;
    }

    private void handle(final HttpExchange exchange) throws IOException {
        requests.incrementAndGet();
        final String raw = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        final JsonObject body = JsonParser.parseString(raw).getAsJsonObject();
        lastBody.set(body);
        lastHeaders.set(exchange.getRequestHeaders());
        if (status != 200) {
            final byte[] out = "{\"error\":{\"message\":\"stub error\"}}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
            return;
        }
        if (gzip) {
            exchange.getResponseHeaders().set("Content-Encoding", "gzip");
        }
        if (body.has("stream") && body.get("stream").getAsBoolean()) {
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = gzip ? new GZIPOutputStream(exchange.getResponseBody()) : exchange.getResponseBody()) {
                send(out, chunk("{\"role\":\"assistant\",\"content\":\"\"}", null));
                for (int i = 0; i < reply.length(); i += chunkSize) {
                    final String piece = reply.substring(i, Math.min(reply.length(), i + chunkSize));
                    final JsonObject delta = new JsonObject();
                    delta.addProperty("content", piece);
                    send(out, logprobs ? chunk(delta.toString(), null, logprobs(piece)) : chunk(delta.toString(), null));
                }
                if (junkEvent) {
                    out.write("data: this is not json\n\n".getBytes(StandardCharsets.UTF_8));
                }
                if (toolArguments != null) {
                    send(out, chunk("{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\","
                            + "\"function\":{\"name\":\"lookup\",\"arguments\":\"\"}}]}", null));
                    for (int i = 0; i < toolArguments.length(); i += chunkSize) {
                        final JsonObject function = new JsonObject();
                        function.addProperty("arguments", toolArguments.substring(i, Math.min(toolArguments.length(), i + chunkSize)));
                        final JsonObject call = new JsonObject();
                        call.addProperty("index", 0);
                        call.add("function", function);
                        final JsonArray calls = new JsonArray();
                        calls.add(call);
                        final JsonObject delta = new JsonObject();
                        delta.add("tool_calls", calls);
                        send(out, chunk(delta.toString(), null));
                    }
                }
                send(out, chunk("{}", toolArguments != null ? "tool_calls" : "stop"));
                out.write(": keep-alive\n\n".getBytes(StandardCharsets.UTF_8));
                out.write("data: [DONE]\n\n".getBytes(StandardCharsets.UTF_8));
            }
            return;
        }
        final JsonObject message = new JsonObject();
        message.addProperty("role", "assistant");
        if (contentParts) {
            final JsonObject part = new JsonObject();
            part.addProperty("type", "text");
            part.addProperty("text", reply);
            final JsonArray parts = new JsonArray();
            parts.add(part);
            message.add("content", parts);
        } else {
            message.addProperty("content", reply);
        }
        if (toolArguments != null) {
            final JsonObject function = new JsonObject();
            function.addProperty("name", "lookup");
            function.addProperty("arguments", toolArguments);
            final JsonObject call = new JsonObject();
            call.addProperty("id", "call_1");
            call.addProperty("type", "function");
            call.add("function", function);
            final JsonArray calls = new JsonArray();
            calls.add(call);
            message.add("tool_calls", calls);
        }
        final JsonObject choice = new JsonObject();
        choice.addProperty("index", 0);
        choice.add("message", message);
        if (logprobs) {
            choice.add("logprobs", JsonParser.parseString(logprobs(reply)));
        }
        choice.addProperty("finish_reason", "stop");
        final JsonArray choices = new JsonArray();
        choices.add(choice);
        final JsonObject response = new JsonObject();
        response.addProperty("id", "chatcmpl-1");
        response.addProperty("object", "chat.completion");
        response.add("choices", choices);
        byte[] out = response.toString().getBytes(StandardCharsets.UTF_8);
        if (gzip) {
            final java.io.ByteArrayOutputStream compressed = new java.io.ByteArrayOutputStream();
            try (GZIPOutputStream z = new GZIPOutputStream(compressed)) {
                z.write(out);
            }
            out = compressed.toByteArray();
        }
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("X-Provider-Header", "kept");
        exchange.sendResponseHeaders(200, out.length);
        exchange.getResponseBody().write(out);
        exchange.close();
    }

    private static String chunk(final String delta, final String finishReason) {
        return chunk(delta, finishReason, null);
    }

    private static String chunk(final String delta, final String finishReason, final String logprobs) {
        return "{\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":"
                + delta + (logprobs == null ? "" : ",\"logprobs\":" + logprobs)
                + ",\"finish_reason\":" + (finishReason == null ? "null" : "\"" + finishReason + "\"") + "}]}";
    }

    /** Logprobs for the text, one token per word, as OpenAI shapes them. */
    private static String logprobs(final String text) {
        final JsonArray content = new JsonArray();
        for (final String token : text.split("(?<= )")) {
            final JsonObject entry = new JsonObject();
            entry.addProperty("token", token);
            entry.addProperty("logprob", -0.1);
            content.add(entry);
        }
        final JsonObject logprobs = new JsonObject();
        logprobs.add("content", content);
        return logprobs.toString();
    }

    private static void send(final OutputStream out, final String json) throws IOException {
        out.write(("data: " + json + "\n\n").getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    @Override
    public void close() {
        server.stop(0);
    }

}
