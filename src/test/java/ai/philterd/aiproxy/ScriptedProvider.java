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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * A provider for tests that records each request and answers with whatever the test scripted: a content type and
 * a body, sent in the given chunks with a flush after each.
 */
public final class ScriptedProvider implements AutoCloseable {

    public volatile String lastMethod;
    public volatile String lastPath;
    public volatile String lastQuery;
    public volatile Headers lastHeaders;
    public volatile String lastRaw;
    public volatile int requests;

    private volatile int status = 200;
    private volatile String contentType = "application/json";
    private volatile List<byte[]> chunks = List.of("{}".getBytes(StandardCharsets.UTF_8));

    private final HttpServer server;

    public ScriptedProvider() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    public String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public JsonObject lastBody() {
        return lastRaw == null || lastRaw.isEmpty() ? null : JsonParser.parseString(lastRaw).getAsJsonObject();
    }

    public void reset() {
        lastMethod = lastPath = lastQuery = lastRaw = null;
        lastHeaders = null;
        requests = 0;
        status = 200;
        reply("application/json", "{}");
    }

    public void reply(final String type, final String body) {
        reply(type, List.of(body.getBytes(StandardCharsets.UTF_8)));
    }

    public void reply(final String type, final List<byte[]> parts) {
        this.contentType = type;
        this.chunks = new ArrayList<>(parts);
    }

    /** Text chunks, each sent and flushed on its own. */
    public void replyChunks(final String type, final List<String> parts) {
        reply(type, parts.stream().map(p -> p.getBytes(StandardCharsets.UTF_8)).toList());
    }

    private void handle(final HttpExchange exchange) throws IOException {
        requests++;
        lastMethod = exchange.getRequestMethod();
        lastPath = exchange.getRequestURI().getRawPath();
        lastQuery = exchange.getRequestURI().getRawQuery();
        lastHeaders = exchange.getRequestHeaders();
        lastRaw = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, 0);
        try (OutputStream out = exchange.getResponseBody()) {
            for (final byte[] chunk : chunks) {
                out.write(chunk);
                out.flush();
            }
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }

}
