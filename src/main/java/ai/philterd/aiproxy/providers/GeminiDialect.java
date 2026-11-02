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
package ai.philterd.aiproxy.providers;

import ai.philterd.aiproxy.proxy.TextSlots;
import ai.philterd.aiproxy.redaction.RedactionException;
import ai.philterd.aiproxy.stream.Framing;
import ai.philterd.aiproxy.stream.SseFraming;
import ai.philterd.aiproxy.stream.StreamDialect;
import ai.philterd.aiproxy.stream.StreamEvent;
import ai.philterd.aiproxy.stream.StreamScanner;
import ai.philterd.aiproxy.stream.StreamScanner.Key;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Google Gemini and Vertex AI: {@code generateContent}, {@code streamGenerateContent}, {@code countTokens},
 * {@code embedContent}, and {@code batchEmbedContents}.
 *
 * <p>Requests: the text of each part of {@code contents} and {@code systemInstruction}, the arguments of
 * {@code functionCall} parts, and the strings in {@code functionResponse.response}; for {@code countTokens}, also
 * those of a wrapped {@code generateContentRequest}; for embeddings, each request's {@code content} parts and
 * {@code title}. Responses: each candidate's text parts (including thought summaries) and function-call arguments;
 * token counts and embeddings carry no text. Inline and file data are not redacted. A
 * {@code streamGenerateContent} response without {@code alt=sse} is a JSON array; it is read whole and scanned as
 * one response.</p>
 */
public final class GeminiDialect implements ProviderDialect {

    enum Method {
        GENERATE, STREAM_GENERATE, COUNT_TOKENS, EMBED, BATCH_EMBED
    }

    /** The method a path names after its last colon, such as {@code models/gemini-2.5-flash:countTokens}, or null. */
    static Method method(final String path) {
        final int colon = path.lastIndexOf(':');
        if (colon == -1 || path.indexOf('/', colon) != -1) {
            return null;
        }
        return switch (path.substring(colon + 1).toLowerCase(Locale.ROOT)) {
            case "generatecontent" -> Method.GENERATE;
            case "streamgeneratecontent" -> Method.STREAM_GENERATE;
            case "counttokens" -> Method.COUNT_TOKENS;
            case "embedcontent" -> Method.EMBED;
            case "batchembedcontents" -> Method.BATCH_EMBED;
            default -> null;
        };
    }

    /** Whether the path names one of the methods the dialect reads. */
    public static boolean isMethodPath(final String path) {
        return method(path) != null;
    }

    private static boolean isEmbed(final Method method) {
        return method == Method.EMBED || method == Method.BATCH_EMBED;
    }

    /**
     * The request bodies in a body: the body itself; for countTokens, also its wrapped generateContentRequest; for
     * batchEmbedContents, each of its requests.
     */
    private static java.util.List<JsonObject> requests(final Method method, final JsonObject body) {
        if (method == Method.BATCH_EMBED) {
            return Json.objects(body, "requests");
        }
        final java.util.List<JsonObject> requests = new java.util.ArrayList<>(java.util.List.of(body));
        if (method == Method.COUNT_TOKENS) {
            for (final String member : new String[]{"generateContentRequest", "generate_content_request"}) {
                final JsonObject wrapped = Json.object(body, member);
                if (wrapped != null) {
                    requests.add(wrapped);
                }
            }
        }
        return requests;
    }

    /** The contents of a request: {@code contents} and {@code systemInstruction}, or an embedding's {@code content}. */
    private static java.util.List<JsonObject> contents(final Method method, final JsonObject request) {
        final java.util.List<JsonObject> contents = new java.util.ArrayList<>();
        if (isEmbed(method)) {
            final JsonObject content = Json.object(request, "content");
            if (content != null) {
                contents.add(content);
            }
            return contents;
        }
        contents.addAll(Json.objects(request, "contents"));
        for (final String member : new String[]{"systemInstruction", "system_instruction"}) {
            final JsonObject instruction = Json.object(request, member);
            if (instruction != null) {
                contents.add(instruction);
            }
        }
        return contents;
    }

    @Override
    public TextSlots requestText(final String path, final JsonObject body) {
        final TextSlots slots = new TextSlots();
        final Method method = method(path);
        for (final JsonObject request : requests(method, body)) {
            for (final JsonObject content : contents(method, request)) {
                addParts(slots, content);
            }
            if (isEmbed(method)) {
                // A document's title, sent with RETRIEVAL_DOCUMENT embeddings.
                slots.addString(request, "title");
            }
            if (method == Method.COUNT_TOKENS && request.get("instances") instanceof com.google.gson.JsonArray instances) {
                // Vertex AI's countTokens also takes instances in the model's own prediction schema: every string.
                slots.addAllStrings(instances);
            }
        }
        return slots;
    }

    private static final String[] MEDIA_PARTS = {"inlineData", "inline_data", "fileData", "file_data"};

    /**
     * generateContent, streamGenerateContent, and countTokens; and on the Gemini API, embedContent and
     * batchEmbedContents. Vertex AI's embedding requests are not read, since their bodies are not known to match.
     */
    @Override
    public boolean supports(final String method, final String path) {
        final Method gemini = method(path);
        return "POST".equals(method) && gemini != null && !(isEmbed(gemini) && isVertex(path));
    }

    private static boolean isVertex(final String path) {
        return path.startsWith("/v1/projects/") || path.startsWith("/v1beta1/projects/");
    }

    @Override
    public String mediaPart(final String path, final JsonObject body) {
        final Method method = method(path);
        final java.util.List<JsonObject> contents = new java.util.ArrayList<>();
        for (final JsonObject request : requests(method, body)) {
            contents.addAll(contents(method, request));
        }
        for (final JsonObject content : contents) {
            final String found = mediaIn(Json.objects(content, "parts"));
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    /** The first media member in the parts, including the parts of a function response. */
    private static String mediaIn(final java.util.List<JsonObject> parts) {
        for (final JsonObject part : parts) {
            for (final String member : MEDIA_PARTS) {
                if (Json.present(part, member)) {
                    return member;
                }
            }
            for (final String response : new String[]{"functionResponse", "function_response"}) {
                final JsonObject functionResponse = Json.object(part, response);
                final String found = functionResponse == null ? null : mediaIn(Json.objects(functionResponse, "parts"));
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static void addParts(final TextSlots slots, final JsonObject content) {
        for (final JsonObject part : Json.objects(content, "parts")) {
            slots.addString(part, "text");
            for (final String[] member : new String[][]{{"executableCode", "code"}, {"executable_code", "code"},
                    {"codeExecutionResult", "output"}, {"code_execution_result", "output"}}) {
                final JsonObject holder = Json.object(part, member[0]);
                if (holder != null) {
                    slots.addString(holder, member[1]);
                }
            }
            for (final String call : new String[]{"functionCall", "function_call"}) {
                final JsonObject functionCall = Json.object(part, call);
                if (functionCall != null && functionCall.get("args") instanceof JsonObject args) {
                    slots.addAllStrings(args);
                }
            }
            for (final String response : new String[]{"functionResponse", "function_response"}) {
                final JsonObject functionResponse = Json.object(part, response);
                if (functionResponse != null && functionResponse.get("response") instanceof JsonObject value) {
                    slots.addAllStrings(value);
                }
            }
        }
    }

    @Override
    public TextSlots responseText(final String path, final JsonElement body) {
        final TextSlots slots = new TextSlots();
        for (final JsonObject response : Json.each(body)) {
            for (final JsonObject candidate : Json.objects(response, "candidates")) {
                final JsonObject content = Json.object(candidate, "content");
                if (content != null) {
                    addParts(slots, content);
                }
                addGrounding(slots, candidate);
            }
        }
        return slots;
    }

    /**
     * A candidate's grounding metadata: the answer passages each citation quotes, the search queries the model
     * wrote, the search suggestions rendered from them, and the titles and text of retrieved documents (Vertex AI
     * Search returns the customer's own documents). Its offsets into the answer are left alone; once the answer is
     * redacted they are approximate.
     */
    static void addGrounding(final TextSlots slots, final JsonObject candidate) {
        final JsonObject grounding = Json.object(candidate, "groundingMetadata");
        if (grounding == null) {
            return;
        }
        for (final JsonObject support : Json.objects(grounding, "groundingSupports")) {
            final JsonObject segment = Json.object(support, "segment");
            if (segment != null) {
                slots.addString(segment, "text");
            }
        }
        for (final String queries : new String[]{"webSearchQueries", "retrievalQueries"}) {
            if (grounding.get(queries) instanceof JsonArray list) {
                slots.addAllStrings(list);
            }
        }
        final JsonObject entryPoint = Json.object(grounding, "searchEntryPoint");
        if (entryPoint != null) {
            slots.addString(entryPoint, "renderedContent");
        }
        for (final JsonObject chunk : Json.objects(grounding, "groundingChunks")) {
            for (final String source : new String[]{"web", "retrievedContext"}) {
                final JsonObject value = Json.object(chunk, source);
                if (value != null) {
                    slots.addString(value, "title");
                    slots.addString(value, "text");
                }
            }
        }
    }

    /** Removes each candidate's {@code logprobsResult}, whose tokens spell out the unredacted text. */
    @Override
    public boolean removeRevealingData(final String path, final JsonElement body) {
        boolean removed = false;
        for (final JsonObject response : Json.each(body)) {
            for (final JsonObject candidate : Json.objects(response, "candidates")) {
                removed |= candidate.remove("logprobsResult") != null;
            }
        }
        return removed;
    }

    /**
     * The model in the path. countTokens and batchEmbedContents bodies can name a model per request: they have a
     * model only when every one names the path's model or none, so a model scope cannot be passed by naming an
     * allowed model in the path and another in the body.
     */
    @Override
    public String model(final String path, final JsonObject body) {
        final String model = ProviderDialect.modelFromPath(path);
        final Method method = method(path);
        if (model == null || (method != Method.COUNT_TOKENS && method != Method.BATCH_EMBED)) {
            return model;
        }
        for (final JsonObject request : requests(method, body)) {
            final JsonElement named = request.get("model");
            if (named == null) {
                continue;
            }
            final String value = named.isJsonPrimitive() ? named.getAsString() : null;
            if (value == null || !(value.equals(model) || value.endsWith("/models/" + model) || value.equals("models/" + model))) {
                return null;
            }
        }
        return model;
    }

    @Override
    public Framing framing(final String contentType) {
        return contentType != null && contentType.toLowerCase(Locale.ROOT).contains("text/event-stream") ? new SseFraming() : null;
    }

    @Override
    public StreamDialect streamDialect(final String path) {
        return new Stream();
    }

    /**
     * {@code streamGenerateContent?alt=sse}: each event is a response whose candidates carry text fragments. Text
     * (and thought text) is held per candidate and released when the candidate has a {@code finishReason};
     * function calls arrive whole and are scanned whole.
     */
    static final class Stream implements StreamDialect {

        private final Map<String, JsonObject> templates = new HashMap<>();

        @Override
        public StreamEvent onEvent(final StreamEvent event, final StreamScanner scanner) throws IOException, RedactionException,
                StreamScanner.BlockedException {
            final JsonObject json = event.json();
            if (!(json.get("candidates") instanceof JsonArray candidates)) {
                scanner.finishAll();
                return event;
            }
            final JsonArray kept = new JsonArray();
            for (final JsonElement element : candidates) {
                if (!(element instanceof JsonObject candidate)) {
                    kept.add(element);
                    continue;
                }
                final String group = ProviderDialect.group(Json.integer(candidate, "index", 0));
                if (scanner.action() != ai.philterd.aiproxy.config.ProxyProperties.Action.FLAG) {
                    candidate.remove("logprobsResult");
                }
                templates.put(group, json);
                final JsonObject content = Json.object(candidate, "content");
                if (content != null && content.get("parts") instanceof JsonArray parts) {
                    final JsonArray keptParts = new JsonArray();
                    for (final JsonElement p : parts) {
                        if (p instanceof JsonObject part && part.get("text") instanceof JsonPrimitive text && text.isString()
                                && part.keySet().stream().allMatch(k -> k.equals("text") || k.equals("thought"))) {
                            scanner.appendText(new Key(group, Json.isTrue(part, "thought") ? "thought" : "text"), text.getAsString());
                        } else {
                            if (p instanceof JsonObject part) {
                                // A function call or other whole part: release held text first, to keep the order.
                                scanner.finish(group);
                                final TextSlots slots = new TextSlots();
                                final JsonObject wrapper = new JsonObject();
                                final JsonArray one = new JsonArray();
                                one.add(part);
                                wrapper.add("parts", one);
                                addParts(slots, wrapper);
                                scanner.scanWhole(slots);
                            }
                            keptParts.add(p);
                        }
                    }
                    if (keptParts.isEmpty()) {
                        candidate.remove("content");
                    } else {
                        content.add("parts", keptParts);
                    }
                }
                if (Json.present(candidate, "groundingMetadata")) {
                    final TextSlots slots = new TextSlots();
                    addGrounding(slots, candidate);
                    scanner.scanWhole(slots);
                }
                if (Json.present(candidate, "finishReason")) {
                    scanner.finish(group);
                }
                if (candidate.keySet().stream().anyMatch(k -> !k.equals("index"))) {
                    kept.add(candidate);
                }
            }
            json.add("candidates", kept);
            final boolean more = json.keySet().stream().anyMatch(k -> !k.equals("candidates") && !k.equals("modelVersion")
                    && !k.equals("responseId") && !k.equals("createTime"));
            return kept.isEmpty() && !more ? null : event;
        }

        @Override
        public StreamEvent textEvent(final Key key, final String text) {
            final JsonObject template = templates.get(key.group());
            final JsonObject event = template == null ? new JsonObject() : template.deepCopy();
            event.remove("usageMetadata");
            final JsonObject part = new JsonObject();
            part.addProperty("text", text);
            if (key.field().equals("thought")) {
                part.addProperty("thought", true);
            }
            final JsonArray parts = new JsonArray();
            parts.add(part);
            final JsonObject content = new JsonObject();
            content.addProperty("role", "model");
            content.add("parts", parts);
            final JsonObject candidate = new JsonObject();
            candidate.add("content", content);
            candidate.addProperty("index", Integer.parseInt(key.group()));
            final JsonArray candidates = new JsonArray();
            candidates.add(candidate);
            event.add("candidates", candidates);
            return new StreamEvent(null, event);
        }

        @Override
        public StreamEvent argumentsEvent(final Key key, final String arguments) {
            throw new IllegalStateException("Gemini streams no argument fragments.");
        }

    }

}
