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
 * Google Gemini and Vertex AI ({@code generateContent} and {@code streamGenerateContent}).
 *
 * <p>Requests: the text of each part of {@code contents} and {@code systemInstruction}, the arguments of
 * {@code functionCall} parts, and the strings in {@code functionResponse.response}. Responses: each candidate's
 * text parts (including thought summaries) and function-call arguments. Inline and file data are not redacted.
 * A {@code streamGenerateContent} response without {@code alt=sse} is a JSON array; it is read whole and scanned
 * as one response.</p>
 */
public final class GeminiDialect implements ProviderDialect {

    @Override
    public TextSlots requestText(final String path, final JsonObject body) {
        final TextSlots slots = new TextSlots();
        for (final JsonObject content : Json.objects(body, "contents")) {
            addParts(slots, content);
        }
        for (final String member : new String[]{"systemInstruction", "system_instruction"}) {
            final JsonObject instruction = Json.object(body, member);
            if (instruction != null) {
                addParts(slots, instruction);
            }
        }
        return slots;
    }

    private static final String[] MEDIA_PARTS = {"inlineData", "inline_data", "fileData", "file_data"};

    @Override
    public String mediaPart(final String path, final JsonObject body) {
        final java.util.List<JsonObject> contents = new java.util.ArrayList<>(Json.objects(body, "contents"));
        for (final String member : new String[]{"systemInstruction", "system_instruction", "content"}) {
            final JsonObject content = Json.object(body, member);
            if (content != null) {
                contents.add(content);
            }
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
            }
        }
        return slots;
    }

    @Override
    public String model(final String path, final JsonObject body) {
        return ProviderDialect.modelFromPath(path);
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
