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
import ai.philterd.aiproxy.stream.NdjsonFraming;
import ai.philterd.aiproxy.stream.StreamDialect;
import ai.philterd.aiproxy.stream.StreamEvent;
import ai.philterd.aiproxy.stream.StreamScanner;
import ai.philterd.aiproxy.stream.StreamScanner.Key;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

/**
 * Ollama's {@code /api/generate} and {@code /api/chat}. Requests: {@code prompt} and {@code system}, or each
 * message's {@code content} and tool-call arguments. Responses: {@code response} and {@code thinking}, or the
 * message's {@code content}, {@code thinking}, and tool-call arguments. Images are not redacted. Ollama streams by
 * default, as newline-delimited JSON.
 */
public final class OllamaDialect implements ProviderDialect {

    private static boolean isChat(final String path) {
        return path.endsWith("/api/chat");
    }

    @Override
    public TextSlots requestText(final String path, final JsonObject body) {
        final TextSlots slots = new TextSlots();
        if (isChat(path)) {
            for (final JsonObject message : Json.objects(body, "messages")) {
                addMessage(slots, message);
            }
        } else {
            slots.addString(body, "prompt");
            slots.addString(body, "system");
        }
        return slots;
    }

    @Override
    public String mediaPart(final String path, final JsonObject body) {
        if (hasImages(body)) {
            return "images";
        }
        for (final JsonObject message : Json.objects(body, "messages")) {
            if (hasImages(message)) {
                return "images";
            }
        }
        return null;
    }

    private static boolean hasImages(final JsonObject object) {
        final com.google.gson.JsonArray images = Json.array(object, "images");
        return images != null && !images.isEmpty();
    }

    private static void addMessage(final TextSlots slots, final JsonObject message) {
        slots.addString(message, "content");
        slots.addString(message, "thinking");
        for (final JsonObject call : Json.objects(message, "tool_calls")) {
            final JsonObject function = Json.object(call, "function");
            if (function != null && function.get("arguments") instanceof JsonObject arguments) {
                slots.addAllStrings(arguments);
            }
        }
    }

    @Override
    public TextSlots responseText(final String path, final JsonElement body) {
        final TextSlots slots = new TextSlots();
        for (final JsonObject response : Json.each(body)) {
            slots.addString(response, "response");
            slots.addString(response, "thinking");
            final JsonObject message = Json.object(response, "message");
            if (message != null) {
                addMessage(slots, message);
            }
        }
        return slots;
    }

    @Override
    public String model(final String path, final JsonObject body) {
        return ProviderDialect.modelMember(body);
    }

    @Override
    public Framing framing(final String contentType) {
        return contentType != null && contentType.toLowerCase(Locale.ROOT).contains("ndjson") ? new NdjsonFraming() : null;
    }

    @Override
    public StreamDialect streamDialect(final String path) {
        return new Stream(isChat(path));
    }

    /** Each line carries a fragment; the last line has {@code "done": true}. */
    static final class Stream implements StreamDialect {

        private static final String GROUP = ProviderDialect.group(0);
        private final boolean chat;
        private JsonObject template;

        Stream(final boolean chat) {
            this.chat = chat;
        }

        @Override
        public StreamEvent onEvent(final StreamEvent event, final StreamScanner scanner) throws IOException, RedactionException,
                StreamScanner.BlockedException {
            final JsonObject json = event.json();
            template = json;
            final JsonObject holder = chat ? Json.object(json, "message") : json;
            boolean whole = false;
            if (holder != null) {
                for (final String field : List.of(chat ? "content" : "response", "thinking")) {
                    if (holder.get(field) instanceof JsonPrimitive text && text.isString()) {
                        scanner.appendText(new Key(GROUP, field), text.getAsString());
                        holder.addProperty(field, "");
                    }
                }
                if (chat && holder.has("tool_calls")) {
                    // Tool calls arrive whole: release held text first, to keep the order, then scan them.
                    scanner.finish(GROUP);
                    final TextSlots slots = new TextSlots();
                    addMessage(slots, holder);
                    scanner.scanWhole(slots);
                    whole = true;
                }
            }
            if (Json.isTrue(json, "done")) {
                scanner.finishAll();
                return event;
            }
            return whole ? event : null;
        }

        @Override
        public StreamEvent textEvent(final Key key, final String text) {
            final JsonObject event = template == null ? new JsonObject() : template.deepCopy();
            event.addProperty("done", false);
            for (final String stat : List.of("done_reason", "total_duration", "load_duration", "prompt_eval_count",
                    "prompt_eval_duration", "eval_count", "eval_duration", "context")) {
                event.remove(stat);
            }
            if (chat) {
                final JsonObject message = new JsonObject();
                message.addProperty("role", "assistant");
                message.addProperty("content", key.field().equals("content") ? text : "");
                if (key.field().equals("thinking")) {
                    message.addProperty("thinking", text);
                }
                event.add("message", message);
            } else {
                event.addProperty("response", key.field().equals("response") ? text : "");
                if (key.field().equals("thinking")) {
                    event.addProperty("thinking", text);
                } else {
                    event.remove("thinking");
                }
            }
            return new StreamEvent(null, event);
        }

        @Override
        public StreamEvent argumentsEvent(final Key key, final String arguments) {
            throw new IllegalStateException("Ollama streams no argument fragments.");
        }

    }

}
