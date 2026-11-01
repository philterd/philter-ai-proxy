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
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.io.IOException;
import java.util.Locale;

/**
 * Anthropic's Messages API ({@code /v1/messages}).
 *
 * <p>Requests: {@code system} (a string or text blocks) and each message's content (a string, or blocks):
 * {@code text}, {@code tool_result} content (a string or text blocks), and {@code tool_use} input. Thinking blocks
 * sent back in a conversation are left alone: Anthropic verifies their signatures, so changing them would make the
 * request fail. Images and documents are not redacted.</p>
 *
 * <p>Responses: {@code text} blocks, {@code tool_use} input, and {@code thinking} text. Redacting a thinking block
 * invalidates its signature, so a client that sends the block back in a later request is refused by Anthropic.</p>
 */
public final class AnthropicDialect implements ProviderDialect {

    @Override
    public TextSlots requestText(final String path, final JsonObject body) {
        final TextSlots slots = new TextSlots();
        slots.addString(body, "system");
        for (final JsonObject block : Json.objects(body, "system")) {
            slots.addString(block, "text");
        }
        for (final JsonObject message : Json.objects(body, "messages")) {
            slots.addString(message, "content");
            for (final JsonObject block : Json.objects(message, "content")) {
                addBlock(slots, block, false);
            }
        }
        return slots;
    }

    private static final java.util.Set<String> MEDIA_BLOCKS = java.util.Set.of("image", "document", "container_upload");

    @Override
    public String mediaPart(final String path, final JsonObject body) {
        for (final JsonObject message : Json.objects(body, "messages")) {
            for (final JsonObject block : Json.objects(message, "content")) {
                final String type = Json.string(block, "type");
                if (type != null && MEDIA_BLOCKS.contains(type)) {
                    return type;
                }
                if ("tool_result".equals(type)) {
                    for (final JsonObject inner : Json.objects(block, "content")) {
                        final String innerType = Json.string(inner, "type");
                        if (innerType != null && MEDIA_BLOCKS.contains(innerType)) {
                            return innerType;
                        }
                    }
                }
            }
        }
        return null;
    }

    private static void addBlock(final TextSlots slots, final JsonObject block, final boolean response) {
        final String type = Json.string(block, "type");
        if (type == null) {
            return;
        }
        switch (type) {
            case "text" -> slots.addString(block, "text");
            case "tool_use", "server_tool_use" -> {
                if (block.get("input") instanceof JsonObject input) {
                    slots.addAllStrings(input);
                }
            }
            case "tool_result" -> {
                slots.addString(block, "content");
                for (final JsonObject inner : Json.objects(block, "content")) {
                    if ("text".equals(Json.string(inner, "type"))) {
                        slots.addString(inner, "text");
                    }
                }
            }
            case "thinking" -> {
                if (response) {
                    slots.addString(block, "thinking");
                }
            }
            default -> { }
        }
    }

    @Override
    public TextSlots responseText(final String path, final JsonElement body) {
        final TextSlots slots = new TextSlots();
        for (final JsonObject response : Json.each(body)) {
            for (final JsonObject block : Json.objects(response, "content")) {
                addBlock(slots, block, true);
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
        return contentType != null && contentType.toLowerCase(Locale.ROOT).contains("text/event-stream") ? new SseFraming() : null;
    }

    @Override
    public StreamDialect streamDialect(final String path) {
        return new Stream();
    }

    /**
     * The Messages stream: {@code content_block_delta} events carry {@code text_delta}, {@code thinking_delta}, and
     * {@code input_json_delta} fragments, held per block and released at the block's {@code content_block_stop}.
     */
    static final class Stream implements StreamDialect {

        @Override
        public StreamEvent onEvent(final StreamEvent event, final StreamScanner scanner) throws IOException, RedactionException,
                StreamScanner.BlockedException {
            final JsonObject json = event.json();
            final String type = Json.string(json, "type") != null ? Json.string(json, "type") : event.type();
            final String group = ProviderDialect.group(Json.integer(json, "index", 0));
            if ("content_block_delta".equals(type) && json.get("delta") instanceof JsonObject delta) {
                final String deltaType = Json.string(delta, "type");
                if ("text_delta".equals(deltaType)) {
                    scanner.appendText(new Key(group, "text"), Json.string(delta, "text"));
                    return null;
                }
                if ("thinking_delta".equals(deltaType)) {
                    scanner.appendText(new Key(group, "thinking"), Json.string(delta, "thinking"));
                    return null;
                }
                if ("input_json_delta".equals(deltaType)) {
                    scanner.appendArguments(new Key(group, "input"), Json.string(delta, "partial_json"));
                    return null;
                }
                if ("citations_delta".equals(deltaType)) {
                    final TextSlots slots = new TextSlots();
                    final JsonObject citation = Json.object(delta, "citation");
                    if (citation != null) {
                        slots.addString(citation, "cited_text");
                    }
                    scanner.scanWhole(slots);
                }
                return event;
            }
            if ("content_block_start".equals(type)) {
                final TextSlots slots = new TextSlots();
                final JsonObject block = Json.object(json, "content_block");
                if (block != null) {
                    addBlock(slots, block, true);
                }
                scanner.scanWhole(slots);
                return event;
            }
            if ("message_start".equals(type)) {
                final JsonObject message = Json.object(json, "message");
                final TextSlots slots = new TextSlots();
                if (message != null) {
                    for (final JsonObject block : Json.objects(message, "content")) {
                        addBlock(slots, block, true);
                    }
                }
                scanner.scanWhole(slots);
                return event;
            }
            if ("content_block_stop".equals(type)) {
                scanner.finish(group);
                return event;
            }
            if ("ping".equals(type)) {
                // A keep-alive: releasing here would split a value that arrives around it.
                return event;
            }
            scanner.finishAll();
            return event;
        }

        @Override
        public StreamEvent textEvent(final Key key, final String text) {
            final JsonObject delta = new JsonObject();
            delta.addProperty("type", key.field().equals("thinking") ? "thinking_delta" : "text_delta");
            delta.add(key.field(), new JsonPrimitive(text));
            return deltaEvent(key, delta);
        }

        @Override
        public StreamEvent argumentsEvent(final Key key, final String arguments) {
            final JsonObject delta = new JsonObject();
            delta.addProperty("type", "input_json_delta");
            delta.addProperty("partial_json", arguments);
            return deltaEvent(key, delta);
        }

        private static StreamEvent deltaEvent(final Key key, final JsonObject delta) {
            final JsonObject event = new JsonObject();
            event.addProperty("type", "content_block_delta");
            event.addProperty("index", Integer.parseInt(key.group()));
            event.add("delta", delta);
            return new StreamEvent("content_block_delta", event);
        }

    }

}
