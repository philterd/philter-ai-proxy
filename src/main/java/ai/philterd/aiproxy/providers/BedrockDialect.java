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
import ai.philterd.aiproxy.stream.EventStreamFraming;
import ai.philterd.aiproxy.stream.Framing;
import ai.philterd.aiproxy.stream.StreamDialect;
import ai.philterd.aiproxy.stream.StreamEvent;
import ai.philterd.aiproxy.stream.StreamScanner;
import ai.philterd.aiproxy.stream.StreamScanner.Key;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.util.Locale;

/**
 * Amazon Bedrock's Converse API ({@code /model/<id>/converse} and {@code /model/<id>/converse-stream}).
 *
 * <p>Requests: {@code system} text, and each message's {@code text} blocks, {@code toolUse} input, and
 * {@code toolResult} content (text and JSON). Reasoning blocks sent back in a conversation are left alone, since
 * Bedrock verifies their signatures. Images, documents, and video are not redacted. Responses: text blocks,
 * {@code toolUse} input, and reasoning text.</p>
 */
public final class BedrockDialect implements ProviderDialect {

    /** The model in {@code /model/<id>/converse}, or null. */
    public static String modelFromPath(final String path) {
        final String[] parts = path.replaceFirst("^/", "").split("/");
        return parts.length >= 2 && parts[0].equals("model") ? parts[1] : null;
    }

    public static boolean isConversePath(final String path) {
        final String[] parts = path.replaceFirst("^/", "").split("/");
        return parts.length == 3 && parts[0].equals("model") && (parts[2].equals("converse") || parts[2].equals("converse-stream"));
    }

    @Override
    public TextSlots requestText(final String path, final JsonObject body) {
        final TextSlots slots = new TextSlots();
        for (final JsonObject block : Json.objects(body, "system")) {
            slots.addString(block, "text");
        }
        for (final JsonObject message : Json.objects(body, "messages")) {
            for (final JsonObject block : Json.objects(message, "content")) {
                addBlock(slots, block, false);
            }
        }
        return slots;
    }

    private static void addBlock(final TextSlots slots, final JsonObject block, final boolean response) {
        slots.addString(block, "text");
        final JsonObject toolUse = Json.object(block, "toolUse");
        if (toolUse != null && toolUse.get("input") instanceof JsonObject input) {
            slots.addAllStrings(input);
        }
        final JsonObject toolResult = Json.object(block, "toolResult");
        if (toolResult != null) {
            for (final JsonObject inner : Json.objects(toolResult, "content")) {
                slots.addString(inner, "text");
                if (inner.get("json") instanceof JsonElement json && !json.isJsonPrimitive()) {
                    slots.addAllStrings(json);
                }
            }
        }
        final JsonObject reasoning = Json.object(block, "reasoningContent");
        if (response && reasoning != null) {
            final JsonObject reasoningText = Json.object(reasoning, "reasoningText");
            if (reasoningText != null) {
                slots.addString(reasoningText, "text");
            }
        }
    }

    @Override
    public TextSlots responseText(final String path, final JsonElement body) {
        final TextSlots slots = new TextSlots();
        for (final JsonObject response : Json.each(body)) {
            final JsonObject output = Json.object(response, "output");
            final JsonObject message = output == null ? null : Json.object(output, "message");
            if (message != null) {
                for (final JsonObject block : Json.objects(message, "content")) {
                    addBlock(slots, block, true);
                }
            }
        }
        return slots;
    }

    @Override
    public String model(final String path, final JsonObject body) {
        return modelFromPath(path);
    }

    @Override
    public Framing framing(final String contentType) {
        return contentType != null && contentType.toLowerCase(Locale.ROOT).contains("vnd.amazon.eventstream")
                ? new EventStreamFraming() : null;
    }

    @Override
    public StreamDialect streamDialect(final String path) {
        return new Stream();
    }

    /**
     * ConverseStream: {@code contentBlockDelta} events carry text, reasoning text, or a fragment of tool-use input,
     * held per content block and released at the block's {@code contentBlockStop}.
     */
    static final class Stream implements StreamDialect {

        @Override
        public StreamEvent onEvent(final StreamEvent event, final StreamScanner scanner) throws IOException, RedactionException,
                StreamScanner.BlockedException {
            final JsonObject json = event.json();
            final String group = ProviderDialect.group(Json.integer(json, "contentBlockIndex", 0));
            if ("contentBlockDelta".equals(event.type()) && json.get("delta") instanceof JsonObject delta) {
                if (Json.string(delta, "text") != null) {
                    scanner.appendText(new Key(group, "text"), Json.string(delta, "text"));
                    return null;
                }
                final JsonObject toolUse = Json.object(delta, "toolUse");
                if (toolUse != null && Json.string(toolUse, "input") != null) {
                    scanner.appendArguments(new Key(group, "toolUse"), Json.string(toolUse, "input"));
                    return null;
                }
                final JsonObject reasoning = Json.object(delta, "reasoningContent");
                if (reasoning != null && Json.string(reasoning, "text") != null) {
                    scanner.appendText(new Key(group, "reasoning"), Json.string(reasoning, "text"));
                    return null;
                }
                return event;
            }
            if ("contentBlockStop".equals(event.type())) {
                scanner.finish(group);
                return event;
            }
            if ("contentBlockStart".equals(event.type())) {
                return event;
            }
            scanner.finishAll();
            return event;
        }

        @Override
        public StreamEvent textEvent(final Key key, final String text) {
            final JsonObject delta = new JsonObject();
            if (key.field().equals("reasoning")) {
                final JsonObject reasoning = new JsonObject();
                reasoning.addProperty("text", text);
                delta.add("reasoningContent", reasoning);
            } else {
                delta.addProperty("text", text);
            }
            return deltaEvent(key, delta);
        }

        @Override
        public StreamEvent argumentsEvent(final Key key, final String arguments) {
            final JsonObject toolUse = new JsonObject();
            toolUse.addProperty("input", arguments);
            final JsonObject delta = new JsonObject();
            delta.add("toolUse", toolUse);
            return deltaEvent(key, delta);
        }

        private static StreamEvent deltaEvent(final Key key, final JsonObject delta) {
            final JsonObject event = new JsonObject();
            event.addProperty("contentBlockIndex", Integer.parseInt(key.group()));
            event.add("delta", delta);
            return new StreamEvent("contentBlockDelta", event);
        }

    }

}
