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
 * Amazon Bedrock's Converse API ({@code /model/<id>/converse} and {@code /model/<id>/converse-stream}), and
 * InvokeModel ({@code /model/<id>/invoke} and {@code /model/<id>/invoke-with-response-stream}) for the model
 * families whose native bodies the proxy reads.
 *
 * <p>Converse requests: {@code system} text, and each message's {@code text} blocks, {@code toolUse} input, and
 * {@code toolResult} content (text and JSON). Reasoning blocks sent back in a conversation are left alone, since
 * Bedrock verifies their signatures. Images, documents, and video are not redacted. Responses: text blocks,
 * {@code toolUse} input, and reasoning text.</p>
 *
 * <p>InvokeModel bodies are the model's own: Anthropic Claude's are the Messages API's, read as
 * {@link AnthropicDialect} reads them, and a response stream carries Messages stream events, base64-encoded in each
 * {@code chunk}. Amazon Titan and Cohere embedding requests have their input text redacted. Other families are not
 * supported.</p>
 */
public final class BedrockDialect implements ProviderDialect {

    private static final AnthropicDialect ANTHROPIC = new AnthropicDialect();

    /** The Messages API path, for reading Claude's native bodies with {@link AnthropicDialect}. */
    private static final String MESSAGES = "/v1/messages";

    enum Operation {
        CONVERSE, CONVERSE_STREAM, INVOKE, INVOKE_STREAM
    }

    /** The model families whose InvokeModel bodies the proxy reads. */
    enum Family {
        ANTHROPIC, TITAN_EMBED, COHERE_EMBED, OTHER
    }

    /** The model in {@code /model/<id>/<operation>}, or null. */
    public static String modelFromPath(final String path) {
        final String[] parts = path.replaceFirst("^/", "").split("/");
        return parts.length >= 2 && parts[0].equals("model") ? parts[1] : null;
    }

    /** Whether the path is a Bedrock runtime model path, {@code /model/<id>/<operation>}. */
    public static boolean isModelPath(final String path) {
        final String[] parts = path.replaceFirst("^/", "").split("/");
        return parts.length == 3 && parts[0].equals("model") && !parts[1].isEmpty() && !parts[2].isEmpty();
    }

    static Operation operation(final String path) {
        if (!isModelPath(path)) {
            return null;
        }
        return switch (path.substring(path.lastIndexOf('/') + 1)) {
            case "converse" -> Operation.CONVERSE;
            case "converse-stream" -> Operation.CONVERSE_STREAM;
            case "invoke" -> Operation.INVOKE;
            case "invoke-with-response-stream" -> Operation.INVOKE_STREAM;
            default -> null;
        };
    }

    /**
     * The family of a model ID such as {@code anthropic.claude-3-haiku-20240307-v1:0}, or a cross-region inference
     * profile ID such as {@code us.anthropic.claude-sonnet-4-20250514-v1:0}. An ARN is not recognized.
     */
    static Family family(final String model) {
        if (model == null) {
            return Family.OTHER;
        }
        final String id = model.toLowerCase(Locale.ROOT);
        for (final String candidate : new String[]{id, id.substring(id.indexOf('.') + 1)}) {
            if (candidate.startsWith("anthropic.")) {
                return Family.ANTHROPIC;
            } else if (candidate.startsWith("amazon.titan-embed-")) {
                return Family.TITAN_EMBED;
            } else if (candidate.startsWith("cohere.embed-")) {
                return Family.COHERE_EMBED;
            }
        }
        return Family.OTHER;
    }

    private static boolean isInvoke(final String path) {
        final Operation operation = operation(path);
        return operation == Operation.INVOKE || operation == Operation.INVOKE_STREAM;
    }

    @Override
    public TextSlots requestText(final String path, final JsonObject body) {
        if (isInvoke(path)) {
            return invokeRequestText(family(modelFromPath(path)), body);
        }
        final TextSlots slots = new TextSlots();
        for (final JsonObject block : Json.objects(body, "system")) {
            slots.addString(block, "text");
            addGuardContent(slots, block);
        }
        for (final JsonObject message : Json.objects(body, "messages")) {
            for (final JsonObject block : Json.objects(message, "content")) {
                addBlock(slots, block, false);
            }
        }
        return slots;
    }

    private static TextSlots invokeRequestText(final Family family, final JsonObject body) {
        return switch (family) {
            case ANTHROPIC -> {
                final TextSlots slots = ANTHROPIC.requestText(MESSAGES, body);
                // Legacy Text Completions models (Claude 2, Instant) take a prompt string instead of messages.
                slots.addString(body, "prompt");
                yield slots;
            }
            case TITAN_EMBED -> {
                final TextSlots slots = new TextSlots();
                slots.addString(body, "inputText");
                yield slots;
            }
            case COHERE_EMBED -> {
                final TextSlots slots = new TextSlots();
                if (body.get("texts") instanceof com.google.gson.JsonArray texts) {
                    slots.addAllStrings(texts);
                }
                // Embed v4's mixed inputs: the text of each text part.
                for (final JsonObject input : Json.objects(body, "inputs")) {
                    for (final JsonObject part : Json.objects(input, "content")) {
                        if ("text".equals(Json.string(part, "type"))) {
                            slots.addString(part, "text");
                        }
                    }
                }
                yield slots;
            }
            case OTHER -> new TextSlots();
        };
    }

    private static final String[] MEDIA_BLOCKS = {"image", "document", "video"};

    /**
     * Converse, and InvokeModel for Claude, Titan embeddings, and Cohere embeddings. Embedding models do not stream,
     * so their response-stream path is not supported.
     */
    @Override
    public boolean supports(final String method, final String path) {
        final Operation operation = operation(path);
        if (!"POST".equals(method) || operation == null) {
            return false;
        }
        final Family family = family(modelFromPath(path));
        return switch (operation) {
            case CONVERSE, CONVERSE_STREAM -> true;
            case INVOKE -> family != Family.OTHER;
            case INVOKE_STREAM -> family == Family.ANTHROPIC;
        };
    }

    @Override
    public String mediaPart(final String path, final JsonObject body) {
        if (isInvoke(path)) {
            return switch (family(modelFromPath(path))) {
                case ANTHROPIC -> ANTHROPIC.mediaPart(MESSAGES, body);
                case TITAN_EMBED -> Json.present(body, "inputImage") ? "inputImage" : null;
                case COHERE_EMBED -> {
                    final com.google.gson.JsonArray images = Json.array(body, "images");
                    if (images != null && !images.isEmpty()) {
                        yield "images";
                    }
                    for (final JsonObject input : Json.objects(body, "inputs")) {
                        for (final JsonObject part : Json.objects(input, "content")) {
                            final String type = Json.string(part, "type");
                            if (type != null && !type.equals("text")) {
                                yield type;
                            }
                        }
                    }
                    yield null;
                }
                case OTHER -> null;
            };
        }
        for (final JsonObject block : Json.objects(body, "system")) {
            if (mediaMember(Json.object(block, "guardContent")) != null) {
                return mediaMember(Json.object(block, "guardContent"));
            }
        }
        for (final JsonObject message : Json.objects(body, "messages")) {
            for (final JsonObject block : Json.objects(message, "content")) {
                if (mediaMember(block) != null) {
                    return mediaMember(block);
                }
                if (mediaMember(Json.object(block, "guardContent")) != null) {
                    return mediaMember(Json.object(block, "guardContent"));
                }
                for (final JsonObject inner : Json.objects(Json.object(block, "toolResult"), "content")) {
                    if (mediaMember(inner) != null) {
                        return mediaMember(inner);
                    }
                }
            }
        }
        return null;
    }

    private static String mediaMember(final JsonObject block) {
        if (block == null) {
            return null;
        }
        for (final String member : MEDIA_BLOCKS) {
            if (Json.present(block, member)) {
                return member;
            }
        }
        return null;
    }

    /** A guardrail-evaluated block's text ({@code guardContent.text.text}). */
    private static void addGuardContent(final TextSlots slots, final JsonObject block) {
        final JsonObject text = Json.object(Json.object(block, "guardContent"), "text");
        if (text != null) {
            slots.addString(text, "text");
        }
    }

    private static void addBlock(final TextSlots slots, final JsonObject block, final boolean response) {
        slots.addString(block, "text");
        addGuardContent(slots, block);
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
        if (isInvoke(path)) {
            // Embeddings carry no text.
            if (family(modelFromPath(path)) != Family.ANTHROPIC) {
                return new TextSlots();
            }
            final TextSlots slots = ANTHROPIC.responseText(MESSAGES, body);
            for (final JsonObject response : Json.each(body)) {
                // A legacy Text Completions response.
                slots.addString(response, "completion");
            }
            return slots;
        }
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

    /** A guardrail trace in a Converse response, or an InvokeModel response's, which can quote the text it matched. */
    private static final String[] TRACES = {"trace", "amazon-bedrock-trace"};

    /** Removes guardrail traces, which quote text the scan does not read. */
    @Override
    public boolean removeRevealingData(final String path, final JsonElement body) {
        boolean removed = false;
        for (final JsonObject response : Json.each(body)) {
            removed |= removeTraces(response);
        }
        return removed;
    }

    static boolean removeTraces(final JsonObject json) {
        boolean removed = false;
        for (final String trace : TRACES) {
            removed |= json.remove(trace) != null;
        }
        return removed;
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
        if (operation(path) == Operation.INVOKE_STREAM) {
            return family(modelFromPath(path)) == Family.ANTHROPIC ? new InvokeStream(new AnthropicDialect.Stream()) : null;
        }
        return new Stream();
    }

    /**
     * InvokeModelWithResponseStream: each {@code chunk} event's {@code bytes} is a base64-encoded event of the
     * model's own stream, handled by the model's stream dialect and encoded back.
     */
    static final class InvokeStream implements StreamDialect {

        private final StreamDialect inner;

        InvokeStream(final StreamDialect inner) {
            this.inner = inner;
        }

        @Override
        public StreamEvent onEvent(final StreamEvent event, final StreamScanner scanner) throws IOException, RedactionException,
                StreamScanner.BlockedException, StreamScanner.UnscannableException {
            // Under flag, nothing is changed or refused: what cannot be read is forwarded as it came.
            final boolean flag = scanner.action() == ai.philterd.aiproxy.config.ProxyProperties.Action.FLAG;
            final String bytes = Json.string(event.json(), "bytes");
            if (!"chunk".equals(event.type()) || bytes == null) {
                return unreadable(event, flag);
            }
            final JsonObject decoded;
            try {
                final JsonElement element = ai.philterd.aiproxy.proxy.StrictJson.parse(new String(
                        java.util.Base64.getDecoder().decode(bytes), java.nio.charset.StandardCharsets.UTF_8));
                if (element == null || !element.isJsonObject()) {
                    return unreadable(event, flag);
                }
                decoded = element.getAsJsonObject();
            } catch (final IllegalArgumentException e) {
                return unreadable(event, flag);
            }
            if (Json.string(decoded, "type") == null) {
                // Not a Messages stream event, such as a legacy Text Completions chunk: its text cannot be scanned.
                return unreadable(event, flag);
            }
            if (scanner.action() != ai.philterd.aiproxy.config.ProxyProperties.Action.FLAG) {
                // The last chunk carries a guardrail trace when tracing is on.
                removeTraces(decoded);
            }
            final StreamEvent out = inner.onEvent(new StreamEvent(Json.string(decoded, "type"), decoded), scanner);
            if (out == null) {
                return null;
            }
            // Other members of the chunk, such as Bedrock's padding, are kept.
            event.json().addProperty("bytes", encode(out.json()));
            return event;
        }

        private static StreamEvent unreadable(final StreamEvent event, final boolean flag) throws StreamScanner.UnscannableException {
            if (flag) {
                return event;
            }
            throw new StreamScanner.UnscannableException();
        }

        @Override
        public StreamEvent textEvent(final Key key, final String text) {
            return chunk(inner.textEvent(key, text));
        }

        @Override
        public StreamEvent argumentsEvent(final Key key, final String arguments) {
            return chunk(inner.argumentsEvent(key, arguments));
        }

        private static StreamEvent chunk(final StreamEvent event) {
            final JsonObject chunk = new JsonObject();
            chunk.addProperty("bytes", encode(event.json()));
            return new StreamEvent("chunk", chunk);
        }

        private static String encode(final JsonObject json) {
            return java.util.Base64.getEncoder().encodeToString(json.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }

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
            if (scanner.action() != ai.philterd.aiproxy.config.ProxyProperties.Action.FLAG) {
                // The metadata event carries a guardrail trace when tracing is on.
                removeTraces(json);
            }
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
