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

import ai.philterd.aiproxy.config.ProxyProperties.Action;
import ai.philterd.aiproxy.redaction.RedactionException;
import ai.philterd.aiproxy.stream.StreamDialect;
import ai.philterd.aiproxy.stream.StreamEvent;
import ai.philterd.aiproxy.stream.StreamScanner;
import ai.philterd.aiproxy.stream.StreamScanner.Key;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Streamed chat completions (and the legacy completions endpoint, with {@code text} in place of {@code delta}).
 * Each choice's {@code content} and {@code refusal} are held as text; tool-call arguments are held whole until the
 * choice finishes. Under {@code redact} and {@code block}, {@code logprobs} are removed, since their tokens spell
 * out the text. The chunks that open a tool call (its id, type, and name) are forwarded at once, with empty
 * arguments.
 */
public class OpenAiChatStream implements StreamDialect {

    private static final List<String> TEXT_FIELDS = List.of("content", "refusal");

    private final Map<String, JsonObject> templates = new HashMap<>();

    @Override
    public StreamEvent onEvent(final StreamEvent event, final StreamScanner scanner) throws IOException, RedactionException,
            StreamScanner.BlockedException {
        final JsonObject chunk = event.json();
        if (!(chunk.get("choices") instanceof JsonArray choices) || choices.isEmpty()) {
            // Usage, errors, and anything else without choices: release held text first, to keep the order.
            scanner.finishAll();
            return event;
        }
        boolean forward = false;
        for (final JsonElement element : choices) {
            if (!(element instanceof JsonObject choice)) {
                forward = true;
                continue;
            }
            final String group = ProviderDialect.group(Json.integer(choice, "index", 0));
            templates.put(group, chunk);
            if (scanner.action() != Action.FLAG) {
                OpenAiDialect.nullOut(choice, "logprobs");
            }
            forward |= takeText(choice, group, scanner);
            if (Json.present(choice, "finish_reason")) {
                scanner.finish(group);
                forward = true;
            }
            if (choice.keySet().stream().anyMatch(k -> !k.equals("index") && !k.equals("delta") && !k.equals("text")
                    && !k.equals("finish_reason") && !k.equals("logprobs") && Json.present(choice, k))) {
                forward = true;
            }
        }
        return forward ? event : null;
    }

    /**
     * Moves the choice's streamed text into the scanner.
     * @return Whether the choice still carries something to forward.
     */
    protected boolean takeText(final JsonObject choice, final String group, final StreamScanner scanner)
            throws IOException, RedactionException, StreamScanner.BlockedException {
        if (!(choice.get("delta") instanceof JsonObject delta)) {
            return false;
        }
        for (final String field : TEXT_FIELDS) {
            if (delta.get(field) instanceof JsonPrimitive text && text.isString()) {
                delta.remove(field);
                scanner.appendText(new Key(group, field), text.getAsString());
            }
        }
        holdToolArguments(group, delta, scanner);
        return !delta.isEmpty();
    }

    /** Moves each tool call's argument fragment into the scanner, dropping deltas left empty. */
    private static void holdToolArguments(final String group, final JsonObject delta, final StreamScanner scanner) {
        if (!(delta.get("tool_calls") instanceof JsonArray calls)) {
            return;
        }
        final JsonArray kept = new JsonArray();
        for (final JsonElement element : calls) {
            if (!(element instanceof JsonObject call)) {
                kept.add(element);
                continue;
            }
            final int toolIndex = Json.integer(call, "index", 0);
            if (call.get("function") instanceof JsonObject function
                    && function.get("arguments") instanceof JsonPrimitive arguments && arguments.isString()) {
                scanner.appendArguments(new Key(group, "tool:" + ProviderDialect.group(toolIndex)), arguments.getAsString());
                function.addProperty("arguments", "");
                if (function.keySet().stream().allMatch(k -> k.equals("arguments"))
                        && call.keySet().stream().allMatch(k -> k.equals("index") || k.equals("function"))) {
                    continue;
                }
            }
            kept.add(call);
        }
        if (kept.isEmpty()) {
            delta.remove("tool_calls");
        } else {
            delta.add("tool_calls", kept);
        }
    }

    @Override
    public StreamEvent textEvent(final Key key, final String text) {
        final JsonObject delta = new JsonObject();
        delta.addProperty(key.field(), text);
        return chunk(key.group(), "delta", delta);
    }

    @Override
    public StreamEvent argumentsEvent(final Key key, final String arguments) {
        final JsonObject function = new JsonObject();
        function.addProperty("arguments", arguments);
        final JsonObject call = new JsonObject();
        call.addProperty("index", Integer.parseInt(key.field().substring("tool:".length())));
        call.add("function", function);
        final JsonArray calls = new JsonArray();
        calls.add(call);
        final JsonObject delta = new JsonObject();
        delta.add("tool_calls", calls);
        return chunk(key.group(), "delta", delta);
    }

    /** A chunk shaped like the last one seen for the choice, carrying only the given member. */
    protected StreamEvent chunk(final String group, final String member, final JsonElement value) {
        final JsonObject template = templates.get(group);
        final JsonObject chunk = template == null ? new JsonObject() : template.deepCopy();
        chunk.remove("usage");
        final JsonObject choice = new JsonObject();
        choice.addProperty("index", Integer.parseInt(group));
        choice.add(member, value);
        choice.add("finish_reason", JsonNull.INSTANCE);
        final JsonArray choices = new JsonArray();
        choices.add(choice);
        chunk.add("choices", choices);
        return new StreamEvent(null, chunk);
    }

}
