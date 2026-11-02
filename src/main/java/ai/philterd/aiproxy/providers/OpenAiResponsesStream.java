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
import ai.philterd.aiproxy.proxy.TextSlots;
import ai.philterd.aiproxy.redaction.RedactionException;
import ai.philterd.aiproxy.stream.StreamDialect;
import ai.philterd.aiproxy.stream.StreamEvent;
import ai.philterd.aiproxy.stream.StreamScanner;
import ai.philterd.aiproxy.stream.StreamScanner.Key;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * The Responses API streamed. Text deltas ({@code response.output_text.delta}, {@code response.refusal.delta},
 * {@code response.reasoning_summary_text.delta}) are held per output item and content part; function-call
 * argument deltas are held whole. Events that repeat the full text ({@code .done} events, finished items and
 * parts, and the final {@code response.completed}) are scanned whole. Under {@code redact} and {@code block},
 * {@code logprobs} are removed. Released text is sent as delta events copied from the last delta for its part, so
 * their {@code sequence_number} repeats that delta's.
 */
public final class OpenAiResponsesStream implements StreamDialect {

    private final Map<String, JsonObject> templates = new HashMap<>();

    private static String group(final JsonObject event) {
        return ProviderDialect.group(Json.integer(event, "output_index", 0)) + ":"
                + ProviderDialect.group(Json.integer(event, "content_index", Json.integer(event, "summary_index", 0)));
    }

    @Override
    public StreamEvent onEvent(final StreamEvent event, final StreamScanner scanner) throws IOException, RedactionException,
            StreamScanner.BlockedException {
        final JsonObject json = event.json();
        final String type = Json.string(json, "type") != null ? Json.string(json, "type") : event.type();
        if (type == null) {
            scanner.finishAll();
            return event;
        }
        if (scanner.action() != Action.FLAG) {
            OpenAiDialect.nullOut(json, "logprobs");
        }
        switch (type) {
            case "response.output_text.delta", "response.refusal.delta", "response.reasoning_summary_text.delta",
                 "response.reasoning_text.delta" -> {
                final String group = group(json);
                templates.put(group, json);
                scanner.appendText(new Key(group, type), Json.string(json, "delta"));
                return null;
            }
            case "response.function_call_arguments.delta", "response.custom_tool_call_input.delta",
                 "response.mcp_call_arguments.delta" -> {
                final String group = group(json);
                templates.put(group, json);
                scanner.appendArguments(new Key(group, type), Json.string(json, "delta"));
                return null;
            }
            case "response.output_text.done", "response.refusal.done", "response.reasoning_summary_text.done",
                 "response.reasoning_text.done" -> {
                scanner.finish(group(json));
                final TextSlots slots = new TextSlots();
                slots.addString(json, "text");
                slots.addString(json, "refusal");
                scanner.scanWhole(slots);
                return event;
            }
            case "response.function_call_arguments.done", "response.custom_tool_call_input.done",
                 "response.mcp_call_arguments.done" -> {
                scanner.finish(group(json));
                final TextSlots slots = new TextSlots();
                slots.addJsonString(json, "arguments");
                slots.addString(json, "input");
                scanner.scanWhole(slots);
                return event;
            }
            case "response.content_part.added", "response.content_part.done",
                 "response.reasoning_summary_part.added", "response.reasoning_summary_part.done" -> {
                if (type.endsWith(".done")) {
                    scanner.finish(group(json));
                }
                final TextSlots slots = new TextSlots();
                final JsonObject part = Json.object(json, "part");
                if (part != null) {
                    slots.addString(part, "text");
                    slots.addString(part, "refusal");
                    if (scanner.action() != Action.FLAG) {
                        OpenAiDialect.nullOut(part, "logprobs");
                    }
                }
                scanner.scanWhole(slots);
                return event;
            }
            case "response.output_item.added", "response.output_item.done" -> {
                if (type.endsWith(".done")) {
                    finishItem(json, scanner);
                }
                final JsonObject item = Json.object(json, "item");
                if (item != null) {
                    final JsonObject wrapper = new JsonObject();
                    final com.google.gson.JsonArray output = new com.google.gson.JsonArray();
                    output.add(item);
                    wrapper.add("output", output);
                    scanWholeResponse(wrapper, scanner);
                }
                return event;
            }
            default -> {
                final JsonObject response = Json.object(json, "response");
                if (response != null) {
                    // response.created, response.in_progress, response.completed, and the like carry the response.
                    scanner.finishAll();
                    scanWholeResponse(response, scanner);
                }
                return event;
            }
        }
    }

    private static void finishItem(final JsonObject json, final StreamScanner scanner) throws IOException, RedactionException,
            StreamScanner.BlockedException {
        final String prefix = ProviderDialect.group(Json.integer(json, "output_index", 0)) + ":";
        for (final String group : scanner.groups()) {
            if (group.startsWith(prefix)) {
                scanner.finish(group);
            }
        }
    }

    private static void scanWholeResponse(final JsonObject response, final StreamScanner scanner) throws RedactionException,
            StreamScanner.BlockedException {
        final TextSlots slots = new TextSlots();
        OpenAiDialect.addResponsesOutput(slots, response);
        if (scanner.action() != Action.FLAG) {
            for (final JsonObject item : Json.objects(response, "output")) {
                for (final JsonObject part : Json.objects(item, "content")) {
                    OpenAiDialect.nullOut(part, "logprobs");
                }
            }
        }
        scanner.scanWhole(slots);
    }

    @Override
    public StreamEvent textEvent(final Key key, final String text) {
        final JsonObject event = templates.get(key.group()).deepCopy();
        event.addProperty("type", key.field());
        event.addProperty("delta", text);
        return new StreamEvent(event.get("type").getAsString(), event);
    }

    @Override
    public StreamEvent argumentsEvent(final Key key, final String arguments) {
        return textEvent(key, arguments);
    }

}
