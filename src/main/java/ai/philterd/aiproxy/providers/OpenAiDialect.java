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

import ai.philterd.aiproxy.proxy.OpenAiChat;
import ai.philterd.aiproxy.proxy.TextSlots;
import ai.philterd.aiproxy.stream.Framing;
import ai.philterd.aiproxy.stream.SseFraming;
import ai.philterd.aiproxy.stream.StreamDialect;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.Locale;

/**
 * OpenAI, Azure OpenAI, and OpenAI-compatible providers. Which fields hold text depends on the endpoint, decided
 * by the end of the path as in earlier versions.
 */
public final class OpenAiDialect implements ProviderDialect {

    public enum Endpoint {
        CHAT, RESPONSES, EMBEDDINGS, MODERATIONS, IMAGE_GENERATIONS, AUDIO_SPEECH, COMPLETIONS, OTHER
    }

    public static Endpoint endpoint(final String path) {
        final String p = path.toLowerCase(Locale.ROOT);
        if (p.endsWith("/chat/completions")) {
            return Endpoint.CHAT;
        } else if (p.endsWith("/responses")) {
            return Endpoint.RESPONSES;
        } else if (p.endsWith("/embeddings")) {
            return Endpoint.EMBEDDINGS;
        } else if (p.endsWith("/moderations")) {
            return Endpoint.MODERATIONS;
        } else if (p.endsWith("/images/generations")) {
            return Endpoint.IMAGE_GENERATIONS;
        } else if (p.endsWith("/audio/speech")) {
            return Endpoint.AUDIO_SPEECH;
        } else if (p.endsWith("/completions")) {
            return Endpoint.COMPLETIONS;
        }
        return Endpoint.OTHER;
    }

    @Override
    public TextSlots requestText(final String path, final JsonObject body) {
        return switch (endpoint(path)) {
            case CHAT -> OpenAiChat.requestText(body);
            case RESPONSES -> responsesRequest(body);
            case EMBEDDINGS, MODERATIONS, AUDIO_SPEECH -> strings(body, "input");
            case IMAGE_GENERATIONS, COMPLETIONS -> strings(body, "prompt");
            case OTHER -> new TextSlots();
        };
    }

    /** Chat content part types that carry text. Every other part (image_url, input_audio, file, ...) is media. */
    private static final java.util.Set<String> CHAT_TEXT_PARTS = java.util.Set.of("text", "input_text", "output_text", "refusal");

    /** Responses API types that carry media, wherever they appear in {@code input}. */
    private static final java.util.Set<String> RESPONSES_MEDIA = java.util.Set.of("input_image", "input_file", "input_audio", "computer_screenshot");

    @Override
    public String mediaPart(final String path, final JsonObject body) {
        return switch (endpoint(path)) {
            case CHAT -> {
                for (final JsonObject message : Json.objects(body, "messages")) {
                    for (final JsonObject part : Json.objects(message, "content")) {
                        final String type = Json.string(part, "type");
                        if (type != null && !CHAT_TEXT_PARTS.contains(type)) {
                            yield type;
                        }
                    }
                }
                yield null;
            }
            case RESPONSES -> findType(body.get("input"), RESPONSES_MEDIA);
            case MODERATIONS -> {
                for (final JsonObject input : Json.objects(body, "input")) {
                    final String type = Json.string(input, "type");
                    if (type != null && !type.equals("text")) {
                        yield type;
                    }
                }
                yield null;
            }
            default -> null;
        };
    }

    /** The first {@code type} in the set found in any object nested in the element, or null. */
    private static String findType(final JsonElement element, final java.util.Set<String> types) {
        if (element instanceof JsonObject object) {
            final String type = Json.string(object, "type");
            if (type != null && types.contains(type)) {
                return type;
            }
            for (final java.util.Map.Entry<String, JsonElement> member : object.entrySet()) {
                final String found = findType(member.getValue(), types);
                if (found != null) {
                    return found;
                }
            }
        } else if (element instanceof JsonArray array) {
            for (final JsonElement item : array) {
                final String found = findType(item, types);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    /** The strings in {@code body.member}: a string, or an array of strings. Token-ID arrays are left alone. */
    private static TextSlots strings(final JsonObject body, final String member) {
        final TextSlots slots = new TextSlots();
        if (body.get(member) instanceof JsonPrimitive) {
            slots.addString(body, member);
        } else if (body.get(member) instanceof JsonArray array) {
            slots.addAllStrings(array);
        }
        return slots;
    }

    private static TextSlots responsesRequest(final JsonObject body) {
        final TextSlots slots = new TextSlots();
        slots.addString(body, "instructions");
        if (body.get("input") instanceof JsonPrimitive) {
            slots.addString(body, "input");
        }
        for (final JsonObject item : Json.objects(body, "input")) {
            addResponsesItem(slots, item);
        }
        return slots;
    }

    /** An input or output item of the Responses API. */
    private static void addResponsesItem(final TextSlots slots, final JsonObject item) {
        final String type = Json.string(item, "type");
        if (type == null || type.equals("message")) {
            slots.addString(item, "content");
            for (final JsonObject part : Json.objects(item, "content")) {
                // input_text, output_text, and refusal parts. Images and files are not redacted.
                slots.addString(part, "text");
                slots.addString(part, "refusal");
            }
        } else if (type.equals("function_call") || type.equals("custom_tool_call")) {
            slots.addJsonString(item, "arguments");
            slots.addString(item, "input");
        } else if (type.equals("function_call_output") || type.equals("custom_tool_call_output")) {
            slots.addJsonString(item, "output");
        } else if (type.equals("reasoning")) {
            for (final JsonObject summary : Json.objects(item, "summary")) {
                slots.addString(summary, "text");
            }
        }
    }

    @Override
    public TextSlots responseText(final String path, final JsonElement body) {
        final TextSlots slots = new TextSlots();
        if (!(body instanceof JsonObject response)) {
            return slots;
        }
        switch (endpoint(path)) {
            case CHAT -> {
                return OpenAiChat.responseText(response);
            }
            case COMPLETIONS -> Json.objects(response, "choices").forEach(choice -> slots.addString(choice, "text"));
            case RESPONSES -> addResponsesOutput(slots, response);
            case IMAGE_GENERATIONS -> Json.objects(response, "data").forEach(image -> slots.addString(image, "revised_prompt"));
            default -> { }
        }
        return slots;
    }

    static void addResponsesOutput(final TextSlots slots, final JsonObject response) {
        for (final JsonObject item : Json.objects(response, "output")) {
            addResponsesItem(slots, item);
        }
    }

    @Override
    public boolean removeRevealingData(final String path, final JsonElement body) {
        if (!(body instanceof JsonObject response)) {
            return false;
        }
        boolean removed = OpenAiChat.removeLogprobs(response);
        for (final JsonObject item : Json.objects(response, "output")) {
            for (final JsonObject part : Json.objects(item, "content")) {
                removed |= nullOut(part, "logprobs");
            }
        }
        return removed;
    }

    static boolean nullOut(final JsonObject object, final String member) {
        if (object.has(member) && !object.get(member).isJsonNull()) {
            if (object.get(member) instanceof JsonArray) {
                object.add(member, new JsonArray());
            } else {
                object.add(member, JsonNull.INSTANCE);
            }
            return true;
        }
        return false;
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
        return switch (endpoint(path)) {
            case CHAT -> new OpenAiChatStream();
            case COMPLETIONS -> new OpenAiCompletionsStream();
            case RESPONSES -> new OpenAiResponsesStream();
            default -> null;
        };
    }

}
