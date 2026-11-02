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
package ai.philterd.aiproxy.proxy;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/** Where the text is in OpenAI chat completions requests and responses. */
public final class OpenAiChat {

    private OpenAiChat() {
    }

    /**
     * The text of a chat completions request: each message's content (a string, or the {@code text} of each
     * content part), refusal, and tool-call and function-call arguments.
     */
    public static TextSlots requestText(final JsonObject request) {
        final TextSlots slots = new TextSlots();
        if (request.get("messages") instanceof JsonArray messages) {
            for (final JsonElement element : messages) {
                if (element instanceof JsonObject message) {
                    addMessage(slots, message);
                }
            }
        }
        // Predicted Outputs: a string, or text parts.
        if (request.get("prediction") instanceof JsonObject prediction) {
            addContent(slots, prediction);
        }
        return slots;
    }

    /**
     * The text of a (non-streaming) chat completions response: each choice's message, read the same way as a
     * request message (content, content parts, refusal, tool-call and function-call arguments).
     */
    public static TextSlots responseText(final JsonObject response) {
        final TextSlots slots = new TextSlots();
        if (response.get("choices") instanceof JsonArray choices) {
            for (final JsonElement element : choices) {
                if (element instanceof JsonObject choice && choice.get("message") instanceof JsonObject message) {
                    addMessage(slots, message);
                }
            }
        }
        return slots;
    }

    /**
     * Removes each choice's {@code logprobs}: their tokens spell out the text, so they would reveal what was
     * redacted, and they cannot be redacted to match.
     * @return Whether any were removed.
     */
    public static boolean removeLogprobs(final JsonObject response) {
        boolean removed = false;
        if (response.get("choices") instanceof JsonArray choices) {
            for (final JsonElement element : choices) {
                if (element instanceof JsonObject choice && choice.has("logprobs") && !choice.get("logprobs").isJsonNull()) {
                    choice.add("logprobs", com.google.gson.JsonNull.INSTANCE);
                    removed = true;
                }
            }
        }
        return removed;
    }

    private static void addMessage(final TextSlots slots, final JsonObject message) {
        addContent(slots, message);
        slots.addString(message, "refusal");
        // Reasoning from OpenAI-compatible servers (vLLM, DeepSeek, Ollama, OpenRouter).
        slots.addString(message, "reasoning_content");
        slots.addString(message, "reasoning");
        if (message.get("tool_calls") instanceof JsonArray toolCalls) {
            for (final JsonElement call : toolCalls) {
                if (call instanceof JsonObject object && object.get("function") instanceof JsonObject function) {
                    slots.addJsonString(function, "arguments");
                }
            }
        }
        if (message.get("function_call") instanceof JsonObject functionCall) {
            slots.addJsonString(functionCall, "arguments");
        }
    }

    /** {@code object.content}: a string, or parts whose text is in {@code text} (or {@code refusal}). */
    private static void addContent(final TextSlots slots, final JsonObject object) {
        slots.addString(object, "content");
        if (object.get("content") instanceof JsonArray parts) {
            for (final JsonElement part : parts) {
                if (part instanceof JsonObject p) {
                    // text, input_text, and output_text parts carry "text"; refusal parts carry "refusal". Images and
                    // audio are not redacted.
                    slots.addString(p, "text");
                    slots.addString(p, "refusal");
                }
            }
        }
    }

    /** The {@code model} member, or null. */
    public static String model(final JsonObject request) {
        final JsonElement model = request.get("model");
        return model != null && model.isJsonPrimitive() ? model.getAsString() : null;
    }

}
