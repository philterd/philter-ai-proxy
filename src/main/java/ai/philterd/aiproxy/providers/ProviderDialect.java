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
import ai.philterd.aiproxy.stream.Framing;
import ai.philterd.aiproxy.stream.StreamDialect;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Where the text is in one provider's requests and responses. Dialects edit the parsed JSON in place, so every
 * field they do not redact is forwarded as it came.
 */
public interface ProviderDialect {

    /** The text to redact in a request to the path. */
    TextSlots requestText(String path, JsonObject body);

    /**
     * The type of the first image, audio, video, or file part in a request to the path, such as
     * {@code image_url}, or null when it has none. The proxy redacts text only, so these parts are forwarded
     * uninspected unless the request is refused.
     */
    String mediaPart(String path, JsonObject body);

    /** The text to scan in a buffered response from the path (an object, or an array of them). */
    TextSlots responseText(String path, JsonElement body);

    /**
     * Removes data that would reveal text that is redacted or blocked and cannot itself be redacted to match,
     * such as OpenAI's {@code logprobs}.
     * @return Whether anything was removed.
     */
    default boolean removeRevealingData(final String path, final JsonElement body) {
        return false;
    }

    /** The model the request asks for, or null. */
    String model(String path, JsonObject body);

    /** The framing of a streamed response with this content type, or null when it is not a stream. */
    Framing framing(String contentType);

    /** Interprets a stream from the path, or null when streams from it cannot be scanned. One per stream. */
    StreamDialect streamDialect(String path);

    /** The {@code model} member, or null. */
    static String modelMember(final JsonObject body) {
        final JsonElement model = body.get("model");
        return model != null && model.isJsonPrimitive() ? model.getAsString() : null;
    }

    /** The model in a path containing {@code /models/<model>} (Gemini, Vertex AI), or null. */
    static String modelFromPath(final String path) {
        final int idx = path.indexOf("/models/");
        if (idx == -1) {
            return null;
        }
        String rest = path.substring(idx + "/models/".length());
        final int colon = rest.indexOf(':');
        if (colon != -1) {
            rest = rest.substring(0, colon);
        }
        final int slash = rest.indexOf('/');
        if (slash != -1) {
            rest = rest.substring(0, slash);
        }
        return rest.isEmpty() ? null : rest;
    }

    /** A stream group name for an index, padded so groups sort in numeric order. */
    static String group(final int index) {
        return String.format("%08d", index);
    }

}
