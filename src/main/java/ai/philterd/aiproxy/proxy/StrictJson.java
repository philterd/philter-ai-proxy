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

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.Strictness;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import java.io.IOException;
import java.io.StringReader;

/**
 * Parses the JSON the proxy reads from clients and providers, strictly (RFC 8259). A lenient parse would accept
 * malformed JSON, such as unquoted or single-quoted values, comments, or raw control characters in strings, and the
 * proxy would then forward its own corrected serialization instead of what was sent.
 */
public final class StrictJson {

    private static final TypeAdapter<JsonElement> ADAPTER = new Gson().getAdapter(JsonElement.class);

    private StrictJson() {
    }

    /**
     * The JSON in the text, or null when it is not one strictly valid JSON value, or when an object repeats a name.
     * Gson keeps the last of repeated names, so the proxy would scan one value while the text it forwards unchanged
     * still carries the others.
     */
    public static JsonElement parse(final String text) {
        try {
            if (hasDuplicateNames(reader(text))) {
                return null;
            }
            final JsonReader reader = reader(text);
            final JsonElement element = ADAPTER.read(reader);
            return element != null && reader.peek() == JsonToken.END_DOCUMENT ? element : null;
        } catch (final IOException | JsonParseException | IllegalStateException e) {
            return null;
        }
    }

    private static JsonReader reader(final String text) {
        final JsonReader reader = new JsonReader(new StringReader(text));
        reader.setStrictness(Strictness.STRICT);
        return reader;
    }

    /** Reads the whole value, token by token, and reports whether any object repeats a name. */
    private static boolean hasDuplicateNames(final JsonReader reader) throws IOException {
        // One entry per open object or array: the names seen so far in an object, null for an array.
        final java.util.ArrayList<java.util.Set<String>> open = new java.util.ArrayList<>();
        do {
            switch (reader.peek()) {
                case BEGIN_OBJECT -> {
                    reader.beginObject();
                    open.add(new java.util.HashSet<>());
                }
                case END_OBJECT -> {
                    reader.endObject();
                    open.removeLast();
                }
                case BEGIN_ARRAY -> {
                    reader.beginArray();
                    open.add(null);
                }
                case END_ARRAY -> {
                    reader.endArray();
                    open.removeLast();
                }
                case NAME -> {
                    if (!open.getLast().add(reader.nextName())) {
                        return true;
                    }
                }
                case END_DOCUMENT -> {
                    return false;
                }
                default -> reader.skipValue();
            }
        } while (!open.isEmpty());
        return false;
    }

}
