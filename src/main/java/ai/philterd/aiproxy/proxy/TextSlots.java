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
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * The text-bearing places in a JSON request or response, collected so they can all be redacted in one call and
 * written back. Everything else in the JSON is left as it is.
 */
public final class TextSlots {

    /** A string in the JSON that is read, redacted, and written back. */
    public record Slot(Supplier<String> getter, Consumer<String> setter) {
    }

    private final List<Slot> slots = new ArrayList<>();
    private final List<Runnable> finishers = new ArrayList<>();

    public List<Slot> slots() {
        return slots;
    }

    public List<String> texts() {
        return slots.stream().map(slot -> slot.getter().get()).toList();
    }

    /** Writes the redacted texts back, in the order {@link #texts()} gave them. */
    public void apply(final List<String> redacted) {
        for (int i = 0; i < slots.size(); i++) {
            slots.get(i).setter().accept(redacted.get(i));
        }
        finishers.forEach(Runnable::run);
    }

    /** Adds {@code object.member} when it is a non-empty string. */
    public void addString(final JsonObject object, final String member) {
        if (object.get(member) instanceof JsonPrimitive p && p.isString() && !p.getAsString().isEmpty()) {
            slots.add(new Slot(() -> object.get(member).getAsString(), value -> object.addProperty(member, value)));
        }
    }

    /**
     * Adds every non-empty string anywhere inside the element, such as tool-call arguments, and every integer of
     * five or more digits, since an SSN, phone number, or account number can be sent as one. A number is read as its
     * JSON text; it stays a number unless redaction changes it, when the redacted text replaces it as a string.
     * Shorter integers and decimals are left alone, so numeric data does not become thousands of texts to redact.
     * Object keys are not redacted.
     */
    public void addAllStrings(final JsonElement element) {
        if (element instanceof JsonObject object) {
            for (final String member : object.keySet()) {
                final JsonElement child = object.get(member);
                if (child instanceof JsonPrimitive p && identifierLike(p)) {
                    final String original = p.getAsString();
                    slots.add(new Slot(() -> original, value -> {
                        if (!value.equals(original)) {
                            object.addProperty(member, value);
                        }
                    }));
                } else if (child instanceof JsonPrimitive) {
                    addString(object, member);
                } else {
                    addAllStrings(child);
                }
            }
        } else if (element instanceof JsonArray array) {
            for (int i = 0; i < array.size(); i++) {
                final int index = i;
                if (array.get(i) instanceof JsonPrimitive p) {
                    if (identifierLike(p)) {
                        final String original = p.getAsString();
                        slots.add(new Slot(() -> original, value -> {
                            if (!value.equals(original)) {
                                array.set(index, new JsonPrimitive(value));
                            }
                        }));
                    } else if (p.isString() && !p.getAsString().isEmpty()) {
                        slots.add(new Slot(() -> array.get(index).getAsString(), value -> array.set(index, new JsonPrimitive(value))));
                    }
                } else {
                    addAllStrings(array.get(i));
                }
            }
        }
    }

    private static boolean identifierLike(final JsonPrimitive p) {
        if (!p.isNumber()) {
            return false;
        }
        final String text = p.getAsString();
        return text.length() >= 5 && text.chars().allMatch(c -> c >= '0' && c <= '9' || c == '-');
    }

    /**
     * Adds {@code object.member}, a string holding JSON such as tool-call arguments: every string inside the JSON
     * is redacted and the JSON written back. When it is not JSON, the whole string is redacted as text.
     */
    public void addJsonString(final JsonObject object, final String member) {
        if (!(object.get(member) instanceof JsonPrimitive p) || !p.isString() || p.getAsString().isEmpty()) {
            return;
        }
        final JsonElement parsed = StrictJson.parse(p.getAsString());
        if (parsed == null || parsed.isJsonPrimitive() || parsed.isJsonNull()) {
            addString(object, member);
            return;
        }
        addAllStrings(parsed);
        // Written back only when a value in it changed, so JSON with nothing redacted is forwarded as it came.
        final String before = parsed.toString();
        finishers.add(() -> {
            final String after = parsed.toString();
            if (!after.equals(before)) {
                object.addProperty(member, after);
            }
        });
    }

}
