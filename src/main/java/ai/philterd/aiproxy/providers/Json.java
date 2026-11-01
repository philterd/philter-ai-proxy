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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.List;

/** Small helpers for reading provider JSON. */
final class Json {

    private Json() {
    }

    static JsonObject object(final JsonElement parent, final String member) {
        return parent instanceof JsonObject o && o.get(member) instanceof JsonObject child ? child : null;
    }

    static JsonArray array(final JsonElement parent, final String member) {
        return parent instanceof JsonObject o && o.get(member) instanceof JsonArray child ? child : null;
    }

    /** The objects in {@code parent.member}, or none. */
    static List<JsonObject> objects(final JsonElement parent, final String member) {
        final JsonArray array = array(parent, member);
        if (array == null) {
            return List.of();
        }
        return array.asList().stream().filter(JsonObject.class::isInstance).map(JsonObject.class::cast).toList();
    }

    static String string(final JsonElement parent, final String member) {
        return parent instanceof JsonObject o && o.get(member) instanceof JsonPrimitive p && p.isString() ? p.getAsString() : null;
    }

    static int integer(final JsonElement parent, final String member, final int otherwise) {
        return parent instanceof JsonObject o && o.get(member) instanceof JsonPrimitive p && p.isNumber() ? p.getAsInt() : otherwise;
    }

    static boolean isTrue(final JsonElement parent, final String member) {
        return parent instanceof JsonObject o && o.get(member) instanceof JsonPrimitive p && p.isBoolean() && p.getAsBoolean();
    }

    /** True when {@code object.member} is present and not null. */
    static boolean present(final JsonObject object, final String member) {
        return object.has(member) && !object.get(member).isJsonNull();
    }

    /** The objects of the element itself: one when it is an object, each object when it is an array. */
    static List<JsonObject> each(final JsonElement element) {
        if (element instanceof JsonObject o) {
            return List.of(o);
        }
        if (element instanceof JsonArray a) {
            return a.asList().stream().filter(JsonObject.class::isInstance).map(JsonObject.class::cast).toList();
        }
        return List.of();
    }

}
