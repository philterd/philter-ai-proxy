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

import ai.philterd.aiproxy.redaction.RedactionException;
import ai.philterd.aiproxy.stream.StreamEvent;
import ai.philterd.aiproxy.stream.StreamScanner;
import ai.philterd.aiproxy.stream.StreamScanner.Key;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.io.IOException;

/** The legacy completions endpoint streamed: each choice's {@code text}. */
public final class OpenAiCompletionsStream extends OpenAiChatStream {

    @Override
    protected boolean takeText(final JsonObject choice, final String group, final StreamScanner scanner)
            throws IOException, RedactionException, StreamScanner.BlockedException {
        if (choice.get("text") instanceof JsonPrimitive text && text.isString()) {
            choice.remove("text");
            scanner.appendText(new Key(group, "text"), text.getAsString());
        }
        return false;
    }

    @Override
    public StreamEvent textEvent(final Key key, final String text) {
        return chunk(key.group(), "text", new JsonPrimitive(text));
    }

}
