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
package ai.philterd.aiproxy.stream;

import ai.philterd.aiproxy.redaction.RedactionException;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Server-sent events, as OpenAI, Anthropic, and Gemini ({@code alt=sse}) stream them: events separated by blank
 * lines, each with {@code data:} lines carrying JSON and optionally an {@code event:} line naming its type.
 */
public final class SseFraming implements Framing {

    @Override
    public void read(final InputStream in, final Handler handler) throws IOException, RedactionException,
            StreamScanner.BlockedException, StreamScanner.UnscannableException {
        final BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        final List<String> lines = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.isEmpty()) {
                if (!lines.isEmpty()) {
                    onEvent(lines, handler);
                    lines.clear();
                }
            } else {
                lines.add(line);
            }
        }
        if (!lines.isEmpty()) {
            onEvent(lines, handler);
        }
    }

    private static void onEvent(final List<String> lines, final Handler handler) throws IOException, RedactionException,
            StreamScanner.BlockedException, StreamScanner.UnscannableException {
        final byte[] raw = (String.join("\n", lines) + "\n\n").getBytes(StandardCharsets.UTF_8);
        final StringBuilder data = new StringBuilder();
        String type = null;
        boolean hasData = false;
        for (final String l : lines) {
            if (l.startsWith("data:")) {
                if (hasData) {
                    data.append('\n');
                }
                data.append(l.startsWith("data: ") ? l.substring(6) : l.substring(5));
                hasData = true;
            } else if (l.startsWith("event:")) {
                type = l.substring(6).strip();
            } else if (!l.startsWith(":") && !l.startsWith("id:") && !l.startsWith("retry:")) {
                // Not a server-sent events line at all, such as a compressed body.
                handler.onUnreadable(raw);
                return;
            }
        }
        if (!hasData) {
            handler.onPassThrough(raw, false);
            return;
        }
        final String payload = data.toString().strip();
        if (payload.equals("[DONE]")) {
            handler.onPassThrough(raw, true);
            return;
        }
        final JsonElement parsed;
        try {
            parsed = JsonParser.parseString(payload);
        } catch (final JsonParseException e) {
            handler.onUnreadable(raw);
            return;
        }
        if (!parsed.isJsonObject()) {
            handler.onUnreadable(raw);
            return;
        }
        handler.onEvent(new StreamEvent(type, parsed.getAsJsonObject()));
    }

    @Override
    public byte[] encode(final StreamEvent event) {
        return ((event.type() == null ? "" : "event: " + event.type() + "\n") + "data: " + event.json() + "\n\n")
                .getBytes(StandardCharsets.UTF_8);
    }

}
