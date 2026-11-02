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
import ai.philterd.aiproxy.proxy.StrictJson;
import com.google.gson.JsonElement;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/** Newline-delimited JSON, as Ollama streams it: one JSON object per line. */
public final class NdjsonFraming implements Framing {

    @Override
    public void read(final InputStream in, final Handler handler) throws IOException, RedactionException,
            StreamScanner.BlockedException, StreamScanner.UnscannableException {
        final BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String line;
        while ((line = ResponseTooLargeException.readLine(reader)) != null) {
            if (line.isBlank()) {
                continue;
            }
            final byte[] raw = (line + "\n").getBytes(StandardCharsets.UTF_8);
            final JsonElement parsed = StrictJson.parse(line);
            if (parsed != null && parsed.isJsonObject()) {
                handler.onEvent(new StreamEvent(null, parsed.getAsJsonObject()));
            } else {
                handler.onUnreadable(raw);
            }
        }
    }

    @Override
    public byte[] encode(final StreamEvent event) {
        return (event.json() + "\n").getBytes(StandardCharsets.UTF_8);
    }

}
