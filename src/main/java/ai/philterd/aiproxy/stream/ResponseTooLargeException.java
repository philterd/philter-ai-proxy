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

import java.io.IOException;

/** A streamed response held more than the proxy will buffer to scan: a line, an event, held text, or arguments. */
public final class ResponseTooLargeException extends IOException {

    /** The most characters held for one line, event, text part, or set of arguments. */
    public static final int MAX_CHARS = 16 * 1024 * 1024;

    public ResponseTooLargeException() {
        super("the provider's response is too large to scan");
    }

    /** Throws when the length is over {@link #MAX_CHARS}. */
    static void check(final long length) throws ResponseTooLargeException {
        if (length > MAX_CHARS) {
            throw new ResponseTooLargeException();
        }
    }

    /** Reads a line as {@link java.io.BufferedReader#readLine()} does, refusing one longer than {@link #MAX_CHARS}. */
    static String readLine(final java.io.Reader reader) throws IOException {
        final StringBuilder line = new StringBuilder();
        int c;
        while ((c = reader.read()) != -1) {
            if (c == '\n') {
                return line.toString();
            }
            if (c == '\r') {
                reader.mark(1);
                if (reader.read() != '\n') {
                    reader.reset();
                }
                return line.toString();
            }
            line.append((char) c);
            check(line.length());
        }
        return line.isEmpty() ? null : line.toString();
    }

}
