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

import java.io.IOException;
import java.io.InputStream;

/** How a streamed response is divided into events, read and written. */
public interface Framing {

    /** Receives what the framing reads. */
    interface Handler {

        /** A JSON event. */
        void onEvent(StreamEvent event) throws IOException, RedactionException, StreamScanner.BlockedException,
                StreamScanner.UnscannableException;

        /**
         * Something to forward exactly as it was, carrying no text: an SSE comment such as a keep-alive, or an end
         * marker such as {@code data: [DONE]}.
         * @param end Whether it ends the stream or a part of it, so held text is released first. A keep-alive does
         *            not: releasing there would split a value that arrives around it.
         */
        void onPassThrough(byte[] raw, boolean end) throws IOException, RedactionException, StreamScanner.BlockedException;

        /** Something that is not a JSON event and cannot be scanned. */
        void onUnreadable(byte[] raw) throws IOException, RedactionException, StreamScanner.BlockedException,
                StreamScanner.UnscannableException;
    }

    void read(InputStream in, Handler handler) throws IOException, RedactionException, StreamScanner.BlockedException,
            StreamScanner.UnscannableException;

    byte[] encode(StreamEvent event);

    /** An error that ends the stream, as clients of this framing expect one. */
    default byte[] encodeError(final String code, final com.google.gson.JsonObject error) {
        return encode(new StreamEvent("error", error));
    }

}
