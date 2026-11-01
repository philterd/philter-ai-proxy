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

/**
 * Where the text is in one provider's stream events. One instance serves one stream, so it can keep the events it
 * needs as templates for the events it builds.
 */
public interface StreamDialect {

    /**
     * Handles one event: moves its streamed text into the scanner ({@link StreamScanner#appendText},
     * {@link StreamScanner#appendArguments}), scans any whole text in it ({@link StreamScanner#scanWhole}), and
     * finishes parts that have ended ({@link StreamScanner#finish}).
     * @return The event to forward after that, changed as needed, or null to forward nothing.
     */
    StreamEvent onEvent(StreamEvent event, StreamScanner scanner) throws IOException, RedactionException,
            StreamScanner.BlockedException, StreamScanner.UnscannableException;

    /** An event carrying released text for the key. */
    StreamEvent textEvent(StreamScanner.Key key, String text);

    /** An event carrying the whole scanned arguments for the key. */
    StreamEvent argumentsEvent(StreamScanner.Key key, String arguments);

}
