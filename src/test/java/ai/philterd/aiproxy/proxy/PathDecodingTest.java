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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PathDecodingTest {

    @Test
    void decodesEscapesOnce() throws ProxyError {
        assertEquals("/v1/chat/completions", ProxyController.decodePath("/v1/chat/completion%73"));
        assertEquals("/model/anthropic.claude-v1:0/converse", ProxyController.decodePath("/model/anthropic.claude-v1%3A0/converse"));
        assertEquals("/v1/models/café", ProxyController.decodePath("/v1/models/caf%C3%A9"));
        assertEquals("/v1/models/a.b", ProxyController.decodePath("/v1/models/a%2Eb"));
    }

    @Test
    void refusesEscapesThatChangeStructureOrAreMalformed() {
        for (final String path : new String[]{
                "/v1/chat%2Fcompletions", "/v1/chat%2fcompletions", "/v1%5Cchat", "/v1/chat/completions%25", "/v1/chat/completions%2573",
                "/v1/chat/completions%3F", "/v1/chat/completions%23", "/v1/%2e%2e/chat/completions", "/v1/%2E/chat",
                "/v1/chat/completions%0a", "/v1/chat/completions%00", "/v1/chat/completions%7F", "/v1/chat/completions%C3",
                "/v1/chat/completions%zz", "/v1/chat/completions%4", "/v1/chat/completions%", "/v1//chat", "v1/chat", ""}) {
            assertThrows(ProxyError.class, () -> ProxyController.decodePath(path), path);
        }
    }

}
