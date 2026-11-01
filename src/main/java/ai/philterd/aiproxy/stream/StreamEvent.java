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

import com.google.gson.JsonObject;

/**
 * One event of a streamed response.
 * @param type The event's type, where the framing carries one (an SSE {@code event:} line, an AWS event stream
 *             {@code :event-type} header), else null.
 * @param json The event's JSON payload.
 */
public record StreamEvent(String type, JsonObject json) {
}
