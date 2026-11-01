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

/**
 * A request the proxy refuses or cannot complete. Sent to the client as
 * {@code {"error": {"message", "type", "code", "request_id"}}}, the shape OpenAI-compatible clients parse.
 * {@code type} and {@code code} are stable; {@code message} may change.
 */
public class ProxyError extends Exception {

    private final int status;
    private final String type;
    private final String code;

    public ProxyError(final int status, final String type, final String code, final String message) {
        super(message);
        this.status = status;
        this.type = type;
        this.code = code;
    }

    public int status() {
        return status;
    }

    public String type() {
        return type;
    }

    public String code() {
        return code;
    }

}
