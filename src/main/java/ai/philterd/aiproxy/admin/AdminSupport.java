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
package ai.philterd.aiproxy.admin;

import ai.philterd.aiproxy.security.ApiKey;
import ai.philterd.aiproxy.security.Authenticator;
import ai.philterd.aiproxy.security.KeyScopes;
import com.google.gson.JsonObject;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Authentication and error responses for the admin API. */
@Component
public class AdminSupport {

    private final Authenticator authenticator;

    public AdminSupport(final Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    /**
     * The admin key the request carries as {@code Authorization: Bearer <key>}, as Philter's clients send it.
     * @throws AdminException 401 without a valid key, 403 for a key without the admin role.
     */
    public ApiKey requireAdmin(final HttpServletRequest request) {
        final String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw new AdminException(401, "invalid_credentials", "An admin API key is required as Authorization: Bearer <key>.");
        }
        final ApiKey key = authenticator.authenticate(header.substring(7).strip())
                .orElseThrow(() -> new AdminException(401, "invalid_credentials", "The API key is not valid."));
        if (!key.scopes().has(KeyScopes.Role.admin)) {
            throw new AdminException(403, "missing_scope", "This API key does not have the admin role.");
        }
        return key;
    }

    static String error(final String message, final String reason, final String field) {
        final JsonObject json = new JsonObject();
        json.addProperty("message", message);
        json.addProperty("reason", reason);
        if (field != null) {
            json.addProperty("field", field);
        }
        return json.toString();
    }

    @RestControllerAdvice(basePackageClasses = AdminSupport.class)
    static class Handler {

        private static final Logger LOGGER = LoggerFactory.getLogger(Handler.class);

        @ExceptionHandler(AdminException.class)
        ResponseEntity<String> handle(final AdminException e) {
            return ResponseEntity.status(e.status()).contentType(MediaType.APPLICATION_JSON)
                    .body(error(e.getMessage(), e.reason(), e.field()));
        }

        @ExceptionHandler(Exception.class)
        ResponseEntity<String> handle(final Exception e) {
            // Spring's own refusals (a missing parameter, an unsupported media type) carry their status.
            if (e instanceof ErrorResponse response) {
                final int status = response.getStatusCode().value();
                return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON)
                        .body(error(response.getBody().getDetail() == null ? "The request was refused." : response.getBody().getDetail(),
                                reasonFor(status), null));
            }
            LOGGER.error("Admin API request failed", e);
            return ResponseEntity.status(500).contentType(MediaType.APPLICATION_JSON)
                    .body(error("The request failed.", "internal_error", null));
        }

        /** The reason Philter gives for a status with no more specific reason. */
        static String reasonFor(final int status) {
            return switch (status) {
                case 400 -> "invalid_request";
                case 401 -> "invalid_credentials";
                case 403 -> "forbidden";
                case 404 -> "not_found";
                case 405 -> "method_not_allowed";
                case 406 -> "not_acceptable";
                case 409 -> "conflict";
                case 413 -> "payload_too_large";
                case 415 -> "unsupported_media_type";
                case 429 -> "rate_limited";
                case 503 -> "service_unavailable";
                default -> "internal_error";
            };
        }

    }

}
