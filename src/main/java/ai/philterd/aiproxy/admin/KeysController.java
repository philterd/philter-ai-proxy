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
import ai.philterd.aiproxy.storage.ApiKeyStore;
import ai.philterd.aiproxy.storage.AuditStore;
import ai.philterd.aiproxy.storage.PolicyStore;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** API keys: created with their roles and scopes, listed without their secrets, and deleted. */
@RestController
@RequestMapping("/admin/api/keys")
public class KeysController {

    private static final Gson GSON = new Gson();
    private static final int MAX_NAME_LENGTH = 256;

    private final ApiKeyStore keys;
    private final PolicyStore policies;
    private final AdminSupport admin;
    private final Authenticator authenticator;
    private final AuditStore audit;

    public KeysController(final ApiKeyStore keys, final PolicyStore policies, final AdminSupport admin,
                          final Authenticator authenticator, final AuditStore audit) {
        this.keys = keys;
        this.policies = policies;
        this.admin = admin;
        this.authenticator = authenticator;
        this.audit = audit;
    }

    /** A create request: a name, then the fields of {@link KeyScopes}. */
    record CreateKey(String name, KeyScopes.Role[] roles, String[] providers, String[] models, String[] paths, String policy) {
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> create(final HttpServletRequest request, @RequestBody final String body) {
        final ApiKey caller = admin.requireAdmin(request);
        final CreateKey create;
        try {
            create = GSON.fromJson(body, CreateKey.class);
        } catch (final JsonParseException e) {
            throw new AdminException(400, "invalid_request", "The body must be a JSON object with name and roles.");
        }
        if (create == null || create.name() == null || create.name().isBlank() || create.name().length() > MAX_NAME_LENGTH) {
            throw new AdminException(400, "invalid_request", "The key needs a name of at most " + MAX_NAME_LENGTH + " characters.", "name");
        }
        if (create.roles() == null || create.roles().length == 0 || java.util.Arrays.stream(create.roles()).anyMatch(r -> r == null)) {
            throw new AdminException(400, "invalid_request", "The key needs roles: admin, proxy, or both.", "roles");
        }
        if (create.policy() != null && !create.policy().isBlank() && policies.findRevision(create.policy().strip()).isEmpty()) {
            throw new AdminException(400, "invalid_request", "There is no policy named '" + create.policy() + "'.", "policy");
        }
        final KeyScopes scopes = new KeyScopes(java.util.Set.of(create.roles()), list(create.providers()),
                list(create.models()), list(create.paths()), create.policy());
        final ApiKeyStore.CreatedKey created = keys.create(create.name().strip(), scopes);
        audit.record(PoliciesController.requestId(request), "api_key_created", details(caller, created.key()));
        final JsonObject json = describe(created.key());
        json.addProperty("key", created.secret());
        return ResponseEntity.status(201).contentType(MediaType.APPLICATION_JSON).body(json.toString());
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public String list(final HttpServletRequest request) {
        admin.requireAdmin(request);
        final JsonArray items = new JsonArray();
        keys.list().forEach(key -> items.add(describe(key)));
        final JsonObject body = new JsonObject();
        body.add("keys", items);
        body.addProperty("total", items.size());
        return body.toString();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(final HttpServletRequest request, @PathVariable final String id) {
        final ApiKey caller = admin.requireAdmin(request);
        if (caller.id().equals(id)) {
            throw new AdminException(409, "self_action_refused", "A key cannot delete itself.");
        }
        final ApiKey key = keys.findById(id).orElseThrow(() -> new AdminException(404, "not_found", "Not found."));
        keys.delete(id);
        authenticator.clearCache();
        audit.record(PoliciesController.requestId(request), "api_key_deleted", details(caller, key));
        return ResponseEntity.noContent().build();
    }

    private static JsonObject describe(final ApiKey key) {
        final JsonObject json = GSON.toJsonTree(key.scopes()).getAsJsonObject();
        json.addProperty("id", key.id());
        json.addProperty("name", key.name());
        json.addProperty("createdAt", key.createdAt().toString());
        return json;
    }

    private static java.util.List<String> list(final String[] values) {
        return values == null ? java.util.List.of()
                : java.util.Arrays.stream(values).filter(v -> v != null && !v.isBlank()).map(String::strip).toList();
    }

    private static Map<String, Object> details(final ApiKey caller, final ApiKey key) {
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("key_id", caller.id());
        details.put("target_key_id", key.id());
        details.put("roles", key.scopes().roles());
        return details;
    }

}
