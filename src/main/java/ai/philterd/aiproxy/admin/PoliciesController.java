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

import ai.philterd.aiproxy.redaction.PolicyCompiler;
import ai.philterd.aiproxy.redaction.PolicyException;
import ai.philterd.aiproxy.redaction.Redactor;
import ai.philterd.aiproxy.security.ApiKey;
import ai.philterd.aiproxy.storage.AuditStore;
import ai.philterd.aiproxy.storage.PolicyStore;
import ai.philterd.aiproxy.storage.PolicyStore.StoredPolicy;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Policies, with the paths and bodies of Philter's policy API under {@code /admin}: a client that takes a Philter
 * base URL can use {@code https://<proxy>/admin}. Bodies are native Phileas policy JSON.
 */
@RestController
@RequestMapping("/admin/api/policies")
public class PoliciesController {

    /** The entity tag format, as Philter's: revision and a hash of the description and notes. */
    private static final Pattern ETAG = Pattern.compile("[0-9]+-[0-9a-f]{16}");
    private static final int MAX_NAME_LENGTH = 256;
    private static final int MAX_LIMIT = 500;

    private final PolicyStore policies;
    private final PolicyCompiler compiler;
    private final Redactor redactor;
    private final AdminSupport admin;
    private final AuditStore audit;

    public PoliciesController(final PolicyStore policies, final PolicyCompiler compiler, final Redactor redactor,
                              final AdminSupport admin, final AuditStore audit) {
        this.policies = policies;
        this.compiler = compiler;
        this.redactor = redactor;
        this.admin = admin;
        this.audit = audit;
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public String list(final HttpServletRequest request,
                       @RequestParam(defaultValue = "0") final int offset,
                       @RequestParam(defaultValue = "25") final int limit) {
        admin.requireAdmin(request);
        if (offset < 0) {
            throw new AdminException(400, "invalid_request", "offset cannot be negative.", "offset");
        }
        if (limit < 1 || limit > MAX_LIMIT) {
            throw new AdminException(400, "invalid_request", "limit must be between 1 and " + MAX_LIMIT + ".", "limit");
        }
        final PolicyStore.Page page = policies.list(offset, limit);
        final JsonArray items = new JsonArray();
        for (final StoredPolicy policy : page.policies()) {
            final JsonObject item = new JsonObject();
            item.addProperty("name", policy.name());
            item.addProperty("revision", policy.revision());
            item.addProperty("description", policy.description());
            item.addProperty("createdAt", policy.createdAt().toString());
            item.addProperty("updatedAt", policy.updatedAt().toString());
            items.add(item);
        }
        final JsonObject body = new JsonObject();
        body.add("policies", items);
        body.addProperty("total", page.total());
        return body.toString();
    }

    @GetMapping(path = "/{policyName}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> get(final HttpServletRequest request, @PathVariable final String policyName) {
        admin.requireAdmin(request);
        final StoredPolicy policy = policies.find(policyName).orElseThrow(PoliciesController::notFound);
        return ResponseEntity.ok().eTag(eTag(policy)).contentType(MediaType.APPLICATION_JSON).body(policy.policy());
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> create(final HttpServletRequest request, @RequestParam final String name,
                                       @RequestBody final String body) {
        final ApiKey key = admin.requireAdmin(request);
        validateName(name);
        compile(body);
        final StoredPolicy created = policies.create(name, body, "", "")
                .orElseThrow(() -> new AdminException(409, "policy_exists", "A policy named '" + name + "' already exists."));
        redactor.evict(name);
        audit.record(requestId(request), "policy_created", details(key, name, created.revision()));
        return ResponseEntity.status(201).eTag(eTag(created)).build();
    }

    @PutMapping(path = "/{policyName}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> replace(final HttpServletRequest request, @PathVariable final String policyName,
                                        @RequestHeader(value = HttpHeaders.IF_MATCH, required = false) final String ifMatch,
                                        @RequestBody final String body) {
        final ApiKey key = admin.requireAdmin(request);
        final String expected = ifMatchETag(ifMatch);
        compile(body);
        final StoredPolicy replaced;
        try {
            replaced = policies.replace(policyName, body, expected).orElseThrow(PoliciesController::notFound);
        } catch (final PolicyStore.ConflictException e) {
            throw new AdminException(409, "policy_changed", e.getMessage());
        }
        redactor.evict(policyName);
        audit.record(requestId(request), "policy_replaced", details(key, policyName, replaced.revision()));
        return ResponseEntity.ok().eTag(eTag(replaced)).build();
    }

    @DeleteMapping("/{policyName}")
    public ResponseEntity<Void> delete(final HttpServletRequest request, @PathVariable final String policyName) {
        final ApiKey key = admin.requireAdmin(request);
        if (PolicyStore.DEFAULT_POLICY_NAME.equals(policyName)) {
            throw new AdminException(409, "policy_default", "The default policy cannot be deleted.");
        }
        if (!policies.delete(policyName)) {
            throw notFound();
        }
        redactor.evict(policyName);
        audit.record(requestId(request), "policy_deleted", details(key, policyName, null));
        return ResponseEntity.noContent().build();
    }

    private void compile(final String body) {
        try {
            compiler.compile(body);
        } catch (final PolicyException e) {
            throw new AdminException(400, "invalid_request", e.getMessage());
        }
    }

    static void validateName(final String name) {
        if (name == null || name.isBlank()) {
            throw new AdminException(400, "invalid_request", "The policy needs a name.", "name");
        }
        if (name.length() > MAX_NAME_LENGTH || name.equals(".") || name.equals("..")
                || name.chars().anyMatch(c -> c == '/' || c == '\\' || c == ';' || c == '%' || Character.isISOControl(c))) {
            throw new AdminException(400, "invalid_request", "A policy name cannot contain /, \\, ;, %, or control "
                    + "characters, cannot be . or .., and is at most " + MAX_NAME_LENGTH + " characters.", "name");
        }
    }

    /** The If-Match entity tag, unquoted, or null when there is none or it is {@code *}. */
    static String ifMatchETag(final String ifMatch) {
        if (ifMatch == null || ifMatch.isBlank() || ifMatch.strip().equals("*")) {
            return null;
        }
        String value = ifMatch.strip();
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
        }
        if (!ETAG.matcher(value).matches()) {
            throw new AdminException(400, "invalid_request", "If-Match must be an entity tag this API returned for the "
                    + "policy, such as \"7-0123456789abcdef\".", HttpHeaders.IF_MATCH);
        }
        return value;
    }

    private static String eTag(final StoredPolicy policy) {
        return "\"" + policy.eTag() + "\"";
    }

    private static AdminException notFound() {
        return new AdminException(404, "not_found", "Not found.");
    }

    private static Map<String, Object> details(final ApiKey key, final String policy, final Integer revision) {
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("key_id", key.id());
        details.put("policy_name", policy);
        if (revision != null) {
            details.put("revision", revision);
        }
        return details;
    }

    static String requestId(final HttpServletRequest request) {
        final Object id = request.getAttribute(RequestIds.ATTRIBUTE);
        return id == null ? "" : id.toString();
    }

}
