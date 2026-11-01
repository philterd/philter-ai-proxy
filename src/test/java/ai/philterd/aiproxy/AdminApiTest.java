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
package ai.philterd.aiproxy;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The admin API: Philter-compatible policy endpoints under /admin, and API keys. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AdminApiTest {

    static final String BOOTSTRAP = "admin-test-bootstrap-0123456789abcdef0123456789";
    static final String POLICY = """
            {"identifiers":{"ssn":{"ssnFilterStrategies":[{"strategy":"REDACT"}]}}}""";
    static final String OTHER_POLICY = """
            {"identifiers":{"emailAddress":{"emailAddressFilterStrategies":[{"strategy":"REDACT"}]}}}""";
    static final Path DATA;

    static {
        try {
            DATA = Files.createTempDirectory("philter-ai-proxy-admin-test");
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("proxy.storage.sqlite-path", () -> DATA.resolve("proxy.db").toString());
        registry.add("proxy.security.encryption-key", () -> "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
        registry.add("proxy.security.bootstrap-api-key", () -> BOOTSTRAP);
        registry.add("proxy.models.directory", () -> DATA.resolve("models").toString());
        for (final String provider : new String[]{"openai", "anthropic", "gemini", "ollama"}) {
            registry.add("proxy.providers." + provider + ".target", () -> "http://127.0.0.1:9");
        }
        registry.add("management.server.port", () -> "0");
    }

    @LocalServerPort
    int port;

    final HttpClient http = HttpClient.newHttpClient();

    HttpResponse<String> call(final String method, final String path, final String body, final String key, final String... headers)
            throws Exception {
        final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        if (key != null) {
            builder.header("Authorization", "Bearer " + key);
        }
        if (body != null) {
            builder.header("Content-Type", "application/json");
        }
        for (int i = 0; i < headers.length; i += 2) {
            builder.header(headers[i], headers[i + 1]);
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> admin(final String method, final String path, final String body, final String... headers) throws Exception {
        return call(method, path, body, BOOTSTRAP, headers);
    }

    static JsonObject json(final String body) {
        return JsonParser.parseString(body).getAsJsonObject();
    }

    static String reason(final HttpResponse<String> response) {
        return json(response.body()).get("reason").getAsString();
    }

    static String name() {
        return "p-" + UUID.randomUUID();
    }

    @Test
    void requiresAnAdminKey() throws Exception {
        final HttpResponse<String> none = call("GET", "/admin/api/policies", null, null);
        assertEquals(401, none.statusCode());
        assertEquals("invalid_credentials", reason(none));
        assertEquals("invalid_credentials", reason(call("GET", "/admin/api/policies", null, "pap_wrong")));
        assertNotNull(none.headers().firstValue("X-Request-Id").orElse(null));

        final HttpResponse<String> created = admin("POST", "/admin/api/keys", "{\"name\":\"app\",\"roles\":[\"proxy\"]}");
        final String proxyKey = json(created.body()).get("key").getAsString();
        final HttpResponse<String> forbidden = call("GET", "/admin/api/policies", null, proxyKey);
        assertEquals(403, forbidden.statusCode());
        assertEquals("missing_scope", reason(forbidden));
    }

    @Test
    void hasTheDefaultPolicy() throws Exception {
        final HttpResponse<String> response = admin("GET", "/admin/api/policies/default", null);
        assertEquals(200, response.statusCode());
        assertTrue(json(response.body()).getAsJsonObject("identifiers").has("person"));
        final HttpResponse<String> delete = admin("DELETE", "/admin/api/policies/default", null);
        assertEquals(409, delete.statusCode());
        assertEquals("policy_default", reason(delete));
    }

    @Test
    void createsReadsReplacesAndDeletesAPolicy() throws Exception {
        final String name = name();
        final HttpResponse<String> created = admin("POST", "/admin/api/policies?name=" + name, POLICY);
        assertEquals(201, created.statusCode());
        final String createdTag = created.headers().firstValue("ETag").orElseThrow();
        assertTrue(createdTag.matches("\"0-[0-9a-f]{16}\""), createdTag);

        final HttpResponse<String> duplicate = admin("POST", "/admin/api/policies?name=" + name, POLICY);
        assertEquals(409, duplicate.statusCode());
        assertEquals("policy_exists", reason(duplicate));

        final HttpResponse<String> read = admin("GET", "/admin/api/policies/" + name, null);
        assertEquals(200, read.statusCode());
        assertEquals(json(POLICY), json(read.body()));
        assertEquals(createdTag, read.headers().firstValue("ETag").orElseThrow());

        final HttpResponse<String> replaced = admin("PUT", "/admin/api/policies/" + name, OTHER_POLICY, "If-Match", createdTag);
        assertEquals(200, replaced.statusCode());
        final String replacedTag = replaced.headers().firstValue("ETag").orElseThrow();
        assertTrue(replacedTag.startsWith("\"1-"), replacedTag);

        final HttpResponse<String> stale = admin("PUT", "/admin/api/policies/" + name, POLICY, "If-Match", createdTag);
        assertEquals(409, stale.statusCode());
        assertEquals("policy_changed", reason(stale));

        final HttpResponse<String> badTag = admin("PUT", "/admin/api/policies/" + name, POLICY, "If-Match", "nonsense");
        assertEquals(400, badTag.statusCode());
        assertEquals("If-Match", json(badTag.body()).get("field").getAsString());

        assertEquals(200, admin("PUT", "/admin/api/policies/" + name, POLICY).statusCode());
        assertEquals(json(POLICY), json(admin("GET", "/admin/api/policies/" + name, null).body()));

        assertEquals(204, admin("DELETE", "/admin/api/policies/" + name, null).statusCode());
        final HttpResponse<String> gone = admin("GET", "/admin/api/policies/" + name, null);
        assertEquals(404, gone.statusCode());
        assertEquals("not_found", reason(gone));
        assertEquals(404, admin("DELETE", "/admin/api/policies/" + name, null).statusCode());
        assertEquals(404, admin("PUT", "/admin/api/policies/" + name, POLICY).statusCode());
    }

    @Test
    void listsPoliciesInPages() throws Exception {
        for (int i = 0; i < 3; i++) {
            admin("POST", "/admin/api/policies?name=list-" + i + "-" + UUID.randomUUID(), POLICY);
        }
        final JsonObject all = json(admin("GET", "/admin/api/policies?limit=500", null).body());
        final long total = all.get("total").getAsLong();
        assertTrue(total >= 4);
        final JsonArray page = json(admin("GET", "/admin/api/policies?offset=1&limit=2", null).body()).getAsJsonArray("policies");
        assertEquals(2, page.size());
        assertTrue(page.get(0).getAsJsonObject().has("revision"));
        assertEquals(400, admin("GET", "/admin/api/policies?limit=0", null).statusCode());
        assertEquals("offset", json(admin("GET", "/admin/api/policies?offset=-1", null).body()).get("field").getAsString());
    }

    @Test
    void refusesPoliciesTheDeploymentDoesNotAllow() throws Exception {
        final String[] refused = {
                "not json",
                "[]",
                "{}",
                "{\"identifiers\":{\"person\":{\"phEyeConfiguration\":{\"endpoint\":\"http://elsewhere.example.com\",\"modelPath\":\"m\"}}}}",
                "{\"identifiers\":{\"person\":{\"phEyeConfiguration\":{\"modelPath\":\"m\",\"bearerToken\":\"t\"}}}}",
                "{\"identifiers\":{\"person\":{\"phEyeConfiguration\":{\"modelPath\":\"not-a-model\"}}}}",
                "{\"identifiers\":{\"person\":{\"phEyeFilterStrategies\":[{\"strategy\":\"REDACT\"}]}}}",
                "{\"identifiers\":{},\"generators\":{\"g\":{\"type\":\"llm\",\"endpoint\":\"http://elsewhere.example.com\"}}}",
                "{\"identifiers\":{\"dictionaries\":[{\"files\":[\"/etc/passwd\"]}]}}",
                "{\"identifiers\":{\"ssn\":{\"ssnFilterStrategies\":[{\"strategy\":\"REDACT\",\"condition\":\"token ==== \"}]}}}",
        };
        for (final String policy : refused) {
            final HttpResponse<String> response = admin("POST", "/admin/api/policies?name=" + name(), policy);
            assertEquals(400, response.statusCode(), policy + " -> " + response.body());
            assertEquals("invalid_request", reason(response));
        }
    }

    @Test
    void refusesUnsafePolicyNames() throws Exception {
        for (final String bad : new String[]{"a%2Fb", "..", "a%3Bb", "a%25b"}) {
            final HttpResponse<String> response = admin("POST", "/admin/api/policies?name=" + bad, POLICY);
            assertEquals(400, response.statusCode(), bad);
        }
        assertEquals(400, admin("POST", "/admin/api/policies", POLICY).statusCode());
    }

    @Test
    void managesApiKeys() throws Exception {
        final HttpResponse<String> created = admin("POST", "/admin/api/keys",
                "{\"name\":\"svc\",\"roles\":[\"proxy\"],\"models\":[\"gpt-4*\"],\"policy\":\"default\"}");
        assertEquals(201, created.statusCode());
        final JsonObject key = json(created.body());
        assertTrue(key.get("key").getAsString().startsWith("pap_"));
        assertEquals("gpt-4*", key.getAsJsonArray("models").get(0).getAsString());
        final String id = key.get("id").getAsString();

        final String listed = admin("GET", "/admin/api/keys", null).body();
        assertTrue(listed.contains(id));
        assertFalse(listed.contains(key.get("key").getAsString()));

        assertEquals(400, admin("POST", "/admin/api/keys", "{\"name\":\"x\"}").statusCode());
        assertEquals(400, admin("POST", "/admin/api/keys", "{\"roles\":[\"proxy\"]}").statusCode());
        assertEquals(400, admin("POST", "/admin/api/keys", "{\"name\":\"x\",\"roles\":[\"root\"]}").statusCode());
        assertEquals("policy", json(admin("POST", "/admin/api/keys",
                "{\"name\":\"x\",\"roles\":[\"proxy\"],\"policy\":\"nope\"}").body()).get("field").getAsString());
        assertEquals(400, admin("POST", "/admin/api/keys", "garbage").statusCode());

        assertEquals(204, admin("DELETE", "/admin/api/keys/" + id, null).statusCode());
        assertEquals(404, admin("DELETE", "/admin/api/keys/" + id, null).statusCode());
        assertEquals(401, call("GET", "/admin/api/policies", null, key.get("key").getAsString()).statusCode());
    }

    @Test
    void aKeyCannotDeleteItself() throws Exception {
        final JsonObject created = json(admin("POST", "/admin/api/keys", "{\"name\":\"admin2\",\"roles\":[\"admin\"]}").body());
        final HttpResponse<String> response = call("DELETE", "/admin/api/keys/" + created.get("id").getAsString(), null,
                created.get("key").getAsString());
        assertEquals(409, response.statusCode());
        assertEquals("self_action_refused", reason(response));
    }

}
