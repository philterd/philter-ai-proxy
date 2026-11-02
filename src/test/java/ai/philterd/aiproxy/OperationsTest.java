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

import ai.philterd.aiproxy.security.KeyScopes;
import ai.philterd.aiproxy.storage.ApiKeyStore;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalManagementPort;
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
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Tracing, the audit file, trusted proxies, and the gauges, with a configuration that turns them on. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OperationsTest {

    static final ScriptedProvider STUB;
    static final Path DATA;

    static {
        try {
            STUB = new ScriptedProvider();
            DATA = Files.createTempDirectory("philter-ai-proxy-operations-test");
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("proxy.storage.sqlite-path", () -> DATA.resolve("proxy.db").toString());
        registry.add("proxy.security.encryption-key", () -> "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        registry.add("proxy.models.directory", () -> DATA.resolve("models").toString());
        registry.add("proxy.audit.file", () -> DATA.resolve("logs").resolve("audit.jsonl").toString());
        registry.add("proxy.security.trusted-proxies", () -> "127.0.0.1,::1");
        registry.add("proxy.limits.max-concurrent-requests", () -> "7");
        registry.add("proxy.defaults.policy", () -> "patterns");
        registry.add("management.server.port", () -> "0");
        for (final String p : new String[]{"openai", "anthropic", "gemini", "ollama"}) {
            registry.add("proxy.providers." + p + ".target", STUB::url);
        }
    }

    @AfterAll
    static void stop() {
        STUB.close();
    }

    @LocalServerPort
    int port;

    @LocalManagementPort
    int managementPort;

    @Autowired
    ApiKeyStore keys;

    @Autowired
    ai.philterd.aiproxy.storage.PolicyStore policies;

    final HttpClient http = HttpClient.newHttpClient();

    @Test
    void recordsTraceIdsClientAddressesAndTheAuditFile() throws Exception {
        if (policies.find("patterns").isEmpty()) {
            policies.create("patterns", "{\"identifiers\":{\"ssn\":{\"ssnFilterStrategies\":[{\"strategy\":\"REDACT\"}]}}}", "", "");
        }
        final String key = keys.create("ops", new KeyScopes(Set.of(KeyScopes.Role.proxy), List.of(), List.of(), List.of(), null)).secret();
        STUB.reply("application/json", "{\"choices\":[]}");
        final HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v1/chat/completions"))
                .header("x-philter-proxy-key", key).header("Content-Type", "application/json")
                .header("X-Request-Id", "ops-1").header("X-Forwarded-For", "203.0.113.50, 127.0.0.1")
                .POST(HttpRequest.BodyPublishers.ofString("{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"SSN 123-45-6789\"}]}"))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        final Path file = DATA.resolve("logs").resolve("audit.jsonl");
        JsonObject entry = null;
        for (int i = 0; i < 50 && entry == null; i++) {
            if (Files.exists(file)) {
                entry = Files.readAllLines(file).stream().map(l -> JsonParser.parseString(l).getAsJsonObject())
                        .filter(e -> "ops-1".equals(e.get("request_id").getAsString())).findFirst().orElse(null);
            }
            if (entry == null) {
                Thread.sleep(20);
            }
        }
        assertTrue(entry != null, "the entry is in the audit file");
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        assertEquals("203.0.113.50", entry.get("client_ip").getAsString());
        assertTrue(entry.get("trace_id").getAsString().matches("[0-9a-f]{32}"), entry.toString());
        assertEquals(1, entry.get("entity_count").getAsInt());
        assertFalse(Files.readString(file).contains("6789"));

        final String metrics = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + managementPort + "/metrics")).build(),
                HttpResponse.BodyHandlers.ofString()).body();
        assertTrue(metrics.contains("philter_proxy_concurrency_limit 7.0"), metrics);
        assertTrue(metrics.contains("philter_proxy_active_requests"), metrics);
    }

}
