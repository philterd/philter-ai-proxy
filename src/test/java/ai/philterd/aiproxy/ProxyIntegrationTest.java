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
import ai.philterd.aiproxy.storage.AuditStore;
import ai.philterd.aiproxy.storage.PolicyStore;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
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
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ProxyIntegrationTest {

    static final String BOOTSTRAP = "test-bootstrap-key-0123456789abcdef0123456789";
    static final String SSN = "123-45-6789";
    static final String EMAIL = "jane.doe@example.com";
    static final String PATTERNS = """
            {"identifiers":{"ssn":{"ssnFilterStrategies":[{"strategy":"REDACT"}]},
             "emailAddress":{"emailAddressFilterStrategies":[{"strategy":"REDACT"}]}}}""";
    static final String RANDOM_SSN = """
            {"identifiers":{"ssn":{"ssnFilterStrategies":[{"strategy":"RANDOM_REPLACE","replacementScope":"CONTEXT"}]}}}""";

    static final StubProvider STUB;
    static final Path DATA;

    static {
        try {
            STUB = new StubProvider();
            DATA = Files.createTempDirectory("philter-ai-proxy-test");
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("proxy.storage.sqlite-path", () -> DATA.resolve("proxy.db").toString());
        registry.add("proxy.security.encryption-key", () -> "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        registry.add("proxy.security.bootstrap-api-key", () -> BOOTSTRAP);
        registry.add("proxy.models.directory", () -> DATA.resolve("models").toString());
        registry.add("proxy.providers.openai.target", STUB::url);
        // No test reaches a real provider.
        registry.add("proxy.providers.anthropic.target", STUB::url);
        registry.add("proxy.providers.gemini.target", STUB::url);
        registry.add("proxy.providers.ollama.target", STUB::url);
        registry.add("proxy.defaults.policy", () -> "patterns");
        registry.add("proxy.streaming.holdback-characters", () -> "16");
        registry.add("management.server.port", () -> "0");
        final String[] actions = {"redact", "block", "flag"};
        for (int i = 0; i < actions.length; i++) {
            registry.add("proxy.routes[" + i + "].match.header", () -> "x-test-outbound");
            final String action = actions[i];
            registry.add("proxy.routes[" + i + "].match.value", () -> action);
            registry.add("proxy.routes[" + i + "].outbound.enabled", () -> "true");
            registry.add("proxy.routes[" + i + "].outbound.action", () -> action);
        }
        registry.add("proxy.routes[3].match.header", () -> "x-test-outbound");
        registry.add("proxy.routes[3].match.value", () -> "missing");
        registry.add("proxy.routes[3].policy", () -> "no-such-policy");
        registry.add("proxy.routes[4].match.model", () -> "context-model");
        registry.add("proxy.routes[4].policy", () -> "random-ssn");
        registry.add("proxy.routes[4].context", () -> "ctx");
        registry.add("proxy.routes[5].match.model", () -> "no-context-model");
        registry.add("proxy.routes[5].policy", () -> "random-ssn");
        registry.add("proxy.routes[6].match.header", () -> "x-media");
        registry.add("proxy.routes[6].match.value", () -> "forward");
        registry.add("proxy.routes[6].media", () -> "forward");
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
    PolicyStore policies;

    @Autowired
    ApiKeyStore keys;

    @Autowired
    AuditStore audit;

    final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    String proxyKey;

    @BeforeEach
    void setUp() {
        STUB.reset();
        if (policies.find("patterns").isEmpty()) {
            policies.create("patterns", PATTERNS, "", "");
            policies.create("random-ssn", RANDOM_SSN, "", "");
        }
        proxyKey = keys.create("test", new KeyScopes(Set.of(KeyScopes.Role.proxy), List.of(), List.of(), List.of(), null)).secret();
    }

    // ---- helpers

    HttpResponse<String> chat(final String body, final String... headers) throws Exception {
        final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v1/chat/completions"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        for (int i = 0; i < headers.length; i += 2) {
            builder.header(headers[i], headers[i + 1]);
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> chatWithKey(final String body, final String... headers) throws Exception {
        final String[] all = new String[headers.length + 2];
        all[0] = "x-philter-proxy-key";
        all[1] = proxyKey;
        System.arraycopy(headers, 0, all, 2, headers.length);
        return chat(body, all);
    }

    HttpResponse<String> admin(final String method, final String path, final String body, final String... headers) throws Exception {
        final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body))
                .header("Authorization", "Bearer " + BOOTSTRAP);
        if (body != null) {
            builder.header("Content-Type", "application/json");
        }
        for (int i = 0; i < headers.length; i += 2) {
            builder.header(headers[i], headers[i + 1]);
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    static JsonObject json(final String body) {
        return JsonParser.parseString(body).getAsJsonObject();
    }

    /** The audit entry for the request, which is written just after the response completes. */
    AuditStore.Entry auditEntry(final String requestId) throws InterruptedException {
        for (int i = 0; i < 50; i++) {
            final var entry = audit.recent(100).stream().filter(e -> e.requestId().equals(requestId)).findFirst();
            if (entry.isPresent()) {
                return entry.get();
            }
            Thread.sleep(20);
        }
        throw new AssertionError("No audit entry for " + requestId);
    }

    static String errorCode(final HttpResponse<String> response) {
        return json(response.body()).getAsJsonObject("error").get("code").getAsString();
    }

    static String reason(final HttpResponse<String> response) {
        return json(response.body()).get("reason").getAsString();
    }

    static String simpleChat(final String model, final String content) {
        final JsonObject message = new JsonObject();
        message.addProperty("role", "user");
        message.addProperty("content", content);
        final JsonArray messages = new JsonArray();
        messages.add(message);
        final JsonObject body = new JsonObject();
        body.addProperty("model", model);
        body.add("messages", messages);
        return body.toString();
    }

    static String streamChat(final String content) {
        final JsonObject body = json(simpleChat("gpt-4o", content));
        body.addProperty("stream", true);
        return body.toString();
    }

    /** The content of a streamed response, reassembled from its events. */
    static String reassemble(final String sse) {
        final StringBuilder text = new StringBuilder();
        for (final String line : sse.split("\n")) {
            if (line.startsWith("data: {")) {
                final JsonObject chunk = json(line.substring(6));
                if (chunk.get("choices") instanceof JsonArray choices) {
                    for (final var choice : choices) {
                        final JsonObject delta = choice.getAsJsonObject().getAsJsonObject("delta");
                        if (delta != null && delta.has("content") && !delta.get("content").isJsonNull()) {
                            text.append(delta.get("content").getAsString());
                        }
                    }
                }
            }
        }
        return text.toString();
    }

    // ---- authentication

    @Test
    void refusesARequestWithoutAKey() throws Exception {
        final HttpResponse<String> response = chat(simpleChat("gpt-4o", "hello"));
        assertEquals(401, response.statusCode());
        assertEquals("missing_api_key", errorCode(response));
        assertNotNull(response.headers().firstValue("X-Request-Id").orElse(null));
        assertEquals(0, STUB.requests.get());
    }

    @Test
    void refusesAnUnknownKey() throws Exception {
        final HttpResponse<String> response = chat(simpleChat("gpt-4o", "hello"), "x-philter-proxy-key", "pap_nope");
        assertEquals(401, response.statusCode());
        assertEquals("invalid_api_key", errorCode(response));
    }

    @Test
    void refusesAnAdminKeyOnProviderTraffic() throws Exception {
        final HttpResponse<String> response = chat(simpleChat("gpt-4o", "hello"), "x-philter-proxy-key", BOOTSTRAP);
        assertEquals(403, response.statusCode());
        assertEquals("scope_denied_role", errorCode(response));
        assertEquals(0, STUB.requests.get());
    }

    @Test
    void enforcesModelScopes() throws Exception {
        final String limited = keys.create("limited", new KeyScopes(Set.of(KeyScopes.Role.proxy), List.of("openai"),
                List.of("gpt-4*"), List.of("/v1/"), null)).secret();
        assertEquals(403, chat(simpleChat("o3", "hi"), "x-philter-proxy-key", limited).statusCode());
        assertEquals("scope_denied_model", errorCode(chat(simpleChat("o3", "hi"), "x-philter-proxy-key", limited)));
        assertEquals(200, chat(simpleChat("gpt-4o", "hi"), "x-philter-proxy-key", limited).statusCode());
        final String otherProvider = keys.create("other", new KeyScopes(Set.of(KeyScopes.Role.proxy), List.of("anthropic"),
                List.of(), List.of(), null)).secret();
        assertEquals("scope_denied_provider", errorCode(chat(simpleChat("gpt-4o", "hi"), "x-philter-proxy-key", otherProvider)));
    }

    // ---- inbound redaction

    @Test
    void redactsEveryTextFieldAndKeepsTheRest() throws Exception {
        final String body = """
                {"model":"gpt-4o","temperature":0.2,"tools":[{"type":"function","function":{"name":"lookup"}}],
                 "messages":[
                  {"role":"system","content":"Customer SSN %1$s"},
                  {"role":"user","content":[{"type":"text","text":"email %2$s"},{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]},
                  {"role":"assistant","refusal":"cannot share %1$s","tool_calls":[{"id":"t1","type":"function","function":{"name":"lookup","arguments":"{\\"ssn\\":\\"%1$s\\",\\"n\\":3}"}}]},
                  {"role":"assistant","function_call":{"name":"legacy","arguments":"SSN %1$s"}},
                  {"role":"user","content":"nothing to see"}
                 ]}""".formatted(SSN, EMAIL);
        final HttpResponse<String> response = chatWithKey(body, "Authorization", "Bearer sk-provider", "Accept-Encoding", "gzip",
                "x-media", "forward");
        assertEquals(200, response.statusCode());

        final JsonObject sent = STUB.lastBody.get();
        assertFalse(sent.toString().contains(SSN), sent.toString());
        assertFalse(sent.toString().contains(EMAIL), sent.toString());
        final JsonArray messages = sent.getAsJsonArray("messages");
        assertEquals("Customer SSN {{{REDACTED-ssn}}}", messages.get(0).getAsJsonObject().get("content").getAsString());
        final JsonArray parts = messages.get(1).getAsJsonObject().getAsJsonArray("content");
        assertEquals("email {{{REDACTED-email-address}}}", parts.get(0).getAsJsonObject().get("text").getAsString());
        assertEquals("https://example.com/a.png", parts.get(1).getAsJsonObject().getAsJsonObject("image_url").get("url").getAsString());
        assertEquals("cannot share {{{REDACTED-ssn}}}", messages.get(2).getAsJsonObject().get("refusal").getAsString());
        final JsonObject args = json(messages.get(2).getAsJsonObject().getAsJsonArray("tool_calls").get(0).getAsJsonObject()
                .getAsJsonObject("function").get("arguments").getAsString());
        assertEquals("{{{REDACTED-ssn}}}", args.get("ssn").getAsString());
        assertEquals(3, args.get("n").getAsInt());
        assertEquals("SSN {{{REDACTED-ssn}}}", messages.get(3).getAsJsonObject().getAsJsonObject("function_call").get("arguments").getAsString());
        assertEquals("nothing to see", messages.get(4).getAsJsonObject().get("content").getAsString());
        assertEquals(0.2, sent.get("temperature").getAsDouble());
        assertEquals("lookup", sent.getAsJsonArray("tools").get(0).getAsJsonObject().getAsJsonObject("function").get("name").getAsString());

        // The provider's credential passes through; the proxy key and Accept-Encoding do not.
        assertEquals("Bearer sk-provider", STUB.lastHeaders.get().getFirst("Authorization"));
        assertNull(STUB.lastHeaders.get().getFirst("x-philter-proxy-key"));
        assertNull(STUB.lastHeaders.get().getFirst("Accept-Encoding"));
    }

    @Test
    void returnsTheResponseUnchangedWithoutOutboundScanning() throws Exception {
        final HttpResponse<String> response = chatWithKey(simpleChat("gpt-4o", "hi"));
        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains(SSN));
        assertEquals("kept", response.headers().firstValue("X-Provider-Header").orElse(null));
    }

    @Test
    void auditsMetadataWithoutText() throws Exception {
        final HttpResponse<String> response = chatWithKey(simpleChat("gpt-4o", "SSN " + SSN), "X-Request-Id", "trace-abc-123");
        assertEquals("trace-abc-123", response.headers().firstValue("X-Request-Id").orElse(null));
        final AuditStore.Entry entry = auditEntry("trace-abc-123");
        assertEquals("proxy_request", entry.event());
        assertEquals(1, entry.details().get("entity_count").getAsInt());
        assertEquals(1, entry.details().getAsJsonObject("entity_types").get("ssn").getAsInt());
        assertEquals("patterns", entry.details().get("policy_name").getAsString());
        assertFalse(entry.details().toString().contains(SSN));
    }

    @Test
    void replacesAnUnsafeRequestId() throws Exception {
        final HttpResponse<String> response = chatWithKey(simpleChat("gpt-4o", "hi"), "X-Request-Id", "x".repeat(200));
        assertNotEquals("x".repeat(200), response.headers().firstValue("X-Request-Id").orElse(null));
    }

    @Test
    void refusesWhenThePolicyDoesNotExistAndDoesNotForward() throws Exception {
        final HttpResponse<String> response = chatWithKey(simpleChat("gpt-4o", "SSN " + SSN), "x-test-outbound", "missing");
        assertEquals(500, response.statusCode());
        assertEquals("policy_not_found", errorCode(response));
        assertEquals(0, STUB.requests.get());
    }

    @Autowired
    ai.philterd.aiproxy.storage.Database database;

    @Autowired
    ai.philterd.aiproxy.storage.ContextStore contexts;

    @Autowired
    ai.philterd.aiproxy.redaction.PolicyCompiler compiler;

    @Test
    void policiesAreEncryptedAndContextsKeepNoOriginals() throws Exception {
        chatWithKey(simpleChat("context-model", "SSN " + SSN));
        try (java.sql.Connection c = database.connect(); java.sql.Statement st = c.createStatement()) {
            try (java.sql.ResultSet rs = st.executeQuery("SELECT policy FROM policies")) {
                while (rs.next()) {
                    assertFalse(rs.getString(1).contains("{"), rs.getString(1));
                }
            }
            int entries = 0;
            try (java.sql.ResultSet rs = st.executeQuery("SELECT token FROM context_entries")) {
                while (rs.next()) {
                    assertEquals("", rs.getString(1));
                    entries++;
                }
            }
            assertTrue(entries > 0);
        }
        assertTrue(policies.find("patterns").orElseThrow().policy().startsWith("{"));
    }

    @Test
    void redactionThatTakesTooLongIsRefused() {
        final ai.philterd.aiproxy.redaction.Redactor slow = new ai.philterd.aiproxy.redaction.Redactor(policies, contexts, compiler,
                java.time.Duration.ofNanos(1));
        final List<String> texts = java.util.Collections.nCopies(50, "SSN " + SSN + " and more text to scan");
        org.junit.jupiter.api.Assertions.assertThrows(ai.philterd.aiproxy.redaction.RedactionTimeoutException.class,
                () -> slow.session("patterns", null).redact(texts));
    }

    @Test
    void prunesTheAuditLogAndBoundsTheModel() throws Exception {
        chatWithKey(simpleChat("m".repeat(1000), "hi"), "X-Request-Id", "long-model");
        assertEquals(256, auditEntry("long-model").details().get("model").getAsString().length());
        assertTrue(audit.prune(java.time.Instant.now().plusSeconds(60)) > 0);
        assertTrue(audit.recent(10).isEmpty());
    }

    @Test
    void aKeyWithABoundPolicyCannotPickAHeaderRoute() throws Exception {
        final String bound = keys.create("bound-media", new KeyScopes(Set.of(KeyScopes.Role.proxy), List.of(), List.of(), List.of(),
                "patterns")).secret();
        final String body = """
                {"model":"gpt-4o","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]}""";
        // x-media: forward selects a route that forwards media; a policy-bound key is held to the defaults instead.
        final HttpResponse<String> response = chat(body, "x-philter-proxy-key", bound, "x-media", "forward");
        assertEquals(400, response.statusCode());
        assertEquals("media_not_allowed", errorCode(response));
        assertEquals(200, chatWithKey(body, "x-media", "forward").statusCode());
    }

    @Test
    void appliesAKeysBoundPolicy() throws Exception {
        final String bound = keys.create("bound", new KeyScopes(Set.of(KeyScopes.Role.proxy), List.of(), List.of(), List.of(),
                "random-ssn")).secret();
        chat(simpleChat("gpt-4o", "SSN " + SSN + " mail " + EMAIL), "x-philter-proxy-key", bound);
        final String content = STUB.lastBody.get().getAsJsonArray("messages").get(0).getAsJsonObject().get("content").getAsString();
        // random-ssn replaces the SSN with another value and does not touch the email address.
        assertFalse(content.contains(SSN));
        assertTrue(content.contains(EMAIL));
    }

    @Test
    void keepsReplacementsConsistentWithinAContext() throws Exception {
        chatWithKey(simpleChat("context-model", "SSN " + SSN));
        final String first = STUB.lastBody.get().getAsJsonArray("messages").get(0).getAsJsonObject().get("content").getAsString();
        chatWithKey(simpleChat("context-model", "SSN " + SSN));
        final String second = STUB.lastBody.get().getAsJsonArray("messages").get(0).getAsJsonObject().get("content").getAsString();
        assertFalse(first.contains(SSN));
        assertEquals(first, second);
    }

    @Test
    void keepsReplacementsConsistentWithinARequest() throws Exception {
        final String body = """
                {"model":"no-context-model","messages":[{"role":"user","content":"SSN %1$s"},{"role":"user","content":"again %1$s"}]}"""
                .formatted(SSN);
        chatWithKey(body);
        final JsonArray messages = STUB.lastBody.get().getAsJsonArray("messages");
        final String first = messages.get(0).getAsJsonObject().get("content").getAsString().substring(4);
        final String second = messages.get(1).getAsJsonObject().get("content").getAsString().substring(6);
        assertFalse(first.contains(SSN));
        assertEquals(first, second);
    }

    @Test
    void refusesBadRequests() throws Exception {
        assertEquals("bad_json", errorCode(chatWithKey("not json")));
        assertEquals("bad_json", errorCode(chatWithKey("[1,2]")));
        final HttpResponse<String> multipart = chat("--x--", "x-philter-proxy-key", proxyKey, "Content-Type", "multipart/form-data; boundary=x");
        assertEquals(400, multipart.statusCode());
        final HttpResponse<String> large = chatWithKey("{\"pad\":\"" + "a".repeat(11 * 1024 * 1024) + "\"}");
        assertEquals(413, large.statusCode());
        assertEquals(0, STUB.requests.get());
    }

    @Test
    void refusesMediaByDefault() throws Exception {
        final String body = """
                {"model":"gpt-4o","messages":[{"role":"user","content":[{"type":"text","text":"SSN %s"},
                 {"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]}""".formatted(SSN);
        final HttpResponse<String> response = chatWithKey(body, "X-Request-Id", "media-1");
        assertEquals(400, response.statusCode());
        assertEquals("media_not_allowed", errorCode(response));
        assertTrue(response.body().contains("'image_url'"), response.body());
        assertFalse(response.body().contains(SSN));
        assertEquals(0, STUB.requests.get());
        assertEquals("media_not_allowed", auditEntry("media-1").details().get("error_code").getAsString());
    }

    @Test
    void refusesImageEditsAndVariations() throws Exception {
        final String body = "--x\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nadd a hat\r\n--x--\r\n";
        for (final String path : new String[]{"/v1/images/edits", "/v1/images/variations"}) {
            final HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                    .header("x-philter-proxy-key", proxyKey)
                    .header("Content-Type", "multipart/form-data; boundary=x")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            final HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(400, response.statusCode(), path);
            assertEquals("unsupported_content_type", errorCode(response), path);
        }
        assertEquals(0, STUB.requests.get());
    }

    @Test
    void passesProviderErrorsThrough() throws Exception {
        STUB.status = 429;
        final HttpResponse<String> response = chatWithKey(simpleChat("gpt-4o", "hi"), "x-test-outbound", "block");
        assertEquals(429, response.statusCode());
        assertTrue(response.body().contains("stub error"));
    }

    // ---- outbound scanning, buffered

    @Test
    void redactsABufferedResponse() throws Exception {
        final HttpResponse<String> response = chatWithKey(simpleChat("gpt-4o", "hi"), "x-test-outbound", "redact");
        assertEquals(200, response.statusCode());
        final String content = json(response.body()).getAsJsonArray("choices").get(0).getAsJsonObject()
                .getAsJsonObject("message").get("content").getAsString();
        assertEquals("Your SSN is {{{REDACTED-ssn}}} and email is {{{REDACTED-email-address}}}, noted.", content);
    }

    @Test
    void blocksABufferedResponse() throws Exception {
        final HttpResponse<String> response = chatWithKey(simpleChat("gpt-4o", "hi"), "x-test-outbound", "block");
        assertEquals(403, response.statusCode());
        assertEquals("outbound_blocked", errorCode(response));
        assertFalse(response.body().contains(SSN));
    }

    @Test
    void allowsACleanBufferedResponseUnderBlock() throws Exception {
        STUB.reply = "Nothing sensitive here.";
        final HttpResponse<String> response = chatWithKey(simpleChat("gpt-4o", "hi"), "x-test-outbound", "block");
        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("Nothing sensitive here."));
    }

    @Test
    void flagsABufferedResponse() throws Exception {
        final HttpResponse<String> response = chatWithKey(simpleChat("gpt-4o", "hi"), "x-test-outbound", "flag", "X-Request-Id", "flag-1");
        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains(SSN));
        final AuditStore.Entry entry = auditEntry("flag-1");
        assertEquals(2, entry.details().get("outbound_entity_count").getAsInt());
    }

    // ---- outbound scanning, streamed

    @Test
    void redactsAStreamedResponse() throws Exception {
        for (final int chunkSize : new int[]{1, 3, 5, 200}) {
            STUB.chunkSize = chunkSize;
            final HttpResponse<String> response = chatWithKey(streamChat("hi"), "x-test-outbound", "redact");
            assertEquals(200, response.statusCode());
            assertEquals("Your SSN is {{{REDACTED-ssn}}} and email is {{{REDACTED-email-address}}}, noted.",
                    reassemble(response.body()), "chunk size " + chunkSize);
            assertFalse(response.body().contains("6789"), "chunk size " + chunkSize);
            assertTrue(response.body().contains("\"finish_reason\":\"stop\""));
            // The keep-alive is forwarded as a bare comment, without its text.
            assertTrue(response.body().contains(":\n\n"));
            assertFalse(response.body().contains(": keep-alive"));
            assertTrue(response.body().strip().endsWith("data: [DONE]"));
        }
    }

    @Test
    void releasesALongStreamInPieces() throws Exception {
        STUB.reply = "word ".repeat(60) + "SSN " + SSN + " " + "tail ".repeat(60);
        STUB.chunkSize = 7;
        final HttpResponse<String> response = chatWithKey(streamChat("hi"), "x-test-outbound", "redact");
        final String text = reassemble(response.body());
        assertEquals(STUB.reply.replace(SSN, "{{{REDACTED-ssn}}}"), text);
        final long events = response.body().lines().filter(l -> l.startsWith("data: {")).count();
        assertTrue(events > 5, "expected the text to be released in several events, got " + events);
    }

    @Test
    void blocksAStreamedResponseBeforeTheValueIsSent() throws Exception {
        STUB.chunkSize = 2;
        final HttpResponse<String> response = chatWithKey(streamChat("hi"), "x-test-outbound", "block");
        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("\"code\":\"outbound_blocked\""));
        assertFalse(response.body().contains("123-"), response.body());
        assertFalse(response.body().contains("[DONE]"));
    }

    @Test
    void flagsAStreamedResponse() throws Exception {
        final HttpResponse<String> response = chatWithKey(streamChat("hi"), "x-test-outbound", "flag");
        assertEquals(STUB.reply, reassemble(response.body()));
    }

    @Test
    void passesAStreamThroughWithoutOutboundScanning() throws Exception {
        final HttpResponse<String> response = chatWithKey(streamChat("hi"));
        assertEquals(STUB.reply, reassemble(response.body()));
    }

    // ---- outbound scanning: fields beyond content, logprobs, and data that cannot be scanned

    static String toolArgumentsIn(final String sse) {
        final StringBuilder arguments = new StringBuilder();
        for (final String line : sse.split("\n")) {
            if (line.startsWith("data: {")) {
                final JsonObject chunk = json(line.substring(6));
                if (chunk.get("choices") instanceof JsonArray choices) {
                    for (final var choice : choices) {
                        final JsonObject delta = choice.getAsJsonObject().getAsJsonObject("delta");
                        if (delta != null && delta.get("tool_calls") instanceof JsonArray calls) {
                            for (final var call : calls) {
                                final JsonObject function = call.getAsJsonObject().getAsJsonObject("function");
                                if (function != null && function.has("arguments")) {
                                    arguments.append(function.get("arguments").getAsString());
                                }
                            }
                        }
                    }
                }
            }
        }
        return arguments.toString();
    }

    @Test
    void redactsContentPartsAndToolArgumentsInABufferedResponse() throws Exception {
        STUB.contentParts = true;
        STUB.toolArguments = "{\"ssn\":\"" + SSN + "\",\"count\":2}";
        final HttpResponse<String> response = chatWithKey(simpleChat("gpt-4o", "hi"), "x-test-outbound", "redact");
        assertEquals(200, response.statusCode());
        assertFalse(response.body().contains("6789"), response.body());
        final JsonObject message = json(response.body()).getAsJsonArray("choices").get(0).getAsJsonObject().getAsJsonObject("message");
        assertEquals("Your SSN is {{{REDACTED-ssn}}} and email is {{{REDACTED-email-address}}}, noted.",
                message.getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString());
        final JsonObject args = json(message.getAsJsonArray("tool_calls").get(0).getAsJsonObject()
                .getAsJsonObject("function").get("arguments").getAsString());
        assertEquals("{{{REDACTED-ssn}}}", args.get("ssn").getAsString());
        assertEquals(2, args.get("count").getAsInt());
    }

    @Test
    void blocksABufferedResponseOnToolArguments() throws Exception {
        STUB.reply = "Looking that up.";
        STUB.toolArguments = "{\"ssn\":\"" + SSN + "\"}";
        final HttpResponse<String> response = chatWithKey(simpleChat("gpt-4o", "hi"), "x-test-outbound", "block");
        assertEquals(403, response.statusCode());
        assertFalse(response.body().contains("6789"));
    }

    @Test
    void removesLogprobsFromABufferedResponse() throws Exception {
        STUB.logprobs = true;
        for (final String action : new String[]{"redact", "block"}) {
            STUB.reply = action.equals("block") ? "Nothing sensitive." : STUB.reply;
            final HttpResponse<String> response = chatWithKey(simpleChat("gpt-4o", "hi"), "x-test-outbound", action);
            assertEquals(200, response.statusCode(), action);
            assertTrue(json(response.body()).getAsJsonArray("choices").get(0).getAsJsonObject().get("logprobs").isJsonNull(), action);
            assertFalse(response.body().contains("6789"), action);
        }
        STUB.reset();
        STUB.logprobs = true;
        final HttpResponse<String> flagged = chatWithKey(simpleChat("gpt-4o", "hi"), "x-test-outbound", "flag");
        assertTrue(json(flagged.body()).getAsJsonArray("choices").get(0).getAsJsonObject().get("logprobs").isJsonObject());
    }

    @Test
    void removesLogprobsFromAStreamedResponse() throws Exception {
        STUB.logprobs = true;
        STUB.chunkSize = 3;
        final HttpResponse<String> redacted = chatWithKey(streamChat("hi"), "x-test-outbound", "redact");
        assertFalse(redacted.body().contains("6789"), redacted.body());
        assertFalse(redacted.body().contains("\"token\""), redacted.body());
        assertEquals("Your SSN is {{{REDACTED-ssn}}} and email is {{{REDACTED-email-address}}}, noted.", reassemble(redacted.body()));

        final HttpResponse<String> blocked = chatWithKey(streamChat("hi"), "x-test-outbound", "block");
        assertFalse(blocked.body().contains("123-"), blocked.body());
        assertFalse(blocked.body().contains("\"token\""), blocked.body());
        assertTrue(blocked.body().contains("outbound_blocked"));
    }

    @Test
    void redactsToolArgumentsInAStreamedResponse() throws Exception {
        STUB.reply = "Looking that up.";
        STUB.toolArguments = "{\"ssn\":\"" + SSN + "\",\"email\":\"" + EMAIL + "\"}";
        STUB.chunkSize = 4;
        final HttpResponse<String> response = chatWithKey(streamChat("hi"), "x-test-outbound", "redact");
        assertEquals(200, response.statusCode());
        assertFalse(response.body().contains("6789"), response.body());
        assertFalse(response.body().contains("jane.doe"), response.body());
        final JsonObject args = json(toolArgumentsIn(response.body()));
        assertEquals("{{{REDACTED-ssn}}}", args.get("ssn").getAsString());
        assertEquals("{{{REDACTED-email-address}}}", args.get("email").getAsString());
        // The call's id and name are forwarded before its arguments, and the finish reason after them.
        final String body = response.body();
        assertTrue(body.indexOf("\"id\":\"call_1\"") < body.indexOf("REDACTED-ssn"));
        assertTrue(body.indexOf("REDACTED-ssn") < body.indexOf("\"finish_reason\":\"tool_calls\""));
        assertEquals("Looking that up.", reassemble(body));
    }

    @Test
    void blocksAStreamedResponseOnToolArguments() throws Exception {
        STUB.reply = "Looking that up.";
        STUB.toolArguments = "{\"ssn\":\"" + SSN + "\"}";
        STUB.chunkSize = 2;
        final HttpResponse<String> response = chatWithKey(streamChat("hi"), "x-test-outbound", "block");
        assertFalse(response.body().contains("123-"), response.body());
        assertTrue(response.body().contains("outbound_blocked"));
    }

    @Test
    void refusesACompressedResponseItCannotScan() throws Exception {
        STUB.gzip = true;
        for (final String body : new String[]{simpleChat("gpt-4o", "hi"), streamChat("hi")}) {
            final HttpResponse<String> response = chatWithKey(body, "x-test-outbound", "redact");
            assertEquals(502, response.statusCode());
            assertEquals("response_unscannable", errorCode(response));
        }
    }

    @Test
    void passesACompressedResponseThroughWithItsEncoding() throws Exception {
        STUB.gzip = true;
        final HttpResponse<byte[]> response = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v1/chat/completions"))
                .header("Content-Type", "application/json").header("x-philter-proxy-key", proxyKey)
                .POST(HttpRequest.BodyPublishers.ofString(simpleChat("gpt-4o", "hi"))).build(), HttpResponse.BodyHandlers.ofByteArray());
        assertEquals("gzip", response.headers().firstValue("Content-Encoding").orElse(null));
        final String body = new String(new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(response.body())).readAllBytes());
        assertTrue(body.contains("chat.completion"));
    }

    @Test
    void endsAStreamOnDataItCannotScan() throws Exception {
        STUB.junkEvent = true;
        final HttpResponse<String> redacted = chatWithKey(streamChat("hi"), "x-test-outbound", "redact");
        assertTrue(redacted.body().contains("response_unscannable"), redacted.body());
        assertFalse(redacted.body().contains("this is not json"));
        assertFalse(redacted.body().contains("[DONE]"));

        final HttpResponse<String> flagged = chatWithKey(streamChat("hi"), "x-test-outbound", "flag");
        assertTrue(flagged.body().contains("this is not json"));
        assertTrue(flagged.body().contains("[DONE]"));
    }

    // ---- health and metrics

    @Test
    void servesHealthAndMetrics() throws Exception {
        final HttpResponse<String> health = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/health")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, health.statusCode());
        assertEquals("UP", json(health.body()).get("status").getAsString());
        assertNotNull(json(health.body()).get("applicationVersion"));
        assertEquals(200, http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/livez")).build(),
                HttpResponse.BodyHandlers.ofString()).statusCode());

        chatWithKey(simpleChat("gpt-4o", "SSN " + SSN));
        final HttpResponse<String> metrics = http.send(HttpRequest.newBuilder(
                URI.create("http://localhost:" + managementPort + "/metrics")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, metrics.statusCode());
        assertTrue(metrics.body().contains("philter_proxy_requests_total"), metrics.body());
        assertTrue(metrics.body().contains("philter_proxy_entities_redacted_total{entity_type=\"ssn\""), metrics.body());
    }

    @Test
    void becomesReady() throws Exception {
        int status = 0;
        for (int i = 0; i < 100 && status != 200; i++) {
            status = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/readyz")).build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode();
            if (status != 200) {
                Thread.sleep(100);
            }
        }
        assertEquals(200, status);
    }

}
