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

import ai.philterd.aiproxy.config.ProxyProperties;
import ai.philterd.aiproxy.proxy.Routes;
import ai.philterd.aiproxy.proxy.TextSlots;
import ai.philterd.aiproxy.security.KeyScopes;
import ai.philterd.aiproxy.storage.ContextStore;
import ai.philterd.aiproxy.storage.Database;
import ai.philterd.aiproxy.storage.Encryptor;
import ai.philterd.phileas.services.context.ContextService;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UnitTests {

    static final String KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    static ProxyProperties properties(final Path db, final String key) {
        return new ProxyProperties(new ProxyProperties.Storage(db.toString()),
                new ProxyProperties.Security(key, null, null), null, null, null, null, null, null, null);
    }

    static jakarta.servlet.http.HttpServletRequest request(final String peer, final String forwardedFor) {
        final org.springframework.mock.web.MockHttpServletRequest request = new org.springframework.mock.web.MockHttpServletRequest();
        request.setRemoteAddr(peer);
        if (forwardedFor != null) {
            request.addHeader("X-Forwarded-For", forwardedFor);
        }
        return request;
    }

    @Test
    void believesForwardedForOnlyFromTrustedProxies() {
        final ai.philterd.aiproxy.proxy.ClientAddress none = new ai.philterd.aiproxy.proxy.ClientAddress(
                new ProxyProperties(null, null, null, null, null, null, null, null, null));
        assertEquals("10.0.0.5", none.of(request("10.0.0.5", "203.0.113.9")));

        final ai.philterd.aiproxy.proxy.ClientAddress trusted = new ai.philterd.aiproxy.proxy.ClientAddress(new ProxyProperties(null,
                new ProxyProperties.Security(KEY, null, null, List.of("10.0.0.0/8", "::1", "192.0.2.7")), null, null, null, null, null, null, null));
        assertEquals("203.0.113.9", trusted.of(request("10.0.0.5", "203.0.113.9")));
        // Read from the right: the client wrote the leftmost entry itself.
        assertEquals("198.51.100.4", trusted.of(request("10.0.0.5", "1.2.3.4, 198.51.100.4, 10.1.1.1")));
        assertEquals("10.0.0.5", trusted.of(request("10.0.0.5", "not-an-address")));
        assertEquals("10.0.0.5", trusted.of(request("10.0.0.5", "10.2.2.2")));
        assertEquals("2001:db8::1", trusted.of(request("0:0:0:0:0:0:0:1", "2001:db8::1")));
        assertEquals("203.0.113.1", trusted.of(request("203.0.113.1", "198.51.100.4")));
        assertEquals("203.0.113.9", trusted.of(request("192.0.2.7", "203.0.113.9")));
        assertThrows(IllegalStateException.class, () -> new ai.philterd.aiproxy.proxy.ClientAddress(new ProxyProperties(null,
                new ProxyProperties.Security(KEY, null, null, List.of("example.com")), null, null, null, null, null, null, null)));
        assertThrows(IllegalStateException.class, () -> new ai.philterd.aiproxy.proxy.ClientAddress(new ProxyProperties(null,
                new ProxyProperties.Security(KEY, null, null, List.of("10.0.0.0/40")), null, null, null, null, null, null, null)));
    }

    @Test
    void validatesConfigurationWithoutOpeningTheDatabase(@TempDir final Path dir) {
        final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        final java.io.ByteArrayOutputStream err = new java.io.ByteArrayOutputStream();
        final Path db = dir.resolve("never.db");
        assertEquals(0, ProxyApplication.validate(new String[]{"--validate-config", "--proxy.security.encryption-key=" + KEY,
                "--proxy.storage.sqlite-path=" + db}, new java.io.PrintStream(out), new java.io.PrintStream(err)));
        assertTrue(out.toString().contains("valid"));
        assertFalse(Files.exists(db));
        assertEquals(1, ProxyApplication.validate(new String[]{"--validate-config"}, new java.io.PrintStream(out), new java.io.PrintStream(err)));
        assertTrue(err.toString().contains("encryption-key"));
        assertEquals(1, ProxyApplication.validate(new String[]{"--proxy.security.encryption-key=" + KEY,
                "--proxy.providers.vertex.project=p"}, new java.io.PrintStream(out), new java.io.PrintStream(err)));
        assertTrue(err.toString().contains("Vertex AI needs"));
        assertNotEquals("", ProxyApplication.version());
    }

    @Test
    void keyScopesMatchExactlyOrByPrefix() {
        final KeyScopes scopes = new KeyScopes(Set.of(KeyScopes.Role.proxy), List.of("openai"), List.of("gpt-4*", "o3"),
                List.of("/v1/chat"), null);
        assertNull(scopes.check("openai", "gpt-4o", "/v1/chat/completions"));
        assertNull(scopes.check("openai", "o3", "/v1/chat/completions"));
        assertEquals("scope_denied_model", scopes.check("openai", "o3-mini", "/v1/chat/completions").code());
        assertEquals("scope_denied_model", scopes.check("openai", null, "/v1/chat/completions").code());
        assertEquals("scope_denied_provider", scopes.check("anthropic", "gpt-4o", "/v1/chat/completions").code());
        assertEquals("scope_denied_path", scopes.check("openai", "gpt-4o", "/v1/embeddings").code());
        assertNull(new KeyScopes(null, null, null, null, " ").check("x", null, "/"));
        assertNull(new KeyScopes(null, null, null, null, " ").policy());
    }

    @Test
    void routesMatchInOrderAndFallBackToDefaults() {
        final ProxyProperties.Outbound redact = new ProxyProperties.Outbound(true, ProxyProperties.Action.REDACT);
        final ProxyProperties p = new ProxyProperties(null, null, null, null, null,
                new ProxyProperties.Defaults("base", "ctx", null),
                List.of(new ProxyProperties.Route(new ProxyProperties.Match(null, "gpt-4o", "x-team", "a"), "team-a", null, redact),
                        new ProxyProperties.Route(new ProxyProperties.Match("/v1/chat/completions", null, null, null), null, "other", null,
                                ProxyProperties.Media.FORWARD)),
                null, null);
        final Map<String, String> headers = Map.of("x-team", "a");
        final Routes.Resolved first = Routes.resolve(p, "/v1/chat/completions", "gpt-4o", headers::get);
        assertEquals("team-a", first.policy());
        assertEquals("ctx", first.context());
        assertTrue(first.outbound().enabled());
        final Routes.Resolved second = Routes.resolve(p, "/v1/chat/completions", "o3", headers::get);
        assertEquals("base", second.policy());
        assertEquals("other", second.context());
        assertFalse(second.outbound().enabled());
        assertEquals(ProxyProperties.Media.REJECT, first.media());
        assertEquals(ProxyProperties.Media.FORWARD, second.media());
        final Routes.Resolved none = Routes.resolve(p, "/v1/embeddings", "o3", h -> null);
        assertEquals("base", none.policy());
        assertEquals(ProxyProperties.Outbound.DISABLED, none.outbound());
        assertEquals(ProxyProperties.Media.REJECT, none.media());
    }

    @Test
    void propertiesHaveSafeDefaults() {
        final ProxyProperties p = new ProxyProperties(null, null, null, null, null, null, null, null, null);
        assertEquals("default", p.defaults().policy());
        assertEquals("x-philter-proxy-key", p.security().proxyKeyHeader());
        assertEquals(10L * 1024 * 1024, p.limits().maxRequestBodyBytes());
        assertEquals(256, p.streaming().holdbackCharacters());
        assertEquals("https://api.openai.com", p.providers().openai().target());
        assertFalse(p.defaults().outbound().enabled());
        assertEquals("block", ProxyProperties.Action.BLOCK.code());
        assertEquals("https://example.com", new ProxyProperties.Provider("https://example.com//").target());
    }

    @Test
    void encryptsAndIndexes(@TempDir final Path dir) {
        final Encryptor encryptor = new Encryptor(properties(dir.resolve("x.db"), KEY));
        final String a = encryptor.encrypt("123-45-6789");
        assertNotEquals(a, encryptor.encrypt("123-45-6789"), "a fresh nonce each time");
        assertFalse(a.contains("6789"));
        assertEquals("123-45-6789", encryptor.decrypt(a));
        assertEquals(encryptor.index("v"), encryptor.index("v"));
        assertNotEquals(encryptor.index("v"), encryptor.index("w"));
        final Encryptor other = new Encryptor(properties(dir.resolve("x.db"),
                java.util.Base64.getEncoder().encodeToString(new byte[32])));
        assertThrows(IllegalStateException.class, () -> other.decrypt(a));
        assertThrows(IllegalStateException.class, () -> new Encryptor(properties(dir, null)));
        assertThrows(IllegalStateException.class, () -> new Encryptor(properties(dir, "abcd")));
    }

    @Test
    void collectsTextSlotsAndWritesThemBack() {
        final JsonObject json = JsonParser.parseString("""
                {"a":"one","b":["two",3,"",{"c":"four"}],"args":"{\\"k\\":\\"five\\",\\"n\\":[\\"six\\"]}","plain":"not {json",
                 "number":"42","empty":""}""").getAsJsonObject();
        final TextSlots slots = new TextSlots();
        slots.addString(json, "a");
        slots.addAllStrings(json.get("b"));
        slots.addJsonString(json, "args");
        slots.addJsonString(json, "plain");
        slots.addJsonString(json, "number");
        slots.addString(json, "empty");
        slots.addString(json, "missing");
        assertEquals(List.of("one", "two", "four", "five", "six", "not {json", "42"), slots.texts());
        slots.apply(slots.texts().stream().map(String::toUpperCase).toList());
        assertEquals("ONE", json.get("a").getAsString());
        assertEquals("[\"TWO\",3,\"\",{\"c\":\"FOUR\"}]", json.get("b").toString());
        assertEquals("{\"k\":\"FIVE\",\"n\":[\"SIX\"]}", json.get("args").getAsString());
        assertEquals("NOT {JSON", json.get("plain").getAsString());
    }

    @Test
    void createsTheDatabaseOwnerOnlyAndRefusesASecondInstance(@TempDir final Path dir) throws Exception {
        final Path db = dir.resolve("data").resolve("proxy.db");
        try (Database database = new Database(properties(db, KEY))) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(db)));
            final IllegalStateException e = assertThrows(IllegalStateException.class, () -> new Database(properties(db, KEY)));
            assertTrue(e.getMessage().contains("Another Philter AI Proxy"));
            try (Connection c = database.connect(); Statement s = c.createStatement();
                 ResultSet rs = s.executeQuery("SELECT MAX(version) FROM schema_version")) {
                rs.next();
                assertEquals(2, rs.getInt(1));
            }
        }
        // Reopening applies no migration twice.
        try (Database ignored = new Database(properties(db, KEY))) {
            assertTrue(Files.exists(db));
        }
    }

    @Test
    void refusesAnEncryptionKeyOtherThanTheDatabases(@TempDir final Path dir) throws Exception {
        final Path db = dir.resolve("proxy.db");
        try (Database database = new Database(properties(db, KEY))) {
            new ai.philterd.aiproxy.storage.KeyCheck(database, new Encryptor(properties(db, KEY)));
            new ai.philterd.aiproxy.storage.KeyCheck(database, new Encryptor(properties(db, KEY)));
            final String other = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
            final IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> new ai.philterd.aiproxy.storage.KeyCheck(database, new Encryptor(properties(db, other))));
            assertTrue(e.getMessage().contains("not the key this database was created with"));
        }
    }

    @Test
    void storesContextsEncrypted(@TempDir final Path dir) throws Exception {
        final ProxyProperties p = properties(dir.resolve("proxy.db"), KEY);
        try (Database database = new Database(p)) {
            final ContextStore store = new ContextStore(database, new Encryptor(p));
            final ContextService context = store.forContext("ctx");
            assertEquals("R1", context.computeReplacementIfAbsent("123-45-6789", "ssn", () -> "R1"));
            assertEquals("R1", context.computeReplacementIfAbsent("123-45-6789", "ssn", () -> "R2"));
            assertTrue(context.containsToken("123-45-6789"));
            assertTrue(context.containsReplacement("R1"));
            assertFalse(store.forContext("other").containsToken("123-45-6789"));
            context.putReplacement("123-45-6789", "R3", "ssn");
            assertEquals("R3", context.getReplacement("123-45-6789"));
            assertNull(context.computeReplacementIfAbsent("new", "ssn", () -> null));
            try (Connection c = database.connect(); Statement s = c.createStatement();
                 ResultSet rs = s.executeQuery("SELECT token, replacement FROM context_entries")) {
                while (rs.next()) {
                    assertFalse(rs.getString(1).contains("6789"));
                    assertFalse(rs.getString(2).contains("R3"));
                }
            }
        }
    }

}
