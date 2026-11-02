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

import ai.philterd.aiproxy.providers.CloudCredentials;
import ai.philterd.aiproxy.security.KeyScopes;
import ai.philterd.aiproxy.storage.ApiKeyStore;
import ai.philterd.aiproxy.storage.PolicyStore;
import ai.philterd.aiproxy.stream.EventStreamFraming;
import ai.philterd.aiproxy.stream.StreamEvent;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Every provider other than OpenAI chat: request redaction, buffered and streamed response scanning, and auth. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ProvidersIntegrationTest {

    static final String SSN = "123-45-6789";
    static final String EMAIL = "jane.doe@example.com";
    static final String R_SSN = "{{{REDACTED-ssn}}}";
    static final String R_EMAIL = "{{{REDACTED-email-address}}}";
    static final String PATTERNS = """
            {"identifiers":{"ssn":{"ssnFilterStrategies":[{"strategy":"REDACT"}]},
             "emailAddress":{"emailAddressFilterStrategies":[{"strategy":"REDACT"}]}}}""";

    static final ScriptedProvider STUB;
    static final Path DATA;

    static {
        try {
            STUB = new ScriptedProvider();
            DATA = Files.createTempDirectory("philter-ai-proxy-providers-test");
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("proxy.storage.sqlite-path", () -> DATA.resolve("proxy.db").toString());
        registry.add("proxy.security.encryption-key", () -> "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        registry.add("proxy.models.directory", () -> DATA.resolve("models").toString());
        registry.add("proxy.defaults.policy", () -> "patterns");
        registry.add("proxy.streaming.holdback-characters", () -> "12");
        registry.add("management.server.port", () -> "0");
        for (final String p : new String[]{"openai", "anthropic", "gemini", "ollama"}) {
            registry.add("proxy.providers." + p + ".target", STUB::url);
        }
        registry.add("proxy.providers.azure.target", STUB::url);
        registry.add("proxy.providers.azure.api-version", () -> "2024-10-21");
        registry.add("proxy.providers.vertex.project", () -> "test-project");
        registry.add("proxy.providers.vertex.target", STUB::url);
        registry.add("proxy.providers.bedrock.region", () -> "us-east-1");
        registry.add("proxy.providers.bedrock.target", STUB::url);
        registry.add("proxy.providers.openai-compatible.local.target", STUB::url);
        final String[] actions = {"redact", "block"};
        for (int i = 0; i < actions.length; i++) {
            final String action = actions[i];
            registry.add("proxy.routes[" + i + "].match.header", () -> "x-out");
            registry.add("proxy.routes[" + i + "].match.value", () -> action);
            registry.add("proxy.routes[" + i + "].outbound.enabled", () -> "true");
            registry.add("proxy.routes[" + i + "].outbound.action", () -> action);
        }
        // The provider tests send images to check they are forwarded unchanged; refusal is tested with x-media.
        registry.add("proxy.defaults.media", () -> "forward");
        registry.add("proxy.limits.max-response-body-bytes", () -> "65536");
        registry.add("proxy.routes[2].match.header", () -> "x-media");
        registry.add("proxy.routes[2].match.value", () -> "reject");
        registry.add("proxy.routes[2].media", () -> "reject");
        registry.add("proxy.routes[3].match.header", () -> "x-unsupported");
        registry.add("proxy.routes[3].match.value", () -> "forward");
        registry.add("proxy.routes[3].unsupported-endpoints", () -> "forward");
        registry.add("proxy.routes[4].match.header", () -> "x-unsupported");
        registry.add("proxy.routes[4].match.value", () -> "forward-scanned");
        registry.add("proxy.routes[4].unsupported-endpoints", () -> "forward");
        registry.add("proxy.routes[4].outbound.enabled", () -> "true");
        registry.add("proxy.routes[4].outbound.action", () -> "block");
        registry.add("proxy.routes[5].match.header", () -> "x-out");
        registry.add("proxy.routes[5].match.value", () -> "flag");
        registry.add("proxy.routes[5].outbound.enabled", () -> "true");
        registry.add("proxy.routes[5].outbound.action", () -> "flag");
        registry.add("proxy.routes[6].match.header", () -> "x-policy");
        registry.add("proxy.routes[6].match.value", () -> "missing");
        registry.add("proxy.routes[6].policy", () -> "no-such-policy");
    }

    @TestConfiguration
    static class Credentials {
        @Bean
        @Primary
        CloudCredentials testCredentials() {
            return new CloudCredentials() {
                @Override
                public String googleAccessToken() {
                    return "google-test-token";
                }

                @Override
                public String azureAccessToken() {
                    return "azure-test-token";
                }

                @Override
                public AwsCredentialsIdentity awsCredentials(final String region, final String roleArn) {
                    return AwsCredentialsIdentity.create("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
                }
            };
        }
    }

    @AfterAll
    static void stop() {
        STUB.close();
    }

    @LocalServerPort
    int port;

    @Autowired
    PolicyStore policies;

    @Autowired
    ApiKeyStore keys;

    final HttpClient http = HttpClient.newHttpClient();
    String key;

    @BeforeEach
    void setUp() {
        STUB.reset();
        if (policies.find("patterns").isEmpty()) {
            policies.create("patterns", PATTERNS, "", "");
        }
        key = keys.create("t", new KeyScopes(Set.of(KeyScopes.Role.proxy), List.of(), List.of(), List.of(), null)).secret();
    }

    HttpResponse<byte[]> send(final String method, final String path, final String body, final String... headers) throws Exception {
        final HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("x-philter-proxy-key", key)
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        if (body != null) {
            b.header("Content-Type", "application/json");
        }
        for (int i = 0; i < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    HttpResponse<byte[]> post(final String path, final String body, final String... headers) throws Exception {
        return send("POST", path, body, headers);
    }

    static String text(final HttpResponse<byte[]> response) {
        return new String(response.body(), StandardCharsets.UTF_8);
    }

    static JsonObject json(final String s) {
        return JsonParser.parseString(s).getAsJsonObject();
    }

    static String sent() {
        return STUB.lastRaw;
    }

    static void assertNoOriginals(final String s) {
        assertFalse(s.contains("6789"), s);
        assertFalse(s.contains("jane.doe"), s);
    }

    /** SSE events, each {@code data:} payload split into small pieces the way a stream delivers it. */
    static List<String> sse(final String... events) {
        final List<String> out = new ArrayList<>();
        for (final String e : events) {
            out.add(e + "\n\n");
        }
        return out;
    }

    // ---- Anthropic

    @Test
    void anthropicRequestIsRedactedAndKeepsItsFields() throws Exception {
        STUB.reply("application/json", "{\"content\":[]}");
        final String body = """
                {"model":"claude-x","max_tokens":256,"stream":false,"system":"Agent notes SSN %1$s",
                 "tools":[{"name":"lookup","input_schema":{"type":"object"}}],
                 "messages":[
                  {"role":"user","content":"my email is %2$s"},
                  {"role":"assistant","content":[{"type":"thinking","thinking":"user SSN %1$s","signature":"sig"},
                    {"type":"text","text":"Looking up %1$s"},{"type":"tool_use","id":"t1","name":"lookup","input":{"ssn":"%1$s","n":1}}]},
                  {"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"found %2$s"},
                    {"type":"tool_result","tool_use_id":"t2","content":[{"type":"text","text":"ssn %1$s"}]}]}
                 ]}""".formatted(SSN, EMAIL);
        assertEquals(200, post("/v1/messages", body, "anthropic-version", "2023-06-01", "x-api-key", "sk-ant").statusCode());
        assertEquals("/v1/messages", STUB.lastPath);
        final JsonObject s = STUB.lastBody();
        assertEquals(256, s.get("max_tokens").getAsInt());
        assertEquals("lookup", s.getAsJsonArray("tools").get(0).getAsJsonObject().get("name").getAsString());
        assertEquals("Agent notes SSN " + R_SSN, s.get("system").getAsString());
        final JsonArray messages = s.getAsJsonArray("messages");
        assertEquals("my email is " + R_EMAIL, messages.get(0).getAsJsonObject().get("content").getAsString());
        final JsonArray assistant = messages.get(1).getAsJsonObject().getAsJsonArray("content");
        // Thinking blocks are signed by Anthropic and left alone.
        assertEquals("user SSN " + SSN, assistant.get(0).getAsJsonObject().get("thinking").getAsString());
        assertEquals("Looking up " + R_SSN, assistant.get(1).getAsJsonObject().get("text").getAsString());
        assertEquals(R_SSN, assistant.get(2).getAsJsonObject().getAsJsonObject("input").get("ssn").getAsString());
        final JsonArray results = messages.get(2).getAsJsonObject().getAsJsonArray("content");
        assertEquals("found " + R_EMAIL, results.get(0).getAsJsonObject().get("content").getAsString());
        assertEquals("ssn " + R_SSN, results.get(1).getAsJsonObject().getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString());
        assertEquals("sk-ant", STUB.lastHeaders.getFirst("x-api-key"));
    }

    @Test
    void anthropicSystemBlocksAreRedacted() throws Exception {
        post("/v1/messages", "{\"model\":\"m\",\"max_tokens\":1,\"system\":[{\"type\":\"text\",\"text\":\"SSN " + SSN + "\"}],\"messages\":[]}");
        assertNoOriginals(sent());
    }

    @Test
    void anthropicResponseIsScanned() throws Exception {
        STUB.reply("application/json", """
                {"id":"m","type":"message","content":[{"type":"thinking","thinking":"the SSN is %1$s","signature":"s"},
                 {"type":"text","text":"SSN %1$s"},{"type":"tool_use","id":"t","name":"f","input":{"email":"%2$s"}}]}""".formatted(SSN, EMAIL));
        final HttpResponse<byte[]> response = post("/v1/messages", "{\"model\":\"m\",\"max_tokens\":1,\"messages\":[]}", "x-out", "redact");
        assertEquals(200, response.statusCode());
        assertNoOriginals(text(response));
        assertTrue(text(response).contains("SSN " + R_SSN));
        assertEquals(403, post("/v1/messages", "{\"model\":\"m\",\"max_tokens\":1,\"messages\":[]}", "x-out", "block").statusCode());
    }

    @Test
    void anthropicCitationsAreScanned() throws Exception {
        STUB.reply("application/json", """
                {"id":"m","type":"message","content":[{"type":"text","text":"See the file.","citations":[
                 {"type":"char_location","cited_text":"SSN %1$s","document_index":0,"document_title":"Record for %2$s",
                  "start_char_index":0,"end_char_index":15},
                 {"type":"web_search_result_location","cited_text":"mail %2$s","url":"https://example.com/a",
                  "title":"Page about %2$s","encrypted_index":"e"}]}]}""".formatted(SSN, EMAIL));
        final HttpResponse<byte[]> response = post("/v1/messages", "{\"model\":\"m\",\"max_tokens\":1,\"messages\":[]}", "x-out", "redact");
        assertEquals(200, response.statusCode());
        assertNoOriginals(text(response));
        final JsonObject citation = json(text(response)).getAsJsonArray("content").get(0).getAsJsonObject()
                .getAsJsonArray("citations").get(0).getAsJsonObject();
        assertEquals("SSN " + R_SSN, citation.get("cited_text").getAsString());
        assertEquals(0, citation.get("start_char_index").getAsInt());
        assertTrue(text(response).contains("https://example.com/a"));
        assertEquals(403, post("/v1/messages", "{\"model\":\"m\",\"max_tokens\":1,\"messages\":[]}", "x-out", "block").statusCode());
    }

    @Test
    void aBodylessRequestDoesNotNeedThePolicy() throws Exception {
        STUB.reply("application/json", "{\"object\":\"list\",\"data\":[]}");
        final HttpResponse<byte[]> listed = send("GET", "/v1/models", null, "x-policy", "missing");
        assertEquals(200, listed.statusCode(), text(listed));
        assertEquals(1, STUB.requests);

        STUB.reset();
        final HttpResponse<byte[]> chat = post("/v1/chat/completions", "{\"model\":\"m\",\"messages\":[]}", "x-policy", "missing");
        assertEquals(500, chat.statusCode());
        assertTrue(text(chat).contains("policy_not_found"), text(chat));
        assertEquals(0, STUB.requests);
    }

    @Test
    void toolArgumentsWithNothingToRedactAreForwardedAsSent() throws Exception {
        STUB.reply("application/json", "{\"choices\":[]}");
        // Spacing and an escape a re-serialization would change, and arguments that are not valid JSON.
        final String spaced = "{ \\\"city\\\": \\\"Paris\\\\u00e9\\\" }";
        final String malformed = "{city: Paris}";
        post("/v1/chat/completions", "{\"model\":\"m\",\"messages\":[{\"role\":\"assistant\",\"tool_calls\":["
                + "{\"id\":\"a\",\"type\":\"function\",\"function\":{\"name\":\"f\",\"arguments\":\"" + spaced + "\"}},"
                + "{\"id\":\"b\",\"type\":\"function\",\"function\":{\"name\":\"f\",\"arguments\":\"" + malformed + "\"}}]}]}");
        final var calls = STUB.lastBody().getAsJsonArray("messages").get(0).getAsJsonObject().getAsJsonArray("tool_calls");
        assertEquals("{ \"city\": \"Paris\\u00e9\" }", calls.get(0).getAsJsonObject().getAsJsonObject("function").get("arguments").getAsString());
        assertEquals(malformed, calls.get(1).getAsJsonObject().getAsJsonObject("function").get("arguments").getAsString());

        // Malformed arguments that hold a value are redacted as a whole string.
        post("/v1/chat/completions", "{\"model\":\"m\",\"messages\":[{\"role\":\"assistant\",\"tool_calls\":["
                + "{\"id\":\"a\",\"type\":\"function\",\"function\":{\"name\":\"f\",\"arguments\":\"{ssn: " + SSN + "}\"}}]}]}");
        assertNoOriginals(sent());
    }

    @Test
    void aResponseThatIsNotStrictJsonIsUnscannable() throws Exception {
        STUB.reply("application/json", "{'choices':[{'index':0,'message':{'role':'assistant','content':'SSN " + SSN + "'}}]}");
        final HttpResponse<byte[]> response = post("/v1/chat/completions", "{\"model\":\"m\",\"messages\":[]}", "x-out", "redact");
        assertEquals(502, response.statusCode());
        assertTrue(text(response).contains("response_unscannable"), text(response));
        assertNoOriginals(text(response));
    }

    @Test
    void adminAndHealthPathsAreNeverProviderTraffic() throws Exception {
        for (final String[] request : new String[][]{{"GET", "/admin/api/nothing"}, {"PATCH", "/admin/api/keys"},
                {"GET", "/ADMIN/api/keys"}, {"GET", "/%61dmin/api/nothing"}, {"POST", "/readyz"}, {"POST", "/health/"},
                {"DELETE", "/admin"}}) {
            final HttpResponse<byte[]> response = send(request[0], request[1], null, "Authorization", "Bearer sk-test");
            assertEquals(404, response.statusCode(), request[0] + " " + request[1] + ": " + text(response));
            assertEquals("not_found", json(text(response)).get("reason").getAsString());
        }
        // A wrong content type on a real admin endpoint.
        final HttpResponse<byte[]> plain = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/admin/api/keys"))
                .header("x-philter-proxy-key", key).header("Content-Type", "text/plain")
                .POST(HttpRequest.BodyPublishers.ofString("{\"model\":\"m\"}")).build(), HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(404, plain.statusCode(), text(plain));
        assertEquals(0, STUB.requests);
    }

    @Test
    void anthropicStreamIsScanned() throws Exception {
        STUB.replyChunks("text/event-stream", sse(
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"content\":[]}}",
                "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Your SSN is 123-\"}}",
                "event: ping\ndata: {\"type\":\"ping\"}",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"45-6789, done.\"}}",
                "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}",
                "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"f\",\"input\":{}}}",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"email\\\":\\\"jane.\"}}",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"doe@example.com\\\"}\"}}",
                "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}",
                "event: message_stop\ndata: {\"type\":\"message_stop\"}"));
        final HttpResponse<byte[]> response = post("/v1/messages", "{\"model\":\"m\",\"max_tokens\":1,\"stream\":true,\"messages\":[]}", "x-out", "redact");
        final String body = text(response);
        assertNoOriginals(body);
        final StringBuilder textOut = new StringBuilder();
        final StringBuilder jsonOut = new StringBuilder();
        for (final String line : body.split("\n")) {
            if (line.startsWith("data: ") && line.contains("content_block_delta")) {
                final JsonObject delta = json(line.substring(6)).getAsJsonObject("delta");
                if (delta.has("text")) {
                    textOut.append(delta.get("text").getAsString());
                }
                if (delta.has("partial_json")) {
                    jsonOut.append(delta.get("partial_json").getAsString());
                }
            }
        }
        assertEquals("Your SSN is " + R_SSN + ", done.", textOut.toString());
        assertEquals(R_EMAIL, json(jsonOut.toString()).get("email").getAsString());
        assertTrue(body.contains("event: content_block_delta\n"), "events keep their event lines");
        assertTrue(body.indexOf(", done.") < body.indexOf("\"index\":0}"), "text is released before its block stops");
        assertTrue(body.contains("message_stop"));

        final String blocked = text(post("/v1/messages", "{\"model\":\"m\",\"max_tokens\":1,\"stream\":true,\"messages\":[]}", "x-out", "block"));
        assertFalse(blocked.contains("123-"), blocked);
        assertTrue(blocked.contains("event: error") && blocked.contains("outbound_blocked"), blocked);
    }

    // ---- media

    @Test
    void mediaIsRefusedForEveryProviderWhenConfigured() throws Exception {
        final String[][] cases = {
                {"/v1/chat/completions", "{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"hi\"},{\"type\":\"image_url\",\"image_url\":{\"url\":\"data:image/png;base64,AAAA\"}}]}]}", "image_url"},
                {"/v1/chat/completions", "{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"input_audio\",\"input_audio\":{\"data\":\"AAAA\",\"format\":\"wav\"}}]}]}", "input_audio"},
                {"/v1/chat/completions", "{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"file\",\"file\":{\"file_id\":\"file-1\"}}]}]}", "file"},
                {"/local/v1/chat/completions", "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"video_url\",\"video_url\":{\"url\":\"https://example.com/v.mp4\"}}]}]}", "video_url"},
                {"/v1/responses", "{\"model\":\"gpt-4o\",\"input\":[{\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"hi\"},{\"type\":\"input_image\",\"image_url\":\"https://example.com/a.png\"}]}]}", "input_image"},
                {"/v1/responses", "{\"model\":\"gpt-4o\",\"input\":[{\"type\":\"function_call_output\",\"call_id\":\"c\",\"output\":[{\"type\":\"input_file\",\"file_id\":\"file-1\"}]}]}", "input_file"},
                {"/v1/moderations", "{\"model\":\"omni-moderation-latest\",\"input\":[{\"type\":\"image_url\",\"image_url\":{\"url\":\"https://example.com/a.png\"}}]}", "image_url"},
                {"/v1/messages", "{\"model\":\"m\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"image\",\"source\":{\"type\":\"base64\",\"media_type\":\"image/png\",\"data\":\"AAAA\"}}]}]}", "image"},
                {"/v1/messages", "{\"model\":\"m\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"tool_use_id\":\"t\",\"content\":[{\"type\":\"document\",\"source\":{\"type\":\"text\",\"media_type\":\"text/plain\",\"data\":\"x\"}}]}]}]}", "document"},
                {"/v1beta/models/gemini-2.5-flash:generateContent", GEMINI_REQUEST, "inlineData"},
                {"/v1beta/models/gemini-2.5-flash:generateContent", "{\"contents\":[{\"role\":\"user\",\"parts\":[{\"functionResponse\":{\"name\":\"f\",\"response\":{},\"parts\":[{\"fileData\":{\"mimeType\":\"application/pdf\",\"fileUri\":\"gs://b/f.pdf\"}}]}}]}]}", "fileData"},
                {"/model/anthropic.claude-3-haiku/converse", "{\"messages\":[{\"role\":\"user\",\"content\":[{\"video\":{\"format\":\"mp4\",\"source\":{\"bytes\":\"AAAA\"}}}]}]}", "video"},
                {"/model/anthropic.claude-3-haiku/converse", "{\"messages\":[{\"role\":\"user\",\"content\":[{\"toolResult\":{\"toolUseId\":\"t\",\"content\":[{\"image\":{\"format\":\"png\",\"source\":{\"bytes\":\"AAAA\"}}}]}}]}]}", "image"},
                {"/api/chat", "{\"model\":\"llama\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\",\"images\":[\"AAAA\"]}]}", "images"},
                {"/api/generate", "{\"model\":\"llama\",\"prompt\":\"hi\",\"images\":[\"AAAA\"]}", "images"},
                {"/v1beta/models/gemini-embedding-001:embedContent", "{\"content\":{\"parts\":[{\"inlineData\":{\"mimeType\":\"image/png\",\"data\":\"AAAA\"}}]}}", "inlineData"},
                {"/v1beta/models/gemini-embedding-001:batchEmbedContents", "{\"requests\":[{\"content\":{\"parts\":[{\"text\":\"a\"}]}},{\"content\":{\"parts\":[{\"fileData\":{\"fileUri\":\"gs://b/f.png\"}}]}}]}", "fileData"},
                {"/v1beta/models/gemini-2.5-flash:countTokens", "{\"generateContentRequest\":{\"model\":\"models/gemini-2.5-flash\",\"contents\":[{\"parts\":[{\"inlineData\":{\"mimeType\":\"image/png\",\"data\":\"AAAA\"}}]}]}}", "inlineData"},
                {"/model/anthropic.claude-3-haiku-20240307-v1%3A0/invoke", "{\"anthropic_version\":\"bedrock-2023-05-31\",\"max_tokens\":1,"
                        + "\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"image\",\"source\":{\"type\":\"base64\",\"data\":\"AAAA\"}}]}]}", "image"},
                {"/model/amazon.titan-embed-image-v1/invoke", "{\"inputText\":\"a cat\",\"inputImage\":\"AAAA\"}", "inputImage"},
                {"/model/cohere.embed-v4%3A0/invoke", "{\"images\":[\"data:image/png;base64,AAAA\"],\"input_type\":\"image\"}", "images"},
                {"/model/cohere.embed-v4%3A0/invoke", "{\"inputs\":[{\"content\":[{\"type\":\"text\",\"text\":\"a\"},{\"type\":\"image_url\",\"image_url\":\"data:image/png;base64,AAAA\"}]}]}", "image_url"},
        };
        for (final String[] c : cases) {
            final HttpResponse<byte[]> response = post(c[0], c[1], "x-media", "reject");
            assertEquals(400, response.statusCode(), c[0] + " " + c[2]);
            assertTrue(text(response).contains("media_not_allowed"), text(response));
            assertTrue(text(response).contains("'" + c[2] + "'"), c[2] + ": " + text(response));
        }
        assertEquals(0, STUB.requests);
    }

    @Test
    void textOnlyRequestsAreNotRefusedAsMedia() throws Exception {
        final String[][] cases = {
                {"/v1/chat/completions", "{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"hi\"}]},{\"role\":\"assistant\",\"content\":[{\"type\":\"refusal\",\"refusal\":\"no\"}]}]}"},
                {"/v1/responses", "{\"model\":\"gpt-4o\",\"input\":[{\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"an input_image\"}]},{\"type\":\"function_call\",\"call_id\":\"c\",\"name\":\"f\",\"arguments\":\"{\\\"type\\\":\\\"input_image\\\"}\"}]}"},
                {"/v1/messages", "{\"model\":\"m\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"hi\"},{\"type\":\"tool_result\",\"tool_use_id\":\"t\",\"content\":\"ok\"}]}]}"},
                {"/v1beta/models/gemini-2.5-flash:generateContent", "{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":\"hi\"}]}]}"},
                {"/api/chat", "{\"model\":\"llama\",\"stream\":false,\"messages\":[{\"role\":\"user\",\"content\":\"hi\",\"images\":[]}]}"},
        };
        for (final String[] c : cases) {
            STUB.reset();
            assertEquals(200, post(c[0], c[1], "x-media", "reject").statusCode(), c[0]);
            assertEquals(1, STUB.requests, c[0]);
        }
    }

    // ---- Gemini and Vertex AI

    static final String GEMINI_REQUEST = """
            {"contents":[{"role":"user","parts":[{"text":"SSN %1$s"},{"inlineData":{"mimeType":"image/png","data":"AAAA"}}]},
              {"role":"model","parts":[{"functionCall":{"name":"f","args":{"email":"%2$s"}}}]},
              {"role":"user","parts":[{"functionResponse":{"name":"f","response":{"result":"ssn %1$s"}}}]}],
             "systemInstruction":{"parts":[{"text":"mail %2$s"}]},"generationConfig":{"temperature":0.1}}""".formatted(SSN, EMAIL);

    @Test
    void geminiRequestIsRedactedAndKeepsItsFields() throws Exception {
        STUB.reply("application/json", "{\"candidates\":[]}");
        post("/v1beta/models/gemini-2.5-flash:generateContent?key=abc", GEMINI_REQUEST, "x-goog-api-key", "g-key");
        assertEquals("/v1beta/models/gemini-2.5-flash:generateContent", STUB.lastPath);
        assertEquals("key=abc", STUB.lastQuery);
        assertNoOriginals(sent());
        final JsonObject s = STUB.lastBody();
        assertEquals(0.1, s.getAsJsonObject("generationConfig").get("temperature").getAsDouble());
        assertEquals("AAAA", s.getAsJsonArray("contents").get(0).getAsJsonObject().getAsJsonArray("parts").get(1)
                .getAsJsonObject().getAsJsonObject("inlineData").get("data").getAsString());
        assertEquals("mail " + R_EMAIL, s.getAsJsonObject("systemInstruction").getAsJsonArray("parts").get(0).getAsJsonObject().get("text").getAsString());
        assertEquals("g-key", STUB.lastHeaders.getFirst("x-goog-api-key"));
    }

    @Test
    void geminiResponsesAreScannedBufferedAsArraysAndStreamed() throws Exception {
        final String candidate = "{\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"SSN %s\"}]},\"index\":0}]}";
        STUB.reply("application/json", candidate.formatted(SSN));
        assertNoOriginals(text(post("/v1beta/models/g:generateContent", "{\"contents\":[]}", "x-out", "redact")));

        STUB.reply("application/json", "[" + candidate.formatted(SSN) + "," + candidate.formatted(EMAIL) + "]");
        final String array = text(post("/v1beta/models/g:streamGenerateContent", "{\"contents\":[]}", "x-out", "redact"));
        assertNoOriginals(array);
        assertTrue(array.contains(R_EMAIL));

        STUB.replyChunks("text/event-stream", sse(
                "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Your SSN is 12\"}]},\"index\":0}]}",
                "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"3-45-6789 ok\"}]},\"index\":0}]}",
                "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"functionCall\":{\"name\":\"f\",\"args\":{\"e\":\"jane.doe@example.com\"}}}]},\"index\":0}]}",
                "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\".\"}]},\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"totalTokenCount\":9}}"));
        final String stream = text(post("/v1beta/models/g:streamGenerateContent?alt=sse", "{\"contents\":[]}", "x-out", "redact"));
        assertNoOriginals(stream);
        final StringBuilder out = new StringBuilder();
        for (final String line : stream.split("\n")) {
            if (line.startsWith("data: ")) {
                for (final var c : json(line.substring(6)).getAsJsonArray("candidates")) {
                    final JsonObject content = c.getAsJsonObject().getAsJsonObject("content");
                    if (content != null) {
                        for (final var p : content.getAsJsonArray("parts")) {
                            if (p.getAsJsonObject().has("text")) {
                                out.append(p.getAsJsonObject().get("text").getAsString());
                            }
                        }
                    }
                }
            }
        }
        assertEquals("Your SSN is " + R_SSN + " ok.", out.toString());
        assertTrue(stream.contains(R_EMAIL) && stream.contains("usageMetadata") && stream.contains("STOP"));
    }

    @Test
    void geminiEmbeddingsAreRedacted() throws Exception {
        STUB.reply("application/json", "{\"embedding\":{\"values\":[0.1,0.2]}}");
        final HttpResponse<byte[]> embed = post("/v1beta/models/gemini-embedding-001:embedContent", """
                {"content":{"parts":[{"text":"SSN %1$s"}]},"taskType":"RETRIEVAL_DOCUMENT","title":"mail %2$s","outputDimensionality":256}"""
                .formatted(SSN, EMAIL), "x-out", "block");
        assertEquals(200, embed.statusCode(), text(embed));
        assertEquals("/v1beta/models/gemini-embedding-001:embedContent", STUB.lastPath);
        assertNoOriginals(sent());
        assertEquals("mail " + R_EMAIL, STUB.lastBody().get("title").getAsString());
        assertEquals(256, STUB.lastBody().get("outputDimensionality").getAsInt());
        assertTrue(text(embed).contains("[0.1,0.2]"), text(embed));

        // The v1 API is routed to Gemini by its method, like v1beta.
        STUB.reply("application/json", "{\"embeddings\":[{\"values\":[0.1]},{\"values\":[0.2]}]}");
        assertEquals(200, post("/v1/models/gemini-embedding-001:batchEmbedContents", """
                {"requests":[{"model":"models/gemini-embedding-001","content":{"parts":[{"text":"SSN %1$s"}]}},
                  {"model":"models/gemini-embedding-001","content":{"parts":[{"text":"x"}]},"title":"mail %2$s"}]}"""
                .formatted(SSN, EMAIL), "x-goog-api-key", "g-key").statusCode());
        assertEquals("/v1/models/gemini-embedding-001:batchEmbedContents", STUB.lastPath);
        assertEquals("g-key", STUB.lastHeaders.getFirst("x-goog-api-key"));
        assertNoOriginals(sent());
        assertTrue(sent().contains(R_SSN), sent());
    }

    @Test
    void geminiTokenCountsAreRedacted() throws Exception {
        STUB.reply("application/json", "{\"totalTokens\":12}");
        assertEquals(200, post("/v1beta/models/gemini-2.5-flash:countTokens", "{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":\"SSN "
                + SSN + "\"}]}]}", "x-out", "redact").statusCode());
        assertEquals("/v1beta/models/gemini-2.5-flash:countTokens", STUB.lastPath);
        assertNoOriginals(sent());
        assertTrue(sent().contains(R_SSN), sent());
        // A wrapped generateContentRequest, as the SDKs send with a system instruction or tools.
        assertEquals(200, post("/v1beta/models/gemini-2.5-flash:countTokens", """
                {"generateContentRequest":{"model":"models/gemini-2.5-flash","contents":[{"role":"user","parts":[{"text":"SSN %1$s"}]}],
                 "systemInstruction":{"parts":[{"text":"mail %2$s"}]}}}""".formatted(SSN, EMAIL)).statusCode());
        assertNoOriginals(sent());
        assertTrue(sent().contains(R_EMAIL), sent());
        // Vertex AI's countTokens has the same shape, and goes to Vertex AI with the proxy's credential.
        final String vertex = "/v1/projects/test-project/locations/us-central1/publishers/google/models/gemini-2.5-pro:countTokens";
        assertEquals(200, post(vertex, "{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":\"SSN " + SSN + "\"}]}]}").statusCode());
        assertEquals(vertex, STUB.lastPath);
        assertEquals("Bearer google-test-token", STUB.lastHeaders.getFirst("Authorization"));
        assertNoOriginals(sent());
    }

    @Test
    void vertexUsesTheProxysGoogleCredentials() throws Exception {
        STUB.reply("application/json", "{\"candidates\":[]}");
        final String path = "/v1/projects/test-project/locations/us-central1/publishers/google/models/gemini-2.5-pro:generateContent";
        assertEquals(200, post(path, GEMINI_REQUEST, "Authorization", "Bearer client-token").statusCode());
        assertEquals(path, STUB.lastPath);
        assertEquals("Bearer google-test-token", STUB.lastHeaders.getFirst("Authorization"));
        assertNoOriginals(sent());
    }

    // ---- Ollama

    @Test
    void ollamaGenerateIsRedactedAndItsDefaultStreamScanned() throws Exception {
        STUB.replyChunks("application/x-ndjson", List.of(
                "{\"model\":\"llama\",\"response\":\"SSN 123-\",\"done\":false}\n",
                "{\"model\":\"llama\",\"response\":\"45-6789 noted\",\"done\":false}\n",
                "{\"model\":\"llama\",\"response\":\"\",\"done\":true,\"eval_count\":5}\n"));
        final HttpResponse<byte[]> response = post("/api/generate", "{\"model\":\"llama\",\"prompt\":\"mail " + EMAIL
                + "\",\"system\":\"ssn " + SSN + "\",\"images\":[\"AAAA\"],\"options\":{\"seed\":1}}", "x-out", "redact");
        assertNoOriginals(sent());
        assertEquals("AAAA", STUB.lastBody().getAsJsonArray("images").get(0).getAsString());
        assertEquals(1, STUB.lastBody().getAsJsonObject("options").get("seed").getAsInt());
        final String body = text(response);
        assertNoOriginals(body);
        final StringBuilder out = new StringBuilder();
        body.lines().forEach(l -> out.append(json(l).get("response").getAsString()));
        assertEquals("SSN " + R_SSN + " noted", out.toString());
        assertTrue(body.strip().endsWith("\"eval_count\":5}"));
    }

    @Test
    void ollamaChatIsRedactedAndScanned() throws Exception {
        STUB.reply("application/json", "{\"model\":\"llama\",\"message\":{\"role\":\"assistant\",\"content\":\"SSN " + SSN
                + "\",\"tool_calls\":[{\"function\":{\"name\":\"f\",\"arguments\":{\"email\":\"" + EMAIL + "\"}}}]},\"done\":true}");
        final HttpResponse<byte[]> response = post("/api/chat", "{\"model\":\"llama\",\"stream\":false,\"messages\":[{\"role\":\"user\",\"content\":\"ssn "
                + SSN + "\"}]}", "x-out", "redact");
        assertNoOriginals(sent());
        assertNoOriginals(text(response));
        assertTrue(text(response).contains(R_EMAIL));
    }

    // ---- Bedrock

    @Test
    void bedrockConverseIsSignedRedactedAndScanned() throws Exception {
        STUB.reply("application/json", "{\"output\":{\"message\":{\"role\":\"assistant\",\"content\":[{\"text\":\"SSN " + SSN
                + "\"},{\"toolUse\":{\"toolUseId\":\"t\",\"name\":\"f\",\"input\":{\"e\":\"" + EMAIL + "\"}}}]}},\"stopReason\":\"end_turn\"}");
        final String request = """
                {"system":[{"text":"ssn %1$s"}],"inferenceConfig":{"maxTokens":10},"toolConfig":{"tools":[]},
                 "messages":[{"role":"user","content":[{"text":"mail %2$s"},{"toolResult":{"toolUseId":"t","content":[{"text":"ssn %1$s"},{"json":{"e":"%2$s"}}]}}]},
                  {"role":"assistant","content":[{"toolUse":{"toolUseId":"t","name":"f","input":{"ssn":"%1$s"}}}]}]}""".formatted(SSN, EMAIL);
        final HttpResponse<byte[]> response = post("/model/anthropic.claude-3-haiku/converse", request, "x-out", "redact",
                "Authorization", "Bearer client", "X-Custom", "not forwarded");
        assertEquals(200, response.statusCode());
        assertEquals("/model/anthropic.claude-3-haiku/converse", STUB.lastPath);
        assertNoOriginals(sent());
        assertEquals(10, STUB.lastBody().getAsJsonObject("inferenceConfig").get("maxTokens").getAsInt());
        assertTrue(STUB.lastBody().has("toolConfig"));
        final String auth = STUB.lastHeaders.getFirst("Authorization");
        assertTrue(auth.startsWith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"), auth);
        assertTrue(auth.contains("/us-east-1/bedrock/aws4_request"), auth);
        assertNull(STUB.lastHeaders.getFirst("X-Custom"));
        assertNoOriginals(text(response));
        assertTrue(text(response).contains("SSN " + R_SSN));
    }

    @Test
    void bedrockConverseStreamIsScanned() throws Exception {
        final EventStreamFraming framing = new EventStreamFraming();
        final List<byte[]> frames = new ArrayList<>();
        frames.add(framing.encode(new StreamEvent("messageStart", json("{\"role\":\"assistant\"}"))));
        for (final String piece : new String[]{"Your SSN is 12", "3-45-67", "89, ok."}) {
            frames.add(framing.encode(new StreamEvent("contentBlockDelta", json("{\"contentBlockIndex\":0,\"delta\":{\"text\":\"" + piece + "\"}}"))));
        }
        frames.add(framing.encode(new StreamEvent("contentBlockStop", json("{\"contentBlockIndex\":0}"))));
        frames.add(framing.encode(new StreamEvent("contentBlockStart", json("{\"contentBlockIndex\":1,\"start\":{\"toolUse\":{\"toolUseId\":\"t\",\"name\":\"f\"}}}"))));
        frames.add(framing.encode(new StreamEvent("contentBlockDelta", json("{\"contentBlockIndex\":1,\"delta\":{\"toolUse\":{\"input\":\"{\\\"e\\\":\\\"jane.\"}}}"))));
        frames.add(framing.encode(new StreamEvent("contentBlockDelta", json("{\"contentBlockIndex\":1,\"delta\":{\"toolUse\":{\"input\":\"doe@example.com\\\"}\"}}}"))));
        frames.add(framing.encode(new StreamEvent("contentBlockStop", json("{\"contentBlockIndex\":1}"))));
        frames.add(framing.encode(new StreamEvent("messageStop", json("{\"stopReason\":\"end_turn\"}"))));
        STUB.reply("application/vnd.amazon.eventstream", frames);

        final HttpResponse<byte[]> response = post("/model/m/converse-stream", "{\"messages\":[]}", "x-out", "redact");
        assertEquals(200, response.statusCode());
        final List<StreamEvent> events = new ArrayList<>();
        framing.read(new ByteArrayInputStream(response.body()), new ai.philterd.aiproxy.stream.Framing.Handler() {
            @Override
            public void onEvent(final StreamEvent event) {
                events.add(event);
            }

            @Override
            public void onPassThrough(final byte[] raw, final boolean end) {
            }

            @Override
            public void onUnreadable(final byte[] raw) {
                throw new AssertionError("the proxy sent an unreadable frame");
            }
        });
        final StringBuilder textOut = new StringBuilder();
        final StringBuilder inputOut = new StringBuilder();
        for (final StreamEvent e : events) {
            if ("contentBlockDelta".equals(e.type())) {
                final JsonObject delta = e.json().getAsJsonObject("delta");
                if (delta.has("text")) {
                    textOut.append(delta.get("text").getAsString());
                }
                if (delta.has("toolUse")) {
                    inputOut.append(delta.getAsJsonObject("toolUse").get("input").getAsString());
                }
            }
        }
        assertEquals("Your SSN is " + R_SSN + ", ok.", textOut.toString());
        assertEquals(R_EMAIL, json(inputOut.toString()).get("e").getAsString());
        assertEquals("messageStop", events.getLast().type());
        assertNoOriginals(new String(response.body(), StandardCharsets.UTF_8));
    }

    @Test
    void bedrockInvokeClaudeIsSignedRedactedAndScanned() throws Exception {
        STUB.reply("application/json", "{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"SSN "
                + SSN + "\"}],\"stop_reason\":\"end_turn\",\"amazon-bedrock-guardrailAction\":\"NONE\",\"amazon-bedrock-trace\":{\"guardrail\":"
                + "{\"output\":[{\"match\":\"" + EMAIL + "\"}]}}}");
        final String request = """
                {"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"system":"ssn %1$s",
                 "messages":[{"role":"user","content":[{"type":"text","text":"mail %2$s"}]}]}""".formatted(SSN, EMAIL);
        final HttpResponse<byte[]> response = post("/model/us.anthropic.claude-sonnet-4-20250514-v1%3A0/invoke", request, "x-out", "redact",
                "X-Amzn-Bedrock-GuardrailIdentifier", "gr-1", "X-Custom", "not forwarded");
        assertEquals(200, response.statusCode(), text(response));
        assertEquals("/model/us.anthropic.claude-sonnet-4-20250514-v1%3A0/invoke", STUB.lastPath);
        assertNoOriginals(sent());
        assertEquals("bedrock-2023-05-31", STUB.lastBody().get("anthropic_version").getAsString());
        final String auth = STUB.lastHeaders.getFirst("Authorization");
        assertTrue(auth.contains("/us-east-1/bedrock/aws4_request"), auth);
        // Bedrock's settings headers are forwarded and signed; other client headers are not forwarded.
        assertEquals("gr-1", STUB.lastHeaders.getFirst("X-Amzn-Bedrock-GuardrailIdentifier"));
        assertTrue(auth.contains("x-amzn-bedrock-guardrailidentifier"), auth);
        assertNull(STUB.lastHeaders.getFirst("X-Custom"));
        assertNoOriginals(text(response));
        assertTrue(text(response).contains("SSN " + R_SSN), text(response));
        // The guardrail trace quotes matched text the scan does not read, so it is removed.
        assertFalse(text(response).contains("amazon-bedrock-trace"), text(response));
        assertTrue(text(response).contains("amazon-bedrock-guardrailAction"), text(response));
    }

    @Test
    void bedrockInvokeClaudeStreamIsScanned() throws Exception {
        final EventStreamFraming framing = new EventStreamFraming();
        final java.util.function.Function<String, byte[]> chunk = inner -> framing.encode(new StreamEvent("chunk",
                json("{\"bytes\":\"" + java.util.Base64.getEncoder().encodeToString(inner.getBytes(StandardCharsets.UTF_8)) + "\",\"p\":\"abcd\"}")));
        final List<byte[]> frames = new ArrayList<>();
        frames.add(chunk.apply("{\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"role\":\"assistant\",\"content\":[]}}"));
        frames.add(chunk.apply("{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}"));
        for (final String piece : new String[]{"Your SSN is 12", "3-45-67", "89, ok."}) {
            frames.add(chunk.apply("{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + piece + "\"}}"));
        }
        frames.add(chunk.apply("{\"type\":\"content_block_stop\",\"index\":0}"));
        frames.add(chunk.apply("{\"type\":\"message_stop\",\"amazon-bedrock-invocationMetrics\":{\"inputTokenCount\":5},"
                + "\"amazon-bedrock-trace\":{\"guardrail\":{\"match\":\"" + EMAIL + "\"}}}"));
        STUB.reply("application/vnd.amazon.eventstream", frames);

        final HttpResponse<byte[]> response = post("/model/anthropic.claude-3-haiku-20240307-v1%3A0/invoke-with-response-stream",
                "{\"anthropic_version\":\"bedrock-2023-05-31\",\"max_tokens\":10,\"messages\":[{\"role\":\"user\",\"content\":\"ssn " + SSN + "\"}]}",
                "x-out", "redact");
        assertEquals(200, response.statusCode(), text(response));
        assertNoOriginals(sent());
        final List<JsonObject> inner = new ArrayList<>();
        framing.read(new ByteArrayInputStream(response.body()), new ai.philterd.aiproxy.stream.Framing.Handler() {
            @Override
            public void onEvent(final StreamEvent event) {
                assertEquals("chunk", event.type());
                inner.add(json(new String(java.util.Base64.getDecoder().decode(event.json().get("bytes").getAsString()), StandardCharsets.UTF_8)));
            }

            @Override
            public void onPassThrough(final byte[] raw, final boolean end) {
            }

            @Override
            public void onUnreadable(final byte[] raw) {
                throw new AssertionError("the proxy sent an unreadable frame");
            }
        });
        final StringBuilder textOut = new StringBuilder();
        for (final JsonObject e : inner) {
            if ("content_block_delta".equals(e.get("type").getAsString())) {
                textOut.append(e.getAsJsonObject("delta").get("text").getAsString());
            }
            assertNoOriginals(e.toString());
        }
        assertEquals("Your SSN is " + R_SSN + ", ok.", textOut.toString());
        assertEquals("message_stop", inner.getLast().get("type").getAsString());
        assertTrue(inner.getLast().has("amazon-bedrock-invocationMetrics"));
        assertFalse(inner.getLast().has("amazon-bedrock-trace"));
    }

    @Test
    void bedrockInvokeEmbeddingInputIsRedacted() throws Exception {
        STUB.reply("application/json", "{\"embedding\":[0.1,0.2],\"inputTextTokenCount\":3}");
        assertEquals(200, post("/model/amazon.titan-embed-text-v2%3A0/invoke", "{\"inputText\":\"ssn " + SSN + "\",\"dimensions\":256}").statusCode());
        assertNoOriginals(sent());
        assertTrue(sent().contains(R_SSN), sent());
        assertEquals(256, STUB.lastBody().get("dimensions").getAsInt());

        STUB.reply("application/json", "{\"embeddings\":[[0.1],[0.2]],\"id\":\"e\"}");
        assertEquals(200, post("/model/cohere.embed-english-v3/invoke", "{\"texts\":[\"ssn " + SSN + "\",\"mail " + EMAIL
                + "\"],\"input_type\":\"search_document\"}").statusCode());
        assertNoOriginals(sent());
        assertEquals(200, post("/model/cohere.embed-v4%3A0/invoke", "{\"inputs\":[{\"content\":[{\"type\":\"text\",\"text\":\"ssn "
                + SSN + "\"}]}],\"input_type\":\"search_query\"}").statusCode());
        assertNoOriginals(sent());
        assertTrue(sent().contains(R_SSN), sent());
    }

    @Test
    void bedrockInvokeOfOtherModelsIsRefused() throws Exception {
        final String[][] cases = {
                {"/model/meta.llama3-8b-instruct-v1%3A0/invoke", "{\"prompt\":\"ssn " + SSN + "\"}", "unsupported_endpoint"},
                {"/model/amazon.titan-embed-text-v2%3A0/invoke-with-response-stream", "{\"inputText\":\"ssn " + SSN + "\"}", "unsupported_endpoint"},
        };
        for (final String[] c : cases) {
            final HttpResponse<byte[]> response = post(c[0], c[1]);
            assertEquals(400, response.statusCode(), c[0]);
            assertTrue(text(response).contains(c[2]), c[0] + ": " + text(response));
            // AWS SDKs read the code from this header and the message from a top-level "message".
            assertEquals(c[2], response.headers().firstValue("x-amzn-ErrorType").orElse(null));
            assertTrue(json(text(response)).get("message").getAsString().startsWith(c[2] + ": "), text(response));
        }
        assertEquals(0, STUB.requests);
    }

    @Test
    void bedrockConverseGuardrailTraceIsRemoved() throws Exception {
        STUB.reply("application/json", "{\"output\":{\"message\":{\"role\":\"assistant\",\"content\":[{\"text\":\"ok\"}]}},"
                + "\"stopReason\":\"end_turn\",\"trace\":{\"guardrail\":{\"outputAssessments\":{\"g\":[{\"match\":\"" + EMAIL + "\"}]}}}}");
        final HttpResponse<byte[]> response = post("/model/m/converse", "{\"messages\":[]}", "x-out", "redact");
        assertEquals(200, response.statusCode());
        assertNoOriginals(text(response));
        assertFalse(text(response).contains("\"trace\""), text(response));
    }

    @Test
    void bedrockInvokeLegacyClaudeIsRedactedAndItsStreamRefusedUnderScanning() throws Exception {
        STUB.reply("application/json", "{\"completion\":\" SSN " + SSN + "\",\"stop_reason\":\"stop_sequence\"}");
        final HttpResponse<byte[]> response = post("/model/anthropic.claude-v2%3A1/invoke",
                "{\"prompt\":\"\\n\\nHuman: SSN " + SSN + "\\n\\nAssistant:\",\"max_tokens_to_sample\":50}", "x-out", "redact");
        assertEquals(200, response.statusCode(), text(response));
        assertNoOriginals(sent());
        assertTrue(sent().contains(R_SSN), sent());
        assertNoOriginals(text(response));

        // A legacy stream's chunks are not Messages events, so under scanning the stream is ended with an exception.
        final EventStreamFraming framing = new EventStreamFraming();
        STUB.reply("application/vnd.amazon.eventstream", List.of(framing.encode(new StreamEvent("chunk", json("{\"bytes\":\""
                + java.util.Base64.getEncoder().encodeToString(("{\"completion\":\"SSN " + SSN + "\"}").getBytes(StandardCharsets.UTF_8)) + "\"}")))));
        final HttpResponse<byte[]> stream = post("/model/anthropic.claude-v2%3A1/invoke-with-response-stream",
                "{\"prompt\":\"\\n\\nHuman: hi\\n\\nAssistant:\",\"max_tokens_to_sample\":5}", "x-out", "redact");
        final String body = new String(stream.body(), StandardCharsets.UTF_8);
        assertNoOriginals(body);
        // AWS SDKs raise an error message with its code; an event named "error" would be skipped.
        assertTrue(body.contains(":message-type") && body.contains(":error-code") && body.contains("response_unscannable"), body);
    }

    @Test
    void bodylessRequestsToProvidersUsingTheProxysCredentialAreRefused() throws Exception {
        // The proxy would otherwise act with its own Google or AWS credential for any key, on any endpoint.
        for (final String[] c : new String[][]{
                {"GET", "/v1/projects/test-project/locations/us-central1/cachedContents"},
                {"DELETE", "/v1/projects/test-project/locations/us-central1/endpoints/123"},
                {"POST", "/v1/projects/test-project/locations/us-central1/tuningJobs/t1:cancel"},
                {"GET", "/model/anthropic.claude-3-haiku-20240307-v1%3A0/invoke"}}) {
            final HttpResponse<byte[]> response = send(c[0], c[1], null);
            assertEquals(400, response.statusCode(), c[1]);
            assertTrue(text(response).contains("unsupported_endpoint") && text(response).contains("own credential"), text(response));
        }
        assertEquals(0, STUB.requests);
        // A provider that receives the client's own credential still forwards bodyless requests.
        assertEquals(200, send("GET", "/v1/models", null).statusCode());
    }

    @Test
    void vertexCountTokensInstancesAreRedacted() throws Exception {
        STUB.reply("application/json", "{\"totalTokens\":3}");
        assertEquals(200, post("/v1/projects/test-project/locations/us-central1/publishers/google/models/gemini-2.5-flash:countTokens",
                "{\"instances\":[{\"prompt\":\"SSN " + SSN + "\",\"nested\":{\"t\":\"mail " + EMAIL + "\"}}]}").statusCode());
        assertNoOriginals(sent());
        assertTrue(sent().contains(R_SSN), sent());
    }

    @Test
    void anyGenerateContentMethodGoesToGemini() throws Exception {
        STUB.reply("application/json", "{}");
        // Not a method the proxy reads, so refused, but by Gemini's route, not sent to OpenAI with the Google key.
        final HttpResponse<byte[]> response = post("/v1/models/gemini-2.5-flash:batchGenerateContent", "{\"batch\":{}}", "x-goog-api-key", "g");
        assertEquals(400, response.statusCode());
        assertTrue(text(response).contains("unsupported_endpoint"), text(response));
        assertEquals(0, STUB.requests);
    }

    static final String GROUNDING = """
            "groundingMetadata":{"webSearchQueries":["records for %1$s"],"retrievalQueries":["mail %2$s"],
             "searchEntryPoint":{"renderedContent":"<div>records for %1$s</div>"},
             "groundingChunks":[{"web":{"uri":"https://example.com/a","title":"Page about %2$s"}},
               {"retrievedContext":{"uri":"gs://bucket/doc.txt","title":"Customer file","text":"SSN %1$s on file"}}],
             "groundingSupports":[{"segment":{"startIndex":0,"endIndex":22,"text":"Your SSN is %1$s"},"groundingChunkIndices":[0,1]}]}"""
            .formatted(SSN, EMAIL);

    @Test
    void geminiGroundingMetadataIsScanned() throws Exception {
        STUB.reply("application/json", "{\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Your SSN is " + SSN
                + "\"}]},\"finishReason\":\"STOP\",\"index\":0," + GROUNDING + "}]}");
        final String redacted = text(post("/v1beta/models/g:generateContent", "{\"contents\":[]}", "x-out", "redact"));
        assertNoOriginals(redacted);
        final JsonObject grounding = json(redacted).getAsJsonArray("candidates").get(0).getAsJsonObject().getAsJsonObject("groundingMetadata");
        assertEquals("Your SSN is " + R_SSN, grounding.getAsJsonArray("groundingSupports").get(0).getAsJsonObject()
                .getAsJsonObject("segment").get("text").getAsString());
        // The citations and their sources are kept.
        assertEquals("https://example.com/a", grounding.getAsJsonArray("groundingChunks").get(0).getAsJsonObject()
                .getAsJsonObject("web").get("uri").getAsString());
        assertEquals(403, post("/v1beta/models/g:generateContent", "{\"contents\":[]}", "x-out", "block").statusCode());

        // Streamed: the metadata arrives with the last chunk.
        STUB.replyChunks("text/event-stream", sse(
                "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Your SSN is 12\"}]},\"index\":0}]}",
                "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"3-45-6789\"}]},\"finishReason\":\"STOP\",\"index\":0,"
                        + GROUNDING.replace("\n", "") + "}]}"));
        final String stream = text(post("/v1beta/models/g:streamGenerateContent?alt=sse", "{\"contents\":[]}", "x-out", "redact"));
        assertNoOriginals(stream);
        assertTrue(stream.contains("groundingMetadata") && stream.contains("https://example.com/a"), stream);
    }

    @Test
    void bedrockInvokeStreamUnderFlagForwardsWhatItCannotRead() throws Exception {
        final EventStreamFraming framing = new EventStreamFraming();
        final java.util.function.Function<String, byte[]> chunk = inner -> framing.encode(new StreamEvent("chunk",
                json("{\"bytes\":\"" + java.util.Base64.getEncoder().encodeToString(inner.getBytes(StandardCharsets.UTF_8)) + "\"}")));
        STUB.reply("application/vnd.amazon.eventstream", List.of(
                chunk.apply("{\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"role\":\"assistant\",\"content\":[]}}"),
                framing.encode(new StreamEvent("chunk", json("{\"bytes\":\"not base64!\"}"))),
                chunk.apply("{\"type\":\"message_stop\"}")));
        final HttpResponse<byte[]> response = post("/model/anthropic.claude-3-haiku-20240307-v1%3A0/invoke-with-response-stream",
                "{\"anthropic_version\":\"bedrock-2023-05-31\",\"max_tokens\":5,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}",
                "x-out", "flag");
        assertEquals(200, response.statusCode());
        final List<String> bytes = new ArrayList<>();
        framing.read(new ByteArrayInputStream(response.body()), new ai.philterd.aiproxy.stream.Framing.Handler() {
            @Override
            public void onEvent(final StreamEvent event) {
                bytes.add(event.json().get("bytes").getAsString());
            }

            @Override
            public void onPassThrough(final byte[] raw, final boolean end) {
            }

            @Override
            public void onUnreadable(final byte[] raw) {
                throw new AssertionError("the proxy ended the stream with an error under flag");
            }
        });
        // All three chunks arrive, the undecodable one unchanged, and the stream is not cut short.
        assertEquals(3, bytes.size(), bytes.toString());
        assertEquals("not base64!", bytes.get(1));
    }

    // ---- Azure OpenAI and OpenAI-compatible providers

    @Test
    void azureAddsTheApiVersionAndPassesTheApiKey() throws Exception {
        STUB.reply("application/json", "{\"choices\":[]}");
        post("/openai/deployments/gpt4o/chat/completions", "{\"messages\":[{\"role\":\"user\",\"content\":\"ssn " + SSN + "\"}]}",
                "api-key", "az-key");
        assertEquals("/openai/deployments/gpt4o/chat/completions", STUB.lastPath);
        assertEquals("api-version=2024-10-21", STUB.lastQuery);
        assertEquals("az-key", STUB.lastHeaders.getFirst("api-key"));
        assertNoOriginals(sent());
        post("/openai/deployments/gpt4o/chat/completions?api-version=2025-01-01", "{\"messages\":[]}");
        assertEquals("api-version=2025-01-01", STUB.lastQuery);
    }

    @Test
    void openAiCompatibleProvidersAreReachedByName() throws Exception {
        STUB.reply("application/json", "{\"choices\":[]}");
        post("/local/v1/chat/completions", "{\"model\":\"qwen\",\"messages\":[{\"role\":\"user\",\"content\":\"ssn " + SSN + "\"}]}");
        assertEquals("/v1/chat/completions", STUB.lastPath);
        assertNoOriginals(sent());
    }

    // ---- OpenAI endpoints other than chat

    @Test
    void openAiEndpointsRedactTheirTextFields() throws Exception {
        STUB.reply("application/json", "{}");
        post("/v1/embeddings", "{\"model\":\"e\",\"input\":[\"ssn " + SSN + "\",\"mail " + EMAIL + "\"]}");
        assertNoOriginals(sent());
        post("/v1/embeddings", "{\"model\":\"e\",\"input\":[[1,2,3]]}");
        assertEquals("[[1,2,3]]", STUB.lastBody().get("input").toString());
        post("/v1/moderations", "{\"input\":\"ssn " + SSN + "\"}");
        assertNoOriginals(sent());
        post("/v1/images/generations", "{\"prompt\":\"a card for " + EMAIL + "\"}");
        assertNoOriginals(sent());
        post("/v1/audio/speech", "{\"model\":\"tts\",\"input\":\"ssn " + SSN + "\",\"voice\":\"alloy\"}");
        assertNoOriginals(sent());
        post("/v1/completions", "{\"model\":\"x\",\"prompt\":[\"ssn " + SSN + "\"]}");
        assertNoOriginals(sent());
        post("/v1/responses", """
                {"model":"o","instructions":"ssn %1$s","input":[{"role":"user","content":[{"type":"input_text","text":"mail %2$s"}]},
                 {"type":"function_call","call_id":"c","name":"f","arguments":"{\\"s\\":\\"%1$s\\"}"},
                 {"type":"function_call_output","call_id":"c","output":"found %2$s"}]}""".formatted(SSN, EMAIL));
        assertNoOriginals(sent());
        post("/v1/responses", "{\"model\":\"o\",\"input\":\"ssn " + SSN + "\"}");
        assertNoOriginals(sent());
    }

    @Test
    void responsesApiOutputIsScannedBufferedAndStreamed() throws Exception {
        STUB.reply("application/json", """
                {"id":"r","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"SSN %1$s",
                 "logprobs":[{"token":"SSN"}]}]},{"type":"function_call","name":"f","arguments":"{\\"e\\":\\"%2$s\\"}"}]}""".formatted(SSN, EMAIL));
        final String buffered = text(post("/v1/responses", "{\"model\":\"o\",\"input\":\"hi\"}", "x-out", "redact"));
        assertNoOriginals(buffered);
        assertTrue(buffered.contains("SSN " + R_SSN));

        final String item = "\"item_id\":\"i\",\"output_index\":0,\"content_index\":0";
        STUB.replyChunks("text/event-stream", sse(
                "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"output\":[]}}",
                "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\"," + item + ",\"delta\":\"SSN 123-\"}",
                "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\"," + item + ",\"delta\":\"45-6789 ok\"}",
                "event: response.output_text.done\ndata: {\"type\":\"response.output_text.done\"," + item + ",\"text\":\"SSN 123-45-6789 ok\"}",
                "event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"SSN 123-45-6789 ok\"}]}}",
                "event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":1,\"delta\":\"{\\\"e\\\":\\\"jane.\"}",
                "event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":1,\"delta\":\"doe@example.com\\\"}\"}",
                "event: response.function_call_arguments.done\ndata: {\"type\":\"response.function_call_arguments.done\",\"output_index\":1,\"arguments\":\"{\\\"e\\\":\\\"jane.doe@example.com\\\"}\"}",
                "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"SSN 123-45-6789 ok\"}]}]}}"));
        final String stream = text(post("/v1/responses", "{\"model\":\"o\",\"stream\":true,\"input\":\"hi\"}", "x-out", "redact"));
        assertNoOriginals(stream);
        final StringBuilder deltas = new StringBuilder();
        for (final String line : stream.split("\n")) {
            if (line.startsWith("data: ") && line.contains("output_text.delta")) {
                deltas.append(json(line.substring(6)).get("delta").getAsString());
            }
        }
        assertEquals("SSN " + R_SSN + " ok", deltas.toString());
        assertTrue(stream.contains("response.completed"));
        assertTrue(stream.contains("event: response.output_text.delta\n"));
    }

    @Test
    void streamsFromEndpointsThatCannotBeScannedAreRefused() throws Exception {
        STUB.replyChunks("text/event-stream", sse("data: {\"x\":1}"));
        final HttpResponse<byte[]> response = post("/v1/embeddings", "{\"model\":\"e\",\"input\":\"hi\"}", "x-out", "redact");
        assertEquals(502, response.statusCode());
        assertTrue(text(response).contains("response_unscannable"));
    }

    // ---- lower-severity hardening

    @Test
    void binaryResponsesAreReturnedUnscannedOnlyFromSpeech() throws Exception {
        STUB.reply("application/octet-stream", "SSN 123-45-6789");
        final HttpResponse<byte[]> chat = post("/v1/chat/completions", "{\"model\":\"m\",\"messages\":[]}", "x-out", "redact");
        assertEquals(502, chat.statusCode());
        assertTrue(text(chat).contains("response_unscannable"));
        STUB.reply("audio/mpeg", "ID3");
        assertEquals(200, post("/v1/audio/speech", "{\"model\":\"tts\",\"input\":\"hi\"}", "x-out", "redact").statusCode());
    }

    @Test
    void redirectsAreRefusedWhenScanning() throws Exception {
        STUB.status(302);
        STUB.reply("text/plain", "SSN 123-45-6789");
        final HttpResponse<byte[]> scanned = post("/v1/chat/completions", "{\"model\":\"m\",\"messages\":[]}", "x-out", "redact");
        assertEquals(502, scanned.statusCode());
        assertNoOriginals(text(scanned));
        assertEquals(302, post("/v1/chat/completions", "{\"model\":\"m\",\"messages\":[]}").statusCode());
    }

    @Test
    void unscannedStreamLinesAreNotForwarded() throws Exception {
        STUB.replyChunks("text/event-stream", sse(
                ": keep-alive 123-45-6789",
                "id: 123-45-6789\nretry: 5",
                "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}",
                "id: 123-45-6789\ndata: [DONE]"));
        final String out = text(post("/v1/chat/completions", "{\"model\":\"m\",\"stream\":true,\"messages\":[]}", "x-out", "redact"));
        assertNoOriginals(out);
        assertTrue(out.contains(":\n\n") && out.contains("data: [DONE]"), out);

        STUB.replyChunks("text/event-stream", sse("event: SSN 123-45-6789\ndata: {\"id\":\"c\",\"choices\":[]}"));
        final String named = text(post("/v1/chat/completions", "{\"model\":\"m\",\"stream\":true,\"messages\":[]}", "x-out", "redact"));
        assertNoOriginals(named);
        assertTrue(named.contains("response_unscannable"), named);
    }

    @Test
    void anInterruptedStreamEndsWithAnError() throws Exception {
        STUB.replyChunks("text/event-stream", sse("data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}"));
        STUB.abortAfterChunks();
        final String out = text(post("/v1/chat/completions", "{\"model\":\"m\",\"stream\":true,\"messages\":[]}", "x-out", "redact"));
        assertTrue(out.contains("stream_interrupted"), out);
    }

    @Test
    void pathScopesIncludeTheCompatibleProvidersPrefix() throws Exception {
        final String chatOnly = keys.create("chat-only", new KeyScopes(Set.of(KeyScopes.Role.proxy), List.of(), List.of(),
                List.of("/v1/chat/completions"), null)).secret();
        final String body = "{\"model\":\"m\",\"messages\":[]}";
        assertEquals(403, sendWithKey(chatOnly, "/local/v1/chat/completions", body).statusCode());
        assertEquals(200, sendWithKey(chatOnly, "/v1/chat/completions", body).statusCode());
        final String local = keys.create("local", new KeyScopes(Set.of(KeyScopes.Role.proxy), List.of(), List.of(),
                List.of("/local/v1"), null)).secret();
        assertEquals(200, sendWithKey(local, "/local/v1/chat/completions", body).statusCode());
    }

    @Test
    void vertexPathsMustNameTheConfiguredProject() throws Exception {
        final HttpResponse<byte[]> response = post("/v1/projects/other-project/locations/us-central1/publishers/google/models/g:generateContent",
                "{\"contents\":[]}");
        assertEquals(403, response.statusCode());
        assertTrue(text(response).contains("vertex_project_denied"));
        // Every project path is checked, whatever its method, including requests without a body.
        for (final String path : new String[]{"/v1/projects/other-project/locations/us-central1/publishers/google/models/g:countTokens",
                "/v1beta1/projects/other-project/locations/us-central1/endpoints"}) {
            final HttpResponse<byte[]> other = send("GET", path, null);
            assertEquals(403, other.statusCode(), path);
            assertTrue(text(other).contains("vertex_project_denied"), text(other));
        }
        assertEquals(0, STUB.requests);
    }

    @Test
    void fieldsGoFoldsToARedactedFieldAreRefused() throws Exception {
        // Go's encoding/json matches "meſſages" (long s) to Messages, and a second "Model" key overrides "model".
        for (final String body : new String[]{
                "{\"model\":\"m\",\"me\u017f\u017fages\":[{\"role\":\"user\",\"content\":\"SSN " + SSN + "\"}]}",
                "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\",\"tool_calls\":[{\"function\":{\"name\":\"f\",\"argument\u017f\":{\"s\":\"" + SSN + "\"}}}]}]}",
                "{\"model\":\"allowed\",\"Model\":\"other\",\"messages\":[]}"}) {
            final HttpResponse<byte[]> response = post("/api/chat", body);
            assertEquals(400, response.statusCode(), body);
            assertTrue(text(response).contains("ambiguous_field"), text(response));
        }
        assertEquals(0, STUB.requests);
    }

    @Test
    void fieldsSpelledInAnotherCaseAreRefused() throws Exception {
        final HttpResponse<byte[]> ollama = post("/api/chat", "{\"model\":\"m\",\"Messages\":[{\"role\":\"user\",\"content\":\"SSN " + SSN + "\"}]}");
        assertEquals(400, ollama.statusCode());
        assertTrue(text(ollama).contains("ambiguous_field"));
        final HttpResponse<byte[]> nested = post("/v1/chat/completions", "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"Content\":\"SSN " + SSN + "\"}]}");
        assertEquals(400, nested.statusCode());
        assertEquals(0, STUB.requests);
        // A tool schema's own property names are the application's, not fields the proxy reads.
        assertEquals(200, post("/v1/chat/completions", "{\"model\":\"m\",\"messages\":[],\"tools\":[{\"type\":\"function\","
                + "\"function\":{\"name\":\"f\",\"parameters\":{\"type\":\"object\",\"properties\":{\"Content\":{\"type\":\"string\"}}}}}]}").statusCode());
        // Anthropic's servers read field names exactly, so the check does not apply there.
        assertEquals(200, post("/v1/messages", "{\"model\":\"m\",\"max_tokens\":1,\"messages\":[],\"Metadata\":{}}").statusCode());
    }

    HttpResponse<byte[]> sendWithKey(final String secret, final String path, final String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).header("x-philter-proxy-key", secret)
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofByteArray());
    }

    // ---- response limits and reasoning text

    @Test
    void aBufferedResponseLargerThanTheLimitIsRefused() throws Exception {
        STUB.reply("application/json", "{\"choices\":[{\"message\":{\"content\":\"" + "a".repeat(70_000) + "\"}}]}");
        final HttpResponse<byte[]> response = post("/v1/chat/completions", "{\"model\":\"m\",\"messages\":[]}", "x-out", "redact");
        assertEquals(502, response.statusCode());
        assertTrue(text(response).contains("response_too_large"), text(response));
        // Without scanning the response is passed through, not buffered.
        assertEquals(200, post("/v1/chat/completions", "{\"model\":\"m\",\"messages\":[]}").statusCode());
    }

    @Test
    void reasoningTextIsScannedInStreams() throws Exception {
        STUB.replyChunks("text/event-stream", sse(
                "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"SSN 123-\"}}]}",
                "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"45-6789 ok\"}}]}",
                "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}",
                "data: [DONE]"));
        final String chat = text(post("/local/v1/chat/completions", "{\"model\":\"m\",\"stream\":true,\"messages\":[]}", "x-out", "redact"));
        assertNoOriginals(chat);
        assertTrue(chat.contains("REDACTED-ssn"), chat);

        final String item = "\"item_id\":\"rs\",\"output_index\":0,\"summary_index\":0";
        STUB.replyChunks("text/event-stream", sse(
                "event: response.reasoning_summary_text.delta\ndata: {\"type\":\"response.reasoning_summary_text.delta\"," + item + ",\"delta\":\"SSN 123-45-6789\"}",
                "event: response.reasoning_summary_text.done\ndata: {\"type\":\"response.reasoning_summary_text.done\"," + item + ",\"text\":\"SSN 123-45-6789\"}",
                "event: response.reasoning_summary_part.done\ndata: {\"type\":\"response.reasoning_summary_part.done\"," + item + ",\"part\":{\"type\":\"summary_text\",\"text\":\"SSN 123-45-6789\"}}",
                "event: response.reasoning_text.delta\ndata: {\"type\":\"response.reasoning_text.delta\",\"item_id\":\"rs\",\"output_index\":1,\"content_index\":0,\"delta\":\"SSN 123-45-6789\"}",
                "event: response.reasoning_text.done\ndata: {\"type\":\"response.reasoning_text.done\",\"item_id\":\"rs\",\"output_index\":1,\"content_index\":0,\"text\":\"SSN 123-45-6789\"}"));
        final String responses = text(post("/v1/responses", "{\"model\":\"o\",\"stream\":true,\"input\":\"hi\"}", "x-out", "redact"));
        assertNoOriginals(responses);
        assertTrue(responses.contains("response.reasoning_summary_part.done"), responses);
    }

    // ---- unsupported endpoints and encoded paths

    @Test
    void anthropicMessageBatchesAreRedacted() throws Exception {
        assertEquals(200, post("/v1/messages/batches", "{\"requests\":[{\"custom_id\":\"a\",\"params\":{\"model\":\"m\",\"max_tokens\":1,"
                + "\"system\":\"mail " + EMAIL + "\",\"messages\":[{\"role\":\"user\",\"content\":\"SSN " + SSN + "\"}]}}]}").statusCode());
        assertEquals("/v1/messages/batches", STUB.lastPath);
        assertNoOriginals(sent());
        assertTrue(sent().contains(R_SSN), sent());
    }

    @Test
    void ollamaEmbeddingInputIsRedacted() throws Exception {
        STUB.reply("application/json", "{\"model\":\"llama\",\"embeddings\":[[0.1,0.2],[0.3,0.4]]}");
        final HttpResponse<byte[]> embed = post("/api/embed", "{\"model\":\"llama\",\"input\":[\"SSN " + SSN + "\",\"mail " + EMAIL + "\"]}", "x-out", "redact");
        assertEquals(200, embed.statusCode(), text(embed));
        assertEquals("/api/embed", STUB.lastPath);
        assertNoOriginals(sent());
        assertTrue(sent().contains(R_SSN), sent());
        assertTrue(text(embed).contains("[[0.1,0.2],[0.3,0.4]]"), text(embed));

        assertEquals(200, post("/api/embed", "{\"model\":\"llama\",\"input\":\"SSN " + SSN + "\"}").statusCode());
        assertNoOriginals(sent());
        assertTrue(sent().contains(R_SSN), sent());

        STUB.reply("application/json", "{\"embedding\":[0.1,0.2]}");
        assertEquals(200, post("/api/embeddings", "{\"model\":\"llama\",\"prompt\":\"SSN " + SSN + "\"}").statusCode());
        assertEquals("/api/embeddings", STUB.lastPath);
        assertNoOriginals(sent());
        assertTrue(sent().contains(R_SSN), sent());
    }

    @Test
    void ollamaShowIsForwardedUnchanged() throws Exception {
        final String metadata = "{\"template\":\"{{ .Prompt }}\",\"details\":{\"family\":\"qwen2\"},\"capabilities\":[\"completion\",\"tools\"]}";
        STUB.reply("application/json", metadata);
        final HttpResponse<byte[]> show = post("/api/show", "{\"model\":\"llama\"}", "x-out", "block");
        assertEquals(200, show.statusCode(), text(show));
        assertEquals("/api/show", STUB.lastPath);
        assertEquals("{\"model\":\"llama\"}", sent());
        assertTrue(text(show).contains("\"capabilities\":[\"completion\",\"tools\"]"), text(show));
    }

    @Test
    void requestsTheProxyCannotRedactAreRefused() throws Exception {
        final String[][] cases = {
                {"/v1/batches", "{\"input_file_id\":\"f\"}"},
                {"/v1/threads/t/messages", "{\"role\":\"user\",\"content\":\"SSN " + SSN + "\"}"},
                {"/v1/chat/completions/c1", "{\"metadata\":{}}"},
                {"/v1/messages/batches/b1/cancel", "{}"},
                {"/v1beta/models/imagen-4.0-generate-001:predict", "{\"instances\":[{\"prompt\":\"SSN " + SSN + "\"}]}"},
                {"/v1/projects/test-project/locations/us-central1/publishers/google/models/text-embedding-005:predict", "{\"instances\":[{\"content\":\"SSN " + SSN + "\"}]}"},
                {"/v1/projects/test-project/locations/us-central1/publishers/google/models/gemini-embedding-001:embedContent", "{\"content\":{\"parts\":[{\"text\":\"SSN " + SSN + "\"}]}}"},
                {"/api/create", "{\"model\":\"llama\",\"system\":\"SSN " + SSN + "\"}"},
                {"/local/v1/threads/t/messages", "{\"content\":\"SSN " + SSN + "\"}"},
        };
        for (final String[] c : cases) {
            final HttpResponse<byte[]> response = post(c[0], c[1]);
            assertEquals(400, response.statusCode(), c[0]);
            assertTrue(text(response).contains("unsupported_endpoint"), c[0] + ": " + text(response));
        }
        assertEquals(0, STUB.requests);
    }

    @Test
    void responsesTheProxyCannotScanAreRefusedWhenScanningIsOn() throws Exception {
        for (final String path : new String[]{"/v1/responses/resp_1", "/v1/chat/completions", "/v1/chat/completions/c1/messages"}) {
            final HttpResponse<byte[]> response = send("GET", path, null, "x-out", "block");
            assertEquals(400, response.statusCode(), path);
            assertTrue(text(response).contains("unsupported_endpoint"), text(response));
        }
        assertEquals(0, STUB.requests);
        // Without scanning, a request with no body has nothing to redact and is forwarded.
        assertEquals(200, send("GET", "/v1/responses/resp_1", null).statusCode());
        assertEquals(1, STUB.requests);
    }

    @Test
    void unsupportedEndpointsCanBeForwardedWhenConfigured() throws Exception {
        assertEquals(200, post("/v1/batches", "{\"input_file_id\":\"f\"}", "x-unsupported", "forward").statusCode());
        assertEquals("/v1/batches", STUB.lastPath);
    }

    @Test
    void forwardedUnsupportedEndpointsAreReturnedUnscanned() throws Exception {
        // Ollama model management: a streamed pull's progress lines carry no text field, and reach the client as
        // sent even with response scanning on for the route.
        final String progress = "{\"status\":\"pulling manifest\"}\n{\"status\":\"pulling 6a0746a1ec1a\",\"digest\":\"sha256:6a07\","
                + "\"total\":2019393189,\"completed\":241970}\n{\"status\":\"success\"}\n";
        STUB.reply("application/x-ndjson", List.of(progress.getBytes(StandardCharsets.UTF_8)));
        final HttpResponse<byte[]> pull = post("/api/pull", "{\"model\":\"llama\"}", "x-unsupported", "forward-scanned");
        assertEquals(200, pull.statusCode(), text(pull));
        assertEquals("/api/pull", STUB.lastPath);
        assertEquals(progress, text(pull));

        // A buffered response from a forwarded endpoint is not scanned either.
        STUB.reply("application/json", "{\"id\":\"batch_1\",\"note\":\"SSN " + SSN + "\"}");
        final HttpResponse<byte[]> batch = post("/v1/batches", "{\"input_file_id\":\"f\"}", "x-unsupported", "forward-scanned");
        assertEquals(200, batch.statusCode(), text(batch));
        assertTrue(text(batch).contains(SSN), text(batch));

        STUB.reply("application/json", "");
        final HttpResponse<byte[]> delete = send("DELETE", "/api/delete", "{\"model\":\"llama\"}", "x-unsupported", "forward");
        assertEquals(200, delete.statusCode(), text(delete));
        assertEquals("DELETE", STUB.lastMethod);
        assertEquals("{\"model\":\"llama\"}", sent());

        // Refused by default.
        assertEquals(400, post("/api/pull", "{\"model\":\"llama\"}").statusCode());
        assertEquals(400, send("DELETE", "/api/delete", "{\"model\":\"llama\"}").statusCode());
    }

    @Test
    void encodedPathsAreClassifiedAsTheProviderDecodesThem() throws Exception {
        STUB.reply("application/json", "{}");
        // An encoded letter: redacted like the endpoint it decodes to, and forwarded as the client encoded it.
        assertEquals(200, post("/v1/chat/completion%73", "{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"SSN " + SSN + "\"}]}").statusCode());
        assertNoOriginals(sent());
        assertEquals("/v1/chat/completion%73", STUB.lastPath);
        STUB.reset();
        assertEquals(200, post("/v1/messag%65s", "{\"model\":\"m\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"SSN " + SSN + "\"}]}").statusCode());
        assertNoOriginals(sent());
        STUB.reset();
        assertEquals(200, post("/loc%61l/v1/chat/completions", "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"SSN " + SSN + "\"}]}").statusCode());
        assertNoOriginals(sent());
        assertEquals("/v1/chat/completions", STUB.lastPath);
        STUB.reset();
        assertEquals(200, post("/model/anthropic.claude-3-haiku-v1%3A0/converse", "{\"messages\":[{\"role\":\"user\",\"content\":[{\"text\":\"SSN " + SSN + "\"}]}]}").statusCode());
        assertNoOriginals(sent());
        assertEquals("/model/anthropic.claude-3-haiku-v1%3A0/converse", STUB.lastPath);
        STUB.reset();
        for (final String path : new String[]{"/v1/chat%2Fcompletions", "/v1/chat/completions%25", "/v1/chat/completions%3F", "/v1/%2e%2e/chat/completions",
                "/v1/chat/completions%0a", "/v1/chat/completions%C3", "/v1/chat/completions%5c"}) {
            final HttpResponse<byte[]> response = post(path, "{\"model\":\"m\",\"messages\":[]}");
            assertEquals(400, response.statusCode(), path);
        }
        assertEquals(0, STUB.requests);
    }

    @Test
    void requestsWithoutABodyAreForwarded() throws Exception {
        STUB.reply("application/json", "{\"data\":[{\"id\":\"gpt-4o\"}]}");
        final HttpResponse<byte[]> response = send("GET", "/v1/models", null);
        assertEquals(200, response.statusCode());
        assertEquals("GET", STUB.lastMethod);
        assertEquals("/v1/models", STUB.lastPath);
        assertTrue(text(response).contains("gpt-4o"));
    }

    @Test
    void refusesNonCanonicalPaths() throws Exception {
        for (final String path : new String[]{"/v1/chat/../embeddings", "/v1//chat/completions", "/v1/%2e%2e/x", "/v1/a%2fb"}) {
            final HttpResponse<byte[]> response = post(path, "{}");
            assertEquals(400, response.statusCode(), path);
        }
        assertEquals(0, STUB.requests);
    }

}
