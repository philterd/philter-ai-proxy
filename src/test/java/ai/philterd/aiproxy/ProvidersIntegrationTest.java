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
        registry.add("proxy.routes[2].match.header", () -> "x-media");
        registry.add("proxy.routes[2].match.value", () -> "reject");
        registry.add("proxy.routes[2].media", () -> "reject");
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
        final HttpResponse<byte[]> response = post("/v1/batches", "{\"input_file_id\":\"f\"}", "x-out", "redact");
        assertEquals(502, response.statusCode());
        assertTrue(text(response).contains("response_unscannable"));
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
