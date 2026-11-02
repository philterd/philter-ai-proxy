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
package ai.philterd.aiproxy.providers;

import ai.philterd.aiproxy.proxy.TextSlots;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The request and response fields found in the 2.0 security review, each of which must be collected. */
class DialectCoverageTest {

    static final String SECRET = "SSN 123-45-6789";

    static JsonObject json(final String s) {
        return JsonParser.parseString(s).getAsJsonObject();
    }

    /** The texts collected from the request, and that writing them back replaces every occurrence of the secret. */
    static void assertCollects(final ProviderDialect dialect, final String path, final String body, final int expected) {
        final JsonObject parsed = json(body);
        final TextSlots slots = dialect.requestText(path, parsed);
        final List<String> texts = slots.texts();
        assertEquals(expected, texts.stream().filter(t -> t.contains("123-45-6789") || t.equals("123456789")).count(), path + " " + texts);
        slots.apply(texts.stream().map(t -> t.replace("123-45-6789", "X").replace("123456789", "X")).toList());
        assertFalse(parsed.toString().contains("123-45-6789"), parsed.toString());
        assertFalse(parsed.toString().contains("123456789"), parsed.toString());
    }

    @Test
    void openAiFields() {
        final OpenAiDialect d = new OpenAiDialect();
        assertCollects(d, "/v1/responses", """
                {"model":"m","prompt":{"id":"p","variables":{"a":"%1$s","b":{"type":"input_text","text":"%1$s"}}}}""".formatted(SECRET), 2);
        assertCollects(d, "/v1/responses", """
                {"model":"m","input":[{"type":"function_call_output","call_id":"c","output":[{"type":"input_text","text":"%1$s"}]},
                 {"type":"mcp_call","arguments":"{\\"q\\":\\"%1$s\\"}","output":"%1$s"},
                 {"type":"local_shell_call_output","output":"%1$s"},
                 {"type":"reasoning","summary":[],"content":[{"type":"reasoning_text","text":"%1$s"}]}]}""".formatted(SECRET), 5);
        assertCollects(d, "/v1/chat/completions", """
                {"model":"m","prediction":{"type":"content","content":"%1$s"},
                 "messages":[{"role":"assistant","content":[{"type":"refusal","refusal":"%1$s"}],"reasoning_content":"%1$s"}]}""".formatted(SECRET), 3);
        assertCollects(d, "/v1/completions", """
                {"model":"m","prompt":"hi","suffix":"%1$s"}""".formatted(SECRET), 1);
        assertCollects(d, "/v1/chat/completions", """
                {"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"t","type":"function","function":{"name":"f","arguments":"{\\"ssn\\":123456789,\\"n\\":3,\\"x\\":1.5}"}}]}]}""", 1);
        assertEquals("input_image", d.mediaPart("/v1/responses", json("""
                {"model":"m","prompt":{"id":"p","variables":{"pic":{"type":"input_image","image_url":"https://example.com/a.png"}}}}""")));
    }

    @Test
    void numbersStayNumbersUnlessRedacted() {
        final JsonObject args = json("{\"ssn\":123456789,\"count\":3,\"total\":12345}");
        final TextSlots slots = new TextSlots();
        slots.addAllStrings(args);
        assertEquals(List.of("123456789", "12345"), slots.texts());
        slots.apply(List.of("{{{REDACTED-ssn}}}", "12345"));
        assertEquals("{{{REDACTED-ssn}}}", args.get("ssn").getAsString());
        assertTrue(args.get("total").getAsJsonPrimitive().isNumber());
        assertTrue(args.get("count").getAsJsonPrimitive().isNumber());
    }

    @Test
    void anthropicFields() {
        final AnthropicDialect d = new AnthropicDialect();
        assertCollects(d, "/v1/messages", """
                {"model":"m","messages":[{"role":"user","content":[{"type":"search_result","source":"https://example.com","title":"%1$s","content":[{"type":"text","text":"%1$s"}]},
                 {"type":"tool_result","tool_use_id":"t","content":[{"type":"search_result","source":"s","title":"t","content":[{"type":"text","text":"%1$s"}]}]}]}]}""".formatted(SECRET), 3);
        final String batch = """
                {"requests":[{"custom_id":"a","params":{"model":"m","max_tokens":1,"system":"%1$s","messages":[{"role":"user","content":"%1$s"}]}},
                 {"custom_id":"b","params":{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"text","text":"%1$s"}]}]}}]}""".formatted(SECRET);
        assertCollects(d, "/v1/messages/batches", batch, 3);
        assertTrue(d.supports("POST", "/v1/messages/batches"));
        assertEquals("m", d.model("/v1/messages/batches", json(batch)));
        assertNull(d.model("/v1/messages/batches", json("""
                {"requests":[{"params":{"model":"a","messages":[]}},{"params":{"model":"b","messages":[]}}]}""")));
        assertEquals("image", d.mediaPart("/v1/messages/batches", json("""
                {"requests":[{"params":{"model":"m","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}]}]}}]}""")));
    }

    @Test
    void bedrockFields() {
        final BedrockDialect d = new BedrockDialect();
        assertCollects(d, "/model/m/converse", """
                {"system":[{"guardContent":{"text":{"text":"%1$s"}}}],
                 "messages":[{"role":"user","content":[{"guardContent":{"text":{"text":"%1$s","qualifiers":["guard_content"]}}}]}]}""".formatted(SECRET), 2);
        assertEquals("image", d.mediaPart("/model/m/converse", json("""
                {"messages":[{"role":"user","content":[{"guardContent":{"image":{"format":"png","source":{"bytes":"AAAA"}}}}]}]}""")));
        assertEquals("image", d.mediaPart("/model/m/converse", json("""
                {"system":[{"guardContent":{"image":{"format":"png","source":{"bytes":"AAAA"}}}}],"messages":[]}""")));
    }

    @Test
    void ollamaAndGeminiFields() {
        assertCollects(new OllamaDialect(), "/api/generate", """
                {"model":"m","prompt":"hi","suffix":"%1$s","template":"%1$s"}""".formatted(SECRET), 2);
        assertCollects(new OllamaDialect(), "/api/embed", """
                {"model":"m","input":["%1$s","%1$s"]}""".formatted(SECRET), 2);
        assertCollects(new OllamaDialect(), "/api/embed", """
                {"model":"m","input":"%1$s","prompt":"not read by /api/embed"}""".formatted(SECRET), 1);
        assertCollects(new OllamaDialect(), "/api/embeddings", """
                {"model":"m","prompt":"%1$s"}""".formatted(SECRET), 1);
        assertTrue(new OllamaDialect().requestText("/api/show", json("{\"model\":\"m\",\"verbose\":true}")).texts().isEmpty());
        assertTrue(new OllamaDialect().supports("POST", "/api/show"));
        assertFalse(new OllamaDialect().supports("POST", "/api/create"));
        assertCollects(new GeminiDialect(), "/v1beta/models/g:generateContent", """
                {"contents":[{"role":"model","parts":[{"executableCode":{"language":"PYTHON","code":"print('%1$s')"}},
                 {"codeExecutionResult":{"outcome":"OUTCOME_OK","output":"%1$s"}}]}]}""".formatted(SECRET), 2);
    }

    @Test
    void geminiModelScopesSeeEveryModelInTheBody() {
        final GeminiDialect d = new GeminiDialect();
        final String batch = "/v1beta/models/gemini-embedding-001:batchEmbedContents";
        assertEquals("gemini-embedding-001", d.model(batch, json("{\"requests\":[{\"model\":\"models/gemini-embedding-001\"},{}]}")));
        assertNull(d.model(batch, json("{\"requests\":[{\"model\":\"models/gemini-embedding-001\"},{\"model\":\"models/other\"}]}")));
        final String count = "/v1beta/models/gemini-2.5-flash:countTokens";
        assertEquals("gemini-2.5-flash", d.model(count, json("{\"generateContentRequest\":{\"model\":\"models/gemini-2.5-flash\"}}")));
        assertNull(d.model(count, json("{\"generateContentRequest\":{\"model\":\"models/gemini-2.5-pro\"}}")));
        assertEquals("gemini-2.5-flash", d.model("/v1beta/models/gemini-2.5-flash:generateContent", json("{\"model\":\"ignored\"}")));
        assertCollects(d, batch, """
                {"requests":[{"content":{"parts":[{"text":"%1$s"}]},"title":"%1$s"},{"content":{"parts":[{"text":"%1$s"}]}}]}""".formatted(SECRET), 3);
    }

    @Test
    void revealingResponseDataIsRemoved() {
        final JsonObject gemini = json("""
                {"candidates":[{"content":{"parts":[{"text":"x"}]},"logprobsResult":{"chosenCandidates":[{"token":"123"}]},"avgLogprobs":-0.1}]}""");
        assertTrue(new GeminiDialect().removeRevealingData("/v1beta/models/g:generateContent", gemini));
        assertFalse(gemini.toString().contains("logprobsResult"));
        final JsonObject ollama = json("{\"response\":\"x\",\"done\":true,\"context\":[1,2,3],\"logprobs\":[{\"token\":\"1\"}]}");
        assertTrue(new OllamaDialect().removeRevealingData("/api/generate", ollama));
        assertFalse(ollama.has("context"));
        assertFalse(ollama.has("logprobs"));
    }

    @Test
    void azureModelIsTheDeployment() {
        final OpenAiDialect d = new OpenAiDialect();
        assertEquals("prod-gpt4o", d.model("/openai/deployments/prod-gpt4o/chat/completions", json("{\"model\":\"allowed\"}")));
        assertEquals("allowed", d.model("/v1/chat/completions", json("{\"model\":\"allowed\"}")));
    }

}
