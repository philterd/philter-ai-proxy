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
package ai.philterd.aiproxy.proxy;

import ai.philterd.aiproxy.config.ProxyProperties.Action;
import ai.philterd.aiproxy.providers.AnthropicDialect;
import ai.philterd.aiproxy.providers.BedrockDialect;
import ai.philterd.aiproxy.providers.GeminiDialect;
import ai.philterd.aiproxy.providers.OllamaDialect;
import ai.philterd.aiproxy.providers.OpenAiDialect;
import ai.philterd.aiproxy.providers.ProviderDialect;
import ai.philterd.aiproxy.redaction.RedactionException;
import ai.philterd.aiproxy.redaction.Redactor.Redaction;
import ai.philterd.aiproxy.stream.EventStreamFraming;
import ai.philterd.aiproxy.stream.Framing;
import ai.philterd.aiproxy.stream.NdjsonFraming;
import ai.philterd.aiproxy.stream.SseFraming;
import ai.philterd.aiproxy.stream.StreamDialect;
import ai.philterd.aiproxy.stream.StreamEvent;
import ai.philterd.aiproxy.stream.StreamScanner;
import ai.philterd.phileas.model.filtering.FilterType;
import ai.philterd.phileas.model.filtering.Span;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.CRC32;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fuzz targets for the code that reads what clients and providers send: path decoding, the three stream framings,
 * and each dialect's request and response fields. Each target fails on an exception the proxy does not expect, which
 * it would answer with a 500 (or end a stream with), and on a broken invariant.
 *
 * <p>With the unit tests, each target runs its seed inputs from {@code src/test/resources/.../ParserFuzzTestInputs}
 * and every crash recorded there. To fuzz, run one target at a time with {@code JAZZER_FUZZ=1}, for example
 * {@code JAZZER_FUZZ=1 ./mvnw test -Dtest='ParserFuzzTest#streams' -Djacoco.skip=true}. A crash is saved to the inputs
 * directory, where it stays as a regression test once fixed.</p>
 */
class ParserFuzzTest {

    private static final Pattern SSN = Pattern.compile("\\d{3}-\\d{2}-\\d{4}");

    /** Each dialect and the paths it reads, so the fuzzer reaches every request and response shape. */
    private record Target(ProviderDialect dialect, String path) {
    }

    private static final List<Target> TARGETS = List.of(
            new Target(new OpenAiDialect(), "/v1/chat/completions"),
            new Target(new OpenAiDialect(), "/v1/responses"),
            new Target(new OpenAiDialect(), "/v1/completions"),
            new Target(new OpenAiDialect(), "/v1/embeddings"),
            new Target(new OpenAiDialect(), "/v1/moderations"),
            new Target(new OpenAiDialect(), "/v1/images/generations"),
            new Target(new OpenAiDialect(), "/v1/audio/speech"),
            new Target(new OpenAiDialect(), "/openai/deployments/d/chat/completions"),
            new Target(new AnthropicDialect(), "/v1/messages"),
            new Target(new AnthropicDialect(), "/v1/messages/batches"),
            new Target(new AnthropicDialect(), "/v1/messages/count_tokens"),
            new Target(new GeminiDialect(), "/v1beta/models/g:generateContent"),
            new Target(new GeminiDialect(), "/v1beta/models/g:streamGenerateContent"),
            new Target(new GeminiDialect(), "/v1beta/models/g:countTokens"),
            new Target(new GeminiDialect(), "/v1beta/models/g:embedContent"),
            new Target(new GeminiDialect(), "/v1beta/models/g:batchEmbedContents"),
            new Target(new GeminiDialect(), "/v1/projects/p/locations/l/publishers/google/models/g:generateContent"),
            new Target(new GeminiDialect(), "/v1/projects/p/locations/l/publishers/google/models/g:countTokens"),
            new Target(new OllamaDialect(), "/api/chat"),
            new Target(new OllamaDialect(), "/api/generate"),
            new Target(new OllamaDialect(), "/api/embed"),
            new Target(new OllamaDialect(), "/api/embeddings"),
            new Target(new BedrockDialect(), "/model/m/converse"),
            new Target(new BedrockDialect(), "/model/m/converse-stream"),
            new Target(new BedrockDialect(), "/model/anthropic.claude-3-haiku-20240307-v1:0/invoke"),
            new Target(new BedrockDialect(), "/model/us.anthropic.claude-sonnet-4-20250514-v1:0/invoke-with-response-stream"),
            new Target(new BedrockDialect(), "/model/anthropic.claude-v2/invoke"),
            new Target(new BedrockDialect(), "/model/anthropic.claude-v2/invoke-with-response-stream"),
            new Target(new BedrockDialect(), "/model/amazon.titan-embed-text-v2:0/invoke"),
            new Target(new BedrockDialect(), "/model/cohere.embed-english-v3/invoke"));

    // ---- Path decoding

    @FuzzTest
    void pathDecoding(final byte[] input) {
        // One char per byte, as the servlet container gives the proxy the raw request URI.
        final String raw = new String(input, StandardCharsets.ISO_8859_1);
        final String decoded;
        try {
            decoded = ProxyController.decodePath(raw);
        } catch (final ProxyError e) {
            assertEquals(400, e.status());
            ProxyController.isReserved(raw);
            return;
        }
        // A decoded path is canonical and has no control characters, so scopes and routing see what the provider will.
        assertTrue(ProxyController.isCanonical(decoded), decoded);
        assertTrue(decoded.chars().noneMatch(c -> c < 0x20 || c == 0x7f), decoded);
        if (ProxyController.isReserved(decoded)) {
            assertTrue(ProxyController.isReserved(raw), raw);
        }
    }

    // ---- Stream framings

    @FuzzTest
    void sse(final byte[] input) throws Exception {
        framing(new SseFraming(), input);
    }

    @FuzzTest
    void ndjson(final byte[] input) throws Exception {
        framing(new NdjsonFraming(), input);
    }

    @FuzzTest
    void eventStream(final byte[] input) throws Exception {
        framing(new EventStreamFraming(), input);
    }

    /**
     * AWS event stream messages with their checksums corrected, so the fuzzer reaches the headers and payloads that
     * random bytes almost never get past the checksums to.
     */
    @FuzzTest
    void eventStreamMessages(final byte[] input) throws Exception {
        framing(new EventStreamFraming(), withChecksums(input));
    }

    /** What a framing reads from arbitrary bytes, and that every event it reads survives encoding and reading again. */
    private static void framing(final Framing framing, final byte[] input) throws Exception {
        final List<StreamEvent> events = new ArrayList<>();
        try {
            framing.read(new ByteArrayInputStream(input), recorder(events));
        } catch (final IOException e) {
            // A truncated message or an oversized line or event ends the stream, as the proxy expects.
        }
        for (final StreamEvent event : events) {
            final List<StreamEvent> again = new ArrayList<>();
            framing.read(new ByteArrayInputStream(framing.encode(event)), recorder(again));
            assertEquals(1, again.size(), event.toString());
            assertEquals(event.json(), again.get(0).json());
            if (!(framing instanceof NdjsonFraming)) {
                assertEquals(blankToNull(event.type()), blankToNull(again.get(0).type()));
            }
        }
    }

    private static String blankToNull(final String s) {
        return s == null || s.isEmpty() ? null : s;
    }

    /** Rewrites the prelude and message checksums of each message whose stated length fits in the input. */
    static byte[] withChecksums(final byte[] input) {
        final byte[] out = input.clone();
        int offset = 0;
        while (offset + 16 <= out.length) {
            final ByteBuffer b = ByteBuffer.wrap(out, offset, out.length - offset);
            final int total = b.getInt();
            if (total < 16 || total > out.length - offset) {
                break;
            }
            final CRC32 crc = new CRC32();
            crc.update(out, offset, 8);
            ByteBuffer.wrap(out, offset + 8, 4).putInt((int) crc.getValue());
            crc.reset();
            crc.update(out, offset, total - 4);
            ByteBuffer.wrap(out, offset + total - 4, 4).putInt((int) crc.getValue());
            offset += total;
        }
        return out;
    }

    private static Framing.Handler recorder(final List<StreamEvent> events) {
        return new Framing.Handler() {
            @Override
            public void onEvent(final StreamEvent event) {
                events.add(event);
            }

            @Override
            public void onPassThrough(final byte[] raw, final boolean end) {
            }

            @Override
            public void onUnreadable(final byte[] raw) {
            }
        };
    }

    // ---- Request and response fields

    /** The target the input's first byte chooses; the rest of the input is the body or stream. */
    private static Target target(final byte[] input) {
        return TARGETS.get(Byte.toUnsignedInt(input[0]) % TARGETS.size());
    }

    private static String rest(final byte[] input, final int from) {
        return new String(input, from, input.length - from, StandardCharsets.UTF_8);
    }

    /**
     * A request body: reading its fields, model, and media never throws, and writing back the fields unchanged
     * leaves the body as it was.
     */
    @FuzzTest
    void requestFields(final byte[] input) {
        if (input.length < 1) {
            return;
        }
        final Target target = target(input);
        final JsonElement parsed = parse(rest(input, 1));
        if (parsed == null || !parsed.isJsonObject()) {
            return;
        }
        final JsonObject body = parsed.getAsJsonObject();
        final JsonObject before = body.deepCopy();
        target.dialect().model(target.path(), body);
        target.dialect().mediaPart(target.path(), body);
        roundTrip(target.dialect().requestText(target.path(), body));
        assertEquals(before, body);
        redactAll(target.dialect().requestText(target.path(), body));
    }

    /** A provider's buffered response: the same, plus removing revealing data. */
    @FuzzTest
    void responseFields(final byte[] input) {
        if (input.length < 1) {
            return;
        }
        final Target target = target(input);
        final JsonElement body = parse(rest(input, 1));
        if (body == null || !(body.isJsonObject() || body.isJsonArray())) {
            return;
        }
        final JsonElement before = body.deepCopy();
        roundTrip(target.dialect().responseText(target.path(), body));
        assertEquals(before, body);
        redactAll(target.dialect().responseText(target.path(), body));
        target.dialect().removeRevealingData(target.path(), body);
    }

    /** As the proxy parses bodies: strictly, so the fuzzer does not spend time on JSON the proxy refuses. */
    private static JsonElement parse(final String text) {
        return StrictJson.parse(text);
    }

    private static void roundTrip(final TextSlots slots) {
        slots.apply(slots.texts());
    }

    private static void redactAll(final TextSlots slots) {
        final List<String> texts = slots.texts();
        slots.apply(texts.stream().map(t -> "[" + t.length() + "]").toList());
    }

    // ---- Streams

    /**
     * A provider's stream, read by each dialect's stream reader under each action. The first byte chooses the
     * target, the second the action and holdback; Bedrock streams have their checksums corrected.
     */
    @FuzzTest
    void streams(final byte[] input) throws Exception {
        if (input.length < 2) {
            return;
        }
        final Target target = target(input);
        final Action action = Action.values()[Byte.toUnsignedInt(input[1]) % Action.values().length];
        final int holdback = Byte.toUnsignedInt(input[1]) / Action.values().length % 64;
        final boolean bedrock = target.dialect() instanceof BedrockDialect;
        final Framing framing = target.dialect().framing(bedrock ? "application/vnd.amazon.eventstream"
                : target.dialect() instanceof OllamaDialect ? "application/x-ndjson" : "text/event-stream");
        final StreamDialect dialect = target.dialect().streamDialect(target.path());
        if (framing == null || dialect == null) {
            return;
        }
        byte[] stream = java.util.Arrays.copyOfRange(input, 2, input.length);
        if (bedrock) {
            stream = withChecksums(stream);
        }
        final StreamScanner scanner = new StreamScanner(framing, dialect, ParserFuzzTest::scan, action, holdback, bytes -> { });
        try {
            scanner.run(new ByteArrayInputStream(stream));
        } catch (final IOException | RedactionException | StreamScanner.BlockedException | StreamScanner.UnscannableException e) {
            // Each ends the stream with an error the proxy sends.
        }
    }

    /** Detects SSNs by pattern, so the scanner releases, redacts, and blocks without loading a policy. */
    private static Redaction scan(final String text) {
        final List<Span> spans = new ArrayList<>();
        final Matcher m = SSN.matcher(text);
        final StringBuilder out = new StringBuilder();
        int last = 0;
        while (m.find()) {
            spans.add(Span.make(m.start(), m.end(), FilterType.SSN, "", 1.0, "", "[SSN]", "", false, true, new String[0], 0));
            out.append(text, last, m.start()).append("[SSN]");
            last = m.end();
        }
        out.append(text.substring(last));
        return new Redaction(text, out.toString(), spans);
    }

}
