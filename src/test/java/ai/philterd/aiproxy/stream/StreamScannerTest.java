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
package ai.philterd.aiproxy.stream;

import ai.philterd.aiproxy.config.ProxyProperties.Action;
import ai.philterd.aiproxy.providers.OpenAiChatStream;
import ai.philterd.aiproxy.redaction.Redactor.Redaction;
import ai.philterd.phileas.model.filtering.FilterType;
import ai.philterd.phileas.model.filtering.Span;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StreamScannerTest {

    private static final Pattern SSN = Pattern.compile("\\d{3}-\\d{2}-\\d{4}");

    /** Detects SSNs by pattern and replaces each with [SSN]. */
    private static Redaction scan(final String text) {
        final List<Span> spans = new ArrayList<>();
        final Matcher m = SSN.matcher(text);
        final StringBuilder out = new StringBuilder();
        int last = 0;
        while (m.find()) {
            spans.add(span(m.start(), m.end()));
            out.append(text, last, m.start()).append("[SSN]");
            last = m.end();
        }
        out.append(text.substring(last));
        return new Redaction(text, out.toString(), spans);
    }

    private static Span span(final int start, final int end) {
        return Span.make(start, end, FilterType.SSN, "", 1.0, "", "[SSN]", "", false, true, new String[0], 0);
    }

    private static String chunk(final String content, final String finish) {
        return "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"" + content + "\"},\"finish_reason\":"
                + (finish == null ? "null" : "\"" + finish + "\"") + "}]}\n\n";
    }

    private static StreamScanner scanner(final Action action, final int holdback, final List<String> events) {
        return new StreamScanner(new SseFraming(), new OpenAiChatStream(), StreamScannerTest::scan, action, holdback,
                bytes -> events.add(new String(bytes, StandardCharsets.UTF_8)));
    }

    private static List<String> run(final String sse, final Action action, final int holdback) throws Exception {
        final List<String> events = new ArrayList<>();
        scanner(action, holdback, events)
                .run(new ByteArrayInputStream(sse.getBytes(StandardCharsets.UTF_8)));
        return events;
    }

    private static String content(final List<String> events) {
        final StringBuilder sb = new StringBuilder();
        final Pattern p = Pattern.compile("\"content\":\"([^\"]*)\"");
        for (final String event : events) {
            final Matcher m = p.matcher(event);
            while (m.find()) {
                sb.append(m.group(1));
            }
        }
        return sb.toString();
    }

    @Test
    void cutsAtWhitespaceAndNeverInsideAValue() {
        final String text = "abc 123-45-6789 tail";
        // A limit inside the value moves back to whitespace before it.
        assertEquals(4, StreamScanner.cutPoint(text, List.of(span(4, 15)), 10, false));
        // On the last release the whole text goes.
        assertEquals(text.length(), StreamScanner.cutPoint(text, List.of(span(4, 15)), text.length(), true));
        // With no whitespace, the limit is kept unless it splits a value.
        assertEquals(5, StreamScanner.cutPoint("abcdefghij", List.of(), 5, false));
        assertEquals(2, StreamScanner.cutPoint("ab123-45-6789", List.of(span(2, 13)), 6, true));
        assertEquals(0, StreamScanner.cutPoint("abc", List.of(), -5, false));
    }

    @Test
    void rebuildsTheRedactedPrefix() {
        final String text = "a 123-45-6789 b 987-65-4321 c";
        assertEquals("a [SSN] b [SSN] c", StreamScanner.rebuild(text, scan(text).spans(), text.length()));
        assertEquals("a [SSN] b", StreamScanner.rebuild(text, List.of(span(2, 13)), 15));
    }

    @Test
    void redactsAValueSplitAcrossManyChunks() throws Exception {
        final String text = "one two three four 123-45-6789 five six seven eight nine ten";
        final StringBuilder sse = new StringBuilder("data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n");
        for (int i = 0; i < text.length(); i += 2) {
            sse.append(chunk(text.substring(i, Math.min(text.length(), i + 2)), null));
        }
        sse.append(chunk("", "stop")).append("data: [DONE]\n\n");
        final List<String> events = run(sse.toString(), Action.REDACT, 12);
        assertEquals(text.replace("123-45-6789", "[SSN]"), content(events));
        assertTrue(events.getFirst().contains("\"role\":\"assistant\""));
        assertTrue(events.get(events.size() - 2).contains("\"finish_reason\":\"stop\""));
        assertEquals("data: [DONE]\n\n", events.getLast());
        assertTrue(events.size() > 4, "expected several releases");
    }

    @Test
    void releasesHeldTextWhenTheStreamEndsWithoutDone() throws Exception {
        final List<String> events = run(chunk("SSN 123-45", null) + chunk("-6789", null), Action.REDACT, 100);
        assertEquals("SSN [SSN]", content(events));
    }

    @Test
    void forwardsCommentsUnknownDataAndUsageInOrder() throws Exception {
        final String sse = chunk("hello ", null) + ": ping\n\n" + "data: not-json\n\n"
                + "data: {\"choices\":[],\"usage\":{\"total_tokens\":3}}\n\n" + "event: x\ndata: [DONE]\n\n";
        final List<String> events = run(sse, Action.FLAG, 100);
        // A keep-alive is forwarded at once and releases nothing.
        assertEquals(": ping\n\n", events.get(0));
        assertTrue(events.get(1).contains("hello "), "held text is released before unknown data");
        assertEquals("data: not-json\n\n", events.get(2));
        assertTrue(events.get(3).contains("usage"));
        assertEquals("event: x\ndata: [DONE]\n\n", events.get(4));
    }

    @Test
    void doesNotReleaseAValueSplitAroundAKeepAlive() throws Exception {
        final String sse = chunk("SSN 123-45-", null) + ": ping\n\n" + chunk("6789 ok", "stop") + "data: [DONE]\n\n";
        final List<String> events = run(sse, Action.REDACT, 100);
        assertEquals("SSN [SSN] ok", content(events));
        assertTrue(!String.join("", events).contains("123-"));
    }

    @Test
    void endsTheStreamOnDataItCannotScan() {
        for (final String bad : new String[]{"data: not-json\n\n", "data: [1,2]\n\n", "\u001f\u008b binary\n\n"}) {
            final List<String> events = new ArrayList<>();
            final StreamScanner scanner = scanner(Action.REDACT, 100, events);
            final String sse = chunk("SSN 123-45-6789 ", null) + bad + "data: [DONE]\n\n";
            assertThrows(StreamScanner.UnscannableException.class,
                    () -> scanner.run(new ByteArrayInputStream(sse.getBytes(StandardCharsets.UTF_8))), bad);
            assertTrue(!String.join("", events).contains("6789"));
        }
    }

    @Test
    void blocksBeforeAValueIsReleased() throws Exception {
        final List<String> events = new ArrayList<>();
        final StreamScanner scanner = scanner(Action.BLOCK, 8, events);
        final String sse = chunk("fine text here ", null) + chunk("123-45-", null) + chunk("6789 more", null) + "data: [DONE]\n\n";
        assertThrows(StreamScanner.BlockedException.class,
                () -> scanner.run(new ByteArrayInputStream(sse.getBytes(StandardCharsets.UTF_8))));
        assertTrue(!String.join("", events).contains("123-"), String.join("", events));
    }

    @Test
    void flagsWithoutChangingText() throws Exception {
        final List<String> events = new ArrayList<>();
        final StreamScanner scanner = scanner(Action.FLAG, 8, events);
        scanner.run(new ByteArrayInputStream((chunk("SSN 123-45-6789 ok", "stop") + "data: [DONE]\n\n").getBytes(StandardCharsets.UTF_8)));
        assertEquals("SSN 123-45-6789 ok", content(events));
        assertEquals(1, scanner.detections().size());
    }

    @Test
    void keepsChoicesApart() throws Exception {
        final String sse = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a 123-45-\"},\"finish_reason\":null},"
                + "{\"index\":1,\"delta\":{\"content\":\"b \"},\"finish_reason\":null}]}\n\n"
                + "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"6789\"},\"finish_reason\":\"stop\"},"
                + "{\"index\":1,\"delta\":{\"content\":\"done\"},\"finish_reason\":\"stop\"}]}\n\n";
        final List<String> events = run(sse, Action.REDACT, 100);
        final String all = String.join("", events);
        assertTrue(all.contains("\"index\":0,\"delta\":{\"content\":\"a [SSN]\"}"), all);
        assertTrue(all.contains("\"index\":1,\"delta\":{\"content\":\"b done\"}"), all);
    }

}
