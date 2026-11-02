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
import ai.philterd.aiproxy.proxy.TextSlots;
import ai.philterd.aiproxy.redaction.RedactionException;
import ai.philterd.aiproxy.redaction.Redactor.Redaction;
import ai.philterd.phileas.model.filtering.Span;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Scans a streamed response as it arrives, for any provider. A {@link Framing} divides the stream into events and
 * a {@link StreamDialect} says where the text is in each event.
 *
 * <p>Streamed text is held back rather than forwarded as it arrives. When enough has accumulated, the held text
 * is scanned and everything except the last {@code holdback} characters is released, cut at whitespace and never
 * inside a detected value. The rest waits for the next event, so a value split across events is scanned whole as
 * long as it is shorter than the holdback. Held text is released when the dialect says its part of the response
 * has finished, before an end marker such as {@code [DONE]}, and when the stream ends. Keep-alive comments are
 * forwarded at once and release nothing.</p>
 *
 * <p>Arguments (tool-call input, which arrives as fragments of JSON) are held whole until their part finishes, then
 * scanned as JSON, each string in it.</p>
 *
 * <p>Under {@code redact} released text is redacted; under {@code flag} it is released unchanged and the
 * detections are reported; under {@code block} the first detection ends the stream, and nothing that contained the
 * value has been sent. Under {@code redact} and {@code block}, data that is not a JSON event ends the stream rather
 * than being forwarded unscanned.</p>
 */
public final class StreamScanner {

    /** Redacts one piece of text. */
    @FunctionalInterface
    public interface Scanner {
        Redaction scan(String text) throws RedactionException;
    }

    /** Receives the bytes to send to the client, one or more complete events at a time. */
    @FunctionalInterface
    public interface Sink {
        void send(byte[] bytes) throws IOException;
    }

    /** Thrown under {@code block} when a value is detected. Nothing containing it has been sent. */
    public static final class BlockedException extends Exception {
        public BlockedException() {
            super("response blocked: PII detected");
        }
    }

    /** Thrown when the stream holds data that cannot be scanned. Nothing of it has been sent. */
    public static final class UnscannableException extends Exception {
        public UnscannableException() {
            super("the provider's response could not be scanned");
        }
    }

    /**
     * Where held text came from: a part of the response (a choice, a content block, a candidate) and the field
     * within it. Parts are released in order of their group, then field.
     */
    public record Key(String group, String field) {
    }

    private static final Comparator<Key> ORDER = Comparator.comparing(Key::group).thenComparing(Key::field);

    private final Framing framing;
    private final StreamDialect dialect;
    private final Scanner scanner;
    private final Action action;
    private final int holdback;
    private final Sink sink;
    private final List<Span> detections = new ArrayList<>();
    private final Map<Key, StringBuilder> text = new TreeMap<>(ORDER);
    private final Map<Key, Integer> retryAt = new java.util.HashMap<>();
    private final Map<Key, StringBuilder> arguments = new LinkedHashMap<>();

    public StreamScanner(final Framing framing, final StreamDialect dialect, final Scanner scanner, final Action action,
                         final int holdback, final Sink sink) {
        this.framing = framing;
        this.dialect = dialect;
        this.scanner = scanner;
        this.action = action;
        this.holdback = holdback;
        this.sink = sink;
    }

    public Action action() {
        return action;
    }

    /** Every value detected in the released text, for the audit log. */
    public List<Span> detections() {
        return detections;
    }

    /** Reads the provider's stream to its end, sending the scanned events. */
    public void run(final InputStream in) throws IOException, RedactionException, BlockedException, UnscannableException {
        framing.read(in, new Framing.Handler() {
            @Override
            public void onEvent(final StreamEvent event) throws IOException, RedactionException, BlockedException,
                    UnscannableException {
                final StreamEvent forward = dialect.onEvent(event, StreamScanner.this);
                if (forward != null) {
                    send(forward);
                }
            }

            @Override
            public void onPassThrough(final byte[] raw, final boolean end) throws IOException, RedactionException, BlockedException {
                if (end) {
                    finishAll();
                }
                sink.send(raw);
            }

            @Override
            public void onUnreadable(final byte[] raw) throws IOException, RedactionException, BlockedException,
                    UnscannableException {
                if (action != Action.FLAG) {
                    throw new UnscannableException();
                }
                finishAll();
                sink.send(raw);
            }
        });
        finishAll();
    }

    /** Sends an event now, after nothing else. */
    public void send(final StreamEvent event) throws IOException {
        sink.send(framing.encode(event));
    }

    /** Holds streamed text, releasing what can be released once enough has accumulated. */
    public void appendText(final Key key, final String fragment) throws IOException, RedactionException, BlockedException {
        if (fragment == null || fragment.isEmpty()) {
            return;
        }
        final StringBuilder held = text.computeIfAbsent(key, k -> new StringBuilder());
        held.append(fragment);
        ResponseTooLargeException.check(held.length());
        // When a scan could release nothing (a detected value runs to the end), wait for the text to double before
        // scanning again, so a long held text is not rescanned on every fragment.
        if (held.length() >= Math.max(2 * holdback, retryAt.getOrDefault(key, 0))) {
            release(key, false);
        }
    }

    /** Holds a fragment of arguments JSON until its group finishes. */
    public void appendArguments(final Key key, final String fragment) throws ResponseTooLargeException {
        if (fragment != null && !fragment.isEmpty()) {
            final StringBuilder held = arguments.computeIfAbsent(key, k -> new StringBuilder()).append(fragment);
            ResponseTooLargeException.check(held.length());
        }
    }

    /** Releases everything held for the group: its text, then its arguments. */
    public void finish(final String group) throws IOException, RedactionException, BlockedException {
        for (final Key key : new ArrayList<>(text.keySet())) {
            if (key.group().equals(group)) {
                release(key, true);
                text.remove(key);
            }
        }
        for (final Key key : new ArrayList<>(arguments.keySet())) {
            if (key.group().equals(group)) {
                final String held = arguments.remove(key).toString();
                send(dialect.argumentsEvent(key, scanJson(held)));
            }
        }
    }

    /** The groups with held text or arguments, in order. */
    public java.util.SortedSet<String> groups() {
        final java.util.SortedSet<String> groups = new java.util.TreeSet<>();
        text.keySet().forEach(k -> groups.add(k.group()));
        arguments.keySet().forEach(k -> groups.add(k.group()));
        return groups;
    }

    /** Releases everything held. */
    public void finishAll() throws IOException, RedactionException, BlockedException {
        for (final String group : groups()) {
            finish(group);
        }
    }

    /**
     * Scans every string in an event that carries whole text rather than a fragment (a function call that arrives
     * complete, a summary event with the full text) and applies the action: under {@code redact} the strings are
     * replaced, under {@code flag} left as they are, under {@code block} a detection ends the stream.
     */
    public void scanWhole(final TextSlots slots) throws RedactionException, BlockedException {
        final List<String> redacted = new ArrayList<>();
        final List<Span> found = new ArrayList<>();
        for (final String t : slots.texts()) {
            final Redaction redaction = scanner.scan(t);
            found.addAll(redaction.spans());
            redacted.add(redaction.text());
        }
        if (found.isEmpty()) {
            return;
        }
        if (action == Action.BLOCK) {
            throw new BlockedException();
        }
        detections.addAll(found);
        if (action == Action.REDACT) {
            slots.apply(redacted);
        }
    }

    /** Scans each string in the JSON (or the whole text, when it is not JSON) and returns it with the action applied. */
    public String scanJson(final String json) throws RedactionException, BlockedException {
        final JsonObject holder = new JsonObject();
        holder.addProperty("value", json);
        final TextSlots slots = new TextSlots();
        slots.addJsonString(holder, "value");
        scanWhole(slots);
        return holder.get("value").getAsString();
    }

    /** Scans the held text and sends what can be released. */
    private void release(final Key key, final boolean last) throws IOException, RedactionException, BlockedException {
        final StringBuilder held = text.get(key);
        if (held == null || held.isEmpty()) {
            return;
        }
        final String t = held.toString();
        final Redaction redaction = scanner.scan(t);
        final int cut = cutPoint(t, redaction.spans(), last ? t.length() : t.length() - holdback, last);
        if (cut <= 0) {
            retryAt.put(key, t.length() * 2);
            return;
        }
        retryAt.remove(key);
        final List<Span> released = redaction.spans().stream().filter(s -> s.getCharacterEnd() <= cut).toList();
        if (action == Action.BLOCK && !released.isEmpty()) {
            throw new BlockedException();
        }
        detections.addAll(released);
        final String out = action == Action.REDACT ? rebuild(t, released, cut) : t.substring(0, cut);
        held.delete(0, cut);
        if (!out.isEmpty()) {
            send(dialect.textEvent(key, out));
        }
    }

    /**
     * Where to cut the held text: at most {@code limit}, moved back to just after whitespace when not the last
     * release, and moved back to the start of any detected value it would split.
     */
    public static int cutPoint(final String text, final List<Span> spans, final int limit, final boolean last) {
        int cut = Math.max(0, Math.min(limit, text.length()));
        if (!last) {
            int i = cut - 1;
            while (i >= 0 && !Character.isWhitespace(text.charAt(i))) {
                i--;
            }
            if (i >= 0) {
                cut = i + 1;
            }
        }
        boolean moved = true;
        while (moved) {
            moved = false;
            for (final Span span : spans) {
                if (span.getCharacterStart() < cut && span.getCharacterEnd() > cut) {
                    cut = span.getCharacterStart();
                    moved = true;
                }
            }
        }
        return cut;
    }

    /** The text up to {@code cut} with each value replaced. */
    public static String rebuild(final String text, final List<Span> spans, final int cut) {
        final StringBuilder sb = new StringBuilder();
        int position = 0;
        for (final Span span : spans) {
            if (span.getCharacterStart() < position) {
                continue;
            }
            sb.append(text, position, span.getCharacterStart());
            sb.append(span.getReplacement());
            position = span.getCharacterEnd();
        }
        sb.append(text, Math.min(position, cut), cut);
        return sb.toString();
    }

}
