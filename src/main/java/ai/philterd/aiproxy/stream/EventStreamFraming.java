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

import ai.philterd.aiproxy.redaction.RedactionException;
import ai.philterd.aiproxy.proxy.StrictJson;
import com.google.gson.JsonElement;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.CRC32;

/**
 * The AWS event stream binary framing, as Bedrock's ConverseStream sends it. Each message is a 12-byte prelude
 * (total length, headers length, prelude CRC32), headers, a JSON payload, and a CRC32 of the whole message. An
 * {@code event} message is passed on as a JSON event typed by its {@code :event-type} header; any other message
 * (an exception or error) ends the stream and cannot be scanned. A message with a bad checksum cannot be scanned.
 */
public final class EventStreamFraming implements Framing {

    /** The largest message accepted, so a corrupt length cannot make the proxy allocate without bound. */
    static final int MAX_MESSAGE_BYTES = 16 * 1024 * 1024;

    @Override
    public void read(final InputStream in, final Handler handler) throws IOException, RedactionException,
            StreamScanner.BlockedException, StreamScanner.UnscannableException {
        final DataInputStream data = new DataInputStream(in);
        while (true) {
            final byte[] prelude = new byte[12];
            try {
                data.readFully(prelude, 0, 1);
            } catch (final EOFException e) {
                return;
            }
            try {
                data.readFully(prelude, 1, 11);
            } catch (final EOFException e) {
                handler.onUnreadable(prelude);
                return;
            }
            final ByteBuffer p = ByteBuffer.wrap(prelude);
            final int total = p.getInt();
            final int headersLength = p.getInt();
            final long preludeCrc = Integer.toUnsignedLong(p.getInt());
            if (crc(prelude, 0, 8) != preludeCrc || total < 16 || total > MAX_MESSAGE_BYTES || headersLength < 0
                    || headersLength > total - 16) {
                handler.onUnreadable(prelude);
                return;
            }
            final byte[] message = new byte[total];
            System.arraycopy(prelude, 0, message, 0, 12);
            data.readFully(message, 12, total - 12);
            final long messageCrc = Integer.toUnsignedLong(ByteBuffer.wrap(message, total - 4, 4).getInt());
            if (crc(message, 0, total - 4) != messageCrc) {
                handler.onUnreadable(message);
                return;
            }
            final Map<String, String> headers = headers(message, 12, headersLength);
            if (headers == null) {
                handler.onUnreadable(message);
                return;
            }
            if (!"event".equals(headers.get(":message-type"))) {
                // An exception or error message ends the stream. Its text is not scanned, so it is treated as
                // unreadable: the stream is ended with an error, or under flag forwarded as it is. Nothing after it
                // is read.
                handler.onUnreadable(message);
                return;
            }
            final String payload = new String(message, 12 + headersLength, total - 16 - headersLength, StandardCharsets.UTF_8);
            final JsonElement parsed = StrictJson.parse(payload);
            if (parsed == null || !parsed.isJsonObject()) {
                handler.onUnreadable(message);
                continue;
            }
            handler.onEvent(new StreamEvent(headers.get(":event-type"), parsed.getAsJsonObject()));
        }
    }

    /** The string headers, or null when a header cannot be read. Headers of other types are skipped. */
    static Map<String, String> headers(final byte[] message, final int offset, final int length) {
        final Map<String, String> headers = new LinkedHashMap<>();
        final ByteBuffer b = ByteBuffer.wrap(message, offset, length);
        try {
            while (b.hasRemaining()) {
                final int nameLength = Byte.toUnsignedInt(b.get());
                final byte[] name = new byte[nameLength];
                b.get(name);
                final int type = b.get();
                switch (type) {
                    case 0, 1 -> { }
                    case 2 -> b.get();
                    case 3 -> b.getShort();
                    case 4 -> b.getInt();
                    case 5, 8 -> b.getLong();
                    case 9 -> b.position(b.position() + 16);
                    case 6, 7 -> {
                        final byte[] value = new byte[Short.toUnsignedInt(b.getShort())];
                        b.get(value);
                        if (type == 7) {
                            headers.put(new String(name, StandardCharsets.UTF_8), new String(value, StandardCharsets.UTF_8));
                        }
                    }
                    default -> {
                        return null;
                    }
                }
            }
        } catch (final RuntimeException e) {
            return null;
        }
        return headers;
    }

    @Override
    public byte[] encode(final StreamEvent event) {
        final ByteArrayOutputStream headers = new ByteArrayOutputStream();
        header(headers, ":event-type", event.type() == null ? "" : event.type());
        header(headers, ":content-type", "application/json");
        header(headers, ":message-type", "event");
        return message(headers.toByteArray(), event.json().toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * An error message ({@code :message-type error}), which AWS SDKs raise with its code and message. An event named
     * "error" is not in any Bedrock stream's event union, so SDKs would skip it and the stream would just stop; an
     * exception message is read against the SDK's model of known exceptions, which loses an unknown code.
     */
    @Override
    public byte[] encodeError(final String code, final com.google.gson.JsonObject error) {
        final ByteArrayOutputStream headers = new ByteArrayOutputStream();
        header(headers, ":message-type", "error");
        header(headers, ":error-code", code);
        header(headers, ":error-message", error.getAsJsonObject("error").get("message").getAsString());
        header(headers, ":content-type", "application/json");
        return message(headers.toByteArray(), error.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] message(final byte[] h, final byte[] payload) {
        final int total = 12 + h.length + payload.length + 4;
        final ByteBuffer b = ByteBuffer.allocate(total);
        b.putInt(total).putInt(h.length);
        b.putInt((int) crc(b.array(), 0, 8));
        b.put(h).put(payload);
        b.putInt((int) crc(b.array(), 0, total - 4));
        return b.array();
    }

    private static void header(final ByteArrayOutputStream out, final String name, final String value) {
        final byte[] n = name.getBytes(StandardCharsets.UTF_8);
        final byte[] v = value.getBytes(StandardCharsets.UTF_8);
        out.write(n.length);
        out.writeBytes(n);
        out.write(7);
        out.write((v.length >> 8) & 0xff);
        out.write(v.length & 0xff);
        out.writeBytes(v);
    }

    private static long crc(final byte[] bytes, final int offset, final int length) {
        final CRC32 crc = new CRC32();
        crc.update(bytes, offset, length);
        return crc.getValue();
    }

}
