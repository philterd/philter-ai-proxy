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
package ai.philterd.aiproxy.storage;

import ai.philterd.aiproxy.config.ProxyProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Encrypts values stored at rest with AES-256-GCM, and computes keyed hashes so an encrypted value can still be
 * looked up. Both keys are derived from {@code proxy.security.encryption-key}, which must be 32 bytes given as 64
 * hex characters or as base64.
 */
@Component
public class Encryptor {

    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecretKeySpec encryptionKey;
    private final SecretKeySpec indexKey;
    private final SecureRandom random = new SecureRandom();

    public Encryptor(final ProxyProperties properties) {
        final byte[] master = parseKey(properties.security().encryptionKey());
        this.encryptionKey = new SecretKeySpec(derive(master, "philter-ai-proxy encryption"), "AES");
        this.indexKey = new SecretKeySpec(derive(master, "philter-ai-proxy index"), "HmacSHA256");
    }

    static byte[] parseKey(final String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("proxy.security.encryption-key (PROXY_SECURITY_ENCRYPTIONKEY) must be set to "
                    + "32 random bytes, as 64 hex characters or base64. Generate one with: openssl rand -hex 32");
        }
        final String key = value.strip();
        byte[] bytes;
        try {
            bytes = key.length() == 64 ? HexFormat.of().parseHex(key) : Base64.getDecoder().decode(key);
        } catch (final IllegalArgumentException e) {
            bytes = null;
        }
        if (bytes == null || bytes.length != 32) {
            throw new IllegalStateException("proxy.security.encryption-key must be 32 bytes, as 64 hex characters or base64.");
        }
        return bytes;
    }

    private static byte[] derive(final byte[] master, final String purpose) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(master, "HmacSHA256"));
            return mac.doFinal(purpose.getBytes(StandardCharsets.UTF_8));
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The value encrypted, as base64 of the nonce followed by the ciphertext and tag. */
    public String encrypt(final String plaintext) {
        try {
            final byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new GCMParameterSpec(TAG_BITS, nonce));
            final byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(ByteBuffer.allocate(nonce.length + ciphertext.length)
                    .put(nonce).put(ciphertext).array());
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("Unable to encrypt a value.", e);
        }
    }

    public String decrypt(final String encrypted) {
        try {
            final byte[] bytes = Base64.getDecoder().decode(encrypted);
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new GCMParameterSpec(TAG_BITS, bytes, 0, NONCE_BYTES));
            return new String(cipher.doFinal(bytes, NONCE_BYTES, bytes.length - NONCE_BYTES), StandardCharsets.UTF_8);
        } catch (final GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("Unable to decrypt a stored value. Was proxy.security.encryption-key changed?", e);
        }
    }

    /** A keyed hash of the value, for looking up an encrypted value without decrypting every row. */
    public String index(final String value) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(indexKey);
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

}
