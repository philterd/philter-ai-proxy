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

import com.google.gson.JsonArray;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/** Stored policies, in native Phileas policy JSON. Each write increments the policy's revision. */
@Component
public class PolicyStore {

    public static final String DEFAULT_POLICY_NAME = "default";

    private final Database database;
    private final Encryptor encryptor;

    /**
     * Policies are stored encrypted, since one can hold a literal encryption key or a dictionary of sensitive terms.
     * A policy stored in plaintext, by a build before this, is encrypted at startup.
     * @param keyCheck Taken so the encryption key is checked against the database before anything is encrypted.
     */
    public PolicyStore(final Database database, final Encryptor encryptor, final KeyCheck keyCheck) {
        this.database = database;
        this.encryptor = encryptor;
        encryptPlaintextPolicies();
    }

    private void encryptPlaintextPolicies() {
        try (Connection c = database.connect()) {
            final java.util.Map<String, String> plaintext = new java.util.LinkedHashMap<>();
            try (PreparedStatement ps = c.prepareStatement("SELECT name, policy FROM policies"); ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    if (isPlaintext(rs.getString(2))) {
                        plaintext.put(rs.getString(1), rs.getString(2));
                    }
                }
            }
            for (final java.util.Map.Entry<String, String> entry : plaintext.entrySet()) {
                try (PreparedStatement ps = c.prepareStatement("UPDATE policies SET policy = ? WHERE name = ? AND policy = ?")) {
                    ps.setString(1, encryptor.encrypt(entry.getValue()));
                    ps.setString(2, entry.getKey());
                    ps.setString(3, entry.getValue());
                    ps.executeUpdate();
                }
            }
        } catch (final SQLException e) {
            throw new StorageException("Unable to encrypt the stored policies.", e);
        }
    }

    /** Policy JSON is an object; an encrypted policy is base64, which never starts with a brace. */
    private static boolean isPlaintext(final String stored) {
        return stored.stripLeading().startsWith("{");
    }

    public record StoredPolicy(String name, String policy, int revision, String description, String notes,
                               Instant createdAt, Instant updatedAt) {

        /**
         * The entity tag: the revision and a hash of the description and notes, in the format Philter's policy
         * API uses ({@code <revision>-<16 hex>}).
         */
        public String eTag() {
            final JsonArray details = new JsonArray();
            details.add(description);
            details.add(notes);
            return revision + "-" + sha256Hex(details.toString()).substring(0, 16);
        }
    }

    /** Thrown when a conditional write finds the policy changed since the read it names. */
    public static class ConflictException extends Exception {
        public ConflictException(final String message) {
            super(message);
        }
    }

    public Optional<StoredPolicy> find(final String name) {
        try (Connection c = database.connect();
             PreparedStatement ps = c.prepareStatement("SELECT * FROM policies WHERE name = ?")) {
            ps.setString(1, name);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(read(rs)) : Optional.empty();
            }
        } catch (final SQLException e) {
            throw new StorageException("Unable to read the policy.", e);
        }
    }

    /** The current revision of the policy, without reading it, or empty when there is no such policy. */
    public Optional<Integer> findRevision(final String name) {
        try (Connection c = database.connect();
             PreparedStatement ps = c.prepareStatement("SELECT revision FROM policies WHERE name = ?")) {
            ps.setString(1, name);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(rs.getInt(1)) : Optional.empty();
            }
        } catch (final SQLException e) {
            throw new StorageException("Unable to read the policy.", e);
        }
    }

    public record Page(List<StoredPolicy> policies, long total) {
    }

    /** Policies in name order. */
    public Page list(final int offset, final int limit) {
        try (Connection c = database.connect()) {
            long total;
            try (PreparedStatement ps = c.prepareStatement("SELECT COUNT(*) FROM policies"); ResultSet rs = ps.executeQuery()) {
                total = rs.next() ? rs.getLong(1) : 0;
            }
            final List<StoredPolicy> policies = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement("SELECT * FROM policies ORDER BY name LIMIT ? OFFSET ?")) {
                ps.setInt(1, limit);
                ps.setInt(2, offset);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        policies.add(read(rs));
                    }
                }
            }
            return new Page(policies, total);
        } catch (final SQLException e) {
            throw new StorageException("Unable to list the policies.", e);
        }
    }

    /**
     * Creates the policy at revision 0.
     * @return The policy, or empty when one with this name already exists.
     */
    public Optional<StoredPolicy> create(final String name, final String policyJson, final String description, final String notes) {
        final Instant now = Instant.now();
        try (Connection c = database.connect();
             PreparedStatement ps = c.prepareStatement("INSERT INTO policies (name, policy, revision, description, notes, "
                     + "created_at, updated_at) VALUES (?, ?, 0, ?, ?, ?, ?) ON CONFLICT (name) DO NOTHING")) {
            ps.setString(1, name);
            ps.setString(2, encryptor.encrypt(policyJson));
            ps.setString(3, description == null ? "" : description);
            ps.setString(4, notes == null ? "" : notes);
            ps.setString(5, now.toString());
            ps.setString(6, now.toString());
            if (ps.executeUpdate() == 0) {
                return Optional.empty();
            }
        } catch (final SQLException e) {
            throw new StorageException("Unable to create the policy.", e);
        }
        return find(name);
    }

    /**
     * Replaces the policy's JSON and increments its revision.
     * @param expectedETag When not null, the write happens only if the policy's entity tag still matches.
     * @return The policy as written, or empty when there is no such policy.
     */
    public Optional<StoredPolicy> replace(final String name, final String policyJson, final String expectedETag) throws ConflictException {
        try (Connection c = database.connect()) {
            c.setAutoCommit(false);
            try {
                final StoredPolicy current = findIn(c, name);
                if (current == null) {
                    c.rollback();
                    return Optional.empty();
                }
                if (expectedETag != null && !expectedETag.equals(current.eTag())) {
                    c.rollback();
                    throw new ConflictException("The policy changed since it was read. Read it again and retry.");
                }
                try (PreparedStatement ps = c.prepareStatement(
                        "UPDATE policies SET policy = ?, revision = revision + 1, updated_at = ? WHERE name = ? AND revision = ?")) {
                    ps.setString(1, encryptor.encrypt(policyJson));
                    ps.setString(2, Instant.now().toString());
                    ps.setString(3, name);
                    ps.setInt(4, current.revision());
                    if (ps.executeUpdate() == 0) {
                        c.rollback();
                        throw new ConflictException("The policy changed while it was being written. Read it again and retry.");
                    }
                }
                c.commit();
            } catch (final SQLException | RuntimeException e) {
                c.rollback();
                throw e;
            }
        } catch (final SQLException e) {
            throw new StorageException("Unable to replace the policy.", e);
        }
        return find(name);
    }

    /** @return Whether a policy was deleted. */
    public boolean delete(final String name) {
        try (Connection c = database.connect();
             PreparedStatement ps = c.prepareStatement("DELETE FROM policies WHERE name = ?")) {
            ps.setString(1, name);
            return ps.executeUpdate() > 0;
        } catch (final SQLException e) {
            throw new StorageException("Unable to delete the policy.", e);
        }
    }

    private StoredPolicy findIn(final Connection c, final String name) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("SELECT * FROM policies WHERE name = ?")) {
            ps.setString(1, name);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? read(rs) : null;
            }
        }
    }

    private StoredPolicy read(final ResultSet rs) throws SQLException {
        final String stored = rs.getString("policy");
        return new StoredPolicy(rs.getString("name"), isPlaintext(stored) ? stored : encryptor.decrypt(stored), rs.getInt("revision"),
                rs.getString("description"), rs.getString("notes"),
                Instant.parse(rs.getString("created_at")), Instant.parse(rs.getString("updated_at")));
    }

    static String sha256Hex(final String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}
