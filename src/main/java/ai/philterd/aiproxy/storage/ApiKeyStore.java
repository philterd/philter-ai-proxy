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

import ai.philterd.aiproxy.security.ApiKey;
import ai.philterd.aiproxy.security.KeyScopes;
import com.google.gson.Gson;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * API keys. Only a SHA-256 hash of each key is stored: keys are 32 random bytes, so a fast hash is enough, and
 * the key itself is shown once, when it is created.
 */
@Component
public class ApiKeyStore {

    /** The prefix of every generated key, so a leaked key is recognizable to secret scanners. */
    public static final String KEY_PREFIX = "pap_";

    private static final Gson GSON = new Gson();

    private final Database database;
    private final SecureRandom random = new SecureRandom();

    public ApiKeyStore(final Database database) {
        this.database = database;
    }

    /** A newly created key and the only copy of its secret. */
    public record CreatedKey(ApiKey key, String secret) {
    }

    public CreatedKey create(final String name, final KeyScopes scopes) {
        final byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        final String secret = KEY_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        return new CreatedKey(insert(name, secret, scopes), secret);
    }

    /** Stores a key whose secret was chosen elsewhere, such as the bootstrap key. */
    public ApiKey insert(final String name, final String secret, final KeyScopes scopes) {
        final ApiKey key = new ApiKey(UUID.randomUUID().toString(), name, scopes, Instant.now());
        try (Connection c = database.connect();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO api_keys (id, name, key_hash, scopes, created_at) VALUES (?, ?, ?, ?, ?)")) {
            ps.setString(1, key.id());
            ps.setString(2, name);
            ps.setString(3, hash(secret));
            ps.setString(4, GSON.toJson(scopes));
            ps.setString(5, key.createdAt().toString());
            ps.executeUpdate();
        } catch (final SQLException e) {
            throw new StorageException("Unable to store the API key.", e);
        }
        return key;
    }

    public Optional<ApiKey> findBySecret(final String secret) {
        return findOne("SELECT * FROM api_keys WHERE key_hash = ?", hash(secret));
    }

    public Optional<ApiKey> findById(final String id) {
        return findOne("SELECT * FROM api_keys WHERE id = ?", id);
    }

    public List<ApiKey> list() {
        final List<ApiKey> keys = new ArrayList<>();
        try (Connection c = database.connect();
             PreparedStatement ps = c.prepareStatement("SELECT * FROM api_keys ORDER BY created_at");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                keys.add(read(rs));
            }
        } catch (final SQLException e) {
            throw new StorageException("Unable to list the API keys.", e);
        }
        return keys;
    }

    public long count() {
        try (Connection c = database.connect();
             PreparedStatement ps = c.prepareStatement("SELECT COUNT(*) FROM api_keys");
             ResultSet rs = ps.executeQuery()) {
            return rs.next() ? rs.getLong(1) : 0;
        } catch (final SQLException e) {
            throw new StorageException("Unable to count the API keys.", e);
        }
    }

    /** @return Whether a key was deleted. */
    public boolean delete(final String id) {
        try (Connection c = database.connect();
             PreparedStatement ps = c.prepareStatement("DELETE FROM api_keys WHERE id = ?")) {
            ps.setString(1, id);
            return ps.executeUpdate() > 0;
        } catch (final SQLException e) {
            throw new StorageException("Unable to delete the API key.", e);
        }
    }

    private Optional<ApiKey> findOne(final String sql, final String value) {
        try (Connection c = database.connect(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, value);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(read(rs)) : Optional.empty();
            }
        } catch (final SQLException e) {
            throw new StorageException("Unable to read the API key.", e);
        }
    }

    private static ApiKey read(final ResultSet rs) throws SQLException {
        return new ApiKey(rs.getString("id"), rs.getString("name"),
                GSON.fromJson(rs.getString("scopes"), KeyScopes.class).normalized(),
                Instant.parse(rs.getString("created_at")));
    }

    static String hash(final String secret) {
        return PolicyStore.sha256Hex(secret);
    }

}
