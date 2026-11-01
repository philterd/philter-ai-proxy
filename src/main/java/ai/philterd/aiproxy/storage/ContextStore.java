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

import ai.philterd.phileas.services.context.ContextService;
import org.springframework.stereotype.Component;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.function.Supplier;

/**
 * Contexts: the replacement chosen for each original value, so the same value is replaced the same way across
 * requests (consistent pseudonymization). Original values are stored encrypted; lookups use a keyed hash.
 */
@Component
public class ContextStore {

    private final Database database;
    private final Encryptor encryptor;

    public ContextStore(final Database database, final Encryptor encryptor) {
        this.database = database;
        this.encryptor = encryptor;
    }

    /** A Phileas context service backed by the named context. */
    public ContextService forContext(final String context) {
        return new StoredContextService(context);
    }

    private final class StoredContextService implements ContextService {

        private final String context;

        private StoredContextService(final String context) {
            this.context = context;
        }

        @Override
        public boolean containsToken(final String token) {
            return getReplacement(token) != null;
        }

        @Override
        public boolean containsReplacement(final String replacement) {
            try (Connection c = database.connect();
                 PreparedStatement ps = c.prepareStatement(
                         "SELECT 1 FROM context_entries WHERE context = ? AND replacement_index = ?")) {
                ps.setString(1, context);
                ps.setString(2, encryptor.index(replacement));
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next();
                }
            } catch (final SQLException e) {
                throw new StorageException("Unable to read the context.", e);
            }
        }

        @Override
        public String getReplacement(final String token) {
            try (Connection c = database.connect();
                 PreparedStatement ps = c.prepareStatement(
                         "SELECT replacement FROM context_entries WHERE context = ? AND token_index = ?")) {
                ps.setString(1, context);
                ps.setString(2, encryptor.index(token));
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? encryptor.decrypt(rs.getString(1)) : null;
                }
            } catch (final SQLException e) {
                throw new StorageException("Unable to read the context.", e);
            }
        }

        @Override
        public void putReplacement(final String token, final String replacement, final String filterType) {
            insert(token, replacement, filterType, true);
        }

        @Override
        public String computeReplacementIfAbsent(final String token, final String filterType,
                                                 final Supplier<String> replacementSupplier) {
            final String existing = getReplacement(token);
            if (existing != null) {
                return existing;
            }
            final String candidate = replacementSupplier.get();
            if (candidate == null) {
                return null;
            }
            // Insert-if-absent, then read back, so two requests racing on the same value agree on one replacement.
            insert(token, candidate, filterType, false);
            final String stored = getReplacement(token);
            return stored == null ? candidate : stored;
        }

        private void insert(final String token, final String replacement, final String filterType, final boolean overwrite) {
            final String sql = "INSERT INTO context_entries (context, token_index, token, replacement, replacement_index, "
                    + "filter_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (context, token_index) "
                    + (overwrite ? "DO UPDATE SET token = excluded.token, replacement = excluded.replacement, "
                    + "replacement_index = excluded.replacement_index, filter_type = excluded.filter_type" : "DO NOTHING");
            try (Connection c = database.connect(); PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setString(1, context);
                ps.setString(2, encryptor.index(token));
                ps.setString(3, encryptor.encrypt(token));
                // The replacement can itself be a recognizable value (a fake name, a format-preserving number).
                ps.setString(4, encryptor.encrypt(replacement));
                ps.setString(5, encryptor.index(replacement));
                ps.setString(6, filterType == null ? "" : filterType);
                ps.setString(7, Instant.now().toString());
                ps.executeUpdate();
            } catch (final SQLException e) {
                throw new StorageException("Unable to write the context.", e);
            }
        }

    }

}
