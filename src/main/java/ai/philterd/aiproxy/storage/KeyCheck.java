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

import org.springframework.stereotype.Component;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Refuses to start with an encryption key other than the one the database was written with, rather than failing
 * later when a context's stored values cannot be decrypted. The first start stores a value encrypted with the key;
 * each later start decrypts it.
 */
@Component
public class KeyCheck {

    private static final String NAME = "encryption_key_check";
    private static final String VALUE = "philter-ai-proxy";

    public KeyCheck(final Database database, final Encryptor encryptor) {
        try (Connection c = database.connect()) {
            String stored = null;
            try (PreparedStatement ps = c.prepareStatement("SELECT value FROM settings WHERE name = ?")) {
                ps.setString(1, NAME);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        stored = rs.getString(1);
                    }
                }
            }
            if (stored == null) {
                try (PreparedStatement ps = c.prepareStatement("INSERT INTO settings (name, value) VALUES (?, ?)")) {
                    ps.setString(1, NAME);
                    ps.setString(2, encryptor.encrypt(VALUE));
                    ps.executeUpdate();
                }
                return;
            }
            final String decrypted;
            try {
                decrypted = encryptor.decrypt(stored);
            } catch (final IllegalStateException e) {
                throw mismatch();
            }
            if (!VALUE.equals(decrypted)) {
                throw mismatch();
            }
        } catch (final SQLException e) {
            throw new StorageException("Unable to check the encryption key.", e);
        }
    }

    private static IllegalStateException mismatch() {
        return new IllegalStateException("proxy.security.encryption-key is not the key this database was created with. "
                + "Use the original key; the values the database holds cannot be read without it.");
    }

}
