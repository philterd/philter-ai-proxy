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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

/**
 * The proxy's SQLite database: policies, contexts, API keys, and the audit log. One proxy instance uses a file;
 * a second instance on the same file is refused at startup.
 */
@Component
public class Database implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(Database.class);

    /** Each entry upgrades the schema by one version. Never edit an entry once released; append a new one. */
    private static final List<String> MIGRATIONS = List.of(
            """
            CREATE TABLE policies (
                name TEXT PRIMARY KEY,
                policy TEXT NOT NULL,
                revision INTEGER NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE api_keys (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                scopes TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE context_entries (
                context TEXT NOT NULL,
                token_index TEXT NOT NULL,
                token TEXT NOT NULL,
                replacement TEXT NOT NULL,
                replacement_index TEXT NOT NULL,
                filter_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (context, token_index)
            );
            CREATE INDEX context_entries_replacement ON context_entries (context, replacement_index);
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                request_id TEXT NOT NULL,
                event TEXT NOT NULL,
                details TEXT NOT NULL
            );
            CREATE INDEX audit_log_timestamp ON audit_log (timestamp);
            """,
            """
            CREATE TABLE settings (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
    );

    private final String url;
    private final FileChannel lockChannel;
    private final FileLock lock;

    public Database(final ProxyProperties properties) throws IOException, SQLException {
        final Path path = Path.of(properties.storage().sqlitePath()).toAbsolutePath();
        Files.createDirectories(path.getParent());
        createOwnerOnly(path);
        this.url = "jdbc:sqlite:" + path;

        // A second proxy on the same file would corrupt contexts and the audit log under load, so refuse it.
        final Path lockPath = Path.of(path + ".lock");
        createOwnerOnly(lockPath);
        this.lockChannel = FileChannel.open(lockPath, StandardOpenOption.WRITE);
        FileLock acquired;
        try {
            acquired = lockChannel.tryLock();
        } catch (final OverlappingFileLockException e) {
            acquired = null;
        }
        if (acquired == null) {
            lockChannel.close();
            throw new IllegalStateException("Another Philter AI Proxy is using " + path + ". Each instance needs its own database file.");
        }
        this.lock = acquired;

        try (Connection connection = connect()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("PRAGMA journal_mode=WAL");
            }
            migrate(connection);
        }
        LOGGER.info("Using the SQLite database at {}", path);
    }

    /** A new connection. SQLite connections are cheap; close it when done. */
    public Connection connect() throws SQLException {
        final Connection connection = DriverManager.getConnection(url);
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA busy_timeout=5000");
            statement.execute("PRAGMA foreign_keys=ON");
        }
        return connection;
    }

    private static void migrate(final Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)");
        }
        int version = 0;
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("SELECT MAX(version) FROM schema_version")) {
            if (rs.next()) {
                version = rs.getInt(1);
            }
        }
        if (version > MIGRATIONS.size()) {
            throw new IllegalStateException("The database was written by a newer Philter AI Proxy (schema version "
                    + version + "); this version supports up to " + MIGRATIONS.size() + ".");
        }
        for (int i = version; i < MIGRATIONS.size(); i++) {
            connection.setAutoCommit(false);
            try {
                for (final String sql : MIGRATIONS.get(i).split(";")) {
                    if (!sql.isBlank()) {
                        try (Statement statement = connection.createStatement()) {
                            statement.execute(sql);
                        }
                    }
                }
                try (Statement statement = connection.createStatement()) {
                    statement.execute("INSERT INTO schema_version (version) VALUES (" + (i + 1) + ")");
                }
                connection.commit();
            } catch (final SQLException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(true);
            }
            LOGGER.info("Upgraded the database schema to version {}", i + 1);
        }
    }

    /** Creates the file readable only by its owner, where the file system supports POSIX permissions. */
    private static void createOwnerOnly(final Path path) throws IOException {
        if (Files.exists(path)) {
            return;
        }
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } else {
            Files.createFile(path);
        }
    }

    @Override
    public void close() throws IOException {
        lock.release();
        lockChannel.close();
    }

}
