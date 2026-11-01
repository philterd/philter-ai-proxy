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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The audit log. Entries carry metadata only (request ID, provider, model, policy, counts of what was redacted,
 * status), never the text of a prompt or response. Each entry is stored and also written to the
 * {@code philter-ai-proxy.audit} logger as one JSON line, and to {@code proxy.audit.file} when it is set.
 */
@Component
public class AuditStore {

    private static final Logger AUDIT_LOG = LoggerFactory.getLogger("philter-ai-proxy.audit");
    private static final Logger LOGGER = LoggerFactory.getLogger(AuditStore.class);
    private static final Gson GSON = new Gson();

    private final Database database;
    private final java.io.Writer file;

    public AuditStore(final Database database, final ai.philterd.aiproxy.config.ProxyProperties properties) throws java.io.IOException {
        this.database = database;
        final String path = properties.audit().file();
        if (path == null) {
            this.file = null;
        } else {
            final java.nio.file.Path p = java.nio.file.Path.of(path).toAbsolutePath();
            if (p.getParent() != null) {
                java.nio.file.Files.createDirectories(p.getParent());
            }
            if (!java.nio.file.Files.exists(p) && java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                java.nio.file.Files.createFile(p, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
            }
            this.file = java.nio.file.Files.newBufferedWriter(p, java.nio.charset.StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            LOGGER.info("Writing the audit log to {}", p);
        }
    }

    public record Entry(long id, Instant timestamp, String requestId, String event, JsonObject details) {
    }

    /**
     * Records an event. A failure to store it is logged, not thrown, so it cannot fail the request; the JSON line
     * is still written.
     */
    public void record(final String requestId, final String event, final Map<String, Object> details) {
        final Instant now = Instant.now();
        final JsonObject json = GSON.toJsonTree(details).getAsJsonObject();
        final JsonObject line = new JsonObject();
        line.addProperty("timestamp", now.toString());
        line.addProperty("request_id", requestId);
        line.addProperty("event", event);
        json.entrySet().forEach(e -> line.add(e.getKey(), e.getValue()));
        AUDIT_LOG.info(line.toString());
        if (file != null) {
            synchronized (file) {
                try {
                    file.write(line.toString());
                    file.write('\n');
                    file.flush();
                } catch (final java.io.IOException e) {
                    LOGGER.error("Unable to write an audit entry for request {} to the audit file", requestId, e);
                }
            }
        }
        try (Connection c = database.connect();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO audit_log (timestamp, request_id, event, details) VALUES (?, ?, ?, ?)")) {
            ps.setString(1, now.toString());
            ps.setString(2, requestId);
            ps.setString(3, event);
            ps.setString(4, json.toString());
            ps.executeUpdate();
        } catch (final SQLException e) {
            LOGGER.error("Unable to store an audit entry for request {}", requestId, e);
        }
    }

    /** The most recent entries, newest first. */
    public List<Entry> recent(final int limit) {
        final List<Entry> entries = new ArrayList<>();
        try (Connection c = database.connect();
             PreparedStatement ps = c.prepareStatement("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?")) {
            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    entries.add(new Entry(rs.getLong("id"), Instant.parse(rs.getString("timestamp")),
                            rs.getString("request_id"), rs.getString("event"),
                            JsonParser.parseString(rs.getString("details")).getAsJsonObject()));
                }
            }
        } catch (final SQLException e) {
            throw new StorageException("Unable to read the audit log.", e);
        }
        return entries;
    }

}
