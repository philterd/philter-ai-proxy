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
package ai.philterd.aiproxy.admin;

import ai.philterd.aiproxy.Warmup;
import ai.philterd.aiproxy.storage.Database;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Unauthenticated probes. {@code /livez} answers while the process runs. {@code /readyz} answers 200 once the
 * configured policies are loaded and while the database is usable. {@code /health} serves the standard Philterd
 * health response, reporting the database.
 */
@RestController
public class HealthController {

    private final Database database;
    private final Warmup warmup;
    private final String version;

    public HealthController(final Database database, final Warmup warmup, final ObjectProvider<BuildProperties> build) {
        this.database = database;
        this.warmup = warmup;
        final BuildProperties properties = build.getIfAvailable();
        this.version = properties == null ? "unknown" : properties.getVersion();
    }

    @GetMapping(path = "/livez", produces = MediaType.APPLICATION_JSON_VALUE)
    public String livez() {
        return "{\"status\":\"ok\"}";
    }

    @GetMapping(path = "/readyz", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> readyz() {
        return warmup.isDone() && databaseUsable()
                ? ResponseEntity.ok("{\"status\":\"ok\"}")
                : ResponseEntity.status(503).body("{\"status\":\"unavailable\"}");
    }

    @GetMapping(path = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> health() {
        final String status = databaseUsable() ? "UP" : "DOWN";
        return ResponseEntity.status("UP".equals(status) ? 200 : 503)
                .body("{\"status\":\"" + status + "\",\"applicationVersion\":\"" + version + "\"}");
    }

    private boolean databaseUsable() {
        try (Connection c = database.connect(); Statement s = c.createStatement()) {
            s.execute("SELECT 1");
            return true;
        } catch (final SQLException e) {
            return false;
        }
    }

}
