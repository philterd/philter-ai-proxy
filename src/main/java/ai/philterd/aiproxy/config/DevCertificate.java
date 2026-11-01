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
package ai.philterd.aiproxy.config;

import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * When {@code proxy.tls.dev-self-signed-cert} is true and no {@code server.ssl} key material is configured, serves
 * HTTPS with a self-signed certificate generated at startup. The Docker image turns it on, so the proxy is
 * encrypted out of the box; configured key material takes precedence. The keystore is written to a
 * temporary directory readable only by the proxy's user and deleted when the proxy exits. No client trusts the
 * certificate, so it encrypts the connection without proving the proxy's identity.
 */
public class DevCertificate implements EnvironmentPostProcessor {

    @Override
    public void postProcessEnvironment(final ConfigurableEnvironment environment, final SpringApplication application) {
        if (!environment.getProperty("proxy.tls.dev-self-signed-cert", Boolean.class, false)) {
            return;
        }
        if (environment.containsProperty("server.ssl.key-store") || environment.containsProperty("server.ssl.certificate")
                || environment.containsProperty("server.ssl.bundle")) {
            // Real key material wins, so the image's default does not get in the way of configuring it.
            return;
        }
        try {
            final Path directory = Files.createTempDirectory("philter-ai-proxy-tls",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            final Path keystore = directory.resolve("dev.p12");
            final byte[] secret = new byte[24];
            new SecureRandom().nextBytes(secret);
            final String password = HexFormat.of().formatHex(secret);
            final Path keytool = Path.of(System.getProperty("java.home"), "bin", "keytool");
            final Process process = new ProcessBuilder(keytool.toString(), "-genkeypair", "-alias", "philter-ai-proxy",
                    "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "30", "-dname", "CN=localhost",
                    "-ext", "SAN=dns:localhost,ip:127.0.0.1,ip:::1", "-storetype", "PKCS12",
                    "-keystore", keystore.toString(), "-storepass", password, "-keypass", password)
                    .redirectErrorStream(true).start();
            final String output = new String(process.getInputStream().readAllBytes());
            if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
                throw new IllegalStateException("Unable to generate the development certificate: " + output);
            }
            keystore.toFile().deleteOnExit();
            directory.toFile().deleteOnExit();
            environment.getPropertySources().addFirst(new MapPropertySource("philter-ai-proxy-dev-certificate", Map.of(
                    "server.ssl.enabled", "true",
                    "server.ssl.key-store", keystore.toString(),
                    "server.ssl.key-store-type", "PKCS12",
                    "server.ssl.key-store-password", password,
                    "server.ssl.key-alias", "philter-ai-proxy",
                    "server.ssl.enabled-protocols", List.of("TLSv1.3", "TLSv1.2"))));
            System.err.println("WARNING: serving HTTPS with a self-signed development certificate "
                    + "(proxy.tls.dev-self-signed-cert). Configure server.ssl for real use.");
        } catch (final IOException e) {
            throw new IllegalStateException("Unable to generate the development certificate: " + e.getMessage(), e);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while generating the development certificate.", e);
        }
    }

}
