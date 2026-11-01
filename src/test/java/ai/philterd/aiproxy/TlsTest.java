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
package ai.philterd.aiproxy;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** HTTPS with the development certificate, and mutual TLS configured through Spring Boot's server.ssl settings. */
class TlsTest {

    static Path dataDirectory(final String name) {
        try {
            return Files.createTempDirectory(name);
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static void common(final DynamicPropertyRegistry registry, final Path data) {
        registry.add("proxy.storage.sqlite-path", () -> data.resolve("proxy.db").toString());
        registry.add("proxy.security.encryption-key", () -> "1111111111111111111111111111111111111111111111111111111111111111");
        registry.add("proxy.models.directory", () -> data.resolve("models").toString());
        registry.add("management.server.port", () -> "0");
        for (final String p : new String[]{"openai", "anthropic", "gemini", "ollama"}) {
            registry.add("proxy.providers." + p + ".target", () -> "http://127.0.0.1:9");
        }
    }

    static HttpResponse<String> get(final SSLContext context, final String url) throws Exception {
        final SSLParameters parameters = new SSLParameters();
        parameters.setProtocols(new String[]{"TLSv1.3"});
        return HttpClient.newBuilder().sslContext(context).sslParameters(parameters).build()
                .send(HttpRequest.newBuilder(URI.create(url)).build(), HttpResponse.BodyHandlers.ofString());
    }

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "proxy.tls.dev-self-signed-cert=true")
    class DevelopmentCertificate {

        static final Path DATA = dataDirectory("philter-ai-proxy-dev-tls-test");

        @DynamicPropertySource
        static void properties(final DynamicPropertyRegistry registry) {
            common(registry, DATA);
        }

        @LocalServerPort
        int port;

        @Test
        void servesHttpsWithAnUntrustedCertificate() throws Exception {
            assertEquals(200, get(TestCerts.trustingAnything(), "https://localhost:" + port + "/livez").statusCode());
            // The certificate is self-signed, so a client that verifies certificates refuses it.
            assertThrows(IOException.class, () -> get(SSLContext.getDefault(), "https://localhost:" + port + "/livez"));
            // Plain HTTP on the HTTPS port is answered with 400, not served.
            assertEquals(400, HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/livez")).build(), HttpResponse.BodyHandlers.ofString()).statusCode());
        }
    }

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
    class MutualTls {

        static final Path DATA = dataDirectory("philter-ai-proxy-mtls-test");
        static final Path SERVER = TestCerts.keyPair(DATA, "server", "dns:localhost,ip:127.0.0.1");
        static final Path CLIENT = TestCerts.keyPair(DATA, "client", "dns:client");
        static final Path STRANGER = TestCerts.keyPair(DATA, "stranger", "dns:stranger");
        static final Path SERVER_TRUSTS = TestCerts.trusting(DATA, CLIENT, "client", "server-trust");
        static final Path CLIENT_TRUSTS = TestCerts.trusting(DATA, SERVER, "server", "client-trust");

        @DynamicPropertySource
        static void properties(final DynamicPropertyRegistry registry) {
            common(registry, DATA);
            registry.add("server.ssl.key-store", SERVER::toString);
            registry.add("server.ssl.key-store-type", () -> "PKCS12");
            registry.add("server.ssl.key-store-password", () -> TestCerts.PASSWORD);
            registry.add("server.ssl.trust-store", SERVER_TRUSTS::toString);
            registry.add("server.ssl.trust-store-type", () -> "PKCS12");
            registry.add("server.ssl.trust-store-password", () -> TestCerts.PASSWORD);
            registry.add("server.ssl.client-auth", () -> "need");
            registry.add("server.ssl.enabled-protocols", () -> "TLSv1.3,TLSv1.2");
            // As the Docker image sets it: configured key material takes precedence over the development certificate.
            registry.add("proxy.tls.dev-self-signed-cert", () -> "true");
        }

        @LocalServerPort
        int port;

        @Test
        void requiresATrustedClientCertificate() throws Exception {
            final String url = "https://localhost:" + port + "/livez";
            assertEquals(200, get(TestCerts.client(CLIENT, CLIENT_TRUSTS), url).statusCode());
            assertThrows(IOException.class, () -> get(TestCerts.client(null, CLIENT_TRUSTS), url));
            assertThrows(IOException.class, () -> get(TestCerts.client(STRANGER, CLIENT_TRUSTS), url));
        }
    }

}
