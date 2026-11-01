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
package ai.philterd.aiproxy.proxy;

import ai.philterd.aiproxy.config.ProxyProperties;
import jakarta.servlet.http.HttpServletRequest;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Sends redacted requests to one provider. Redirects are not followed. */
public final class UpstreamClient {

    /**
     * Request headers never forwarded: hop-by-hop headers, headers the HTTP client sets itself, and
     * {@code Accept-Encoding}, so the provider answers uncompressed and the response can be scanned.
     */
    private static final Set<String> NOT_FORWARDED = Set.of("host", "connection", "content-length", "expect", "upgrade",
            "keep-alive", "proxy-authorization", "proxy-authenticate", "proxy-connection", "te", "trailer",
            "transfer-encoding", "accept-encoding", "http2-settings", "x-request-id", "x-forwarded-for",
            "x-forwarded-host", "x-forwarded-proto", "forwarded");

    /** Response headers not copied to the client. */
    public static final Set<String> NOT_RETURNED = Set.of("connection", "keep-alive", "proxy-authenticate",
            "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "content-length", "content-encoding");

    /** Adds the provider's own authentication to a request, after the client's headers. */
    @FunctionalInterface
    public interface Authentication {
        /**
         * @param headers The headers the request will carry, which may be changed.
         */
        void apply(String method, URI uri, Map<String, List<String>> headers, byte[] body) throws IOException;
    }

    /** The proxy could not get or apply the provider's credentials. */
    public static final class AuthenticationException extends IOException {
        AuthenticationException(final Exception cause) {
            super(cause.getMessage(), cause);
        }
    }

    private final String name;
    private final String target;
    private final HttpClient client;
    private final ProxyProperties.Provider provider;
    private final String proxyKeyHeader;
    private final boolean forwardClientHeaders;
    private final Authentication authentication;

    /**
     * @param target               The base URL requests are sent to.
     * @param forwardClientHeaders Whether the client's headers are forwarded; when not, only {@code Content-Type}
     *                             and the provider's authentication are sent.
     * @param authentication       The provider's own authentication, or null to pass the client's through.
     */
    public UpstreamClient(final String name, final String target, final ProxyProperties.Provider provider,
                          final String proxyKeyHeader, final boolean forwardClientHeaders, final Authentication authentication) {
        this.name = name;
        this.target = target;
        this.provider = provider;
        this.proxyKeyHeader = proxyKeyHeader.toLowerCase(Locale.ROOT);
        this.forwardClientHeaders = forwardClientHeaders;
        this.authentication = authentication;
        final HttpClient.Builder builder = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofMillis(provider.connectTimeoutMs()));
        if (provider.caCert() != null) {
            builder.sslContext(trusting(Path.of(provider.caCert()), name));
        }
        this.client = builder.build();
    }

    public String name() {
        return name;
    }

    public String target() {
        return target;
    }

    /** Trusts only the certificate authorities in the PEM file. */
    static SSLContext trusting(final Path pem, final String provider) {
        try (InputStream in = Files.newInputStream(pem)) {
            final KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            int i = 0;
            for (final Certificate certificate : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                store.setCertificateEntry("ca-" + i++, certificate);
            }
            if (i == 0) {
                throw new IllegalStateException("The caCert for provider " + provider + " holds no certificate: " + pem);
            }
            final TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
            final SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trust.getTrustManagers(), null);
            return context;
        } catch (final IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Unable to read the caCert for provider " + provider + " (" + pem + "): " + e.getMessage(), e);
        }
    }

    /** Sends the body to the provider at the path and the request's query, with the request's forwardable headers. */
    public HttpResponse<InputStream> send(final HttpServletRequest request, final String path, final byte[] body)
            throws IOException, InterruptedException {
        String query = request.getQueryString();
        if (provider.apiVersion() != null && (query == null || !query.matches("(^|.*&)api-version=.*"))) {
            final String version = "api-version=" + URLEncoder.encode(provider.apiVersion(), StandardCharsets.UTF_8);
            query = query == null || query.isEmpty() ? version : query + "&" + version;
        }
        final URI uri = URI.create(target + path + (query == null || query.isEmpty() ? "" : "?" + query));
        final Map<String, List<String>> headers = new LinkedHashMap<>();
        if (forwardClientHeaders) {
            for (final String header : Collections.list(request.getHeaderNames())) {
                if (forwardable(header)) {
                    headers.put(header, Collections.list(request.getHeaders(header)));
                }
            }
        } else {
            headers.put("Content-Type", List.of("application/json"));
        }
        if (authentication != null) {
            try {
                authentication.apply(request.getMethod(), uri, headers, body);
            } catch (final IOException | RuntimeException e) {
                throw new AuthenticationException(e);
            }
        }
        final boolean hasBody = body.length > 0 || !(request.getMethod().equals("GET") || request.getMethod().equals("DELETE")
                || request.getMethod().equals("HEAD"));
        final HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofMillis(provider.responseTimeoutMs()))
                .method(request.getMethod(), hasBody ? HttpRequest.BodyPublishers.ofByteArray(body) : HttpRequest.BodyPublishers.noBody());
        headers.forEach((header, values) -> {
            if (forwardable(header)) {
                values.forEach(value -> builder.header(header, value));
            }
        });
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
    }

    boolean forwardable(final String header) {
        final String lower = header.toLowerCase(Locale.ROOT);
        return !NOT_FORWARDED.contains(lower) && !lower.equals(proxyKeyHeader) && !lower.startsWith("x-philter-");
    }

}
