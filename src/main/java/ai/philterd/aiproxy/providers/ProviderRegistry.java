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
package ai.philterd.aiproxy.providers;

import ai.philterd.aiproxy.config.ProxyProperties;
import ai.philterd.aiproxy.proxy.ProxyError;
import ai.philterd.aiproxy.proxy.UpstreamClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * The configured providers, and which one a request path goes to. Paths are resolved in the order earlier versions
 * used: an OpenAI-compatible prefix ({@code /<name>/...}), Anthropic ({@code /v1/messages}), Vertex AI
 * ({@code /v1/projects/...:generateContent}), Gemini (any other {@code generateContent} path, or {@code /v1beta/}),
 * Ollama ({@code /api/generate}, {@code /api/chat}), Azure OpenAI ({@code /openai/deployments/}), Bedrock
 * ({@code /model/<id>/converse}), and otherwise OpenAI.
 */
@Component
public class ProviderRegistry {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProviderRegistry.class);

    /** A name an OpenAI-compatible provider can have, so it is safe as a path segment. */
    static final Pattern COMPATIBLE_NAME = Pattern.compile("[a-z0-9][a-z0-9_-]{0,62}");

    /** A provider a request is sent to. */
    public record Upstream(String name, ProviderDialect dialect, UpstreamClient client) {
    }

    /**
     * Where a request goes.
     * @param path The path to send to the provider, without an OpenAI-compatible prefix.
     */
    public record Route(Upstream upstream, String path) {
    }

    private final Upstream openai;
    private final Upstream anthropic;
    private final Upstream gemini;
    private final Upstream ollama;
    private final Upstream azure;
    private final Upstream vertex;
    private final Upstream bedrock;
    private final Map<String, Upstream> compatible = new TreeMap<>();

    public ProviderRegistry(final ProxyProperties properties, final CloudCredentials credentials) {
        final ProxyProperties.Providers p = properties.providers();
        final String header = properties.security().proxyKeyHeader();
        this.openai = simple("openai", p.openai(), new OpenAiDialect(), header);
        this.anthropic = simple("anthropic", p.anthropic(), new AnthropicDialect(), header);
        this.gemini = simple("gemini", p.gemini(), new GeminiDialect(), header);
        this.ollama = simple("ollama", p.ollama(), new OllamaDialect(), header);

        final ProxyProperties.Provider az = p.azure();
        this.azure = az.target() == null || az.isDisabled() ? null : new Upstream("azure", new OpenAiDialect(),
                new UpstreamClient("azure", az.target(), az, header, true, az.entraId() ? (method, uri, headers, body) -> {
                    headers.keySet().removeIf(h -> h.equalsIgnoreCase("authorization") || h.equalsIgnoreCase("api-key"));
                    headers.put("Authorization", List.of("Bearer " + credentials.azureAccessToken()));
                } : null));

        final ProxyProperties.Provider vx = p.vertex();
        if (vx.project() == null || vx.isDisabled()) {
            this.vertex = null;
        } else {
            final String target = vx.target() != null ? vx.target() : vx.location() == null ? null
                    : "https://" + vx.location() + "-aiplatform.googleapis.com";
            if (target == null) {
                throw new IllegalStateException("Vertex AI needs proxy.providers.vertex.location or target.");
            }
            this.vertex = new Upstream("vertex", new GeminiDialect(), new UpstreamClient("vertex", target, vx, header, true,
                    (method, uri, headers, body) -> {
                        headers.keySet().removeIf(h -> h.equalsIgnoreCase("authorization"));
                        headers.put("Authorization", List.of("Bearer " + credentials.googleAccessToken()));
                    }));
        }

        final ProxyProperties.Provider br = p.bedrock();
        if (br.region() == null || br.isDisabled()) {
            this.bedrock = null;
        } else {
            final String target = br.target() != null ? br.target() : "https://bedrock-runtime." + br.region() + ".amazonaws.com";
            final AwsV4HttpSigner signer = AwsV4HttpSigner.create();
            this.bedrock = new Upstream("bedrock", new BedrockDialect(), new UpstreamClient("bedrock", target, br, header, false,
                    (method, uri, headers, body) -> {
                        final SdkHttpRequest.Builder unsigned = SdkHttpRequest.builder().method(SdkHttpMethod.fromValue(method)).uri(uri);
                        headers.forEach(unsigned::putHeader);
                        final SignedRequest signed = signer.sign(r -> r
                                .identity(awsCredentials(credentials, br))
                                .request(unsigned.build())
                                .payload(ContentStreamProvider.fromByteArray(body))
                                // Bedrock Runtime signs as "bedrock", not by its host name.
                                .putProperty(AwsV4HttpSigner.SERVICE_SIGNING_NAME, "bedrock")
                                .putProperty(AwsV4HttpSigner.REGION_NAME, br.region()));
                        headers.clear();
                        headers.putAll(signed.request().headers());
                    }));
        }

        for (final Map.Entry<String, ProxyProperties.Provider> entry : p.openaiCompatible().entrySet()) {
            final String name = entry.getKey().toLowerCase(Locale.ROOT);
            if (!COMPATIBLE_NAME.matcher(name).matches() || List.of("v1", "v1beta", "api", "openai", "model", "admin").contains(name)) {
                throw new IllegalStateException("The OpenAI-compatible provider name '" + entry.getKey() + "' is not allowed: use "
                        + "lowercase letters, digits, - and _, and not a name the proxy's own paths use.");
            }
            if (entry.getValue().target() == null) {
                throw new IllegalStateException("The OpenAI-compatible provider '" + name + "' needs a target.");
            }
            compatible.put(name, simple(name, entry.getValue(), new OpenAiDialect(), header));
        }
        LOGGER.info("Providers: openai={}, anthropic={}, gemini={}, ollama={}, azure={}, vertex={}, bedrock={}, openai-compatible={}",
                target(openai), target(anthropic), target(gemini), target(ollama), target(azure), target(vertex), target(bedrock),
                compatible.keySet());
    }

    private static software.amazon.awssdk.identity.spi.AwsCredentialsIdentity awsCredentials(final CloudCredentials credentials,
                                                                                         final ProxyProperties.Provider br) {
        try {
            return credentials.awsCredentials(br.region(), br.roleArn());
        } catch (final IOException e) {
            throw new UncheckedProviderAuthException(e);
        }
    }

    /** Wraps a credential failure inside the signer callback, unwrapped by the caller. */
    public static final class UncheckedProviderAuthException extends RuntimeException {
        UncheckedProviderAuthException(final IOException cause) {
            super(cause.getMessage(), cause);
        }
    }

    private static Upstream simple(final String name, final ProxyProperties.Provider provider, final ProviderDialect dialect,
                                   final String header) {
        return provider.target() == null || provider.isDisabled() ? null
                : new Upstream(name, dialect, new UpstreamClient(name, provider.target(), provider, header, true, null));
    }

    private static String target(final Upstream upstream) {
        return upstream == null ? "off" : upstream.client().target();
    }

    /**
     * The provider for the path.
     * @throws ProxyError 404 when the path's provider is not configured.
     */
    public Route resolve(final String path) throws ProxyError {
        final int second = path.indexOf('/', 1);
        if (second > 1) {
            final Upstream named = compatible.get(path.substring(1, second));
            if (named != null) {
                return new Route(named, path.substring(second));
            }
        }
        final String lower = path.toLowerCase(Locale.ROOT);
        if (path.startsWith("/v1/messages")) {
            return route(anthropic, "anthropic", path);
        }
        if (path.startsWith("/v1/projects/") && (lower.contains(":generatecontent") || lower.contains(":streamgeneratecontent"))) {
            return route(vertex, "vertex", path);
        }
        if (lower.contains("generatecontent") || path.startsWith("/v1beta/")) {
            return route(gemini, "gemini", path);
        }
        if (path.equals("/api/generate") || path.equals("/api/chat")) {
            return route(ollama, "ollama", path);
        }
        if (path.startsWith("/openai/deployments/")) {
            return route(azure, "azure", path);
        }
        if (BedrockDialect.isConversePath(path)) {
            return route(bedrock, "bedrock", path);
        }
        return route(openai, "openai", path);
    }

    private static Route route(final Upstream upstream, final String name, final String path) throws ProxyError {
        if (upstream == null) {
            throw new ProxyError(404, "not_found", name + "_disabled", name + " provider not configured");
        }
        return new Route(upstream, path);
    }

    /** The provider name a path resolves to, whether or not that provider is configured, for scope checks. */
    public String providerName(final String path) {
        try {
            return resolve(path).upstream().name();
        } catch (final ProxyError e) {
            return e.code().replace("_disabled", "");
        }
    }

}
