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

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Locale;

/**
 * The proxy's configuration, bound from {@code proxy.*} in {@code application.yaml} or the matching
 * environment variables ({@code PROXY_STORAGE_SQLITE_PATH} and so on).
 */
@ConfigurationProperties(prefix = "proxy")
public record ProxyProperties(
        Storage storage,
        Security security,
        Models models,
        PolicyFiles policyFiles,
        Providers providers,
        Defaults defaults,
        List<Route> routes,
        Limits limits,
        Streaming streaming,
        Audit audit,
        Tls tls) {

    @org.springframework.boot.context.properties.bind.ConstructorBinding
    public ProxyProperties {
        storage = storage == null ? new Storage(null) : storage;
        security = security == null ? new Security(null, null, null, null) : security;
        models = models == null ? new Models(null) : models;
        policyFiles = policyFiles == null ? new PolicyFiles(null, null) : policyFiles;
        providers = providers == null ? new Providers(null, null, null, null, null, null, null, null) : providers;
        defaults = defaults == null ? new Defaults(null, null, null, null) : defaults;
        routes = routes == null ? List.of() : List.copyOf(routes);
        limits = limits == null ? new Limits(0, 0) : limits;
        streaming = streaming == null ? new Streaming(0) : streaming;
        audit = audit == null ? new Audit(null) : audit;
        tls = tls == null ? new Tls(false) : tls;
    }

    /** The constructor without the settings added after the first, for tests. */
    public ProxyProperties(final Storage storage, final Security security, final Models models, final PolicyFiles policyFiles,
                           final Providers providers, final Defaults defaults, final List<Route> routes, final Limits limits,
                           final Streaming streaming) {
        this(storage, security, models, policyFiles, providers, defaults, routes, limits, streaming, null, null);
    }

    /**
     * @param file A file each audit entry is also appended to, one JSON line each. Entries are always stored in the
     *             database and written to the {@code philter-ai-proxy.audit} logger.
     */
    public record Audit(String file) {
        public Audit {
            file = blank(file) ? null : file.strip();
        }
    }

    /**
     * @param devSelfSignedCert For evaluation only: serve HTTPS with a self-signed certificate generated at
     *                          startup, which no client trusts. Configure {@code server.ssl.*} for real use. Read by
     *                          {@link DevCertificate} before the server starts.
     */
    public record Tls(boolean devSelfSignedCert) {
    }

    /** Where the proxy keeps policies, contexts, API keys, and the audit log. */
    public record Storage(String sqlitePath) {
        public Storage {
            sqlitePath = blank(sqlitePath) ? "/var/lib/philter-ai-proxy/philter-ai-proxy.db" : sqlitePath.strip();
        }
    }

    /**
     * @param encryptionKey Encrypts sensitive values at rest, such as the original values a context stores.
     * @param bootstrapApiKey An admin key created on first start, so the admin API can be reached.
     * @param proxyKeyHeader The request header that carries a proxy key on provider traffic.
     * @param trustedProxies Load balancers and proxies (IP addresses or CIDR ranges) whose {@code X-Forwarded-For}
     *                       header is believed for the client address in the audit log. None by default.
     */
    public record Security(String encryptionKey, String bootstrapApiKey, String proxyKeyHeader, List<String> trustedProxies) {
        @org.springframework.boot.context.properties.bind.ConstructorBinding
        public Security {
            proxyKeyHeader = blank(proxyKeyHeader) ? "x-philter-proxy-key" : proxyKeyHeader.strip();
            trustedProxies = trustedProxies == null ? List.of() : List.copyOf(trustedProxies);
        }

        public Security(final String encryptionKey, final String bootstrapApiKey, final String proxyKeyHeader) {
            this(encryptionKey, bootstrapApiKey, proxyKeyHeader, null);
        }
    }

    /**
     * @param directory Local PhEye models. Each subdirectory holding a complete model is a model a policy names
     *                  in its ph-eye {@code modelPath}.
     */
    public record Models(String directory) {
        public Models {
            directory = blank(directory) ? "/opt/philter-ai-proxy/models" : directory.strip();
        }
    }

    /**
     * @param directories Directories the files a policy names must be inside. Empty: a policy may name no file.
     * @param allowedEnvironmentVariables Environment variables a policy may name as {@code env:NAME}. Empty: none.
     */
    public record PolicyFiles(List<String> directories, List<String> allowedEnvironmentVariables) {
        public PolicyFiles {
            directories = directories == null ? List.of() : List.copyOf(directories);
            allowedEnvironmentVariables = allowedEnvironmentVariables == null ? List.of() : List.copyOf(allowedEnvironmentVariables);
        }
    }

    /**
     * The providers requests are forwarded to. OpenAI, Anthropic, Gemini, and Ollama are enabled with their public
     * (or local, for Ollama) addresses unless configured otherwise; Azure OpenAI, Vertex AI, and Bedrock are
     * enabled by configuring them; OpenAI-compatible providers are named entries reached at {@code /<name>/v1/...}.
     */
    public record Providers(Provider openai, Provider anthropic, Provider gemini, Provider ollama, Provider azure,
                            Provider vertex, Provider bedrock, java.util.Map<String, Provider> openaiCompatible) {
        public Providers {
            openai = withDefault(openai, "https://api.openai.com");
            anthropic = withDefault(anthropic, "https://api.anthropic.com");
            gemini = withDefault(gemini, "https://generativelanguage.googleapis.com");
            ollama = withDefault(ollama, "http://localhost:11434");
            azure = azure == null ? Provider.NONE : azure;
            vertex = vertex == null ? Provider.NONE : vertex;
            bedrock = bedrock == null ? Provider.NONE : bedrock;
            openaiCompatible = openaiCompatible == null ? java.util.Map.of() : java.util.Map.copyOf(openaiCompatible);
        }

        private static Provider withDefault(final Provider provider, final String target) {
            if (provider == null) {
                return new Provider(target, 0, 0, null, null, false, null, null, null, null, null);
            }
            return provider.target() == null && !provider.disabled()
                    ? new Provider(target, provider.connectTimeoutMs(), provider.responseTimeoutMs(), provider.caCert(),
                    provider.apiVersion(), provider.entraId(), provider.project(), provider.location(), provider.region(),
                    provider.roleArn(), provider.disabled()) : provider;
        }
    }

    /**
     * One provider. Fields that do not apply to a provider are ignored.
     *
     * @param target            The provider's base URL. For Vertex AI, the default is built from {@code location}.
     * @param connectTimeoutMs  How long to wait to connect.
     * @param responseTimeoutMs How long to wait for the response to begin. A stream may then run as long as it lasts.
     * @param caCert            A PEM file of certificate authorities to trust for this provider instead of the
     *                          system's, such as for a self-hosted OpenAI-compatible server.
     * @param apiVersion        Azure OpenAI: the {@code api-version} added to requests that do not send one.
     * @param entraId           Azure OpenAI: authenticate with an Entra ID token from the default Azure credential
     *                          chain instead of passing the client's {@code api-key} through.
     * @param project           Vertex AI: the Google Cloud project. Setting it enables Vertex AI.
     * @param location          Vertex AI: the region, such as {@code us-central1}.
     * @param region            Bedrock: the AWS region. Setting it enables Bedrock.
     * @param roleArn           Bedrock: an IAM role to assume for signing requests.
     * @param disabled          Turns off a provider that is otherwise enabled by default.
     */
    public record Provider(String target, int connectTimeoutMs, int responseTimeoutMs, String caCert, String apiVersion,
                           boolean entraId, String project, String location, String region, String roleArn, Boolean disabled) {

        static final Provider NONE = new Provider(null, 0, 0, null, null, false, null, null, null, null, null);

        @org.springframework.boot.context.properties.bind.ConstructorBinding
        public Provider {
            target = blank(target) ? null : target.strip().replaceAll("/+$", "");
            connectTimeoutMs = connectTimeoutMs <= 0 ? 5_000 : connectTimeoutMs;
            responseTimeoutMs = responseTimeoutMs <= 0 ? 120_000 : responseTimeoutMs;
            caCert = blank(caCert) ? null : caCert.strip();
            apiVersion = blank(apiVersion) ? null : apiVersion.strip();
            project = blank(project) ? null : project.strip();
            location = blank(location) ? null : location.strip();
            region = blank(region) ? null : region.strip();
            roleArn = blank(roleArn) ? null : roleArn.strip();
            disabled = disabled != null && disabled;
        }

        /** A provider with only a target, for tests and defaults. */
        public Provider(final String target) {
            this(target, 0, 0, null, null, false, null, null, null, null, null);
        }

        public boolean isDisabled() {
            return Boolean.TRUE.equals(disabled);
        }
    }

    /**
     * What applies to a request no route matches.
     * @param media Whether a request carrying images, audio, video, or files is refused (the default) or forwarded.
     */
    public record Defaults(String policy, String context, Outbound outbound, Media media) {
        @org.springframework.boot.context.properties.bind.ConstructorBinding
        public Defaults {
            policy = blank(policy) ? "default" : policy.strip();
            context = blank(context) ? null : context.strip();
            outbound = outbound == null ? Outbound.DISABLED : outbound;
            media = media == null ? Media.REJECT : media;
        }

        public Defaults(final String policy, final String context, final Outbound outbound) {
            this(policy, context, outbound, null);
        }
    }

    /**
     * The first route whose every set condition matches applies. A route with no policy, context, or media
     * setting uses the default's.
     */
    public record Route(Match match, String policy, String context, Outbound outbound, Media media) {
        @org.springframework.boot.context.properties.bind.ConstructorBinding
        public Route {
            match = match == null ? new Match(null, null, null, null) : match;
            policy = blank(policy) ? null : policy.strip();
            context = blank(context) ? null : context.strip();
        }

        public Route(final Match match, final String policy, final String context, final Outbound outbound) {
            this(match, policy, context, outbound, null);
        }
    }

    /**
     * What happens to a request carrying images, audio, video, or files, which the proxy does not redact.
     * {@code REJECT} refuses it with 400 {@code media_not_allowed}; {@code FORWARD} sends it on with the media
     * unchanged.
     */
    public enum Media {
        REJECT, FORWARD
    }

    public record Match(String path, String model, String header, String value) {
    }

    /**
     * Scanning of provider responses.
     * @param enabled Whether responses are scanned.
     * @param action {@code redact} (the default), {@code block}, or {@code flag}.
     */
    public record Outbound(boolean enabled, Action action) {
        public static final Outbound DISABLED = new Outbound(false, Action.REDACT);

        public Outbound {
            action = action == null ? Action.REDACT : action;
        }
    }

    public enum Action {
        REDACT, BLOCK, FLAG;

        public String code() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /**
     * @param maxRequestBodyBytes The largest request body accepted.
     * @param maxConcurrentRequests Requests handled at once before the rest are refused with 503. Zero: no limit.
     */
    public record Limits(long maxRequestBodyBytes, int maxConcurrentRequests) {
        public Limits {
            maxRequestBodyBytes = maxRequestBodyBytes <= 0 ? 10L * 1024 * 1024 : maxRequestBodyBytes;
            maxConcurrentRequests = Math.max(0, maxConcurrentRequests);
        }
    }

    /**
     * @param holdbackCharacters How much of a streamed response is held back before it is released, so a value
     *                           split across chunks is seen whole. A value longer than this can be split.
     */
    public record Streaming(int holdbackCharacters) {
        public Streaming {
            holdbackCharacters = holdbackCharacters <= 0 ? 256 : holdbackCharacters;
        }
    }

    private static boolean blank(final String value) {
        return value == null || value.isBlank();
    }

}
