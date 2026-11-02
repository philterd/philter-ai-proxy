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

import ai.philterd.aiproxy.admin.AdminSupport;
import ai.philterd.aiproxy.config.ProxyProperties;
import ai.philterd.aiproxy.config.ProxyProperties.Action;
import ai.philterd.aiproxy.providers.ProviderDialect;
import ai.philterd.aiproxy.providers.ProviderRegistry;
import ai.philterd.aiproxy.redaction.PolicyException;
import ai.philterd.aiproxy.redaction.RedactionException;
import ai.philterd.aiproxy.redaction.Redactor;
import ai.philterd.aiproxy.redaction.Redactor.Redaction;
import ai.philterd.aiproxy.security.ApiKey;
import ai.philterd.aiproxy.security.Authenticator;
import ai.philterd.aiproxy.security.KeyScopes;
import ai.philterd.aiproxy.storage.AuditStore;
import ai.philterd.aiproxy.stream.Framing;
import ai.philterd.aiproxy.stream.StreamDialect;
import ai.philterd.aiproxy.stream.StreamEvent;
import ai.philterd.aiproxy.stream.StreamScanner;
import ai.philterd.phileas.model.filtering.Span;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Semaphore;

/**
 * Provider traffic, for every provider: authenticates the proxy key, resolves the provider from the path, redacts
 * the request, forwards it, and scans the response when the route asks for it. A request is never forwarded when
 * redaction fails, and a response that cannot be scanned is refused rather than returned unscanned.
 */
@RestController
public class ProxyController {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProxyController.class);
    private static final int MAX_REQUEST_ID_LENGTH = 128;

    private final ProxyProperties properties;
    private final Authenticator authenticator;
    private final Redactor redactor;
    private final AuditStore audit;
    private final ProxyMetrics metrics;
    private final ProviderRegistry providers;
    private final ClientAddress clientAddress;
    private final org.springframework.beans.factory.ObjectProvider<io.micrometer.tracing.Tracer> tracer;
    private final Semaphore concurrency;
    private final java.util.concurrent.atomic.AtomicInteger active = new java.util.concurrent.atomic.AtomicInteger();

    public ProxyController(final ProxyProperties properties, final Authenticator authenticator, final Redactor redactor,
                           final AuditStore audit, final ProxyMetrics metrics, final ProviderRegistry providers,
                           final ClientAddress clientAddress,
                           final org.springframework.beans.factory.ObjectProvider<io.micrometer.tracing.Tracer> tracer) {
        this.properties = properties;
        this.authenticator = authenticator;
        this.redactor = redactor;
        this.audit = audit;
        this.metrics = metrics;
        this.providers = providers;
        this.clientAddress = clientAddress;
        this.tracer = tracer;
        this.concurrency = properties.limits().maxConcurrentRequests() > 0
                ? new Semaphore(properties.limits().maxConcurrentRequests()) : null;
        metrics.gauges(active, properties.limits().maxConcurrentRequests());
    }

    /** Every path no other controller serves is provider traffic. */
    @RequestMapping("/**")
    public void proxy(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        if (isReserved(request.getRequestURI())) {
            // A request to the admin API or a health endpoint that no handler there accepts (an unknown path, the
            // wrong method or content type) lands here; it is not provider traffic and is never forwarded.
            response.setHeader("X-Request-Id", requestId(request));
            response.setStatus(404);
            response.setContentType("application/json");
            response.getOutputStream().write(AdminSupport.error("No endpoint accepts this method, path, and content type.",
                    "not_found", null).getBytes(StandardCharsets.UTF_8));
            return;
        }
        final Exchange exchange = new Exchange(requestId(request), clientAddress.of(request));
        exchange.traceId = traceId();
        response.setHeader("X-Request-Id", exchange.requestId);
        boolean acquired = false;
        active.incrementAndGet();
        try {
            final String rawPath = request.getRequestURI();
            final String path = decodePath(rawPath);
            exchange.provider = providers.providerName(path);
            final ApiKey key = authenticate(request, exchange);
            if (concurrency != null) {
                if (!concurrency.tryAcquire()) {
                    metrics.concurrencyShed();
                    response.setHeader("Retry-After", "1");
                    throw new ProxyError(503, "capacity", "concurrency_exceeded", "concurrency limit exceeded");
                }
                acquired = true;
            }
            final ProviderRegistry.Route route = providers.resolve(path);
            // The provider receives the client's own encoding of the path. An OpenAI-compatible prefix is one segment,
            // and an encoded slash is refused, so the first raw slash after it marks the same boundary.
            final String forwardPath = route.path().equals(path) ? rawPath : rawPath.substring(rawPath.indexOf('/', 1));
            handle(request, response, exchange, key, route, forwardPath, path);
        } catch (final ProxyError e) {
            fail(response, exchange, e);
        } catch (final RuntimeException e) {
            LOGGER.error("Request {} failed", exchange.requestId, e);
            fail(response, exchange, new ProxyError(500, "internal_error", "internal_error", "the request failed"));
        } finally {
            active.decrementAndGet();
            if (acquired) {
                concurrency.release();
            }
            finish(exchange);
        }
    }

    /** The current trace's ID when tracing is on and the request is sampled, else null. */
    private String traceId() {
        final io.micrometer.tracing.Tracer t = tracer.getIfAvailable();
        final io.micrometer.tracing.Span span = t == null ? null : t.currentSpan();
        return span == null || !Boolean.TRUE.equals(span.context().sampled()) ? null : span.context().traceId();
    }

    /** The field names the OpenAI and Ollama dialects read text, media, or the model from. */
    private static final java.util.Set<String> READ_FIELDS = java.util.Set.of("model", "name", "messages", "content", "prompt", "system",
            "suffix", "template", "images", "text", "input", "instructions", "refusal", "thinking", "tool_calls",
            "function", "arguments", "function_call", "prediction", "output", "reasoning", "reasoning_content",
            "variables", "type", "summary", "error", "stdout", "stderr");

    /**
     * Members whose contents are the application's own, such as tool schemas, structured-output schemas, and tool
     * arguments: their keys are not checked, so a schema property named {@code Content} is not refused.
     */
    private static final java.util.Set<String> APPLICATION_MEMBERS = java.util.Set.of("tools", "functions",
            "response_format", "metadata", "format", "options", "arguments", "parameters", "schema", "json_schema", "text");

    /** The first object key, at any depth, that is a read field in another case, or null. */
    static String miscasedField(final JsonElement element) {
        if (element instanceof JsonObject object) {
            for (final Map.Entry<String, JsonElement> member : object.entrySet()) {
                // Go's encoding/json also folds the long s and the Kelvin sign to s and k.
                final String lower = member.getKey().replace('\u017F', 's').replace('\u212A', 'k').toLowerCase(Locale.ROOT);
                if (!lower.equals(member.getKey()) && READ_FIELDS.contains(lower)) {
                    return member.getKey();
                }
                final String nested = APPLICATION_MEMBERS.contains(member.getKey()) ? null : miscasedField(member.getValue());
                if (nested != null) {
                    return nested;
                }
            }
        } else if (element instanceof com.google.gson.JsonArray array) {
            for (final JsonElement item : array) {
                final String nested = miscasedField(item);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    /**
     * Decodes the request path once, so routing, scopes, and endpoint classification see what the provider will see
     * when it decodes the same path. Refuses malformed escapes, escapes that would change the path's structure or
     * be decoded twice ({@code /}, {@code \}, {@code %}, {@code ?}, {@code #}), control characters, invalid UTF-8,
     * and a decoded path that is not canonical.
     */
    static String decodePath(final String raw) throws ProxyError {
        final ProxyError invalid = new ProxyError(400, "invalid_request", "path_not_canonical", "request path is not in canonical form");
        if (raw == null) {
            throw invalid;
        }
        final java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < raw.length(); i++) {
            final char c = raw.charAt(i);
            if (c == '%') {
                if (i + 2 >= raw.length() || Character.digit(raw.charAt(i + 1), 16) < 0 || Character.digit(raw.charAt(i + 2), 16) < 0) {
                    throw invalid;
                }
                final int b = Integer.parseInt(raw.substring(i + 1, i + 3), 16);
                if (b == '/' || b == '\\' || b == '%' || b == '?' || b == '#') {
                    throw invalid;
                }
                bytes.write(b);
                i += 2;
            } else {
                bytes.writeBytes(String.valueOf(c).getBytes(StandardCharsets.UTF_8));
            }
        }
        final String decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(bytes.toByteArray())).toString();
        } catch (final java.nio.charset.CharacterCodingException e) {
            throw invalid;
        }
        if (decoded.chars().anyMatch(ch -> ch < 0x20 || ch == 0x7f) || !isCanonical(decoded)) {
            throw invalid;
        }
        return decoded;
    }

    /** Whether the path belongs to the admin API or the health endpoints, however it is cased or encoded. */
    static boolean isReserved(final String raw) {
        String path;
        try {
            path = decodePath(raw);
        } catch (final ProxyError e) {
            path = raw == null ? "" : raw;
        }
        // Path parameters (";x") are ignored when the servlet container matches a path to a controller.
        path = path.toLowerCase(Locale.ROOT).replaceAll(";[^/]*", "");
        while (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return path.equals("/admin") || path.startsWith("/admin/")
                || path.equals("/livez") || path.equals("/readyz") || path.equals("/health");
    }

    /**
     * Refuses a path that is not already in canonical form, so a path scope cannot be bypassed with
     * {@code ..}, empty segments, or encoded dots and slashes that a provider would normalize.
     */
    static boolean isCanonical(final String path) {
        if (path == null || path.isEmpty() || !path.startsWith("/") || path.contains("//")) {
            return false;
        }
        final String lower = path.toLowerCase(Locale.ROOT);
        if (lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") || path.contains("\\")) {
            return false;
        }
        for (final String segment : path.split("/", -1)) {
            if (segment.equals(".") || segment.equals("..")) {
                return false;
            }
        }
        return true;
    }

    private void handle(final HttpServletRequest request, final HttpServletResponse response, final Exchange exchange,
                        final ApiKey key, final ProviderRegistry.Route route, final String forwardPath, final String scopePath)
            throws ProxyError, IOException {
        final ProviderDialect dialect = route.upstream().dialect();
        final String path = route.path();
        exchange.provider = route.upstream().name();

        final String contentType = request.getContentType();
        if (contentType != null && contentType.toLowerCase(Locale.ROOT).startsWith("multipart/")) {
            throw new ProxyError(400, "invalid_request", "unsupported_content_type", path.startsWith("/v1/files")
                    ? "file uploads are not proxied; redact the file contents before uploading"
                    : "multipart/form-data requests are not proxied; this proxy redacts JSON request bodies");
        }
        final byte[] raw = readBody(request);
        final JsonObject body = raw.length == 0 ? null : parseObject(raw);
        exchange.model = body == null ? ProviderDialect.modelFromPath(path) : dialect.model(path, body);

        // Path scopes see the path as sent, with any OpenAI-compatible provider's prefix, so a scope of
        // /v1/chat/completions does not also admit every compatible provider.
        final KeyScopes.ScopeDenial denial = key.scopes().check(exchange.provider, exchange.model, scopePath);
        if (denial != null) {
            throw new ProxyError(403, "forbidden", denial.code(), "request not permitted by API key scope");
        }

        if (body != null && dialect.caseInsensitiveFields()) {
            final String field = miscasedField(body);
            if (field != null) {
                throw new ProxyError(400, "invalid_request", "ambiguous_field", "the field '" + field
                        + "' differs only in case from a field the proxy redacts; use the provider's own spelling");
            }
        }
        final Routes.Resolved resolved = Routes.resolve(properties, path, exchange.model, request::getHeader,
                key.scopes().policy() != null);
        final boolean supported = dialect.supports(request.getMethod(), path);
        // A provider the proxy authenticates to with its own credential (Vertex AI, Bedrock, Azure with Entra ID)
        // would otherwise act for any proxy key on any endpoint, such as listing or deleting resources.
        final boolean ownCredential = route.upstream().client().usesOwnCredential();
        if (resolved.unsupportedEndpoints() == ProxyProperties.Mode.REJECT && !supported
                && (body != null || resolved.outbound().enabled() || ownCredential)) {
            throw new ProxyError(400, "invalid_request", "unsupported_endpoint", body != null
                    ? "the proxy cannot redact requests to this endpoint, and is configured to refuse them"
                    : resolved.outbound().enabled()
                    ? "the proxy cannot scan responses from this endpoint, and is configured to refuse them"
                    : "the proxy authenticates to this provider with its own credential, and is configured to refuse "
                    + "endpoints it does not redact");
        }
        if (body != null && resolved.media() == ProxyProperties.Mode.REJECT) {
            final String media = dialect.mediaPart(path, body);
            if (media != null) {
                throw new ProxyError(400, "invalid_request", "media_not_allowed", "the request contains a '" + media
                        + "' part; images, audio, video, and files are not redacted, and this proxy is configured to refuse them");
            }
        }
        exchange.policy = key.scopes().policy() != null ? key.scopes().policy() : resolved.policy();
        exchange.context = resolved.context();

        // Only a request that is redacted, or whose response is scanned, needs the policy, so a bodyless request
        // that is neither still works while its route's policy cannot be used.
        final Redactor.Session session = body != null || (resolved.outbound().enabled() && supported) ? session(exchange) : null;
        byte[] forward = raw;
        if (body != null) {
            final TextSlots slots = dialect.requestText(path, body);
            final long start = System.nanoTime();
            final List<Redaction> redactions = redact(session, slots.texts(), exchange);
            exchange.redactLatency = Duration.ofNanos(System.nanoTime() - start);
            slots.apply(redactions.stream().map(Redaction::text).toList());
            for (final Redaction r : redactions) {
                if (r.changed()) {
                    exchange.fieldsRedacted++;
                    exchange.countInbound(r.spans());
                }
            }
            metrics.redaction(exchange.provider, exchange.policy, exchange.redactLatency);
            forward = body.toString().getBytes(StandardCharsets.UTF_8);
        }

        final HttpResponse<InputStream> upstream = send(route, request, forwardPath, forward, exchange);
        if (upstream.statusCode() >= 400) {
            metrics.upstreamError(exchange.provider, upstream.statusCode());
        }
        final ProxyProperties.Outbound outbound = resolved.outbound();
        try (InputStream in = upstream.body()) {
            final String responseType = upstream.headers().firstValue("content-type").orElse("");
            final Framing framing = dialect.framing(responseType);
            final boolean success = upstream.statusCode() >= 200 && upstream.statusCode() < 300;
            exchange.streamed = framing != null;
            if (outbound.enabled() && upstream.statusCode() < 400 && !success) {
                // A redirect or other non-error status the proxy does not follow: its body is not scanned.
                throw unscannable();
            }
            // A response from an endpoint the proxy cannot scan, forwarded under unsupported-endpoints: forward, is
            // returned unscanned, as documented, rather than read with a dialect that does not know its shape.
            if (!outbound.enabled() || !success || !supported) {
                passThrough(response, upstream, in, framing != null, exchange);
                return;
            }
            exchange.outboundAction = outbound.action().code();
            final String encoding = upstream.headers().firstValue("content-encoding").orElse("identity").strip();
            if (!encoding.isEmpty() && !encoding.equalsIgnoreCase("identity")) {
                // The proxy asks for an uncompressed response; one that arrives compressed cannot be scanned.
                throw unscannable();
            }
            if (framing != null) {
                final StreamDialect streamDialect = dialect.streamDialect(path);
                if (streamDialect == null) {
                    throw unscannable();
                }
                scanStream(response, upstream, in, framing, streamDialect, session, outbound.action(), exchange);
            } else if (isBinary(responseType)) {
                // Generated audio carries no text the proxy reads, and is documented as not scanned. A binary response
                // from any other endpoint is not one the proxy expects, so it is not returned unscanned.
                if (!dialect.binaryResponse(path)) {
                    throw unscannable();
                }
                passThrough(response, upstream, in, false, exchange);
            } else {
                scanBuffered(response, upstream, in, dialect, path, session, outbound.action(), exchange);
            }
        }
    }

    private static boolean isBinary(final String contentType) {
        final String type = contentType.toLowerCase(Locale.ROOT);
        return type.startsWith("audio/") || type.startsWith("image/") || type.startsWith("video/")
                || type.startsWith("application/octet-stream");
    }

    private static ProxyError unscannable() {
        return new ProxyError(502, "provider_error", "response_unscannable", "the provider's response could not be scanned");
    }

    private HttpResponse<InputStream> send(final ProviderRegistry.Route route, final HttpServletRequest request, final String path,
                                           final byte[] body, final Exchange exchange) throws ProxyError {
        try {
            return route.upstream().client().send(request, path, body);
        } catch (final UpstreamClient.AuthenticationException e) {
            LOGGER.error("Authenticating to {} failed for request {}: {}", exchange.provider, exchange.requestId, e.getMessage());
            metrics.upstreamError(exchange.provider, 502);
            throw new ProxyError(502, "provider_error", exchange.provider + "_auth_failed",
                    "the proxy could not authenticate to the provider");
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            metrics.upstreamError(exchange.provider, 502);
            throw new ProxyError(502, "provider_error", "unreachable", "provider request failed");
        } catch (final IOException | IllegalArgumentException e) {
            LOGGER.warn("Provider request failed for request {}: {}", exchange.requestId, e.toString());
            metrics.upstreamError(exchange.provider, 502);
            throw new ProxyError(502, "provider_error", "unreachable", "provider request failed");
        }
    }

    private ApiKey authenticate(final HttpServletRequest request, final Exchange exchange) throws ProxyError {
        final String secret = request.getHeader(properties.security().proxyKeyHeader());
        if (secret == null || secret.isBlank()) {
            throw new ProxyError(401, "unauthorized", "missing_api_key", "missing API key");
        }
        final ApiKey key = authenticator.authenticate(secret)
                .orElseThrow(() -> new ProxyError(401, "unauthorized", "invalid_api_key", "invalid API key"));
        exchange.keyId = key.id();
        if (!key.scopes().has(KeyScopes.Role.proxy)) {
            throw new ProxyError(403, "forbidden", "scope_denied_role", "API key may not send provider traffic");
        }
        return key;
    }

    private Redactor.Session session(final Exchange exchange) throws ProxyError {
        try {
            return redactor.session(exchange.policy, exchange.context);
        } catch (final Redactor.PolicyNotFoundException e) {
            LOGGER.error("Request {} uses policy '{}', which does not exist.", exchange.requestId, exchange.policy);
            throw new ProxyError(500, "configuration_error", "policy_not_found", e.getMessage());
        } catch (final PolicyException e) {
            LOGGER.error("Request {} uses policy '{}', which cannot be used: {}", exchange.requestId, exchange.policy, e.getMessage());
            throw new ProxyError(500, "configuration_error", "policy_invalid",
                    "the policy '" + exchange.policy + "' cannot be used: " + e.getMessage());
        }
    }

    private List<Redaction> redact(final Redactor.Session session, final List<String> texts, final Exchange exchange) throws ProxyError {
        try {
            return session.redact(texts);
        } catch (final ai.philterd.aiproxy.redaction.RedactionTimeoutException e) {
            LOGGER.error("Redaction of request {} timed out", exchange.requestId);
            metrics.redactionError(exchange.provider);
            throw new ProxyError(503, "redaction_error", "redaction_timeout", "redaction took too long; the request was not forwarded");
        } catch (final RedactionException e) {
            LOGGER.error("Redaction failed", e);
            metrics.redactionError(exchange.provider);
            throw new ProxyError(500, "redaction_error", "redaction_failed", "redaction failed; the request was not forwarded");
        }
    }

    private void passThrough(final HttpServletResponse response, final HttpResponse<InputStream> upstream, final InputStream in,
                             final boolean streaming, final Exchange exchange) throws IOException {
        // The body is copied unchanged, so its encoding is too.
        copyHeaders(upstream, response, true);
        response.setStatus(upstream.statusCode());
        exchange.status = upstream.statusCode();
        final OutputStream out = response.getOutputStream();
        final byte[] buffer = new byte[8192];
        int n;
        while (true) {
            try {
                n = in.read(buffer);
            } catch (final IOException e) {
                // The response is already under way, so the client sees it cut short; the audit log says why.
                LOGGER.warn("The provider's response to request {} ended unexpectedly: {}", exchange.requestId, e.getMessage());
                exchange.errorType = "provider_error";
                exchange.errorCode = "stream_interrupted";
                return;
            }
            if (n == -1) {
                break;
            }
            out.write(buffer, 0, n);
            if (streaming) {
                out.flush();
            }
        }
        out.flush();
    }

    private void scanBuffered(final HttpServletResponse response, final HttpResponse<InputStream> upstream, final InputStream in,
                              final ProviderDialect dialect, final String path, final Redactor.Session session,
                              final Action action, final Exchange exchange) throws IOException, ProxyError {
        final long limit = properties.limits().maxResponseBodyBytes();
        final byte[] raw = in.readNBytes((int) limit + 1);
        if (raw.length > limit) {
            throw new ProxyError(502, "provider_error", "response_too_large",
                    "the provider's response is larger than the proxy will scan");
        }
        final JsonElement json = StrictJson.parse(new String(raw, StandardCharsets.UTF_8));
        if (json == null || !json.isJsonObject() && !json.isJsonArray()) {
            throw unscannable();
        }
        final TextSlots slots = dialect.responseText(path, json);
        final List<Redaction> redactions = redact(session, slots.texts(), exchange);
        // Under flag the response is never changed; otherwise revealing data would expose what is redacted or blocked.
        boolean changed = action != Action.FLAG && dialect.removeRevealingData(path, json);
        final List<Span> found = new ArrayList<>();
        redactions.forEach(r -> found.addAll(r.spans()));
        exchange.countOutbound(found);
        if (!found.isEmpty()) {
            switch (action) {
                case BLOCK -> throw new ProxyError(403, "pii_blocked", "outbound_blocked", "response blocked: PII detected");
                case FLAG -> LOGGER.warn("PII detected in the response to request {}: {}", exchange.requestId, exchange.outboundEntityCounts);
                case REDACT -> {
                    slots.apply(redactions.stream().map(Redaction::text).toList());
                    changed = true;
                }
            }
        }
        final byte[] body = changed ? json.toString().getBytes(StandardCharsets.UTF_8) : raw;
        copyHeaders(upstream, response, false);
        response.setStatus(upstream.statusCode());
        exchange.status = upstream.statusCode();
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }

    private void scanStream(final HttpServletResponse response, final HttpResponse<InputStream> upstream, final InputStream in,
                            final Framing framing, final StreamDialect streamDialect, final Redactor.Session session,
                            final Action action, final Exchange exchange) throws IOException {
        copyHeaders(upstream, response, false);
        response.setStatus(upstream.statusCode());
        exchange.status = upstream.statusCode();
        final OutputStream out = response.getOutputStream();
        final boolean[] clientGone = {false};
        final StreamScanner scanner = new StreamScanner(framing, streamDialect, session::redact, action,
                properties.streaming().holdbackCharacters(), bytes -> {
                    try {
                        out.write(bytes);
                        out.flush();
                    } catch (final IOException e) {
                        clientGone[0] = true;
                        throw e;
                    }
                });
        try {
            scanner.run(in);
        } catch (final StreamScanner.BlockedException e) {
            endStream(out, framing, exchange, "pii_blocked", "outbound_blocked", "response blocked: PII detected");
        } catch (final StreamScanner.UnscannableException e) {
            endStream(out, framing, exchange, "provider_error", "response_unscannable",
                    "the provider's response could not be scanned; the stream was ended");
        } catch (final ai.philterd.aiproxy.stream.ResponseTooLargeException e) {
            endStream(out, framing, exchange, "provider_error", "response_too_large",
                    "the provider's response is larger than the proxy will scan; the stream was ended");
        } catch (final IOException e) {
            // Held text is discarded either way. Record why the stream ended, rather than a clean 200.
            if (clientGone[0]) {
                exchange.errorType = "client_error";
                exchange.errorCode = "client_disconnected";
            } else {
                LOGGER.warn("The provider's stream for request {} ended unexpectedly: {}", exchange.requestId, e.getMessage());
                metrics.upstreamError(exchange.provider, 502);
                endStream(out, framing, exchange, "provider_error", "stream_interrupted",
                        "the provider's stream ended unexpectedly");
            }
        } catch (final RedactionException e) {
            LOGGER.error("Scanning the streamed response to request {} failed", exchange.requestId, e);
            metrics.redactionError(exchange.provider);
            endStream(out, framing, exchange, "redaction_error", "redaction_failed", "scanning the response failed; the stream was ended");
        } finally {
            exchange.countOutbound(scanner.detections());
        }
    }

    /** Ends a stream that has already started with an error event in the stream's own framing. */
    private static void endStream(final OutputStream out, final Framing framing, final Exchange exchange, final String type,
                                  final String code, final String message) throws IOException {
        exchange.errorType = type;
        exchange.errorCode = code;
        final JsonObject error = JsonParser.parseString(errorJson(type, code, message, exchange.requestId)).getAsJsonObject();
        out.write(framing.encodeError(code, error));
        out.flush();
    }

    private static void copyHeaders(final HttpResponse<InputStream> upstream, final HttpServletResponse response,
                                    final boolean keepEncoding) {
        for (final Map.Entry<String, List<String>> header : upstream.headers().map().entrySet()) {
            final String name = header.getKey();
            final String lower = name.toLowerCase(Locale.ROOT);
            if (name.startsWith(":") || (UpstreamClient.NOT_RETURNED.contains(lower) && !(keepEncoding && lower.equals("content-encoding")))) {
                continue;
            }
            for (final String value : header.getValue()) {
                response.addHeader(name, value);
            }
        }
    }

    private byte[] readBody(final HttpServletRequest request) throws ProxyError, IOException {
        final long max = properties.limits().maxRequestBodyBytes();
        if (request.getContentLengthLong() > max) {
            throw new ProxyError(413, "payload_too_large", "request_body_too_large", "request body exceeds the maximum allowed size");
        }
        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        final byte[] buffer = new byte[8192];
        try (InputStream in = request.getInputStream()) {
            int n;
            while ((n = in.read(buffer)) != -1) {
                if (body.size() + n > max) {
                    throw new ProxyError(413, "payload_too_large", "request_body_too_large", "request body exceeds the maximum allowed size");
                }
                body.write(buffer, 0, n);
            }
        }
        return body.toByteArray();
    }

    private static JsonObject parseObject(final byte[] body) throws ProxyError {
        final JsonElement element = StrictJson.parse(new String(body, StandardCharsets.UTF_8));
        if (element != null && element.isJsonObject()) {
            return element.getAsJsonObject();
        }
        throw new ProxyError(400, "invalid_request", "bad_json", "invalid JSON in request body");
    }

    private void fail(final HttpServletResponse response, final Exchange exchange, final ProxyError error) throws IOException {
        exchange.status = error.status();
        exchange.errorType = error.type();
        exchange.errorCode = error.code();
        if (response.isCommitted()) {
            return;
        }
        response.resetBuffer();
        response.setStatus(error.status());
        response.setContentType("application/json");
        String body = errorJson(error.type(), error.code(), error.getMessage(), exchange.requestId);
        if ("bedrock".equals(exchange.provider)) {
            // AWS SDKs read an error's code from this header and its message from a top-level "message".
            response.setHeader("x-amzn-ErrorType", error.code());
            final JsonObject root = JsonParser.parseString(body).getAsJsonObject();
            root.addProperty("message", error.code() + ": " + error.getMessage());
            body = root.toString();
        }
        response.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
    }

    static String errorJson(final String type, final String code, final String message, final String requestId) {
        final JsonObject error = new JsonObject();
        error.addProperty("message", message);
        error.addProperty("type", type);
        error.addProperty("code", code);
        error.addProperty("request_id", requestId);
        final JsonObject root = new JsonObject();
        root.add("error", error);
        return root.toString();
    }

    private void finish(final Exchange exchange) {
        audit.record(exchange.requestId, "proxy_request", exchange.details());
        metrics.request(exchange.provider, exchange.status, exchange.policy, exchange.elapsed());
        metrics.entities(exchange.provider, exchange.entityCounts);
    }

    /**
     * The inbound {@code X-Request-Id} when it is a sane identifier (at most 128 printable ASCII characters),
     * else a new UUID, so a client cannot inject control characters or bulk into the audit log.
     */
    static String requestId(final HttpServletRequest request) {
        final String id = request.getHeader("X-Request-Id");
        if (id != null && !id.isEmpty() && id.length() <= MAX_REQUEST_ID_LENGTH && id.chars().allMatch(c -> c >= 0x20 && c <= 0x7E)) {
            return id;
        }
        return UUID.randomUUID().toString();
    }

}
