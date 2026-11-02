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

import ai.philterd.phileas.model.filtering.Span;

import java.time.Duration;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * What the audit log and metrics record about one request: metadata only, never request or response text.
 */
final class Exchange {

    final String requestId;
    final String clientIp;
    final long startNanos = System.nanoTime();
    String provider;
    String model;
    String policy;
    String context;
    String keyId;
    String traceId;
    int status;
    String errorType;
    String errorCode;
    int fieldsRedacted;
    Duration redactLatency = Duration.ZERO;
    final Map<String, Integer> entityCounts = new TreeMap<>();
    boolean streamed;
    String outboundAction;
    final Map<String, Integer> outboundEntityCounts = new TreeMap<>();

    Exchange(final String requestId, final String clientIp) {
        this.requestId = requestId;
        this.clientIp = clientIp;
    }

    void countInbound(final Collection<Span> spans) {
        count(entityCounts, spans);
    }

    void countOutbound(final Collection<Span> spans) {
        count(outboundEntityCounts, spans);
    }

    private static void count(final Map<String, Integer> counts, final Collection<Span> spans) {
        for (final Span span : spans) {
            counts.merge(span.getFilterType().getType(), 1, Integer::sum);
        }
    }

    Duration elapsed() {
        return Duration.ofNanos(System.nanoTime() - startNanos);
    }

    Map<String, Object> details() {
        final Map<String, Object> d = new LinkedHashMap<>();
        d.put("provider", provider);
        // The model comes from the client: keep a bounded copy, so a request cannot write megabytes into the log.
        d.put("model", model == null || model.length() <= 256 ? model : model.substring(0, 256));
        d.put("policy_name", policy);
        d.put("context", context);
        d.put("key_id", keyId);
        d.put("trace_id", traceId);
        d.put("client_ip", clientIp);
        d.put("http_status", status);
        d.put("fields_redacted", fieldsRedacted);
        d.put("entity_count", entityCounts.values().stream().mapToInt(Integer::intValue).sum());
        d.put("entity_types", entityCounts);
        d.put("redact_latency_ms", redactLatency.toMillis());
        d.put("duration_ms", elapsed().toMillis());
        d.put("streamed", streamed);
        if (outboundAction != null) {
            d.put("outbound_action", outboundAction);
            d.put("outbound_entity_count", outboundEntityCounts.values().stream().mapToInt(Integer::intValue).sum());
            d.put("outbound_entity_types", outboundEntityCounts);
        }
        if (errorCode != null) {
            d.put("error_type", errorType);
            d.put("error_code", errorCode);
        }
        return d;
    }

}
