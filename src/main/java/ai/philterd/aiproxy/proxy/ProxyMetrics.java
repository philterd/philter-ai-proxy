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

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;

/**
 * Prometheus metrics, named {@code philter_proxy_*} as in earlier versions. Labels never carry text from a
 * request or response.
 */
@Component
public class ProxyMetrics {

    private final MeterRegistry registry;

    public ProxyMetrics(final MeterRegistry registry) {
        this.registry = registry;
    }

    public void request(final String provider, final int status, final String policy, final Duration duration) {
        Counter.builder("philter.proxy.requests").description("Requests handled.")
                .tag("provider", nonNull(provider)).tag("status", Integer.toString(status)).tag("policy", nonNull(policy))
                .register(registry).increment();
        Timer.builder("philter.proxy.request.duration").description("Time to handle a request, including the provider.")
                .tag("provider", nonNull(provider)).publishPercentileHistogram().register(registry).record(duration);
    }

    public void redaction(final String provider, final String policy, final Duration duration) {
        Timer.builder("philter.proxy.redaction.duration").description("Time spent redacting a request.")
                .tag("provider", nonNull(provider)).tag("policy", nonNull(policy)).publishPercentileHistogram()
                .register(registry).record(duration);
    }

    public void entities(final String provider, final Map<String, Integer> counts) {
        counts.forEach((type, count) -> Counter.builder("philter.proxy.entities.redacted")
                .description("Values detected, by filter type.")
                .tag("entity_type", type).tag("provider", nonNull(provider)).register(registry).increment(count));
    }

    public void upstreamError(final String provider, final int status) {
        Counter.builder("philter.proxy.upstream.errors").description("Failed or error responses from providers.")
                .tag("provider", nonNull(provider)).tag("status", Integer.toString(status)).register(registry).increment();
    }

    /** Requests in flight, and the configured concurrency limit (0 when unlimited). */
    public void gauges(final java.util.concurrent.atomic.AtomicInteger active, final int limit) {
        io.micrometer.core.instrument.Gauge.builder("philter.proxy.active.requests", active, java.util.concurrent.atomic.AtomicInteger::get)
                .description("Requests in flight.").register(registry);
        io.micrometer.core.instrument.Gauge.builder("philter.proxy.concurrency.limit", () -> limit)
                .description("The configured concurrency limit; 0 is unlimited.").register(registry);
    }

    /** A request or response that could not be redacted or scanned, so it was refused. */
    public void redactionError(final String provider) {
        Counter.builder("philter.proxy.redaction.errors").description("Requests refused because redaction or scanning failed.")
                .tag("provider", nonNull(provider)).register(registry).increment();
    }

    public void concurrencyShed() {
        Counter.builder("philter.proxy.concurrency.shed").description("Requests refused at the concurrency limit.")
                .register(registry).increment();
    }

    private static String nonNull(final String value) {
        return value == null ? "" : value;
    }

}
