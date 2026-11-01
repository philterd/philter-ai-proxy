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

import ai.philterd.aiproxy.config.ProxyProperties;
import ai.philterd.aiproxy.redaction.Redactor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Loads the configured policies once at startup, so their PhEye models are in memory before the first request
 * rather than loaded during it. {@code /readyz} reports not ready until this finishes.
 */
@Component
public class Warmup {

    private static final Logger LOGGER = LoggerFactory.getLogger(Warmup.class);

    private final ProxyProperties properties;
    private final Redactor redactor;
    private volatile boolean done;

    public Warmup(final ProxyProperties properties, final Redactor redactor) {
        this.properties = properties;
        this.redactor = redactor;
    }

    public boolean isDone() {
        return done;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void warm() {
        Thread.ofVirtual().name("warmup").start(() -> {
            final Set<String> names = new LinkedHashSet<>();
            names.add(properties.defaults().policy());
            properties.routes().forEach(route -> {
                if (route.policy() != null) {
                    names.add(route.policy());
                }
            });
            for (final String name : names) {
                final long start = System.nanoTime();
                try {
                    redactor.session(name, null).redact("Warm up.");
                    LOGGER.info("Loaded policy '{}' in {} ms", name, (System.nanoTime() - start) / 1_000_000);
                } catch (final Exception e) {
                    // Requests that use it are refused with the reason; the proxy still serves the others.
                    LOGGER.error("Policy '{}' cannot be used: {}", name, e.getMessage());
                }
            }
            done = true;
        });
    }

}
