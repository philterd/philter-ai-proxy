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
package ai.philterd.aiproxy.redaction;

import ai.philterd.aiproxy.storage.ContextStore;
import ai.philterd.aiproxy.storage.PolicyStore;
import ai.philterd.phileas.model.filtering.Span;
import ai.philterd.phileas.model.filtering.TextFilterResult;
import ai.philterd.phileas.policy.Policy;
import ai.philterd.phileas.services.context.ContextService;
import ai.philterd.phileas.services.context.DefaultContextService;
import ai.philterd.phileas.services.disambiguation.vector.InMemoryVectorService;
import ai.philterd.phileas.services.filters.filtering.PlainTextFilterService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Redacts text in-process with Phileas. All the text fields of one request are redacted together (see
 * {@link Session}): the policy is resolved once, and the fields are filtered concurrently on virtual threads.
 */
@Component
public class Redactor {

    private final PolicyStore policies;
    private final ContextStore contexts;
    private final PolicyCompiler compiler;
    private final PlainTextFilterService filterService;

    /** Compiled policies by name, valid while the stored revision matches. */
    private final ConcurrentMap<String, CompiledPolicy> compiled = new ConcurrentHashMap<>();

    private record CompiledPolicy(int revision, Policy policy) {
    }

    public Redactor(final PolicyStore policies, final ContextStore contexts, final PolicyCompiler compiler) {
        this.policies = policies;
        this.contexts = contexts;
        this.compiler = compiler;
        // No HTTP client: detection runs in-process, and PolicyCompiler refuses a policy that names a service.
        this.filterService = new PlainTextFilterService(compiler.getPhileasConfiguration(), null);
    }

    /**
     * One redacted text.
     * @param text The text with the policy applied.
     * @param spans The values that were replaced, by position in the original text.
     */
    public record Redaction(String original, String text, List<Span> spans) {

        public boolean changed() {
            return !spans.isEmpty();
        }
    }

    /** Thrown when the named policy does not exist. */
    public static class PolicyNotFoundException extends RuntimeException {
        public PolicyNotFoundException(final String name) {
            super("The policy '" + name + "' does not exist.");
        }
    }

    /**
     * Starts redacting for one exchange with a provider: the request and its response. The policy is resolved
     * once, and one context is used throughout, so a value is replaced the same way in the request, the response,
     * and every window of a streamed response.
     * @param context The stored context that keeps replacements consistent across exchanges, or null to keep them
     *                consistent only within this one.
     */
    public Session session(final String policyName, final String context) {
        final Policy policy = resolve(policyName);
        final ContextService contextService = context == null ? new DefaultContextService() : contexts.forContext(context);
        return new Session(policy, contextService, context == null ? "" : context);
    }

    /** Redaction with one policy and one context. Safe to use from several threads. */
    public final class Session {

        private final Policy policy;
        private final ContextService contextService;
        private final String contextName;

        private Session(final Policy policy, final ContextService contextService, final String contextName) {
            this.policy = policy;
            this.contextService = contextService;
            this.contextName = contextName;
        }

        public Redaction redact(final String text) throws RedactionException {
            return filter(policy, contextService, contextName, text);
        }

        /** Redacts the texts concurrently. One redaction per text, in order. */
        public List<Redaction> redact(final List<String> texts) throws RedactionException {
            if (texts.isEmpty()) {
                return List.of();
            }
            if (texts.size() == 1) {
                return List.of(redact(texts.getFirst()));
            }
            try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
                final List<Future<Redaction>> futures = new ArrayList<>(texts.size());
                for (final String text : texts) {
                    futures.add(executor.submit(() -> redact(text)));
                }
                final List<Redaction> results = new ArrayList<>(texts.size());
                for (final Future<Redaction> future : futures) {
                    results.add(future.get());
                }
                return results;
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RedactionException("Redaction was interrupted.", e);
            } catch (final ExecutionException e) {
                if (e.getCause() instanceof RedactionException re) {
                    throw re;
                }
                throw new RedactionException("Redaction failed.", e.getCause());
            }
        }

    }

    private Redaction filter(final Policy policy, final ContextService contextService, final String contextName,
                             final String text) throws RedactionException {
        if (text == null || text.isEmpty()) {
            return new Redaction(text, text, List.of());
        }
        try {
            final TextFilterResult result = filterService.filter(policy, contextService, new InMemoryVectorService(),
                    contextName, text);
            final List<Span> spans = new ArrayList<>(result.getExplanation().appliedSpans());
            spans.sort(Comparator.comparingInt(Span::getCharacterStart));
            return new Redaction(text, result.getFilteredText(), List.copyOf(spans));
        } catch (final Exception e) {
            throw new RedactionException("Redaction failed.", e);
        }
    }

    /** The compiled policy, recompiled when its stored revision changes. */
    Policy resolve(final String name) {
        final int revision = policies.findRevision(name).orElseThrow(() -> new PolicyNotFoundException(name));
        final CompiledPolicy cached = compiled.get(name);
        if (cached != null && cached.revision() == revision) {
            return cached.policy();
        }
        final PolicyStore.StoredPolicy stored = policies.find(name).orElseThrow(() -> new PolicyNotFoundException(name));
        final Policy policy = compiler.compile(stored.policy());
        compiled.put(name, new CompiledPolicy(stored.revision(), policy));
        return policy;
    }

    /** Drops a cached policy, so its next use reads the store. */
    public void evict(final String name) {
        compiled.remove(name);
    }

}
