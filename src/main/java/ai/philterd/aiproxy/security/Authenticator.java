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
package ai.philterd.aiproxy.security;

import ai.philterd.aiproxy.storage.ApiKeyStore;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Looks up API keys. A key found is cached briefly, so a busy proxy does not read the database on every request;
 * a deleted key stops working within {@link #CACHE_TTL}.
 */
@Component
public class Authenticator {

    static final Duration CACHE_TTL = Duration.ofSeconds(10);
    private static final int MAX_CACHED = 10_000;

    private final ApiKeyStore keys;
    private final ConcurrentMap<String, Cached> cache = new ConcurrentHashMap<>();

    private record Cached(ApiKey key, Instant expires) {
    }

    public Authenticator(final ApiKeyStore keys) {
        this.keys = keys;
    }

    /** The key with this secret, or empty when there is none. */
    public Optional<ApiKey> authenticate(final String secret) {
        if (secret == null || secret.isBlank()) {
            return Optional.empty();
        }
        final Cached cached = cache.get(secret);
        if (cached != null && cached.expires().isAfter(Instant.now())) {
            return Optional.of(cached.key());
        }
        final Optional<ApiKey> key = keys.findBySecret(secret.strip());
        if (key.isPresent()) {
            if (cache.size() >= MAX_CACHED) {
                cache.clear();
            }
            cache.put(secret, new Cached(key.get(), Instant.now().plus(CACHE_TTL)));
        } else {
            cache.remove(secret);
        }
        return key;
    }

    /** Forgets cached keys, so a deleted key stops working at once on this instance. */
    public void clearCache() {
        cache.clear();
    }

}
