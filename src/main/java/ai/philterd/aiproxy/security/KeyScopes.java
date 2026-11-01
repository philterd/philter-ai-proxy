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

import java.util.List;
import java.util.Set;

/**
 * What an API key may do.
 *
 * @param roles     {@code admin} (the admin API), {@code proxy} (provider traffic), or both. A key has no access
 *                  outside its roles.
 * @param providers Providers a proxy key may reach. Empty: any. An entry ending in {@code *} matches by prefix.
 * @param models    Models a proxy key may request. Empty: any. An entry ending in {@code *} matches by prefix.
 * @param paths     Request path prefixes a proxy key may use. Empty: any.
 * @param policy    When set, the policy applied to this key's requests, whatever the route says.
 */
public record KeyScopes(Set<Role> roles, List<String> providers, List<String> models, List<String> paths, String policy) {

    public enum Role {
        admin, proxy
    }

    public KeyScopes {
        roles = roles == null ? Set.of() : Set.copyOf(roles);
        providers = providers == null ? List.of() : List.copyOf(providers);
        models = models == null ? List.of() : List.copyOf(models);
        paths = paths == null ? List.of() : List.copyOf(paths);
        policy = policy == null || policy.isBlank() ? null : policy.strip();
    }

    /** Applies the compact constructor's defaults to a value Gson built without calling it. */
    public KeyScopes normalized() {
        return new KeyScopes(roles, providers, models, paths, policy);
    }

    public boolean has(final Role role) {
        return roles.contains(role);
    }

    /** Why this key may not make the request, or null when it may. */
    public ScopeDenial check(final String provider, final String model, final String path) {
        if (!providers.isEmpty() && providers.stream().noneMatch(entry -> matches(entry, provider, false))) {
            return new ScopeDenial("scope_denied_provider", "provider");
        }
        if (!models.isEmpty() && (model == null || models.stream().noneMatch(entry -> matches(entry, model, false)))) {
            return new ScopeDenial("scope_denied_model", "model");
        }
        if (!paths.isEmpty() && paths.stream().noneMatch(entry -> matches(entry, path, true))) {
            return new ScopeDenial("scope_denied_path", "path");
        }
        return null;
    }

    public record ScopeDenial(String code, String field) {
    }

    static boolean matches(final String entry, final String value, final boolean alwaysPrefix) {
        if (value == null) {
            return false;
        }
        if (entry.equals(value)) {
            return true;
        }
        if (alwaysPrefix) {
            return value.startsWith(entry);
        }
        return entry.endsWith("*") && value.startsWith(entry.substring(0, entry.length() - 1));
    }

}
