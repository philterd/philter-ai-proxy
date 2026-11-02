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

import java.util.function.UnaryOperator;

/** Chooses the policy, context, and outbound scanning for a request. */
public final class Routes {

    public record Resolved(String policy, String context, ProxyProperties.Outbound outbound,
                           ProxyProperties.Mode media, ProxyProperties.Mode unsupportedEndpoints) {
    }

    private Routes() {
    }

    /**
     * The first route whose every set condition matches, else the defaults. A route without a policy or context
     * uses the default's; a route without outbound settings does not scan responses; a route without a media or
     * unsupported-endpoints setting uses the default's.
     */
    public static Resolved resolve(final ProxyProperties properties, final String path, final String model,
                                   final UnaryOperator<String> header) {
        return resolve(properties, path, model, header, false);
    }

    /**
     * @param skipHeaderRoutes Skip routes that match on a header. A header is chosen by the client, so a key whose
     *                         policy is bound must not be able to pick a route that forwards media, turns off response
     *                         scanning, or names a context.
     */
    public static Resolved resolve(final ProxyProperties properties, final String path, final String model,
                                   final UnaryOperator<String> header, final boolean skipHeaderRoutes) {
        final ProxyProperties.Defaults defaults = properties.defaults();
        for (final ProxyProperties.Route route : properties.routes()) {
            final ProxyProperties.Match match = route.match();
            if (skipHeaderRoutes && match.header() != null && !match.header().isBlank()) {
                continue;
            }
            if (match.header() != null && !match.header().isBlank()
                    && !java.util.Objects.equals(header.apply(match.header()), match.value())) {
                continue;
            }
            if (match.path() != null && !match.path().isBlank() && !match.path().equals(path)) {
                continue;
            }
            if (match.model() != null && !match.model().isBlank() && !match.model().equals(model)) {
                continue;
            }
            return new Resolved(route.policy() == null ? defaults.policy() : route.policy(),
                    route.context() == null ? defaults.context() : route.context(),
                    route.outbound() == null ? ProxyProperties.Outbound.DISABLED : route.outbound(),
                    route.media() == null ? defaults.media() : route.media(),
                    route.unsupportedEndpoints() == null ? defaults.unsupportedEndpoints() : route.unsupportedEndpoints());
        }
        return new Resolved(defaults.policy(), defaults.context(), defaults.outbound(), defaults.media(),
                defaults.unsupportedEndpoints());
    }

}
