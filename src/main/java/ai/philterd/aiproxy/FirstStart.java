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
import ai.philterd.aiproxy.security.KeyScopes;
import ai.philterd.aiproxy.storage.ApiKeyStore;
import ai.philterd.aiproxy.storage.PolicyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/**
 * Creates what a new deployment needs: the built-in {@code default} policy, and an admin key from
 * {@code proxy.security.bootstrap-api-key} while no key exists. Runs at startup, before requests are served.
 */
@Component
public class FirstStart {

    private static final Logger LOGGER = LoggerFactory.getLogger(FirstStart.class);
    static final int MIN_BOOTSTRAP_KEY_LENGTH = 32;

    /**
     * The default policy, as Philter's: person names with the bundled ph-eye-pii-en-small model at the threshold
     * the model recommends, SSNs, and email addresses.
     */
    static final String DEFAULT_POLICY_JSON = """
            {
              "identifiers": {
                "person": {
                  "phEyeConfiguration": {
                    "modelPath": "ph-eye-pii-en-small",
                    "labels": ["name"],
                    "threshold": 0.9
                  },
                  "phEyeFilterStrategies": [
                    { "strategy": "REDACT" }
                  ]
                },
                "ssn": {
                  "ssnFilterStrategies": [
                    { "strategy": "REDACT" }
                  ]
                },
                "emailAddress": {
                  "emailAddressFilterStrategies": [
                    { "strategy": "REDACT" }
                  ]
                }
              }
            }
            """;

    public FirstStart(final ProxyProperties properties, final PolicyStore policies, final ApiKeyStore keys) {
        if (policies.create(PolicyStore.DEFAULT_POLICY_NAME, DEFAULT_POLICY_JSON, "Default policy",
                "Created on first start. It can be changed, but not deleted.").isPresent()) {
            LOGGER.info("Created the default policy.");
        }
        if (keys.count() == 0) {
            final String bootstrap = properties.security().bootstrapApiKey();
            if (bootstrap == null || bootstrap.isBlank()) {
                LOGGER.warn("There are no API keys. Set proxy.security.bootstrap-api-key (PROXY_SECURITY_BOOTSTRAPAPIKEY) "
                        + "to create an admin key, then create proxy keys with POST /admin/api/keys.");
            } else if (bootstrap.strip().length() < MIN_BOOTSTRAP_KEY_LENGTH) {
                throw new IllegalStateException("proxy.security.bootstrap-api-key must be at least "
                        + MIN_BOOTSTRAP_KEY_LENGTH + " characters. Generate one with: openssl rand -hex 32");
            } else {
                keys.insert("bootstrap", bootstrap.strip(), new KeyScopes(Set.of(KeyScopes.Role.admin), List.of(), List.of(), List.of(), null));
                LOGGER.info("Created the bootstrap admin key.");
            }
        }
    }

}
