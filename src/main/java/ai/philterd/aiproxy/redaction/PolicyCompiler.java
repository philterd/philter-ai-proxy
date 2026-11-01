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

import ai.philterd.aiproxy.config.ProxyProperties;
import ai.philterd.phileas.PhileasConfiguration;
import ai.philterd.phileas.policy.Identifiers;
import ai.philterd.phileas.policy.InvalidPolicyEnvironmentException;
import ai.philterd.phileas.policy.Policy;
import ai.philterd.phileas.policy.PolicyEnvironment;
import ai.philterd.phileas.policy.filters.PhEye;
import ai.philterd.phileas.services.FilterPolicyLoader;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

/**
 * Turns stored policy JSON into a Phileas {@link Policy}, refusing one the deployment does not allow or Phileas
 * will not load. The same checks run when a policy is saved and before it is used, so a policy that became
 * invalid (a model removed, a Phileas upgrade) is refused with its reason rather than failing redaction.
 */
@Component
public class PolicyCompiler {

    private static final Logger LOGGER = LoggerFactory.getLogger(PolicyCompiler.class);

    /** The largest policy accepted, in characters. */
    public static final int MAX_POLICY_CHARACTERS = 1_000_000;

    private final Gson gson = new Gson();
    private final PhEyeModels models;
    private final PolicyResourceCheck resources;
    private final PhileasConfiguration phileasConfiguration;
    private final FilterPolicyLoader loader;

    public PolicyCompiler(final ProxyProperties properties) {
        this.models = new PhEyeModels(Path.of(properties.models().directory()));
        this.resources = new PolicyResourceCheck(models);
        this.phileasConfiguration = phileasConfiguration(properties);
        // No HTTP client: a policy cannot reach a PhEye service from here, and building filters needs none.
        this.loader = new FilterPolicyLoader(phileasConfiguration, new SecureRandom(), null);
        PolicyEnvironment.restrictTo(properties.policyFiles().allowedEnvironmentVariables());
    }

    static PhileasConfiguration phileasConfiguration(final ProxyProperties properties) {
        final Properties p = new Properties();
        p.put("incremental.redactions.enabled", "false");
        p.put("span.disambiguation.enabled", "false");
        // A policy may name only files in these directories, and no file when there are none.
        p.put("policy.files.restricted", "true");
        p.put("policy.files.directories", String.join(",", properties.policyFiles().directories()));
        return new PhileasConfiguration(p);
    }

    public PhileasConfiguration getPhileasConfiguration() {
        return phileasConfiguration;
    }

    public PhEyeModels getModels() {
        return models;
    }

    /**
     * Parses, checks, and loads the policy.
     * @throws PolicyException With a reason safe to return to whoever wrote the policy.
     */
    public Policy compile(final String policyJson) {
        if (policyJson == null || policyJson.isBlank()) {
            throw new PolicyException("The policy is empty.");
        }
        if (policyJson.length() > MAX_POLICY_CHARACTERS) {
            throw new PolicyException("The policy is larger than " + MAX_POLICY_CHARACTERS + " characters.");
        }
        final JsonObject json;
        try {
            final JsonElement element = JsonParser.parseString(policyJson);
            if (!element.isJsonObject()) {
                throw new PolicyException("The policy must be a JSON object.");
            }
            json = element.getAsJsonObject();
        } catch (final JsonParseException e) {
            throw new PolicyException("The policy is not valid JSON.");
        }
        if (!(json.get("identifiers") instanceof JsonObject)) {
            throw new PolicyException("The policy needs an identifiers object.");
        }

        final String resource = resources.refusal(json);
        if (resource != null) {
            throw new PolicyException(resource);
        }

        final Policy policy;
        try {
            policy = gson.fromJson(json, Policy.class);
        } catch (final JsonParseException | IllegalStateException | NumberFormatException e) {
            throw new PolicyException("The policy is not a valid Phileas policy: " + e.getMessage());
        }
        if (policy.getIgnored() == null) {
            policy.setIgnored(new ArrayList<>());
        }
        requireLocalModels(policy);
        models.resolveNames(policy);

        try {
            loader.getFiltersForPolicy(policy, new HashMap<>());
        } catch (final InvalidPolicyEnvironmentException e) {
            throw new PolicyException(e.getMessage());
        } catch (final IllegalArgumentException e) {
            throw new PolicyException("Phileas refused the policy: " + e.getMessage());
        } catch (final Exception e) {
            // Phileas's own refusals (an invalid condition or pattern) arrive as checked exceptions.
            LOGGER.debug("Building the policy's filters failed", e);
            throw new PolicyException("Phileas refused the policy: " + e.getMessage());
        }
        return policy;
    }

    /** Every PhEye filter runs a local model: the proxy does not call a PhEye service. */
    private static void requireLocalModels(final Policy policy) {
        final Identifiers identifiers = policy.getIdentifiers();
        final List<PhEye> phEyes = new ArrayList<>();
        if (identifiers.getPerson() != null) {
            phEyes.add(identifiers.getPerson());
        }
        if (identifiers.getPhEyes() != null) {
            phEyes.addAll(identifiers.getPhEyes());
        }
        for (final PhEye phEye : phEyes) {
            final String modelPath = phEye.getPhEyeConfiguration().getModelPath();
            if (modelPath == null || modelPath.isBlank()) {
                throw new PolicyException("A PhEye filter needs phEyeConfiguration.modelPath naming a model in the "
                        + "models directory. The proxy runs models in-process and does not call a PhEye service.");
            }
        }
    }

}
