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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.Map;

/**
 * Keeps a policy from directing the proxy's requests or credentials. Whoever writes a policy must not be able to
 * send the text being redacted to a server of their choosing, so a policy may not name a PhEye {@code endpoint} or
 * {@code bearerToken}, a PhEye {@code modelPath} outside the models directory, or generators.
 * Detection runs in-process; the proxy does not call a PhEye service.
 *
 * <p>Stricter than Philter's equivalent, which allows listed PhEye and generator endpoints.
 * Checks the policy JSON as submitted, so a default Phileas fills in is not mistaken for one the policy set.</p>
 */
public final class PolicyResourceCheck {

    private final PhEyeModels models;

    public PolicyResourceCheck(final PhEyeModels models) {
        this.models = models;
    }

    /**
     * Why the policy reaches a service or file the deployment does not allow, or null when it does not.
     * @param policy The policy as JSON.
     */
    public String refusal(final JsonObject policy) {
        final String pheye = refusalInPhEyeConfigurations(policy);
        if (pheye != null) {
            return pheye;
        }
        if (policy.get("generators") instanceof JsonObject generators && !generators.isEmpty()) {
            return "A policy cannot define generators here. They call an external service, and the proxy does not.";
        }
        return null;
    }

    /** Checks every phEyeConfiguration object in the policy, wherever it is. */
    private String refusalInPhEyeConfigurations(final JsonElement element) {
        if (element instanceof JsonObject object) {
            for (final Map.Entry<String, JsonElement> entry : object.entrySet()) {
                final String reason = "phEyeConfiguration".equals(entry.getKey()) && entry.getValue() instanceof JsonObject configuration
                        ? refusalOfPhEye(configuration)
                        : refusalInPhEyeConfigurations(entry.getValue());
                if (reason != null) {
                    return reason;
                }
            }
        } else if (element != null && element.isJsonArray()) {
            for (final JsonElement item : element.getAsJsonArray()) {
                final String reason = refusalInPhEyeConfigurations(item);
                if (reason != null) {
                    return reason;
                }
            }
        }
        return null;
    }

    private String refusalOfPhEye(final JsonObject configuration) {
        if (isSet(configuration, "endpoint")) {
            return "A policy cannot name a PhEye endpoint. The proxy runs PhEye models in-process: set modelPath to "
                    + "a model in the models directory instead.";
        }
        if (isSet(configuration, "bearerToken")) {
            return "A policy cannot set a PhEye bearerToken.";
        }
        if (!isSet(configuration, "modelPath")) {
            // A PhEye filter without a modelPath is refused by PolicyCompiler, which also sees filters that
            // have no phEyeConfiguration object at all.
            return null;
        }
        final String modelPath = configuration.get("modelPath").getAsString();
        if (!models.contains(modelPath)) {
            return "The PhEye modelPath '" + modelPath + "' is not a model in the models directory.";
        }
        return null;
    }

    private static boolean isSet(final JsonObject object, final String field) {
        return object.has(field) && !object.get(field).isJsonNull();
    }

}
