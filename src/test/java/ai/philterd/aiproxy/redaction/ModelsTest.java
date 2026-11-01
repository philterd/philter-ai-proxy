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
import ai.philterd.aiproxy.storage.ContextStore;
import ai.philterd.aiproxy.storage.Database;
import ai.philterd.aiproxy.storage.Encryptor;
import ai.philterd.aiproxy.storage.PolicyStore;
import ai.philterd.phileas.policy.Policy;
import com.google.gson.Gson;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModelsTest {

    static Path fakeModel(final Path dir, final String name, final boolean nested) throws Exception {
        final Path model = dir.resolve(name);
        Files.createDirectories(nested ? model.resolve("onnx") : model);
        Files.writeString(model.resolve("gliner_config.json"), "{}");
        Files.writeString(model.resolve("tokenizer.json"), "{}");
        Files.writeString((nested ? model.resolve("onnx") : model).resolve("model.onnx"), "");
        return model;
    }

    @Test
    void findsCompleteModelsByName(@TempDir final Path dir) throws Exception {
        final Path flat = fakeModel(dir, "flat-model", false);
        fakeModel(dir, "nested.model_1", true);
        Files.createDirectories(dir.resolve("incomplete"));
        Files.writeString(dir.resolve("incomplete").resolve("tokenizer.json"), "{}");
        Files.createDirectories(dir.resolve(".hidden"));
        Files.writeString(dir.resolve("a-file"), "");

        final PhEyeModels models = new PhEyeModels(dir);
        assertEquals(List.of("flat-model", "nested.model_1"), models.list().stream().map(PhEyeModels.PhEyeModel::name).toList());
        assertTrue(models.contains("flat-model"));
        assertTrue(models.contains(flat.toString()));
        assertFalse(models.contains("incomplete"));
        assertFalse(models.contains("../flat-model"));
        assertFalse(models.contains(dir.resolve("incomplete").toString()));
        assertFalse(models.contains(""));
        assertFalse(models.contains(null));
        assertTrue(PhEyeModels.isName("flat-model"));
        assertFalse(PhEyeModels.isName("a/b"));
        assertEquals(dir, models.getDirectory());
        assertEquals(List.of(), new PhEyeModels(dir.resolve("absent")).list());

        final Policy policy = new Gson().fromJson("""
                {"identifiers":{"person":{"phEyeConfiguration":{"modelPath":"flat-model"}},
                 "pheyes":[{"phEyeConfiguration":{"modelPath":"nested.model_1"}}]}}""", Policy.class);
        models.resolveNames(policy);
        assertEquals(flat.toRealPath().toString(), policy.getIdentifiers().getPerson().getPhEyeConfiguration().getModelPath());
        assertTrue(policy.getIdentifiers().getPhEyes().getFirst().getPhEyeConfiguration().getModelPath().endsWith("nested.model_1"));

        final Policy missing = new Gson().fromJson("""
                {"identifiers":{"person":{"phEyeConfiguration":{"modelPath":"gone"}}}}""", Policy.class);
        assertThrows(PolicyException.class, () -> models.resolveNames(missing));
    }

    /**
     * Runs the default policy's person-name filter with a real model. Set PHILTER_AI_PROXY_TEST_MODELS to a
     * directory holding ph-eye-pii-en-small, such as /opt/philter/models copied out of the philterd/philter image.
     */
    @Test
    @EnabledIfEnvironmentVariable(named = "PHILTER_AI_PROXY_TEST_MODELS", matches = ".+")
    void redactsPersonNamesWithTheBundledModel(@TempDir final Path dir) throws Exception {
        final ProxyProperties properties = new ProxyProperties(new ProxyProperties.Storage(dir.resolve("p.db").toString()),
                new ProxyProperties.Security("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", null, null),
                new ProxyProperties.Models(System.getenv("PHILTER_AI_PROXY_TEST_MODELS")), null, null, null, null, null, null);
        try (Database database = new Database(properties)) {
            final PolicyStore policies = new PolicyStore(database);
            policies.create("default", ai.philterd.aiproxy.FirstStartAccess.defaultPolicy(), "", "");
            final Redactor redactor = new Redactor(policies, new ContextStore(database, new Encryptor(properties)),
                    new PolicyCompiler(properties));
            final List<Redactor.Redaction> out = redactor.session("default", null)
                    .redact(List.of("George Washington was the first president.", "Write to jane.doe@example.com."));
            assertEquals("{{{REDACTED-name}}} was the first president.", out.get(0).text());
            assertEquals("Write to {{{REDACTED-email-address}}}.", out.get(1).text());
        }
    }

}
