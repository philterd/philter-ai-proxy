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
import ai.philterd.aiproxy.proxy.ClientAddress;
import ai.philterd.aiproxy.providers.DefaultCloudCredentials;
import ai.philterd.aiproxy.providers.ProviderRegistry;
import ai.philterd.aiproxy.redaction.PolicyCompiler;
import ai.philterd.aiproxy.storage.Encryptor;
import org.springframework.boot.Banner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;

import java.io.InputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Properties;

/**
 * Starts the proxy. Two options run instead and exit: {@code --version} prints the version, and
 * {@code --validate-config} checks the configuration (settings, providers, the encryption key, trusted proxies)
 * without opening the database or serving requests, exiting non-zero when it is invalid.
 */
@SpringBootApplication
@EnableConfigurationProperties(ProxyProperties.class)
public class ProxyApplication {

    public static void main(final String[] args) {
        if (Arrays.asList(args).contains("--version")) {
            System.out.println("philter-ai-proxy " + version());
            return;
        }
        if (Arrays.asList(args).contains("--validate-config")) {
            System.exit(validate(args, System.out, System.err));
        }
        SpringApplication.run(ProxyApplication.class, args);
    }

    /** The version from the build, or {@code unknown} when run outside a packaged build. */
    static String version() {
        try (InputStream in = ProxyApplication.class.getResourceAsStream("/META-INF/build-info.properties")) {
            if (in != null) {
                final Properties p = new Properties();
                p.load(in);
                return p.getProperty("build.version", "unknown");
            }
        } catch (final Exception e) {
            // Reported as unknown.
        }
        return "unknown";
    }

    /** Only the configuration properties, for {@code --validate-config}. */
    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(ProxyProperties.class)
    static class ConfigurationOnly {
    }

    /** @return The exit status: 0 when the configuration is valid. */
    static int validate(final String[] args, final PrintStream out, final PrintStream err) {
        final String[] rest = Arrays.stream(args).filter(a -> !a.equals("--validate-config")).toArray(String[]::new);
        final SpringApplication application = new SpringApplication(ConfigurationOnly.class);
        application.setWebApplicationType(WebApplicationType.NONE);
        application.setBannerMode(Banner.Mode.OFF);
        application.setLogStartupInfo(false);
        try (ConfigurableApplicationContext context = application.run(rest)) {
            final ProxyProperties properties = context.getBean(ProxyProperties.class);
            new Encryptor(properties);
            new ClientAddress(properties);
            new ProviderRegistry(properties, new DefaultCloudCredentials());
            new PolicyCompiler(properties);
            out.println("The configuration is valid.");
            return 0;
        } catch (final RuntimeException e) {
            Throwable cause = e;
            while (cause.getCause() != null) {
                cause = cause.getCause();
            }
            err.println("The configuration is not valid: " + cause.getMessage());
            return 1;
        }
    }

}
