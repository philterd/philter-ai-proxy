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

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/** Certificates generated with keytool for TLS tests, so none are committed. */
final class TestCerts {

    static final String PASSWORD = "test-password";

    private TestCerts() {
    }

    static void keytool(final String... args) {
        final List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        command.addAll(List.of(args));
        try {
            final Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            final String output = new String(process.getInputStream().readAllBytes());
            if (process.waitFor() != 0) {
                throw new IllegalStateException("keytool failed: " + output);
            }
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A PKCS12 keystore with a self-signed key pair. */
    static Path keyPair(final Path dir, final String name, final String san) {
        final Path store = dir.resolve(name + ".p12");
        keytool("-genkeypair", "-alias", name, "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "2",
                "-dname", "CN=" + name, "-ext", "SAN=" + san, "-storetype", "PKCS12", "-keystore", store.toString(),
                "-storepass", PASSWORD, "-keypass", PASSWORD);
        return store;
    }

    /** A PKCS12 truststore holding the certificate of the key pair in {@code keystore}. */
    static Path trusting(final Path dir, final Path keystore, final String alias, final String name) {
        final Path certificate = dir.resolve(alias + ".crt");
        keytool("-exportcert", "-alias", alias, "-keystore", keystore.toString(), "-storepass", PASSWORD, "-rfc",
                "-file", certificate.toString());
        final Path store = dir.resolve(name + ".p12");
        keytool("-importcert", "-noprompt", "-alias", alias, "-file", certificate.toString(), "-storetype", "PKCS12",
                "-keystore", store.toString(), "-storepass", PASSWORD);
        return store;
    }

    static KeyStore load(final Path store) throws Exception {
        final KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(store)) {
            keyStore.load(in, PASSWORD.toCharArray());
        }
        return keyStore;
    }

    /** A client context presenting {@code keystore} (or nothing) and trusting {@code truststore}. */
    static SSLContext client(final Path keystore, final Path truststore) throws Exception {
        final SSLContext context = SSLContext.getInstance("TLS");
        KeyManagerFactory keys = null;
        if (keystore != null) {
            keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(load(keystore), PASSWORD.toCharArray());
        }
        final TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(load(truststore));
        context.init(keys == null ? null : keys.getKeyManagers(), trust.getTrustManagers(), null);
        return context;
    }

    /** Trusts any server certificate: only for testing the development certificate, which nothing can trust. */
    static SSLContext trustingAnything() throws Exception {
        final SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{new X509TrustManager() {
            @Override
            public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
            }

            @Override
            public void checkServerTrusted(final X509Certificate[] chain, final String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }}, null);
        return context;
    }

}
