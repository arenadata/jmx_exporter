/*
 * Copyright (C) The Prometheus jmx_exporter Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.prometheus.jmx.common.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.prometheus.jmx.common.ConfigurationException;
import io.prometheus.jmx.common.HTTPServerFactory;
import io.prometheus.jmx.common.vault.MockVault;
import io.prometheus.jmx.common.vault.VaultTrustStoreTest;
import io.prometheus.metrics.exporter.httpserver.HTTPServer;
import io.prometheus.metrics.model.registry.PrometheusRegistry;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class HTTPServerFactoryCredentialProviderTest {

    private static final String KEYSTORE_ALIAS = "keystore.password";
    private static final String TRUSTSTORE_ALIAS = "truststore.password";
    private static final String KEYSTORE_PASSWORD_PROPERTY = "javax.net.ssl.keyStorePassword";

    @TempDir File tempDir;

    private MockVault vault;
    private File tokenFile;
    private HTTPServer httpServer;
    private String previousKeyStorePassword;

    @BeforeEach
    public void setUp() throws IOException {
        vault = new MockVault();
        tokenFile = new File(tempDir, "vault-token");
        Files.write(tokenFile.toPath(), MockVault.TOKEN.getBytes(StandardCharsets.UTF_8));
        previousKeyStorePassword = System.clearProperty(KEYSTORE_PASSWORD_PROPERTY);
    }

    @AfterEach
    public void tearDown() {
        if (httpServer != null) {
            httpServer.stop();
        }
        vault.close();
        if (previousKeyStorePassword == null) {
            System.clearProperty(KEYSTORE_PASSWORD_PROPERTY);
        } else {
            System.setProperty(KEYSTORE_PASSWORD_PROPERTY, previousKeyStorePassword);
        }
    }

    private String providerBlock(String uri) {
        return "  credentialProvider:\n"
                + "    uri: "
                + uri
                + "\n"
                + "    tokenPath: "
                + tokenFile.getAbsolutePath()
                + "\n"
                + "    retryCount: 0\n";
    }

    private static String keyStoreBlock(String... settings) {
        StringBuilder yaml =
                new StringBuilder("  ssl:\n")
                        .append("    certificate:\n")
                        .append("      alias: localhost\n")
                        .append("    keyStore:\n")
                        .append("      filename: ")
                        .append(VaultTrustStoreTest.resource("localhost.p12").getAbsolutePath())
                        .append("\n")
                        .append("      type: PKCS12\n");
        for (String setting : settings) {
            yaml.append("      ").append(setting).append('\n');
        }
        return yaml.toString();
    }

    private HTTPServer start(String yaml) throws IOException {
        File config = new File(tempDir, "exporter.yaml");
        Files.write(config.toPath(), ("httpServer:\n" + yaml).getBytes(StandardCharsets.UTF_8));
        httpServer =
                HTTPServerFactory.createAndStartHTTPServer(
                        PrometheusRegistry.defaultRegistry,
                        InetAddress.getLoopbackAddress(),
                        0,
                        config);
        return httpServer;
    }

    private static int getMetrics(HTTPServer server) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        try (InputStream in =
                Files.newInputStream(VaultTrustStoreTest.resource("localhost.pem").toPath())) {
            trustStore.setCertificateEntry(
                    "localhost", CertificateFactory.getInstance("X.509").generateCertificate(in));
        }
        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        HttpsURLConnection connection =
                (HttpsURLConnection)
                        new URL("https://localhost:" + server.getPort() + "/metrics")
                                .openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        try {
            return connection.getResponseCode();
        } finally {
            connection.disconnect();
        }
    }

    private List<String> reads() {
        List<String> reads = new ArrayList<>();
        for (String request : vault.requests()) {
            if (request.startsWith("GET /v1/secret/")) {
                reads.add(request.substring(request.lastIndexOf('/') + 1));
            }
        }
        return reads;
    }

    @Test
    public void testKeyStorePasswordFromProvider() throws Exception {
        vault.putSecret("secret/data/jmx/" + KEYSTORE_ALIAS, "value", "changeit");
        start(
                providerBlock(vault.uri("secret/jmx"))
                        + keyStoreBlock("passwordAlias: " + KEYSTORE_ALIAS));
        assertThat(getMetrics(httpServer)).isEqualTo(200);
        assertThat(reads()).containsExactly(KEYSTORE_ALIAS);
    }

    @Test
    public void testProviderTakesPrecedence() throws Exception {
        vault.putSecret("secret/data/jmx/" + KEYSTORE_ALIAS, "value", "changeit");
        System.setProperty(KEYSTORE_PASSWORD_PROPERTY, "wrong");
        start(
                providerBlock(vault.uri("secret/jmx"))
                        + keyStoreBlock("passwordAlias: " + KEYSTORE_ALIAS, "password: wrong"));
        assertThat(getMetrics(httpServer)).isEqualTo(200);
    }

    @Test
    public void testAbsentAliasFallsBackToPassword() throws Exception {
        start(
                providerBlock(vault.uri("secret/jmx"))
                        + keyStoreBlock("passwordAlias: " + KEYSTORE_ALIAS, "password: changeit"));
        assertThat(getMetrics(httpServer)).isEqualTo(200);
        assertThat(reads()).containsExactly(KEYSTORE_ALIAS);
    }

    @Test
    public void testDeniedAliasFallsBackToSystemProperty() throws Exception {
        vault.putSecret("secret/data/jmx/" + KEYSTORE_ALIAS, "value", "wrong");
        vault.deny("secret/data/jmx/" + KEYSTORE_ALIAS);
        System.setProperty(KEYSTORE_PASSWORD_PROPERTY, "changeit");
        start(
                providerBlock(vault.uri("secret/jmx"))
                        + keyStoreBlock("passwordAlias: " + KEYSTORE_ALIAS));
        assertThat(getMetrics(httpServer)).isEqualTo(200);
    }

    @Test
    public void testNoRequestWithoutAlias() throws Exception {
        start(providerBlock(vault.uri("secret/jmx")) + keyStoreBlock("password: changeit"));
        assertThat(getMetrics(httpServer)).isEqualTo(200);
        assertThat(vault.requests()).isEmpty();
    }

    @Test
    public void testAliasWithoutProviderFails() {
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> start(keyStoreBlock("passwordAlias: " + KEYSTORE_ALIAS)))
                .withMessageContaining(
                        "/httpServer/ssl/keyStore/passwordAlias requires"
                                + " /httpServer/credentialProvider");
    }

    @Test
    public void testUnreachableProviderFails() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(
                        () ->
                                start(
                                        providerBlock(
                                                        "vault://http@localhost:"
                                                                + port
                                                                + "/secret/jmx")
                                                + keyStoreBlock(
                                                        "passwordAlias: " + KEYSTORE_ALIAS,
                                                        "password: changeit")))
                .withMessageContaining("Exception loading SSL configuration")
                .withMessageContaining("failed after 1 attempts");
    }

    @Test
    public void testTrustStorePasswordFromProvider() throws Exception {
        vault.putSecret("secret/data/jmx/" + KEYSTORE_ALIAS, "value", "changeit");
        String trustStore =
                "    mutualTLS: true\n"
                        + "    trustStore:\n"
                        + "      filename: "
                        + VaultTrustStoreTest.resource("localhost-truststore.p12").getAbsolutePath()
                        + "\n"
                        + "      type: PKCS12\n"
                        + "      passwordAlias: "
                        + TRUSTSTORE_ALIAS
                        + "\n";

        vault.putSecret("secret/data/jmx/" + TRUSTSTORE_ALIAS, "value", "wrong");
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(
                        () ->
                                start(
                                        providerBlock(vault.uri("secret/jmx"))
                                                + keyStoreBlock("passwordAlias: " + KEYSTORE_ALIAS)
                                                + trustStore));

        vault.putSecret("secret/data/jmx/" + TRUSTSTORE_ALIAS, "value", "changeit");
        start(
                providerBlock(vault.uri("secret/jmx"))
                        + keyStoreBlock("passwordAlias: " + KEYSTORE_ALIAS)
                        + trustStore);
        assertThat(reads())
                .containsExactlyElementsOf(
                        Arrays.asList(
                                KEYSTORE_ALIAS,
                                TRUSTSTORE_ALIAS,
                                KEYSTORE_ALIAS,
                                TRUSTSTORE_ALIAS));
    }

    @Test
    public void testTrustStoreAliasIsNotReadWithoutMutualTLS() throws Exception {
        vault.putSecret("secret/data/jmx/" + KEYSTORE_ALIAS, "value", "changeit");
        start(
                providerBlock(vault.uri("secret/jmx"))
                        + keyStoreBlock("passwordAlias: " + KEYSTORE_ALIAS)
                        + "    trustStore:\n"
                        + "      passwordAlias: "
                        + TRUSTSTORE_ALIAS
                        + "\n");
        assertThat(reads()).containsExactly(KEYSTORE_ALIAS);
    }
}
