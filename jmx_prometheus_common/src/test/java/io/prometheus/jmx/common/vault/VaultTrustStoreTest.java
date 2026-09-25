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

package io.prometheus.jmx.common.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class VaultTrustStoreTest {

    /** Password of the test key store and of the PKCS12 trust store. */
    public static final String PASSWORD = "changeit";

    private static final String ALIAS = "keystore.password";

    @TempDir File tempDir;

    private MockVault vault;
    private List<String> settings;

    /** A test resource of this package as a file. */
    public static File resource(String name) {
        try {
            return new File(VaultTrustStoreTest.class.getResource(name).toURI());
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The server context of {@code localhost.p12}, whose certificate is self-signed. */
    public static SSLContext serverContext() throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(resource("localhost.p12").toPath())) {
            keyStore.load(in, PASSWORD.toCharArray());
        }
        KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, PASSWORD.toCharArray());
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
        return sslContext;
    }

    @BeforeEach
    public void setUp() throws Exception {
        vault = new MockVault(serverContext());
        vault.putSecret("secret/data/jmx/" + ALIAS, "value", "s3cret");
        File tokenFile = new File(tempDir, "vault-token");
        Files.write(tokenFile.toPath(), MockVault.TOKEN.getBytes(StandardCharsets.UTF_8));
        settings = new ArrayList<>();
        settings.add("tokenPath: " + tokenFile.getAbsolutePath());
        settings.add("retryIntervalMs: 1");
    }

    @AfterEach
    public void tearDown() {
        vault.close();
    }

    private String read(String... trustStoreSettings) throws IOException {
        for (String setting : trustStoreSettings) {
            settings.add(setting);
        }
        return VaultCredentialProviderTest.create("uri: " + vault.uri("secret/jmx"), settings)
                .getCredential(ALIAS);
    }

    private static String trustStore(String name) {
        return "trustStore: {filename: " + resource(name).getAbsolutePath() + "}";
    }

    @Test
    public void testPemTrustStore() throws Exception {
        assertThat(read(trustStore("localhost.pem"))).isEqualTo("s3cret");
    }

    @Test
    public void testPemTrustStoreOfAnyName() throws Exception {
        File file = new File(tempDir, "ca-bundle");
        Files.copy(
                resource("localhost.pem").toPath(),
                file.toPath(),
                StandardCopyOption.REPLACE_EXISTING);
        assertThat(read("trustStore: {filename: " + file.getAbsolutePath() + ", type: PEM}"))
                .isEqualTo("s3cret");
    }

    @Test
    public void testJksTrustStoreWithoutPassword() throws Exception {
        assertThat(read(trustStore("localhost-truststore.jks"))).isEqualTo("s3cret");
    }

    @Test
    public void testJksTrustStoreWithWrongPassword() {
        String setting =
                "trustStore: {filename: "
                        + resource("localhost-truststore.jks").getAbsolutePath()
                        + ", password: wrong}";
        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> read(setting))
                .withMessageContaining("Failed to load the Vault trust store");
    }

    @Test
    public void testPkcs12TrustStoreNeedsItsPassword() throws Exception {
        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> read(trustStore("localhost-truststore.p12")))
                .withMessageContaining("no certificate readable without a password");

        settings.remove(settings.size() - 1);
        String setting =
                "trustStore: {filename: "
                        + resource("localhost-truststore.p12").getAbsolutePath()
                        + ", type: PKCS12, password: "
                        + PASSWORD
                        + "}";
        assertThat(read(setting)).isEqualTo("s3cret");
    }

    @Test
    public void testServerOutsideTrustStore() {
        assertThatExceptionOfType(SSLHandshakeException.class).isThrownBy(this::read);
        assertThat(vault.requests()).isEmpty();
    }

    @Test
    public void testTypeByExtension() {
        assertThat(VaultTrustStore.typeOf("/etc/ssl/ca.PEM")).isEqualTo("PEM");
        assertThat(VaultTrustStore.typeOf("ca.crt")).isEqualTo("PEM");
        assertThat(VaultTrustStore.typeOf("truststore.p12")).isEqualTo("PKCS12");
        assertThat(VaultTrustStore.typeOf("vault-ca.jks")).isEqualTo("JKS");
        assertThat(VaultTrustStore.typeOf("truststore")).isEqualTo(KeyStore.getDefaultType());
    }
}
