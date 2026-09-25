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

import io.prometheus.jmx.common.ConfigurationException;
import io.prometheus.jmx.common.util.MapAccessor;
import io.prometheus.jmx.common.util.YamlSupport;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLHandshakeException;
import javax.security.auth.login.LoginException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class VaultCredentialProviderTest {

    private static final String ALIAS = "keystore.password";
    private static final String DATA_PATH = "secret/data/jmx/" + ALIAS;
    private static final String TRUSTSTORE_ALIAS = "truststore.password";
    private static final String TRUSTSTORE_DATA_PATH = "secret/data/jmx/" + TRUSTSTORE_ALIAS;

    @TempDir File tempDir;

    private MockVault vault;
    private File tokenFile;
    private List<String> settings;

    @BeforeEach
    public void setUp() throws IOException {
        vault = new MockVault();
        tokenFile = new File(tempDir, "vault-token");
        writeToken(MockVault.TOKEN + "\n");
        settings = new ArrayList<>();
        settings.add("tokenPath: " + tokenFile.getAbsolutePath());
        settings.add("retryIntervalMs: 1");
    }

    @AfterEach
    public void tearDown() {
        vault.close();
    }

    private void writeToken(String content) throws IOException {
        Files.write(tokenFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
    }

    private VaultCredentialProvider provider() throws IOException {
        return provider(vault.uri("secret/jmx"));
    }

    private VaultCredentialProvider provider(String uri) throws IOException {
        return create("uri: " + uri, settings);
    }

    static VaultCredentialProvider create(String uriSetting, List<String> settings)
            throws IOException {
        StringBuilder yaml = new StringBuilder("httpServer:\n  credentialProvider:\n");
        yaml.append("    ").append(uriSetting).append('\n');
        for (String setting : settings) {
            yaml.append("    ").append(setting).append('\n');
        }
        return VaultCredentialProvider.create(
                MapAccessor.of(YamlSupport.loadYaml(yaml.toString())),
                "/httpServer/credentialProvider");
    }

    private static IOException failure(ThrowingCall call) {
        try {
            call.call();
        } catch (IOException e) {
            return e;
        }
        throw new AssertionError("expected an IOException");
    }

    private interface ThrowingCall {

        void call() throws IOException;
    }

    @Test
    public void testReadsCredential() throws Exception {
        vault.putSecret(DATA_PATH, "value", "s3cret");
        assertThat(provider().getCredential(ALIAS)).isEqualTo("s3cret");
    }

    @Test
    public void testNoRequestBeforeFirstRead() throws Exception {
        provider();
        assertThat(vault.requests()).isEmpty();
    }

    @Test
    public void testAbsentAliasIsNull() throws Exception {
        vault.putSecret(DATA_PATH, "other", "s3cret");
        VaultCredentialProvider provider = provider();
        assertThat(provider.getCredential(ALIAS)).isNull();
        assertThat(provider.getCredential(TRUSTSTORE_ALIAS)).isNull();
    }

    @Test
    public void testFieldNamedByUri() throws Exception {
        vault.putSecret(DATA_PATH, "password", "s3cret");
        assertThat(provider(vault.uri("secret/jmx?key=password")).getCredential(ALIAS))
                .isEqualTo("s3cret");
    }

    @Test
    public void testNullFieldIsAbsent() throws Exception {
        vault.putSecretJson(DATA_PATH, "value", "null");
        assertThat(provider().getCredential(ALIAS)).isNull();
    }

    @Test
    public void testNumberFieldIsRejected() {
        vault.putSecretJson(DATA_PATH, "value", "12345678.5");
        assertThat(failure(() -> provider().getCredential(ALIAS)))
                .hasMessageContaining("is not a string");
    }

    @Test
    public void testObjectFieldIsRejected() {
        vault.putSecretJson(DATA_PATH, "value", "{\"a\":1}");
        assertThat(failure(() -> provider().getCredential(ALIAS)))
                .hasMessageContaining("is not a string");
    }

    @Test
    public void testAnswerWithoutSecretIsAnError() {
        vault.putRaw(DATA_PATH, "{\"data\":{\"value\":\"kv1\"}}");
        vault.putRaw(TRUSTSTORE_DATA_PATH, "");
        assertThat(failure(() -> provider().getCredential(ALIAS)))
                .hasMessageContaining("holds no KV v2 secret");
        assertThat(failure(() -> provider().getCredential(TRUSTSTORE_ALIAS)))
                .hasMessageContaining("is not a JSON object");
    }

    @Test
    public void testJsonEscapes() throws Exception {
        vault.putRaw(
                DATA_PATH,
                "{\"data\":\t{\"data\":{\"value\":"
                        + "\"a\\/b\\\\/c\\\"\\u003c\\t\\ud83d\\ude00\"}}}");
        assertThat(provider().getCredential(ALIAS))
                .isEqualTo("a/b\\/c\"<\t" + new String(Character.toChars(0x1F600)));
    }

    @Test
    public void testCharactersYamlDoesNotAllowAreRead() throws Exception {
        String value =
                "a"
                        + (char) 0x7F
                        + "b"
                        + (char) 0x80
                        + "c"
                        + (char) 0xFFFF
                        + "d"
                        + (char) 0x85
                        + " e "
                        + (char) 0x2028
                        + " f"
                        + (char) 0x2029;
        vault.putRaw(DATA_PATH, "{\"data\":{\"data\":{\"value\":\"" + value + "\"}}}");
        assertThat(provider().getCredential(ALIAS)).isEqualTo(value);
    }

    @Test
    public void testMalformedAnswerIsNotQuoted() {
        vault.putRaw(DATA_PATH, "{\"data\":{\"data\":{\"value\":\"s3cret\\x\"}}}");
        IOException e = failure(() -> provider().getCredential(ALIAS));
        assertThat(e).hasMessageContaining("is not JSON").hasNoCause();
        assertThat(e.getMessage()).doesNotContain("s3cret");
    }

    @Test
    public void testYamlTagsAreRejected() {
        vault.putRaw(DATA_PATH, "{\"data\": !!java.io.File [\"/tmp\"]}");
        assertThat(failure(() -> provider().getCredential(ALIAS)))
                .hasMessageContaining("is not JSON");
    }

    @Test
    public void testLongErrorAnswerIsCut() {
        StringBuilder page = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            page.append("<p>error page</p>");
        }
        vault.fail(400, 1, page.toString());
        IOException e = failure(() -> provider().getCredential(ALIAS));
        assertThat(e.getMessage().length()).isLessThan(2000);
        assertThat(e.getMessage()).endsWith("...");
    }

    @Test
    public void testTransientFailures() {
        SSLHandshakeException closedHandshake =
                new SSLHandshakeException("Remote host terminated the handshake");
        closedHandshake.initCause(new EOFException());
        SSLHandshakeException untrusted = new SSLHandshakeException("PKIX path building failed");
        untrusted.initCause(new CertificateException());
        LoginException kdcDown = new LoginException("Cannot contact any KDC");
        kdcDown.initCause(new SocketTimeoutException());

        assertThat(VaultHttpClient.isTransient(new SocketTimeoutException())).isTrue();
        assertThat(VaultHttpClient.isTransient(closedHandshake)).isTrue();
        assertThat(VaultHttpClient.isTransient(new IOException("Kerberos login failed", kdcDown)))
                .isTrue();
        assertThat(VaultHttpClient.isTransient(untrusted)).isFalse();
        assertThat(
                        VaultHttpClient.isTransient(
                                new IOException(
                                        "Kerberos login failed", new LoginException("no keytab"))))
                .isFalse();
    }

    @Test
    public void testUnservedMountFails() throws Exception {
        writeToken(MockVault.ROOT_TOKEN);
        assertThat(failure(() -> provider(vault.uri("missing/jmx")).getCredential(ALIAS)))
                .hasMessageContaining("404");
    }

    @Test
    public void testUnservedMountLooksLikeDenialToALimitedToken() throws Exception {
        assertThat(provider(vault.uri("missing/jmx")).getCredential(ALIAS)).isNull();
    }

    @Test
    public void testDeletedVersionIsAbsent() throws Exception {
        StringBuilder metadata = new StringBuilder("{");
        for (int i = 0; i < 40; i++) {
            metadata.append(i == 0 ? "" : ",").append("\"key").append(i).append("\":\"");
            for (int j = 0; j < 40; j++) {
                metadata.append('v');
            }
            metadata.append('"');
        }
        vault.putDeleted(DATA_PATH, metadata.append('}').toString());
        assertThat(provider().getCredential(ALIAS)).isNull();
    }

    @Test
    public void testTokenLookupIsRetried() throws Exception {
        vault.putSecret(DATA_PATH, "value", "s3cret");
        vault.deny(DATA_PATH);
        vault.failLookups(503, 2);
        assertThat(provider().getCredential(ALIAS)).isNull();
        assertThat(vault.requests())
                .containsExactly(
                        "GET /v1/" + DATA_PATH,
                        "GET " + MockVault.LOOKUP_SELF_PATH,
                        "GET " + MockVault.LOOKUP_SELF_PATH,
                        "GET " + MockVault.LOOKUP_SELF_PATH);
    }

    @Test
    public void testRequestHeaderIsSent() throws Exception {
        vault.requireRequestHeader();
        vault.putSecret(DATA_PATH, "value", "s3cret");
        assertThat(provider().getCredential(ALIAS)).isEqualTo("s3cret");
        assertThat(vault.requestsWithoutHeader()).isZero();
    }

    @Test
    public void testTokenFromFileIsNotRevoked() throws Exception {
        vault.putSecret(DATA_PATH, "value", "s3cret");
        try (VaultCredentialProvider provider = provider()) {
            assertThat(provider.getCredential(ALIAS)).isEqualTo("s3cret");
        }
        assertThat(vault.revokedTokens()).isEmpty();
        assertThat(provider().getCredential(ALIAS)).isEqualTo("s3cret");
    }

    @Test
    public void testRotatedTokenIsReadAfterRefusal() throws Exception {
        vault.putSecret(DATA_PATH, "value", "s3cret");
        vault.putSecret(TRUSTSTORE_DATA_PATH, "value", "tr0st");
        VaultCredentialProvider provider = provider();
        assertThat(provider.getCredential(ALIAS)).isEqualTo("s3cret");

        vault.revokeToken(MockVault.TOKEN);
        vault.acceptToken("s.rotated");
        writeToken("s.rotated");
        assertThat(provider.getCredential(TRUSTSTORE_ALIAS)).isEqualTo("tr0st");
    }

    @Test
    public void testPolicyDenialIsAbsence() throws Exception {
        vault.putSecret(DATA_PATH, "value", "s3cret");
        vault.deny(DATA_PATH);
        assertThat(provider().getCredential(ALIAS)).isNull();
    }

    @Test
    public void testLineEndIsStripped() throws Exception {
        vault.putSecret(DATA_PATH, "value", "s3cret\n");
        vault.putSecret(TRUSTSTORE_DATA_PATH, "value", "tr0st\r\n");
        VaultCredentialProvider provider = provider();
        assertThat(provider.getCredential(ALIAS)).isEqualTo("s3cret");
        assertThat(provider.getCredential(TRUSTSTORE_ALIAS)).isEqualTo("tr0st");
        assertThat(VaultCredentialProvider.stripLineEnd("a\n\n")).isEqualTo("a\n");
        assertThat(VaultCredentialProvider.stripLineEnd("a b")).isEqualTo("a b");
    }

    @Test
    public void testRefusedTokenFails() {
        vault.revokeToken(MockVault.TOKEN);
        assertThat(failure(() -> provider().getCredential(ALIAS))).hasMessageContaining("403");
    }

    @Test
    public void testTransientFailuresAreRetried() throws Exception {
        vault.putSecret(DATA_PATH, "value", "s3cret");
        vault.fail(503, 2);
        assertThat(provider().getCredential(ALIAS)).isEqualTo("s3cret");
        vault.fail(429, 1);
        assertThat(provider().getCredential(ALIAS)).isEqualTo("s3cret");
    }

    @Test
    public void testRetriesAreBounded() {
        settings.add("retryCount: 1");
        vault.putSecret(DATA_PATH, "value", "s3cret");
        vault.fail(503, 5);
        assertThat(failure(() -> provider().getCredential(ALIAS)))
                .hasMessageContaining("failed after 2 attempts");
        assertThat(vault.requests()).hasSize(2);
    }

    @Test
    public void testClientErrorsAreNotRetried() {
        vault.putSecret(DATA_PATH, "value", "s3cret");
        vault.fail(400, 1);
        assertThat(failure(() -> provider().getCredential(ALIAS))).hasMessageContaining("400");
        assertThat(vault.requests()).hasSize(1);
    }

    @Test
    public void testUnreachableVaultFails() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        settings.add("retryCount: 2");
        assertThat(
                        failure(
                                () ->
                                        provider("vault://http@localhost:" + port + "/secret/jmx")
                                                .getCredential(ALIAS)))
                .hasMessageContaining("failed after 3 attempts");
    }

    @Test
    public void testTokenFile() throws Exception {
        vault.putSecret(DATA_PATH, "value", "s3cret");
        writeToken((char) 0xFEFF + MockVault.TOKEN + "\r\n");
        assertThat(provider().getCredential(ALIAS)).isEqualTo("s3cret");

        writeToken(" \n");
        assertThat(failure(() -> provider().getCredential(ALIAS))).hasMessageContaining("empty");

        for (String token : Arrays.asList("s.tok" + (char) 0xE9 + "n", "s.to ken")) {
            writeToken(token);
            assertThat(failure(() -> provider().getCredential(ALIAS)))
                    .hasMessageContaining("printable ASCII");
        }

        assertThat(tokenFile.delete()).isTrue();
        assertThat(failure(() -> provider().getCredential(ALIAS)))
                .hasMessageContaining(tokenFile.getName());
    }

    @Test
    public void testInvalidSettings() {
        for (String setting :
                Arrays.asList(
                        "readTimeoutMs: 0",
                        "connectTimeoutMs: -1",
                        "retryCount: many",
                        "retryIntervalMs: -1",
                        "authMethod: ldap")) {
            List<String> invalid = new ArrayList<>(settings);
            invalid.add(setting);
            assertThatExceptionOfType(ConfigurationException.class)
                    .isThrownBy(() -> create("uri: " + vault.uri("secret/jmx"), invalid))
                    .withMessageContaining(
                            "/httpServer/credentialProvider/" + setting.split(":")[0]);
        }

        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> create("uri: ''", settings))
                .withMessageContaining("/httpServer/credentialProvider/uri");
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> create("uri: " + vault.uri("secret/jmx"), new ArrayList<>()))
                .withMessageContaining("/httpServer/credentialProvider/tokenPath");
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(
                        () ->
                                create(
                                        "uri: " + vault.uri("secret/jmx"),
                                        Arrays.asList("authMethod: kerberos")))
                .withMessageContaining("/httpServer/credentialProvider/kerberos/principal");
    }

    @Test
    public void testInvalidAlias() {
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> provider().getCredential("../other"));
        assertThat(vault.requests()).isEmpty();
    }
}
