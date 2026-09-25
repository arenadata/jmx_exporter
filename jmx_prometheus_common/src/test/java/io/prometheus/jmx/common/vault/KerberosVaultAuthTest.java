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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class KerberosVaultAuthTest {

    private static final String REALM = "EXAMPLE.COM";
    private static final String CLIENT = "jmx";
    private static final String SERVER = "HTTP/localhost";
    private static final String NEGOTIATE = "Negotiate ";
    private static final String ALIAS = "keystore.password";
    private static final String KRB5_CONF = "java.security.krb5.conf";

    @TempDir static File tempDir;

    private static SimpleKdcServer kdc;
    private static String previousKrb5Conf;
    private static String clientPrincipal;
    private static File clientKeytab;
    private static File serverKeytab;

    private MockVault vault;
    private List<String> settings;

    @BeforeAll
    public static void startKdc() throws Exception {
        previousKrb5Conf = System.getProperty(KRB5_CONF);
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        kdc = new SimpleKdcServer();
        kdc.setWorkDir(tempDir);
        kdc.setKdcHost("localhost");
        kdc.setKdcRealm(REALM);
        kdc.setKdcTcpPort(port);
        kdc.setAllowUdp(false);
        // Also points java.security.krb5.conf at the realm.
        kdc.init();
        kdc.start();

        String host = InetAddress.getLocalHost().getCanonicalHostName().toLowerCase(Locale.ROOT);
        clientPrincipal = CLIENT + "/" + host + "@" + REALM;
        clientKeytab = new File(tempDir, "client.keytab");
        serverKeytab = new File(tempDir, "server.keytab");
        kdc.createPrincipal(clientPrincipal);
        kdc.createPrincipal(SERVER + "@" + REALM);
        kdc.exportPrincipal(clientPrincipal, clientKeytab);
        kdc.exportPrincipal(SERVER + "@" + REALM, serverKeytab);
    }

    @AfterAll
    public static void stopKdc() throws Exception {
        if (kdc != null) {
            kdc.stop();
        }
        if (previousKrb5Conf == null) {
            System.clearProperty(KRB5_CONF);
        } else {
            System.setProperty(KRB5_CONF, previousKrb5Conf);
        }
    }

    @BeforeEach
    public void setUp() throws IOException {
        vault = new MockVault();
        vault.setLoginHandler(KerberosVaultAuthTest::login);
        vault.revokeToken(MockVault.TOKEN);
        vault.putSecret("secret/data/jmx/" + ALIAS, "value", "s3cret");
        vault.putSecret("secret/data/jmx/truststore.password", "value", "tr0st");
        settings = new ArrayList<>();
        settings.add("retryIntervalMs: 1");
        settings.add("authMethod: kerberos");
        settings.add("kerberos:");
        settings.add("  principal: " + CLIENT + "/_HOST@" + REALM);
        settings.add("  keytab: " + clientKeytab.getAbsolutePath());
        settings.add("  servicePrincipal: HTTP/_HOST@" + REALM);
    }

    @AfterEach
    public void tearDown() {
        vault.close();
    }

    private VaultCredentialProvider provider() throws IOException {
        return provider(vault.uri("secret/jmx"));
    }

    private VaultCredentialProvider provider(String uri) throws IOException {
        return VaultCredentialProviderTest.create("uri: " + uri, settings);
    }

    private static String login(String authorization) throws Exception {
        return clientPrincipal.equals(acceptSpnego(authorization)) ? "s.kerberos" : null;
    }

    /** Accepts a SPNEGO token as the Vault service principal and returns the client principal. */
    private static String acceptSpnego(String authorization) throws Exception {
        if (authorization == null || !authorization.startsWith(NEGOTIATE)) {
            throw new IOException("missing Negotiate header: " + authorization);
        }
        byte[] token = Base64.getDecoder().decode(authorization.substring(NEGOTIATE.length()));
        LoginContext loginContext =
                new LoginContext("server", new Subject(), null, serverConfiguration());
        loginContext.login();
        try {
            return Subject.doAs(
                    loginContext.getSubject(),
                    (PrivilegedExceptionAction<String>)
                            () -> {
                                GSSManager manager = GSSManager.getInstance();
                                Oid spnego = new Oid("1.3.6.1.5.5.2");
                                Oid krb5 = new Oid("1.2.840.113554.1.2.2");
                                GSSCredential credential =
                                        manager.createCredential(
                                                manager.createName(
                                                        SERVER + "@" + REALM,
                                                        new Oid("1.2.840.113554.1.2.2.1")),
                                                GSSCredential.INDEFINITE_LIFETIME,
                                                new Oid[] {spnego, krb5},
                                                GSSCredential.ACCEPT_ONLY);
                                GSSContext context = manager.createContext(credential);
                                try {
                                    context.acceptSecContext(token, 0, token.length);
                                    if (!context.isEstablished()) {
                                        throw new GSSException(GSSException.DEFECTIVE_TOKEN);
                                    }
                                    return context.getSrcName().toString();
                                } finally {
                                    context.dispose();
                                }
                            });
        } finally {
            loginContext.logout();
        }
    }

    private static Configuration serverConfiguration() {
        Map<String, String> options = new HashMap<>();
        options.put("principal", SERVER + "@" + REALM);
        options.put("keyTab", serverKeytab.getAbsolutePath());
        options.put("useKeyTab", "true");
        options.put("storeKey", "true");
        options.put("doNotPrompt", "true");
        options.put("refreshKrb5Config", "true");
        options.put("isInitiator", "false");
        AppConfigurationEntry entry =
                new AppConfigurationEntry(
                        "com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        options);
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                return new AppConfigurationEntry[] {entry};
            }
        };
    }

    @Test
    public void testLogsInWithSpnego() throws Exception {
        assertThat(provider().getCredential(ALIAS)).isEqualTo("s3cret");
        assertThat(vault.loginRoles()).isEqualTo(Collections.singletonList(null));
    }

    @Test
    public void testOneLoginForSeveralCredentials() throws Exception {
        VaultCredentialProvider provider = provider();
        assertThat(provider.getCredential(ALIAS)).isEqualTo("s3cret");
        assertThat(provider.getCredential("truststore.password")).isEqualTo("tr0st");
        assertThat(vault.loginRoles()).hasSize(1);
    }

    @Test
    public void testLogsInAgainWhenTheTokenIsRefused() throws Exception {
        VaultCredentialProvider provider = provider();
        provider.getCredential(ALIAS);
        vault.revokeToken("s.kerberos");
        assertThat(provider.getCredential("truststore.password")).isEqualTo("tr0st");
        assertThat(vault.loginRoles()).hasSize(2);
    }

    @Test
    public void testHostOfServicePrincipalIsLowerCased() throws Exception {
        assertThat(
                        provider("vault://http@LocalHost:" + vault.port() + "/secret/jmx")
                                .getCredential(ALIAS))
                .isEqualTo("s3cret");
    }

    @Test
    public void testFollowsLoginRedirectWithTheToken() throws Exception {
        try (MockVault active = new MockVault()) {
            active.setLoginHandler(KerberosVaultAuthTest::login);
            vault.redirectLoginTo(active);
            vault.acceptToken("s.kerberos");
            assertThat(provider().getCredential(ALIAS)).isEqualTo("s3cret");
            assertThat(active.loginRoles()).hasSize(1);
            assertThat(vault.loginRoles()).isEmpty();
        }
    }

    @Test
    public void testSendsRole() throws Exception {
        settings.add("  role: jmx-exporter");
        provider().getCredential(ALIAS);
        assertThat(vault.loginRoles()).isEqualTo(Collections.singletonList("jmx-exporter"));
    }

    @Test
    public void testMountPath() {
        settings.add("  mountPath: /auth/krb/");
        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> provider().getCredential(ALIAS));
        assertThat(vault.requests()).contains("POST /v1/auth/krb/login");
    }

    @Test
    public void testRefusedLoginFails() {
        vault.setLoginHandler(authorization -> null);
        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> provider().getCredential(ALIAS))
                .withMessageContaining("401");
        assertThat(vault.loginRoles()).hasSize(1);
    }

    @Test
    public void testPrincipalMissingFromKeytabFails() {
        settings.set(3, "  principal: other@" + REALM);
        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> provider().getCredential(ALIAS))
                .withMessageContaining("Kerberos login of other@" + REALM);
        assertThat(vault.requests()).isEmpty();
    }
}
