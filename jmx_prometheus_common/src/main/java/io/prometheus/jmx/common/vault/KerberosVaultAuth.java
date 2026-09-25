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

import io.prometheus.jmx.logger.Logger;
import io.prometheus.jmx.logger.LoggerFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * Login to the Vault Kerberos auth method over SPNEGO, as a principal of a keytab. Each login
 * authenticates to the KDC afresh, so no ticket has to be renewed in between. The token travels in
 * the Authorization header, which the auth mount must pass through ({@code
 * passthrough_request_headers}).
 */
final class KerberosVaultAuth implements VaultAuthMethod {

    private static final Logger LOGGER = LoggerFactory.getLogger(KerberosVaultAuth.class);

    private static final String KRB5_LOGIN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";
    private static final String LOGIN_CONTEXT_NAME = "jmx-exporter-vault";
    private static final String SPNEGO_MECH_OID = "1.3.6.1.5.5.2";
    private static final String KRB5_PRINCIPAL_NAME_OID = "1.2.840.113554.1.2.2.1";
    private static final String HOSTNAME_PATTERN = "_HOST";

    private final String principal;
    private final String keytab;
    private final String servicePrincipal;
    private final String loginUrl;
    private final String role;

    /**
     * Creates the login of a keytab principal.
     *
     * @param connInfo the Vault server
     * @param principal the principal to log in as; {@code _HOST} stands for the canonical name of
     *     the local host in lower case
     * @param keytab the keytab of the principal
     * @param servicePrincipal the Vault service principal; {@code _HOST} stands for the Vault host
     *     in lower case, null means {@code HTTP@<Vault host>}
     * @param mountPath the mount path of the Kerberos auth method
     * @param role the role to log in with, or null to let Vault pick the one bound to the principal
     * @throws IOException if the principal names the local host, which cannot be resolved
     */
    KerberosVaultAuth(
            VaultConnectionInfo connInfo,
            String principal,
            String keytab,
            String servicePrincipal,
            String mountPath,
            String role)
            throws IOException {
        this.principal =
                principal.contains(HOSTNAME_PATTERN)
                        ? principal.replace(HOSTNAME_PATTERN, localHostName())
                        : principal;
        this.keytab = keytab;
        String host = connInfo.getHost().toLowerCase(Locale.ROOT);
        this.servicePrincipal =
                servicePrincipal == null
                        ? "HTTP@" + host
                        : servicePrincipal.replace(HOSTNAME_PATTERN, host);
        String mount = VaultConnectionInfo.stripSlashes(mountPath);
        VaultConnectionInfo.checkPath(mount);
        this.loginUrl = connInfo.apiUrl(mount + "/login");
        this.role = role;
    }

    private static String localHostName() throws IOException {
        return InetAddress.getLocalHost().getCanonicalHostName().toLowerCase(Locale.ROOT);
    }

    String getPrincipal() {
        return principal;
    }

    @Override
    public String authenticate(VaultHttpClient client) throws IOException {
        String body = VaultHttpClient.json("role", role);
        String response =
                client.retrying(
                        "Vault Kerberos login to " + loginUrl,
                        () -> client.post(loginUrl, "Negotiate " + spnegoToken(), body));
        Object token =
                VaultHttpClient.field(
                        VaultHttpClient.field(VaultHttpClient.parse(response, loginUrl), "auth"),
                        "client_token");
        if (!(token instanceof String) || ((String) token).isEmpty()) {
            throw new IOException(
                    "Vault login response from " + loginUrl + " has no auth.client_token");
        }
        LOGGER.info("Logged in to %s as %s", loginUrl, principal);
        return (String) token;
    }

    private String spnegoToken() throws IOException {
        LoginContext loginContext;
        try {
            loginContext =
                    new LoginContext(
                            LOGIN_CONTEXT_NAME,
                            new Subject(),
                            null,
                            new KeytabConfiguration(principal, keytab));
            loginContext.login();
        } catch (LoginException | SecurityException e) {
            throw new IOException(
                    "Kerberos login of " + principal + " with keytab " + keytab + " failed", e);
        }
        try {
            return Subject.doAs(
                    loginContext.getSubject(),
                    (PrivilegedExceptionAction<String>) this::initSecContext);
        } catch (PrivilegedActionException e) {
            throw new IOException(
                    "Failed to create a SPNEGO token for " + servicePrincipal, e.getException());
        } finally {
            try {
                loginContext.logout();
            } catch (LoginException e) {
                LOGGER.trace("Kerberos logout of %s failed: %s", principal, e);
            }
        }
    }

    private String initSecContext() throws GSSException {
        GSSManager manager = GSSManager.getInstance();
        Oid nameType =
                servicePrincipal.contains("/")
                        ? new Oid(KRB5_PRINCIPAL_NAME_OID)
                        : GSSName.NT_HOSTBASED_SERVICE;
        GSSName serverName = manager.createName(servicePrincipal, nameType);
        GSSContext context =
                manager.createContext(
                        serverName, new Oid(SPNEGO_MECH_OID), null, GSSContext.DEFAULT_LIFETIME);
        try {
            context.requestMutualAuth(true);
            context.requestCredDeleg(false);
            byte[] token = context.initSecContext(new byte[0], 0, 0);
            return Base64.getEncoder().encodeToString(token);
        } finally {
            context.dispose();
        }
    }

    /** A JAAS configuration that logs in from a keytab, apart from the JVM-wide one. */
    private static final class KeytabConfiguration extends Configuration {

        private final AppConfigurationEntry entry;

        KeytabConfiguration(String principal, String keytab) {
            Map<String, String> options = new HashMap<>();
            options.put("principal", principal);
            options.put("keyTab", keytab);
            options.put("useKeyTab", "true");
            options.put("storeKey", "false");
            options.put("useTicketCache", "false");
            options.put("doNotPrompt", "true");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", "true");
            entry =
                    new AppConfigurationEntry(
                            KRB5_LOGIN_MODULE,
                            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                            options);
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            return new AppConfigurationEntry[] {entry};
        }
    }
}
