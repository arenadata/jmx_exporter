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

import static java.lang.String.format;

import io.prometheus.jmx.common.ConfigurationException;
import io.prometheus.jmx.common.util.MapAccessor;
import io.prometheus.jmx.common.util.functions.IntegerInRange;
import io.prometheus.jmx.common.util.functions.StringIsNotBlank;
import io.prometheus.jmx.common.util.functions.ToInteger;
import io.prometheus.jmx.common.util.functions.ToString;
import io.prometheus.jmx.logger.Logger;
import io.prometheus.jmx.logger.LoggerFactory;
import io.prometheus.jmx.variable.VariableResolver;
import java.io.IOException;
import java.util.Locale;
import javax.net.ssl.SSLSocketFactory;

/**
 * Reads credentials from a KV v2 secrets engine of HashiCorp Vault or OpenBao. The URI and the
 * secret layout are those of the Hadoop {@code vault://} credential provider, so {@code hadoop
 * credential create} writes secrets this provider reads.
 */
public final class VaultCredentialProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(VaultCredentialProvider.class);

    private static final String AUTH_METHOD_TOKEN = "token";
    private static final String AUTH_METHOD_KERBEROS = "kerberos";
    private static final String KERBEROS_MOUNT_PATH_DEFAULT = "auth/kerberos";
    private static final int CONNECT_TIMEOUT_MS_DEFAULT = 30000;
    private static final int READ_TIMEOUT_MS_DEFAULT = 30000;
    private static final int RETRY_COUNT_DEFAULT = 3;
    private static final int RETRY_INTERVAL_MS_DEFAULT = 1000;

    private final VaultConnectionInfo connInfo;
    private final VaultHttpClient client;

    private VaultCredentialProvider(VaultConnectionInfo connInfo, VaultHttpClient client) {
        this.connInfo = connInfo;
        this.client = client;
    }

    /**
     * Creates the provider a configuration block describes. No request is sent before the first
     * credential is read.
     *
     * @param rootMapAccessor the exporter configuration
     * @param path the path of the provider block, such as {@code /httpServer/credentialProvider}
     * @return the provider
     * @throws ConfigurationException if the block is invalid
     * @throws IOException if the Vault trust store or the local host name cannot be read
     */
    public static VaultCredentialProvider create(MapAccessor rootMapAccessor, String path)
            throws IOException {
        VaultConnectionInfo connInfo =
                new VaultConnectionInfo(requiredString(rootMapAccessor, path + "/uri"));

        String authMethodName = string(rootMapAccessor, path + "/authMethod");
        authMethodName =
                authMethodName == null
                        ? AUTH_METHOD_TOKEN
                        : authMethodName.toLowerCase(Locale.ROOT);
        VaultAuthMethod authMethod;
        String login;
        if (authMethodName.equals(AUTH_METHOD_TOKEN)) {
            authMethod = new TokenVaultAuth(requiredString(rootMapAccessor, path + "/tokenPath"));
            login = "token auth";
        } else if (authMethodName.equals(AUTH_METHOD_KERBEROS)) {
            String mountPath = string(rootMapAccessor, path + "/kerberos/mountPath");
            KerberosVaultAuth kerberosVaultAuth =
                    new KerberosVaultAuth(
                            connInfo,
                            requiredString(rootMapAccessor, path + "/kerberos/principal"),
                            requiredString(rootMapAccessor, path + "/kerberos/keytab"),
                            string(rootMapAccessor, path + "/kerberos/servicePrincipal"),
                            mountPath == null ? KERBEROS_MOUNT_PATH_DEFAULT : mountPath,
                            string(rootMapAccessor, path + "/kerberos/role"));
            authMethod = kerberosVaultAuth;
            login = "kerberos auth as " + kerberosVaultAuth.getPrincipal();
        } else {
            throw new ConfigurationException(
                    format(
                            "Invalid configuration for %s/authMethod must be %s or %s",
                            path, AUTH_METHOD_TOKEN, AUTH_METHOD_KERBEROS));
        }

        SSLSocketFactory sslSocketFactory = null;
        String trustStoreFilename = string(rootMapAccessor, path + "/trustStore/filename");
        if (connInfo.isHttps() && trustStoreFilename != null) {
            sslSocketFactory =
                    VaultTrustStore.socketFactory(
                            trustStoreFilename,
                            string(rootMapAccessor, path + "/trustStore/type"),
                            VariableResolver.resolveVariable(
                                    string(rootMapAccessor, path + "/trustStore/password")));
        }

        VaultHttpClient client =
                new VaultHttpClient(
                        connInfo,
                        authMethod,
                        integer(
                                rootMapAccessor,
                                path + "/connectTimeoutMs",
                                CONNECT_TIMEOUT_MS_DEFAULT,
                                1),
                        integer(
                                rootMapAccessor,
                                path + "/readTimeoutMs",
                                READ_TIMEOUT_MS_DEFAULT,
                                1),
                        integer(rootMapAccessor, path + "/retryCount", RETRY_COUNT_DEFAULT, 0),
                        integer(
                                rootMapAccessor,
                                path + "/retryIntervalMs",
                                RETRY_INTERVAL_MS_DEFAULT,
                                0),
                        sslSocketFactory);

        LOGGER.info("Reading credentials from %s with %s", connInfo, login);
        if (!connInfo.isHttps()) {
            LOGGER.warn(
                    "%s uses plain http: the Vault token travels unencrypted and Vault is not"
                            + " authenticated",
                    connInfo);
        }
        return new VaultCredentialProvider(connInfo, client);
    }

    /**
     * Returns the credential stored under an alias.
     *
     * @param alias the alias
     * @return the credential, or null when Vault holds no such alias or the policy of the token
     *     denies reading it
     * @throws ConfigurationException if the alias cannot name a secret
     * @throws IOException if Vault cannot be read
     */
    public String getCredential(String alias) throws IOException {
        VaultConnectionInfo.checkPath(alias);
        String value = client.readField(connInfo.dataPath(alias), connInfo.getField());
        if (value == null) {
            return null;
        }
        LOGGER.info("Read %s from %s", alias, connInfo);
        return stripLineEnd(value);
    }

    /**
     * A value written from a file, as by {@code bao kv put key=@file}, keeps the line end of the
     * file.
     */
    static String stripLineEnd(String value) {
        if (value.endsWith("\r\n")) {
            return value.substring(0, value.length() - 2);
        }
        return value.endsWith("\n") ? value.substring(0, value.length() - 1) : value;
    }

    @Override
    public String toString() {
        return connInfo.toString();
    }

    private static String string(MapAccessor rootMapAccessor, String path) {
        return rootMapAccessor
                .get(path)
                .map(
                        new ToString(
                                ConfigurationException.supplier(
                                        format(
                                                "Invalid configuration for %s must be a string",
                                                path))))
                .map(
                        new StringIsNotBlank(
                                ConfigurationException.supplier(
                                        format(
                                                "Invalid configuration for %s must not be blank",
                                                path))))
                .orElse(null);
    }

    private static String requiredString(MapAccessor rootMapAccessor, String path) {
        String value = string(rootMapAccessor, path);
        if (value == null) {
            throw new ConfigurationException(format("%s is a required string", path));
        }
        return value;
    }

    private static int integer(
            MapAccessor rootMapAccessor, String path, int defaultValue, int minimum) {
        return rootMapAccessor
                .get(path)
                .map(
                        new ToInteger(
                                ConfigurationException.supplier(
                                        format(
                                                "Invalid configuration for %s must be an integer",
                                                path))))
                .map(
                        new IntegerInRange(
                                minimum,
                                Integer.MAX_VALUE,
                                ConfigurationException.supplier(
                                        format(
                                                "Invalid configuration for %s must be %d or"
                                                        + " greater",
                                                path, minimum))))
                .orElse(defaultValue);
    }
}
