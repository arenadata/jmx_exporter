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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;
import java.util.Locale;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/** The trust store of the https connection to Vault: PEM, JKS or PKCS12. */
final class VaultTrustStore {

    static final String PEM = "PEM";

    private VaultTrustStore() {
        // INTENTIONALLY BLANK
    }

    /**
     * Returns a socket factory that trusts the certificates of a trust store.
     *
     * @param filename the trust store file
     * @param type PEM, JKS or PKCS12; null to tell by the file extension
     * @param password the trust store password, or null: a PEM or JKS trust store needs none
     * @throws IOException if the trust store cannot be read or holds no certificate
     */
    static SSLSocketFactory socketFactory(String filename, String type, String password)
            throws IOException {
        try {
            KeyStore trustStore = load(filename, type == null ? typeOf(filename) : type, password);
            // A PKCS12 store read without its password silently drops its encrypted
            // certificates.
            if (!holdsCertificate(trustStore)) {
                throw new KeyStoreException(
                        "no certificate"
                                + (password == null ? " readable without a password" : ""));
            }
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
            return sslContext.getSocketFactory();
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            throw new IOException(
                    "Failed to load the Vault trust store " + filename + ": " + e.getMessage(), e);
        }
    }

    /**
     * Returns a socket factory that trusts the JVM default trust store and presents no client key.
     * The JVM default SSL context would also load {@code javax.net.ssl.keyStore}, whose password
     * may be the one about to be read from Vault.
     *
     * @throws IOException if the default trust store cannot be read
     */
    static SSLSocketFactory defaultSocketFactory() throws IOException {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            return sslContext.getSocketFactory();
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed to set up TLS to Vault: " + e.getMessage(), e);
        }
    }

    static String typeOf(String filename) {
        String name = filename.toLowerCase(Locale.ROOT);
        if (name.endsWith(".pem") || name.endsWith(".crt") || name.endsWith(".cer")) {
            return PEM;
        }
        if (name.endsWith(".p12") || name.endsWith(".pfx") || name.endsWith(".pkcs12")) {
            return "PKCS12";
        }
        if (name.endsWith(".jks")) {
            return "JKS";
        }
        return KeyStore.getDefaultType();
    }

    private static KeyStore load(String filename, String type, String password)
            throws IOException, GeneralSecurityException {
        try (InputStream in = Files.newInputStream(Paths.get(filename))) {
            if (PEM.equalsIgnoreCase(type)) {
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                int index = 0;
                for (Certificate certificate :
                        CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                    keyStore.setCertificateEntry("certificate-" + index++, certificate);
                }
                return keyStore;
            }
            KeyStore keyStore = KeyStore.getInstance(type);
            // A null password skips the integrity check of a JKS store.
            keyStore.load(in, password == null ? null : password.toCharArray());
            return keyStore;
        }
    }

    private static boolean holdsCertificate(KeyStore keyStore) throws KeyStoreException {
        for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
            if (keyStore.getCertificate(aliases.nextElement()) != null) {
                return true;
            }
        }
        return false;
    }
}
