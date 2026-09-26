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

import io.prometheus.jmx.common.ConfigurationException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * A Vault credential provider URI: {@code vault://[protocol@]host[:port]/mount[/path][?key=field]}.
 * Each alias is a KV v2 secret at {@code mount/data/path/alias}; the credential is its {@code
 * field}, {@code value} unless the URI names another.
 */
final class VaultConnectionInfo {

    static final String SCHEME = "vault";
    static final int DEFAULT_PORT = 8200;
    static final String DEFAULT_PROTOCOL = "https";
    static final String DEFAULT_FIELD = "value";

    private static final int MAX_PORT = 65535;
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private final String protocol;
    private final String host;
    private final int port;
    private final String mount;
    private final String basePath;
    private final String field;

    VaultConnectionInfo(String uriString) {
        URI uri;
        try {
            uri = new URI(uriString);
        } catch (URISyntaxException e) {
            throw new ConfigurationException("Invalid Vault URI: " + e.getMessage());
        }
        if (!SCHEME.equalsIgnoreCase(uri.getScheme())) {
            throw new ConfigurationException(
                    "Invalid Vault URI: " + uri + " is not a " + SCHEME + ":// URI");
        }
        // Parsed by hand: java.net.URI drops the host of an authority it cannot parse, such as
        // one with '_'.
        String authority = uri.getRawAuthority();
        if (authority == null || authority.isEmpty()) {
            throw new ConfigurationException("Invalid Vault URI: missing host in " + uri);
        }
        int at = authority.indexOf('@');
        String userInfo = at < 0 ? "" : authority.substring(0, at);
        protocol = userInfo.isEmpty() ? DEFAULT_PROTOCOL : userInfo.toLowerCase(Locale.ROOT);
        if (!protocol.equals("https") && !protocol.equals("http")) {
            throw new ConfigurationException(
                    "Invalid Vault URI: protocol must be http or https in " + uri);
        }
        String hostPort = authority.substring(at + 1);
        int portSeparator = hostPort.lastIndexOf(':');
        if (hostPort.startsWith("[")) {
            int close = hostPort.indexOf(']');
            portSeparator = close < 0 ? -1 : hostPort.indexOf(':', close);
        }
        host = portSeparator < 0 ? hostPort : hostPort.substring(0, portSeparator);
        if (host.isEmpty()) {
            throw new ConfigurationException("Invalid Vault URI: missing host in " + uri);
        }
        port =
                portSeparator < 0
                        ? DEFAULT_PORT
                        : parsePort(hostPort.substring(portSeparator + 1), uri);

        String path = stripSlashes(uri.getPath());
        if (path.isEmpty()) {
            throw new ConfigurationException("Invalid Vault URI: missing mount in " + uri);
        }
        checkPath(path);
        int slash = path.indexOf('/');
        mount = slash < 0 ? path : path.substring(0, slash);
        basePath = slash < 0 ? null : path.substring(slash + 1);

        String key = null;
        String query = uri.getQuery();
        if (query != null) {
            for (String param : query.split("&")) {
                if (param.startsWith("key=")) {
                    key = param.substring("key=".length());
                    break;
                }
            }
        }
        field = key == null || key.isEmpty() ? DEFAULT_FIELD : key;
    }

    private static int parsePort(String port, URI uri) {
        int value;
        try {
            value = Integer.parseInt(port);
        } catch (NumberFormatException e) {
            value = -1;
        }
        if (value < 1 || value > MAX_PORT) {
            throw new ConfigurationException(
                    "Invalid Vault URI: bad port '" + port + "' in " + uri);
        }
        return value;
    }

    /**
     * Rejects a path that cannot name one secret: empty, with control characters, or with an empty,
     * {@code .} or {@code ..} segment.
     */
    static void checkPath(String path) {
        if (path == null || path.isEmpty()) {
            throw new ConfigurationException("Vault path must not be empty");
        }
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c < ' ' || c == 0x7f) {
                throw new ConfigurationException("Vault path contains control characters");
            }
        }
        for (String segment : path.split("/", -1)) {
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) {
                throw new ConfigurationException("'" + path + "' is not a valid Vault path");
            }
        }
    }

    static String stripSlashes(String path) {
        if (path == null) {
            return "";
        }
        int start = 0;
        int end = path.length();
        while (start < end && path.charAt(start) == '/') {
            start++;
        }
        while (end > start && path.charAt(end - 1) == '/') {
            end--;
        }
        return path.substring(start, end);
    }

    /** The KV v2 data path of an alias: {@code mount/data/path/alias}. */
    String dataPath(String alias) {
        StringBuilder sb = new StringBuilder(mount).append("/data");
        if (basePath != null) {
            sb.append('/').append(basePath);
        }
        return sb.append('/').append(alias).toString();
    }

    /** The URL of an API path relative to {@code /v1/}, each segment percent-encoded. */
    String apiUrl(String path) {
        return baseUrl() + "/v1/" + encodePath(path);
    }

    String baseUrl() {
        return protocol + "://" + host + ":" + port;
    }

    boolean isHttps() {
        return protocol.equals("https");
    }

    String getHost() {
        return host;
    }

    String getField() {
        return field;
    }

    static String encodePath(String path) {
        StringBuilder sb = new StringBuilder(path.length());
        String separator = "";
        for (String segment : path.split("/", -1)) {
            sb.append(separator);
            separator = "/";
            for (byte b : segment.getBytes(StandardCharsets.UTF_8)) {
                int c = b & 0xff;
                if ((c >= 'A' && c <= 'Z')
                        || (c >= 'a' && c <= 'z')
                        || (c >= '0' && c <= '9')
                        || c == '-'
                        || c == '.'
                        || c == '_'
                        || c == '~') {
                    sb.append((char) c);
                } else {
                    sb.append('%').append(HEX[c >> 4]).append(HEX[c & 0xf]);
                }
            }
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return SCHEME
                + "://"
                + protocol
                + "@"
                + host
                + ":"
                + port
                + "/"
                + mount
                + (basePath == null ? "" : "/" + basePath);
    }
}
