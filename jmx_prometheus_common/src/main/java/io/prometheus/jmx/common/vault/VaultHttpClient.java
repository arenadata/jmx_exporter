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
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpRetryException;
import java.net.HttpURLConnection;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.error.Mark;
import org.yaml.snakeyaml.error.MarkedYAMLException;
import org.yaml.snakeyaml.error.YAMLException;

/**
 * HTTP client of the Vault KV v2 read API. Transport failures and 5xx or 429 answers are retried at
 * a fixed interval. A 401 or 403 answer to a token Vault still accepts is a policy that denies the
 * path; to any other token it gets one fresh login.
 */
final class VaultHttpClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(VaultHttpClient.class);

    private static final String TOKEN_HEADER = "X-Vault-Token";
    private static final int TEMPORARY_REDIRECT = 307;
    private static final int PERMANENT_REDIRECT = 308;
    private static final int MAX_REDIRECTS = 3;
    private static final int TOO_MANY_REQUESTS = 429;
    private static final int MAX_BODY_BYTES = 1 << 20;
    private static final int MAX_ERROR_BYTES = 1024;

    private final VaultConnectionInfo connInfo;
    private final VaultAuthMethod authMethod;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int retryCount;
    private final int retryIntervalMs;
    private final SSLSocketFactory sslSocketFactory;
    private String clientToken;

    VaultHttpClient(
            VaultConnectionInfo connInfo,
            VaultAuthMethod authMethod,
            int connectTimeoutMs,
            int readTimeoutMs,
            int retryCount,
            int retryIntervalMs,
            SSLSocketFactory sslSocketFactory) {
        this.connInfo = connInfo;
        this.authMethod = authMethod;
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
        this.retryCount = retryCount;
        this.retryIntervalMs = retryIntervalMs;
        this.sslSocketFactory = sslSocketFactory;
    }

    /**
     * Reads one field of a secret as text.
     *
     * @param dataPath the KV v2 data path
     * @param field the field within the secret
     * @return the field, or null when the secret, its current version or the field does not exist,
     *     or when the policy of the token denies reading it
     * @throws IOException if the request fails, the answer is not a KV v2 secret or the field is
     *     not a string
     */
    String readField(String dataPath, String field) throws IOException {
        String url = connInfo.apiUrl(dataPath);
        Response response = execute(url);
        if (response.status == HttpURLConnection.HTTP_NOT_FOUND) {
            checkAbsent(response);
            return null;
        }
        if (isRefusal(response.status)) {
            LOGGER.info("The Vault policy denies reading %s; treating it as absent", dataPath);
            return null;
        }
        Object data = field(field(parse(response.body, url), "data"), "data");
        if (!(data instanceof Map)) {
            throw new IOException("Vault response from " + url + " holds no KV v2 secret");
        }
        Object value = ((Map<?, ?>) data).get(field);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String)) {
            throw new IOException("Field " + field + " of " + dataPath + " is not a string");
        }
        return (String) value;
    }

    /**
     * A KV v2 404 without errors is a secret that does not exist, or whose current version is
     * deleted; with errors, the path is not served by any engine.
     */
    private static void checkAbsent(Response response) throws IOException {
        if (response.body.trim().isEmpty()) {
            return;
        }
        Object errors;
        try {
            errors = parse(response.body, response.url).get("errors");
        } catch (IOException e) {
            throw response.failure();
        }
        if (errors instanceof List && !((List<?>) errors).isEmpty()) {
            throw response.failure();
        }
    }

    private Response execute(String url) throws IOException {
        String action = "Vault request GET " + url;
        if (clientToken == null) {
            clientToken = authMethod.authenticate(this);
        }
        Response response = read(action, url, clientToken);
        if (isRefusal(response.status) && !isAccepted(clientToken)) {
            LOGGER.trace(
                    "%s answered %d and the token is no longer valid, logging in again",
                    action, response.status);
            clientToken = authMethod.authenticate(this);
            response = read(action, url, clientToken);
            if (isRefusal(response.status) && !isAccepted(clientToken)) {
                throw response.failure();
            }
        }
        return response;
    }

    /** GETs with retries; an answer other than 200, 404, 401 or 403 is a failure. */
    private Response read(String action, String url, String token) throws IOException {
        return retrying(
                action,
                () -> {
                    Response response = get(url, token);
                    int status = response.status;
                    if (status == HttpURLConnection.HTTP_OK
                            || status == HttpURLConnection.HTTP_NOT_FOUND
                            || isRefusal(status)) {
                        return response;
                    }
                    throw response.failure();
                });
    }

    private static boolean isRefusal(int status) {
        return status == HttpURLConnection.HTTP_UNAUTHORIZED
                || status == HttpURLConnection.HTTP_FORBIDDEN;
    }

    /**
     * Whether Vault still accepts the token. A token whose policy has no access to {@code
     * auth/token/lookup-self} counts as refused.
     */
    private boolean isAccepted(String token) {
        try {
            return get(connInfo.apiUrl("auth/token/lookup-self"), token).status
                    == HttpURLConnection.HTTP_OK;
        } catch (IOException e) {
            LOGGER.trace("Vault token lookup failed: %s", e);
            return false;
        }
    }

    /** Runs a request that is safe to repeat, retrying transient failures. */
    <T> T retrying(String action, RetriableCall<T> call) throws IOException {
        for (int attempt = 0; ; attempt++) {
            if (attempt > 0) {
                sleep(retryIntervalMs);
            }
            try {
                return call.call();
            } catch (IOException e) {
                if (!isTransient(e)) {
                    throw e;
                }
                LOGGER.warn(
                        "%s failed (attempt %d/%d): %s",
                        action, attempt + 1, retryCount + 1, e.getMessage());
                if (attempt >= retryCount) {
                    throw new IOException(
                            action + " failed after " + (attempt + 1) + " attempts", e);
                }
            }
        }
    }

    /** A request that may be repeated. */
    interface RetriableCall<T> {

        T call() throws IOException;
    }

    /**
     * POSTs a JSON body with the given Authorization header and returns the response body. A
     * redirect, such as a standby node sends, is followed with the header: the JDK would drop it.
     *
     * @throws RequestFailedException if the answer is not 200
     */
    String post(String url, String authorization, String jsonBody) throws IOException {
        byte[] body = jsonBody.getBytes(StandardCharsets.UTF_8);
        URL target = new URL(url);
        for (int redirects = 0; ; redirects++) {
            HttpURLConnection conn = open(target, "POST");
            conn.setInstanceFollowRedirects(false);
            conn.setRequestProperty("Authorization", authorization);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            // In streaming mode the JDK does not answer a 401 with a Negotiate login of its own.
            conn.setFixedLengthStreamingMode(body.length);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }
            int status = responseCode(conn);
            if (status == HttpURLConnection.HTTP_OK) {
                return readBody(conn.getInputStream());
            }
            String location = conn.getHeaderField("Location");
            if ((status == TEMPORARY_REDIRECT || status == PERMANENT_REDIRECT)
                    && location != null
                    && redirects < MAX_REDIRECTS) {
                readErrorBody(conn.getInputStream());
                URL next = new URL(target, location);
                if (!next.getProtocol().equals(target.getProtocol())) {
                    throw new IOException(
                            "POST "
                                    + target
                                    + " was redirected to "
                                    + next
                                    + " over another protocol");
                }
                LOGGER.trace("Following the redirect of POST %s to %s", target, next);
                target = next;
                continue;
            }
            throw new RequestFailedException(
                    status,
                    "POST "
                            + target
                            + " failed with status "
                            + status
                            + ": "
                            + readErrorBody(conn.getErrorStream()));
        }
    }

    private Response get(String url, String token) throws IOException {
        HttpURLConnection conn = open(new URL(url), "GET");
        conn.setRequestProperty(TOKEN_HEADER, token);
        int status = responseCode(conn);
        String body;
        if (status == HttpURLConnection.HTTP_OK) {
            body = readBody(conn.getInputStream());
        } else {
            body =
                    readErrorBody(
                            status >= HttpURLConnection.HTTP_BAD_REQUEST
                                    ? conn.getErrorStream()
                                    : conn.getInputStream());
        }
        return new Response(url, status, body);
    }

    private HttpURLConnection open(URL url, String method) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(connectTimeoutMs);
        conn.setReadTimeout(readTimeoutMs);
        conn.setUseCaches(false);
        if (sslSocketFactory != null && conn instanceof HttpsURLConnection) {
            ((HttpsURLConnection) conn).setSSLSocketFactory(sslSocketFactory);
        }
        return conn;
    }

    private static int responseCode(HttpURLConnection conn) throws IOException {
        try {
            return conn.getResponseCode();
        } catch (HttpRetryException e) {
            return e.responseCode();
        }
    }

    private static String readBody(InputStream is) throws IOException {
        byte[] body = readUpTo(is, MAX_BODY_BYTES);
        if (body.length > MAX_BODY_BYTES) {
            throw new IOException("Vault response is longer than " + MAX_BODY_BYTES + " bytes");
        }
        return new String(body, StandardCharsets.UTF_8);
    }

    /** The start of an error answer, which goes into exception messages. */
    private static String readErrorBody(InputStream is) throws IOException {
        byte[] body = readUpTo(is, MAX_ERROR_BYTES);
        String text =
                new String(body, 0, Math.min(body.length, MAX_ERROR_BYTES), StandardCharsets.UTF_8);
        return body.length > MAX_ERROR_BYTES ? text + "..." : text;
    }

    /** Reads a stream until it ends or holds more than limit bytes. */
    private static byte[] readUpTo(InputStream is, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (is != null) {
            try (InputStream in = is) {
                byte[] buffer = new byte[4096];
                int n;
                while (out.size() <= limit && (n = in.read(buffer)) > 0) {
                    out.write(buffer, 0, n);
                }
            }
        }
        return out.toByteArray();
    }

    /** Parses a JSON object with the YAML parser, which reads JSON as YAML flow style. */
    static Map<?, ?> parse(String body, String url) throws IOException {
        Object json;
        try {
            json = new Yaml(new SafeConstructor(new LoaderOptions())).load(toYaml(body));
        } catch (YAMLException e) {
            // Not chained: the parser's message quotes the answer, which may hold a secret.
            throw new IOException("Vault response from " + url + " is not JSON" + position(e));
        }
        if (!(json instanceof Map)) {
            throw new IOException("Vault response from " + url + " is not a JSON object");
        }
        return (Map<?, ?>) json;
    }

    private static String position(YAMLException e) {
        if (e instanceof MarkedYAMLException) {
            Mark mark = ((MarkedYAMLException) e).getProblemMark();
            if (mark != null) {
                return " at line " + (mark.getLine() + 1) + ", column " + (mark.getColumn() + 1);
            }
        }
        return "";
    }

    /**
     * Rewrites the JSON that YAML 1.1 reads otherwise or rejects: the {@code \/} escape, tabs
     * between tokens, and characters YAML does not allow in a document, which JSON strings may hold
     * unescaped.
     */
    static String toYaml(String json) {
        StringBuilder sb = new StringBuilder(json.length());
        boolean inString = false;
        for (int i = 0; i < json.length(); ) {
            int c = json.codePointAt(i);
            i += Character.charCount(c);
            if (!inString) {
                if (c == '"') {
                    inString = true;
                }
                sb.appendCodePoint(c == '\t' ? ' ' : c);
            } else if (c == '\\' && i < json.length()) {
                char escaped = json.charAt(i++);
                if (escaped != '/') {
                    sb.append('\\');
                }
                sb.append(escaped);
            } else if (isYamlPrintable(c)) {
                if (c == '"') {
                    inString = false;
                }
                sb.appendCodePoint(c);
            } else {
                sb.append(String.format("\\u%04X", c));
            }
        }
        return sb.toString();
    }

    private static boolean isYamlPrintable(int c) {
        return c == 0x9
                || c == 0xA
                || c == 0xD
                || (c >= 0x20 && c <= 0x7E)
                || c == 0x85
                || (c >= 0xA0 && c <= 0xD7FF)
                || (c >= 0xE000 && c <= 0xFFFD)
                || (c >= 0x10000 && c <= 0x10FFFF);
    }

    /** The member of a JSON object, null when the node is not an object. */
    static Object field(Object node, String name) {
        return node instanceof Map ? ((Map<?, ?>) node).get(name) : null;
    }

    /** A JSON object with one string member, empty when the value is null. */
    static String json(String key, String value) {
        return value == null ? "{}" : "{" + quote(key) + ":" + quote(value) + "}";
    }

    private static String quote(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                sb.append('\\').append(c);
            } else if (c < 0x20) {
                sb.append(String.format("\\u%04X", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    /**
     * Whether a later attempt may succeed: the server answered that it is busy or down, or a
     * connection failed, also under a TLS handshake or a Kerberos login.
     */
    static boolean isTransient(IOException e) {
        if (e instanceof RequestFailedException) {
            return ((RequestFailedException) e).isTransient();
        }
        for (Throwable cause = e; cause != null; cause = cause.getCause()) {
            if (cause instanceof SocketException
                    || cause instanceof SocketTimeoutException
                    || cause instanceof UnknownHostException
                    || cause instanceof EOFException) {
                return true;
            }
        }
        return false;
    }

    private static void sleep(long ms) throws IOException {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while retrying a Vault request", e);
        }
    }

    private static final class Response {

        private final String url;
        private final int status;
        private final String body;

        Response(String url, int status, String body) {
            this.url = url;
            this.status = status;
            this.body = body;
        }

        RequestFailedException failure() {
            return new RequestFailedException(
                    status, "GET " + url + " failed with status " + status + ": " + body);
        }
    }

    /** An answer with a status the caller cannot use. */
    static final class RequestFailedException extends IOException {

        private static final long serialVersionUID = 1L;
        private final int status;

        RequestFailedException(int status, String message) {
            super(message);
            this.status = status;
        }

        /** Whether a later attempt may succeed: the server is busy or down. */
        boolean isTransient() {
            return status >= HttpURLConnection.HTTP_INTERNAL_ERROR || status == TOO_MANY_REQUESTS;
        }
    }
}
