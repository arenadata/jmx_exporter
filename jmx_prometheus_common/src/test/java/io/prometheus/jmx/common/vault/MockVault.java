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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;

/**
 * A KV v2 engine, token lookup and a Kerberos auth method served over HTTP or HTTPS by {@code
 * com.sun.net.httpserver}.
 */
public final class MockVault implements AutoCloseable {

    public static final String TOKEN = "s.mock-token";
    public static final String KERBEROS_LOGIN_PATH = "/v1/auth/kerberos/login";
    public static final String LOOKUP_SELF_PATH = "/v1/auth/token/lookup-self";

    /** Checks the SPNEGO token of a Kerberos login. */
    public interface LoginHandler {

        /**
         * Returns the client token to issue, or null to refuse the login.
         *
         * @param authorization the Authorization header of the login request
         */
        String login(String authorization) throws Exception;
    }

    private final HttpServer server;
    private final String protocol;
    private final Map<String, Map<String, String>> secrets = new ConcurrentHashMap<>();
    private final Map<String, String> rawResponses = new ConcurrentHashMap<>();
    private final List<String> requests = new CopyOnWriteArrayList<>();
    private final Set<String> acceptedTokens =
            Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());
    private final Set<String> deniedPaths =
            Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());
    private final List<String> loginRoles = new CopyOnWriteArrayList<>();
    private final AtomicInteger failures = new AtomicInteger();
    private volatile int failureStatus;
    private volatile String failureBody;
    private volatile LoginHandler loginHandler;
    private volatile String loginRedirect;

    public MockVault() throws IOException {
        this(null);
    }

    /** Serves HTTPS with the given server context, or HTTP when it is null. */
    public MockVault(SSLContext sslContext) throws IOException {
        InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        if (sslContext == null) {
            server = HttpServer.create(address, 0);
            protocol = "http";
        } else {
            HttpsServer httpsServer = HttpsServer.create(address, 0);
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
            server = httpsServer;
            protocol = "https";
        }
        server.createContext("/v1/", this::handle);
        server.start();
        acceptedTokens.add(TOKEN);
    }

    /** The provider URI of a KV path on this server, such as {@code secret/app}. */
    public String uri(String path) {
        return "vault://" + protocol + "@localhost:" + port() + "/" + path;
    }

    public int port() {
        return server.getAddress().getPort();
    }

    /**
     * Stores a string field of the secret at a KV v2 data path such as {@code
     * secret/data/app/alias}.
     */
    public void putSecret(String dataPath, String field, String value) {
        putSecretJson(dataPath, field, quote(value));
    }

    /** Stores a field of a secret as JSON text, such as a number. */
    public void putSecretJson(String dataPath, String field, String json) {
        secrets.computeIfAbsent(dataPath, path -> new ConcurrentHashMap<>()).put(field, json);
    }

    /** Answers reads of a KV v2 data path with 200 and the given body. */
    public void putRaw(String dataPath, String body) {
        rawResponses.put(dataPath, body);
    }

    public void acceptToken(String token) {
        acceptedTokens.add(token);
    }

    public void revokeToken(String token) {
        acceptedTokens.remove(token);
    }

    public void setLoginHandler(LoginHandler loginHandler) {
        this.loginHandler = loginHandler;
    }

    /** Answers reads of a KV v2 data path with the 403 of a policy that does not cover it. */
    public void deny(String dataPath) {
        deniedPaths.add(dataPath);
    }

    /** Answers Kerberos logins with a 307 to the same path on another server, as a standby does. */
    public void redirectLoginTo(MockVault active) {
        loginRedirect = active.protocol + "://localhost:" + active.port() + KERBEROS_LOGIN_PATH;
    }

    /** Answers the next {@code count} requests with {@code status}. */
    public void fail(int status, int count) {
        fail(status, count, "{\"errors\":[\"injected failure\"]}");
    }

    public void fail(int status, int count, String body) {
        failureStatus = status;
        failureBody = body;
        failures.set(count);
    }

    /** Every request received, as method and path. */
    public List<String> requests() {
        return requests;
    }

    /** The {@code role} member of every login request, null where it was not sent. */
    public List<String> loginRoles() {
        return loginRoles;
    }

    private void handle(HttpExchange exchange) throws IOException {
        String body = read(exchange.getRequestBody());
        String path = exchange.getRequestURI().getPath();
        requests.add(exchange.getRequestMethod() + " " + path);
        if (failures.getAndUpdate(n -> n > 0 ? n - 1 : 0) > 0) {
            respond(exchange, failureStatus, failureBody);
            return;
        }
        if (path.equals(KERBEROS_LOGIN_PATH) && exchange.getRequestMethod().equals("POST")) {
            String redirect = loginRedirect;
            if (redirect != null) {
                exchange.getResponseHeaders().set("Location", redirect);
                respond(exchange, 307, "");
                return;
            }
            login(exchange, body);
            return;
        }
        String token = exchange.getRequestHeaders().getFirst("X-Vault-Token");
        boolean accepted = token != null && acceptedTokens.contains(token);
        if (path.equals(LOOKUP_SELF_PATH)) {
            respond(
                    exchange,
                    accepted ? 200 : 403,
                    accepted ? "{\"data\":{}}" : "{\"errors\":[\"permission denied\"]}");
            return;
        }
        String dataPath = path.substring("/v1/".length());
        if (!exchange.getRequestMethod().equals("GET") || !dataPath.startsWith("secret/data/")) {
            respond(
                    exchange,
                    404,
                    "{\"errors\":[\"no handler for route \\\"" + dataPath + "\\\"\"]}");
            return;
        }
        if (!accepted || deniedPaths.contains(dataPath)) {
            respond(exchange, 403, "{\"errors\":[\"permission denied\"]}");
            return;
        }
        String raw = rawResponses.get(dataPath);
        if (raw != null) {
            respond(exchange, 200, raw);
            return;
        }
        Map<String, String> fields = secrets.get(dataPath);
        if (fields == null) {
            respond(exchange, 404, "{\"errors\":[]}");
            return;
        }
        StringBuilder data = new StringBuilder();
        for (Map.Entry<String, String> field : fields.entrySet()) {
            data.append(data.length() == 0 ? "" : ",")
                    .append(quote(field.getKey()))
                    .append(':')
                    .append(field.getValue());
        }
        respond(
                exchange,
                200,
                "{\"request_id\":\"1\",\"data\":{\"data\":{"
                        + data
                        + "},\"metadata\":{\"version\":1}},\"warnings\":null}");
    }

    private void login(HttpExchange exchange, String body) throws IOException {
        Object role = body.isEmpty() ? null : VaultHttpClient.parse(body, "login").get("role");
        loginRoles.add(role == null ? null : role.toString());
        LoginHandler handler = loginHandler;
        String token;
        try {
            token =
                    handler == null
                            ? null
                            : handler.login(exchange.getRequestHeaders().getFirst("Authorization"));
        } catch (Exception e) {
            token = null;
        }
        if (token == null) {
            exchange.getResponseHeaders().set("WWW-Authenticate", "Negotiate");
            respond(exchange, 401, "{\"errors\":[\"login refused\"]}");
            return;
        }
        acceptedTokens.add(token);
        respond(exchange, 200, "{\"auth\":{\"client_token\":" + quote(token) + "}}");
    }

    private static String quote(String value) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            if (c == '"' || c == '\\') {
                sb.append('\\').append(c);
            } else if (c < 0x20) {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    private static String read(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = in.read(buffer)) > 0) {
            out.write(buffer, 0, n);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
