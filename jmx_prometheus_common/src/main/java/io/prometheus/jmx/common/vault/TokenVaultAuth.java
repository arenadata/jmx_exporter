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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * A Vault token read from a file. The file is read again at every login, so a rotated token is
 * picked up once Vault refuses the old one.
 */
final class TokenVaultAuth implements VaultAuthMethod {

    private static final char BYTE_ORDER_MARK = 0xFEFF;

    private final String tokenPath;

    TokenVaultAuth(String tokenPath) {
        this.tokenPath = tokenPath;
    }

    @Override
    public String authenticate(VaultHttpClient client) throws IOException {
        String content =
                new String(Files.readAllBytes(Paths.get(tokenPath)), StandardCharsets.UTF_8);
        // Some editors start the file with a byte order mark.
        if (!content.isEmpty() && content.charAt(0) == BYTE_ORDER_MARK) {
            content = content.substring(1);
        }
        String token = content.trim();
        if (token.isEmpty()) {
            throw new IOException("Vault token file " + tokenPath + " is empty");
        }
        checkToken(token);
        return token;
    }

    /**
     * Vault tokens are printable ASCII. Anything else would reach Vault as a different token, or be
     * rejected by the HTTP header code with an exception that quotes the value.
     */
    static void checkToken(String token) throws IOException {
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (c <= ' ' || c >= 0x7f) {
                throw new IOException(
                        "Vault token contains whitespace or characters other than printable"
                                + " ASCII");
            }
        }
    }
}
