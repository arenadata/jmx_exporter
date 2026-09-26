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

/** A way to obtain a Vault client token. */
interface VaultAuthMethod {

    /**
     * Logs in and returns the client token.
     *
     * @param client the client to send login requests through
     * @return the client token
     * @throws IOException if the login fails
     */
    String authenticate(VaultHttpClient client) throws IOException;

    /**
     * Whether each login issues a new token, which the client revokes once it is done.
     *
     * @return true for a login that issues tokens, false for a token supplied from outside
     */
    default boolean issuesToken() {
        return false;
    }
}
