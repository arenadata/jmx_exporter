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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class VaultConnectionInfoTest {

    @Test
    public void testFullUri() {
        VaultConnectionInfo info =
                new VaultConnectionInfo(
                        "vault://https@bao.example.com:8201/secret/jmx/prod?key=password");
        assertThat(info.baseUrl()).isEqualTo("https://bao.example.com:8201");
        assertThat(info.isHttps()).isTrue();
        assertThat(info.getHost()).isEqualTo("bao.example.com");
        assertThat(info.getField()).isEqualTo("password");
        assertThat(info.dataPath("keystore.password"))
                .isEqualTo("secret/data/jmx/prod/keystore.password");
        assertThat(info).hasToString("vault://https@bao.example.com:8201/secret/jmx/prod");
    }

    @Test
    public void testDefaults() {
        VaultConnectionInfo info = new VaultConnectionInfo("vault://bao.example.com/secret");
        assertThat(info.baseUrl()).isEqualTo("https://bao.example.com:8200");
        assertThat(info.getField()).isEqualTo("value");
        assertThat(info.dataPath("alias")).isEqualTo("secret/data/alias");
    }

    @Test
    public void testHttp() {
        VaultConnectionInfo info = new VaultConnectionInfo("vault://HTTP@localhost:8200/kv/jmx/");
        assertThat(info.baseUrl()).isEqualTo("http://localhost:8200");
        assertThat(info.isHttps()).isFalse();
        assertThat(info.dataPath("a")).isEqualTo("kv/data/jmx/a");
    }

    @Test
    public void testIpv6Host() {
        assertThat(new VaultConnectionInfo("vault://https@[::1]:8200/secret").baseUrl())
                .isEqualTo("https://[::1]:8200");
        assertThat(new VaultConnectionInfo("vault://https@[::1]/secret").baseUrl())
                .isEqualTo("https://[::1]:8200");
    }

    @Test
    public void testHostWithUnderscore() {
        VaultConnectionInfo info = new VaultConnectionInfo("vault://http@open_bao:18200/secret");
        assertThat(info.baseUrl()).isEqualTo("http://open_bao:18200");
        assertThat(info.getHost()).isEqualTo("open_bao");
    }

    @Test
    public void testApiUrlEncodesSegments() {
        VaultConnectionInfo info = new VaultConnectionInfo("vault://localhost:8200/secret/jmx");
        assertThat(info.apiUrl(info.dataPath("a b?c/d.e_f~g-h")))
                .isEqualTo("https://localhost:8200/v1/secret/data/jmx/a%20b%3Fc/d.e_f~g-h");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://localhost:8200/secret",
                "vault://ftp@localhost:8200/secret",
                "vault:///secret",
                "vault://localhost:8200",
                "vault://localhost:8200/",
                "vault://localhost:8200/secret//jmx",
                "vault://localhost:8200/secret/../jmx",
                "vault://localhost:0/secret",
                "vault://localhost:70000/secret",
                "vault://localhost:port/secret",
                "vault://https@:8200/secret",
                "vault://local host/secret",
            })
    public void testInvalidUri(String uri) {
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> new VaultConnectionInfo(uri));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "a//b", "./a", "a/..", "a\nb", "/a"})
    public void testInvalidPath(String path) {
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> VaultConnectionInfo.checkPath(path));
    }
}
