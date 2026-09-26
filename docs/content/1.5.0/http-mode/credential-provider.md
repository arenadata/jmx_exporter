---
title: Credential provider
weight: 5
---

The keystore and truststore passwords of the [SSL](../ssl) configuration can be read from the KV v2 secrets engine of HashiCorp Vault or OpenBao instead of the exporter YAML file or the `javax.net.ssl.*Password` system properties.

Every alias is a separate secret of a KV v2 engine whose `value` field holds the password, so `bao kv put <mount>/<path>/<alias> value=<password>` stores it. The value must be a JSON string, as the `bao` CLI writes it. One line end at the end of a value is dropped, so `value=@file` stores a password file as it is.

### Configuration

```yaml
httpServer:
  credentialProvider:
    uri: vault://https@bao.example.com:8200/secret/jmx
    authMethod: kerberos
    kerberos:
      principal: jmx/_HOST@EXAMPLE.COM
      keytab: /etc/security/keytabs/jmx.keytab
      servicePrincipal: HTTP/_HOST@EXAMPLE.COM
    trustStore:
      filename: /etc/ssl/bao-ca.pem
  ssl:
    keyStore:
      filename: localhost.p12
      type: PKCS12
      passwordAlias: keystore.password
    certificate:
      alias: localhost
```

A keystore or truststore password is the first of:

1. the secret named by `passwordAlias`
2. `password`
3. the `javax.net.ssl.keyStorePassword` or `javax.net.ssl.trustStorePassword` system property

An alias the engine does not hold, or the token's policy does not allow to read, falls back to the next source with a warning; a wrong mount or path, or a KV v1 engine, looks the same. The exporter does not start when such an alias has no next source, or when the alias holds a blank value. The truststore password is read only with `mutualTLS: true`, as the truststore is not used otherwise.

The passwords are read once, before the HTTP server starts. If Vault cannot be read after the retries, the exporter does not start: the Java agent exits the JVM, as on any other configuration error. A token obtained by the Kerberos login is revoked once the passwords are read; the token of `tokenPath` stays valid.

| Key                         | Description                                                                                                                                                                               | Default                                  |
|-----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------|
| `uri`                       | `vault://[protocol@]host[:port]/mount[/path][?key=field]`; the protocol is `https` or `http`, `key` names the field that holds a password                                                  | required                                 |
| `authMethod`                | `token` or `kerberos`                                                                                                                                                                     | `token`                                  |
| `tokenPath`                 | File that holds the Vault token, read again whenever Vault refuses the current token                                                                                                      | required for `token`                     |
| `kerberos.principal`        | Principal to log in as; `_HOST` stands for the canonical name of the local host in lower case                                                                                             | required for `kerberos`                  |
| `kerberos.keytab`           | Keytab of the principal                                                                                                                                                                   | required for `kerberos`                  |
| `kerberos.servicePrincipal` | Service principal of Vault; `_HOST` stands for the Vault host in lower case                                                                                                               | `HTTP@<Vault host>`                      |
| `kerberos.mountPath`        | Mount path of the Kerberos auth method                                                                                                                                                    | `auth/kerberos`                          |
| `kerberos.role`             | Role to log in with, needed only when several roles are bound to the principal                                                                                                            |                                          |
| `trustStore.filename`       | Trust store of the https connection to Vault                                                                                                                                              | the JVM default trust store, no client key |
| `trustStore.type`           | `PEM`, `JKS` or `PKCS12`                                                                                                                                                                  | by file extension                        |
| `trustStore.password`       | Trust store password; a PEM or JKS trust store needs none                                                                                                                                 |                                          |
| `connectTimeoutMs`          | Connect timeout of the requests to Vault                                                                                                                                                  | `5000`                                   |
| `readTimeoutMs`             | Read timeout of the requests to Vault                                                                                                                                                     | `10000`                                  |
| `retryCount`                | Retries of transport failures and 5xx or 429 answers                                                                                                                                      | `3`                                      |
| `retryIntervalMs`           | Interval between the retries                                                                                                                                                              | `1000`                                   |

**Notes**

- The Java agent reads the passwords while the JVM starts, so it sets up the JVM default TLS and Kerberos settings from the system properties given at that point. Set `javax.net.ssl.*` and `java.security.krb5.*` on the command line, not from the application.
- The `kerberos` login sends the SPNEGO token in the Authorization header, so the Kerberos auth mount must pass that header through: `bao auth tune -passthrough-request-headers=Authorization kerberos/`. A login that a standby node redirects to the active node follows the redirect with the header.
- Telling a policy that denies an alias from a token that is no longer valid takes a token lookup, so the token's policies must allow reading `auth/token/lookup-self`, as the `default` policy does.
- The trust store password cannot come from the provider. A JKS trust store without a password is read without its integrity check. A PKCS12 trust store written by keytool needs its password, as its certificates are encrypted; keytool of Java 9 and later writes PKCS12, whatever the file extension, unless given `-storetype JKS`.
- The trust store type follows the file extension when not set: `.pem`, `.crt` and `.cer` are PEM, `.p12`, `.pfx` and `.pkcs12` are PKCS12, `.jks` is JKS, anything else is the JVM default keystore type.
- Over `http` the Vault token travels unencrypted and nothing proves the server is Vault, so it suits tests only.
