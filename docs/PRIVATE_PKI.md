# Private PKI, Host Enrollment, and PKINIT

## Four-tier hierarchy

Create Root → Intermediate 1 → Intermediate 2 → Issuing CA with enforced path lengths 3, 2, 1, and 0:

```bash
python cli/ssl_manager.py ca bootstrap corp --common-name-prefix "Corp" --org "Example Corp"
```

Keep root and upper-intermediate keys offline in a serious deployment. The built-in file key store is suitable for evaluation and controlled environments; production deployments should restrict the service account and key directory and plan an HSM/PKCS#11 plugin before treating it as a high-assurance CA.

## Host enrollment and renewal

Create a one-time token against the issuing CA:

```bash
python cli/ssl_manager.py ca create-token ISSUING_CA_ID web-01
python agents/certificate_agent.py --config /etc/sslmgr-agent/config.json enroll --token TOKEN
systemctl enable --now sslmgr-agent.timer
```

The agent generates its private key and CSR locally. The private key is never sent to the service. The token is stored only as SHA-256 of 256 bits of randomness, expires, and is single-use by default. Renewals rotate the key and require a TLS client certificate. Put the WSGI service behind a TLS terminator that verifies the client chain and sets the WSGI variables `SSL_CLIENT_VERIFY=SUCCESS` and `SSL_CLIENT_FINGERPRINT=<lowercase SHA-256 hex>`. Caller-supplied HTTP fingerprint headers are ignored.

The agent installs keys with mode `0600`, certificates with `0644`, uses fsync plus atomic rename, and accepts a non-shell post-install command list. See `config/agent.example.json` and the systemd examples.

## MIT/Heimdal PKINIT

Profiles `pkinit_client` and `pkinit_kdc` implement RFC 4556:

- client EKU `1.3.6.1.5.2.3.4`;
- KDC EKU `1.3.6.1.5.2.3.5`;
- `id-pkinit-san` OtherName `1.3.6.1.5.2.2` with DER-encoded `KRB5PrincipalName`;
- digital-signature key usage.

Create a constrained client token:

```bash
python cli/ssl_manager.py ca create-token ISSUING_CA_ID alice \
  --type pkinit_client --pkinit-principal alice@EXAMPLE.COM
```

For a KDC use `pkinit_kdc` and a principal such as `krbtgt/EXAMPLE.COM@EXAMPLE.COM`. Configure MIT Kerberos `pkinit_identity`, `pkinit_anchors`, `pkinit_pool`, and `pkinit_revoke`; enable strict CRL checking when your CRL publication path is reliable. Microsoft smart-card-logon/UPN certificate profiles are intentionally deferred to the next compatibility layer.

## Production API

Do not expose Flask's development server. Run `wsgi:application` with gunicorn using `examples/systemd/sslmgr-api.service`, terminate TLS with mandatory client verification on enrollment renewal paths, restrict CORS origins, protect the Fernet encryption key, and back up the database and CA material separately.
