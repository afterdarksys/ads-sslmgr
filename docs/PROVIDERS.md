# Certificate and DNS Providers

SSL Manager ships with Let's Encrypt, DigiCert, and Sectigo certificate-authority providers and Cloudflare and bunny.net DNS-01 providers.

## Configuration and secrets

JSON remains supported, but every provider field can be overridden without placing a secret on disk:

```bash
export SSLMGR_CA_DIGICERT_API_KEY='...'
export SSLMGR_CA_DIGICERT_ORGANIZATION_ID='12345'
export SSLMGR_CA_SECTIGO_LOGIN='automation@example.com'
export SSLMGR_CA_SECTIGO_PASSWORD='...'
export SSLMGR_CA_SECTIGO_CUSTOMER_URI='example'
export SSLMGR_DNS_CLOUDFLARE_API_TOKEN='...'
export SSLMGR_DNS_BUNNY_API_KEY='...'
```

Use a Cloudflare API token restricted to `Zone:DNS:Edit` for only the required zones. Bunny uses its `AccessKey`; configure `zone_id` and `zone_name`. SSL Manager remembers the exact record ID it creates and deletes only that record.

Let's Encrypt uses certbot. Set `certificate_authorities.letsencrypt.dns_provider` to `cloudflare` or `bunny`. To use a native certbot plugin instead, set `certbot_plugin` (for example `dns-route53`) and optional `certbot_plugin_options`.

## Operations

```bash
python cli/ssl_manager.py providers list
python cli/ssl_manager.py providers health digicert --kind ca
python cli/ssl_manager.py providers health cloudflare --kind dns
```

The API exposes `GET /api/providers`, `POST /api/providers/{kind}/{name}/health`, `POST /api/providers/{name}/orders`, order status, and revocation endpoints. Health probes are explicit because they may call billable or rate-limited remote APIs.

## Writing a plugin

Implement `CertificateAuthorityProvider` or `DNSChallengeProvider` from `providers.base`, then expose a factory accepting `(config, db_manager)`:

```toml
[project.entry-points."sslmgr.dns_providers"]
route53 = "my_ssl_plugin:build_provider"
```

CA plugins use the `sslmgr.ca_providers` group. Duplicate names are rejected. A broken installed plugin is reported through provider status without preventing the server from starting. Local applications may also call `ProviderRegistry.register_ca()` or `register_dns()` directly.
