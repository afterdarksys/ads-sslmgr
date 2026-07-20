# Provider, Private PKI, and Host Agent Implementation Plan

> **For Codex:** Use `${SUPERPOWERS_SKILLS_ROOT}/skills/collaboration/executing-plans/SKILL.md` to implement this plan task-by-task.

**Goal:** Deliver production-oriented public CA plugins, Cloudflare/Bunny ACME DNS automation, a four-tier private PKI, an enrollment API, a renewable host agent, and MIT/Heimdal PKINIT certificate profiles.

**Architecture:** A typed provider registry loads built-ins and Python entry points. Public CA adapters share normalized errors/results; Let's Encrypt delegates ACME execution to certbot and typed DNS plugins. The private PKI API issues CSR-bound certificates through an issuing CA, authenticates first enrollment with hashed one-time tokens, and authenticates later renewals with the existing certificate fingerprint. A small host agent generates and retains keys locally, renews before expiry, and installs files atomically.

**Tech Stack:** Python 3, Flask, SQLAlchemy/Alembic, cryptography, requests, certbot, pytest.

---

### Task 1: Provider contracts, configuration, and discovery

**Files:**
- Create: `providers/__init__.py`
- Create: `providers/base.py`
- Create: `providers/config.py`
- Create: `providers/registry.py`
- Test: `tests/test_provider_registry.py`
- Modify: `setup.py`

1. Write failing tests for built-in registration, aliases, environment overrides, third-party entry-point discovery, duplicate rejection, and safe status serialization.
2. Run `/usr/bin/python3 -m pytest tests/test_provider_registry.py -q` and verify failure.
3. Implement typed CA/DNS contracts, normalized errors/results, configuration lookup with `SSLMGR_*` overrides, and `importlib.metadata` entry-point discovery.
4. Run the tests and verify they pass.
5. Commit with `feat: add extensible certificate provider registry`.

### Task 2: Cloudflare and Bunny DNS-01 providers

**Files:**
- Create: `providers/dns/__init__.py`
- Create: `providers/dns/cloudflare.py`
- Create: `providers/dns/bunny.py`
- Create: `providers/dns/hook.py`
- Test: `tests/test_dns_providers.py`
- Modify: `config/config.example.json`

1. Write mocked HTTP tests for zone selection, TXT creation, record-ID cleanup, auth failures, timeouts, and redacted errors.
2. Run the tests and verify failure.
3. Implement Cloudflare `POST/DELETE /zones/{zone}/dns_records` with Bearer tokens and Bunny `PUT/DELETE /dnszone/{zone}/records` with `AccessKey`, plus a certbot hook entry point using `CERTBOT_DOMAIN` and `CERTBOT_VALIDATION`.
4. Run the tests and verify they pass.
5. Commit with `feat: add Cloudflare and Bunny ACME DNS providers`.

### Task 3: Certbot-backed Let's Encrypt provider

**Files:**
- Modify: `integrations/letsencrypt.py`
- Test: `tests/test_letsencrypt_provider.py`

1. Write process-mocking tests for HTTP-01, built-in DNS hooks, native certbot plugin selection, missing email/binary, cleanup environment, timeout, and command redaction.
2. Run the tests and verify failure.
3. Replace placeholder shell-hook generation with the typed DNS hook runner; add configurable certbot paths/options and safe subprocess execution.
4. Run the tests and verify they pass.
5. Commit with `feat: automate Lets Encrypt DNS challenges`.

### Task 4: Harden DigiCert and Sectigo providers

**Files:**
- Modify: `integrations/digicert.py`
- Modify: `integrations/comodo.py`
- Create: `tests/test_commercial_ca_providers.py`

1. Write mocked API tests for order/enroll, bounded retry, `Retry-After`, polling, collection, revocation, credential redaction, atomic certificate writes, and malformed certificates.
2. Run tests and verify failure.
3. Implement shared safe request behavior and certificate/key/name validation before atomic installation.
4. Run tests and verify they pass.
5. Commit with `feat: harden DigiCert and Sectigo workflows`.

### Task 5: Four-tier private PKI and PKINIT profiles

**Files:**
- Modify: `ca/private_ca.py`
- Modify: `ca/ca_manager.py`
- Test: `tests/test_private_pki_profiles.py`

1. Write tests for root → intermediate-1 → intermediate-2 → issuing path-length constraints and complete chain construction.
2. Write tests for MIT/Heimdal PKINIT client and KDC EKUs, digital-signature key usage, and DER-encoded `id-pkinit-san` principals.
3. Run tests and verify failure.
4. Implement hierarchy bootstrap and the `pkinit_client`/`pkinit_kdc` certificate profiles using RFC 4556 OIDs.
5. Run tests and verify they pass.
6. Commit with `feat: add four-tier PKI and PKINIT profiles`.

### Task 6: Enrollment state and service

**Files:**
- Modify: `database/models.py`
- Create: `pki/__init__.py`
- Create: `pki/enrollment.py`
- Create: `migrations/versions/8c1a6f91c1e2_add_enrollment_agents.py`
- Test: `tests/test_enrollment_service.py`

1. Write tests for one-time token hashing/consumption, CSR issuance, agent identity binding, renewal threshold, fingerprint authentication, revocation, and audit state.
2. Run tests and verify failure.
3. Add enrollment-token and managed-agent models and implement the service without storing host private keys.
4. Run tests and verify they pass.
5. Commit with `feat: add private PKI enrollment service`.

### Task 7: REST API and host renewal agent

**Files:**
- Modify: `web/api.py`
- Create: `agents/certificate_agent.py`
- Create: `tests/test_pki_api.py`
- Create: `tests/test_certificate_agent.py`

1. Write API tests for provider discovery/health and private PKI bootstrap, token creation, enroll, renew, download-chain, revoke, and CRL endpoints.
2. Write agent tests for local key generation, CSR enrollment, mTLS-style fingerprint renewal, expiry scheduling, atomic installation, permissions, and post-install hooks.
3. Run tests and verify failure.
4. Implement authenticated API routes and a dependency-light agent CLI suitable for cron/systemd.
5. Run tests and verify they pass.
6. Commit with `feat: add PKI API and renewable host agent`.

### Task 8: CLI, packaging, examples, and documentation

**Files:**
- Modify: `cli/ssl_manager.py`
- Modify: `setup.py`
- Modify: `README.md`
- Modify: `config/config.example.json`
- Create: `docs/PROVIDERS.md`
- Create: `docs/PRIVATE_PKI.md`
- Create: `examples/systemd/sslmgr-agent.service`
- Create: `examples/systemd/sslmgr-agent.timer`
- Test: `tests/test_cli_provider_pki.py`

1. Add failing CLI tests for provider listing/health, hierarchy bootstrap, token creation, and agent commands.
2. Implement commands and package entry points.
3. Document least-privilege credentials, plugin authoring, API deployment behind a production WSGI server, four-tier PKI operations, MIT/Heimdal configuration, and agent installation.
4. Run focused tests, then `/usr/bin/python3 -m pytest tests/ -q` and `git diff --check`.
5. Commit with `docs: complete provider and private PKI operations`.

