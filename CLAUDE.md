# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Product

ads-sslmgr is SSL management tools: a comprehensive SSL certificate management system for monitoring, renewing,
and managing certificates across public CAs, cloud providers, and internal private CAs. Primary implementation
is Python; a parallel PHP component set exists under `composer.json` (`src/php/`, PSR-4 `SSLManager\`) but the
Python stack (Flask API, Click CLI, SQLAlchemy/Alembic, Celery) is the actively developed core.

## Commands

```bash
# Install Python dependencies
pip install -r requirements.txt

# One-time setup: writes config/config.json, creates DB tables, creates directories, chmods CLI scripts
python setup.py

# Database schema (Alembic-managed; script_location = migrations)
alembic upgrade head
# Or, create tables directly without Alembic:
python -c "from database.models import DatabaseManager, get_database_url; import json; cfg=json.load(open('config/config.json')); DatabaseManager(get_database_url(cfg)).create_tables()"

# Smoke test: imports, DB init, CertificateManager, OAuth2Handler, API init
python test_startup.py

# Run the CLI
python cli/ssl_manager.py --help
python cli/ssl_manager.py scan directory /etc/ssl/certs
python cli/ssl_manager.py list certificates --expiring 30
python cli/ssl_manager.py renew certificate <id>
python cli/ssl_manager.py ca create-root my-root-ca --common-name "My Root CA" --validity-years 20
python cli/ssl_manager.py ca issue <ca-id> server.example.com --san server.example.com --days 365 --out-cert cert.pem --out-key key.pem
python cli/ssl_manager.py ca revoke <ca-id> <cert-id> --reason key_compromise
python cli/ssl_manager.py ca crl <ca-id> --regenerate --out ca.crl.pem

# Run the web server / REST API
python start_web_server.py --host 0.0.0.0 --port 5000
# or directly:
python web/api.py --host 0.0.0.0 --port 5000

# Test suite (pytest, tests/ directory)
python -m pytest tests/ -q
# Single test file / single test (tests are organized as classes, e.g. TestRootCA)
python -m pytest tests/test_ca_manager.py -q
python -m pytest tests/test_ca_manager.py::TestRootCA::test_create_root_rsa -q

# PHP components (composer.json), separate from the Python core
composer test        # phpunit
composer cs-check     # phpcs
composer cs-fix       # phpcbf
```

Before running anything that touches secrets (private CA key storage, encrypted API credentials in
`CAConfiguration`), set `SSLMGR_ENCRYPTION_KEY`:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
export SSLMGR_ENCRYPTION_KEY=<output>
```

`tests/conftest.py` sets a throwaway Fernet key automatically, so the test suite does not require this env var.

## Architecture

**Config-driven wiring.** Nearly every component (`CertificateManager`, `RenewalRouter`, `CAManager`,
`EmailNotifier`, `SNMPNotifier`, integrations) is constructed with the same `config` dict loaded from
`config/config.json` (see `config/config.example.json` for the full schema: `database`, `certificate_authorities`,
`cloud_providers`, `email`, `snmp`, `prometheus`, `private_ca`, `oauth2`, `web`, `pkcs11`). CLI (`cli/ssl_manager.py`)
and the Flask API (`web/api.py`) both load this config and wire up the same set of managers independently —
there is no shared long-lived process between them.

**Certificate lifecycle: parse → store → route → renew.**
- `core/certificate_parser.py` (`CertificateParser`) parses certificate material from many formats
  (PEM, DER, PKCS#7, PKCS#10, PKCS#12, PVK, COSE, CWT), including CT/SCT parsing (`helpers/ct_utils.py`)
  and optional PKCS11 hardware token support.
- `core/certificate_manager.py` (`CertificateManager`) owns scanning (`scan_directory`), dedup via file hash,
  and persistence into the `database/models.py` `Certificate` / `CertificateOwnership` tables via
  `DatabaseManager`. Every scan is tracked as a `ScanJob` row.
- `core/renewal_router.py` (`RenewalRouter`) is the dispatch layer: given a `Certificate`, it detects the
  issuing CA (from `issuer_category` or issuer-string pattern matching) and forwards the renewal to the
  matching integration under `integrations/` (`letsencrypt.py`, `digicert.py`, `comodo.py` — aliased as
  both `sectigo`/`comodo`, `aws_certificates.py`, `cloudflare_certificates.py`, `private_ca_integration.py`).
  Each integration exposes `enabled`, `check_renewal_eligibility`, and `renew_certificate`.

**Private CA is a separate PKI engine wrapped by a DB layer.** `ca/private_ca.py` (`PrivateCAManager`) does the
actual cryptography — root → intermediate → issuing CA hierarchy, certificate issuance, revocation, CRL
generation. `ca/ca_manager.py` (`CAManager`) wraps it: persists `PrivateCA` / `PrivatelyIssuedCertificate` rows,
saves private keys to disk (`SSLMGR_KEY_DIR` / `private_ca.key_storage_dir`, chmod 600), and is the object both
the CLI and `web/api.py` call into. `integrations/private_ca_integration.py` adapts `CAManager` to the same
CA-integration interface used by the public CAs so `RenewalRouter` can route to it uniformly.

**Two interfaces, one core.** `cli/ssl_manager.py` (Click-based) and `web/api.py` (`SSLManagerAPI`, a Flask app
with JWT/OAuth2 via `auth/oauth2_handler.py`) both sit directly on top of `CertificateManager`, `RenewalRouter`,
`CAManager`, and the notifiers — the API adds authentication/authorization and exposes the same operations as
REST endpoints. `start_web_server.py` is the process entrypoint for the API (also handles `--create-admin`).

**Database and migrations.** `database/models.py` defines SQLAlchemy models (`Certificate`, `CertificateOwnership`,
`NotificationLog`, `RenewalAttempt`, `PrivateCA`, `PrivatelyIssuedCertificate`, `CAConfiguration`, `ScanJob`, ...)
plus Fernet-based `encrypt_secret`/`decrypt_secret` helpers used for anything stored in `CAConfiguration`
(API keys/secrets) and private CA key material — this is why `SSLMGR_ENCRYPTION_KEY` is required outside tests.
Schema changes go through Alembic (`alembic.ini`, `migrations/env.py`, `migrations/versions/`); `setup.py` and
`DatabaseManager.create_tables()` offer a non-Alembic path for quick local bring-up. SQLite and PostgreSQL are
both supported via `get_database_url(config)`.

**Async work and monitoring are optional add-ons layered on the same DB.** `queue/tasks.py` defines Celery tasks
(priority queues: critical/high/normal/low) for renewal and validation, backed by `queue/celeryconfig.py` and
tracked via `queue/job_tracker.py` — this replaces constant polling with distributed background jobs when Celery
is deployed. `notifications/cron_scheduler.py`, `email_notifier.py`, and `snmp_notifier.py` independently check
certificate expiry against `notification_days` (default `[120, 90, 60, 30, 15, 5, 2, 1]`) and escalating SNMP trap
frequencies, logging results to `NotificationLog`. `scripts/prometheus_exporter.py` and `scripts/run_monitoring.py`
export expiry metrics for Prometheus/Grafana via the node_exporter textfile collector.

**Certificate Transparency compliance** is computed in `helpers/ct_utils.py` (SCT OID `1.3.6.1.4.1.11129.2.4.2`
parsing, Chrome CT policy: ≥2 SCTs for validity >180 days, ≥1 SCT for ≤180 days) and folded into validation
results produced by `validators/certificate_validator.py`; private/internal CA certificates are exempt.

**Integrations directory has a mixed maturity level.** Some integration modules under `integrations/`
(`darkapi_integration.py`, `dnsscience_integration.py`, `jira_integration.py`, `ticketing/`) are enterprise
add-ons beyond the core CA-renewal set described in the README — check `enabled` flags in
`config/config.json` before assuming they are wired into `RenewalRouter`.
