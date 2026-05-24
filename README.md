# SSL Certificate Management System

A comprehensive SSL certificate management system for monitoring, renewing, and managing certificates across public CAs, cloud providers, and internal private CAs.

## Features

### Certificate Management
- **Multi-format support**: PEM, DER, PKCS#7, PKCS#10, PKCS#12, PVK, COSE, CWT
- **Deep parsing**: issuer, subject, SANs, expiry, key usage, extended key usage, issuer categorization
- **Ownership tracking**: map certificates to teams, applications, and environments
- **Database-backed**: SQLite or PostgreSQL via SQLAlchemy, schema managed with Alembic

### Certificate Authorities
- **Let's Encrypt** — automated ACME renewal
- **DigiCert** — API-based issuance with CSR generation and polling
- **Sectigo (Comodo)** — SCM API integration
- **AWS ACM** — cloud certificate management
- **Cloudflare** — zone-based certificate management
- **Private CA** — full internal PKI: root → intermediate → issuing CA hierarchy, certificate issuance, revocation, CRL generation

### Certificate Transparency
- Real SCT parsing (OID `1.3.6.1.4.1.11129.2.4.2`)
- Chrome CT policy enforcement (≥2 SCTs for validity >180 days, ≥1 for ≤180 days)
- Private/internal CAs automatically exempt
- CT compliance status embedded in validation results

### COSE / CWT
- Real `COSE_Sign1` export (CBOR tag 18, RFC 8152) with ES256 ECDSA signing
- Signed CWT export (RFC 8392) — claims wrapped in `COSE_Sign1` envelope
- COSE/CWT certificate parsing and format detection

### Notifications & Monitoring
- **Email alerts** at 120, 90, 60, 30, 15, 5, 2, and 1 days before expiration
- **SNMP traps** with escalating frequency as expiration approaches
- **Prometheus metrics** export for Grafana dashboards

### Interfaces
- **Python CLI** (`cli/ssl_manager.py`) — scan, list, renew, revoke, export, private CA management
- **REST API** (`web/api.py`) — full Flask API with JWT auth, all operations exposed as endpoints
- **OAuth2** — user authentication and role-based access control

---

## Installation

```bash
pip install -r requirements.txt
```

### Database setup

```bash
# Initialize schema
alembic upgrade head

# Or let the app create tables directly
python -c "from database.models import DatabaseManager, get_database_url; import json; cfg=json.load(open('config/config.json')); DatabaseManager(get_database_url(cfg)).create_tables()"
```

---

## Configuration

```bash
cp config/config.example.json config/config.json
# Edit config/config.json with your settings
```

Key sections: `database`, `certificate_authorities`, `cloud_providers`, `email`, `snmp`, `prometheus`, `private_ca`.

---

## CLI Usage

```bash
python cli/ssl_manager.py --help

# Scan a directory for certificates
python cli/ssl_manager.py scan directory /etc/ssl/certs

# List expiring certificates
python cli/ssl_manager.py list certificates --expiring 30

# Renew a certificate
python cli/ssl_manager.py renew certificate <id>

# Private CA — create root CA
python cli/ssl_manager.py ca create-root my-root-ca --common-name "My Root CA" --validity-years 20

# Private CA — issue a certificate
python cli/ssl_manager.py ca issue <ca-id> server.example.com --san server.example.com --days 365 --out-cert cert.pem --out-key key.pem

# Private CA — revoke and regenerate CRL
python cli/ssl_manager.py ca revoke <ca-id> <cert-id> --reason key_compromise
python cli/ssl_manager.py ca crl <ca-id> --regenerate --out ca.crl.pem
```

---

## Web API

```bash
python web/api.py --host 0.0.0.0 --port 5000
```

Key endpoints:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/login` | Obtain JWT token |
| GET | `/api/certificates` | List certificates |
| POST | `/api/certificates/scan` | Scan directory |
| POST | `/api/certificates/<id>/renew` | Renew certificate |
| GET | `/api/ca` | List private CAs |
| POST | `/api/ca/root` | Create root CA |
| POST | `/api/ca/<id>/issue` | Issue certificate |
| POST | `/api/ca/<id>/certificates/<id>/revoke` | Revoke certificate |
| GET | `/api/ca/<id>/crl` | Fetch CRL |

---

## Private CA

Full PKI hierarchy support: root → intermediate → issuing → leaf certificates.

```bash
# Create chain
python cli/ssl_manager.py ca create-root corp-root --common-name "Corp Root CA" --validity-years 20
python cli/ssl_manager.py ca create-intermediate corp-inter <root-id> --validity-years 10
python cli/ssl_manager.py ca create-issuing corp-issuing <inter-id> --validity-years 5

# Issue server cert with SANs
python cli/ssl_manager.py ca issue <issuing-id> web.corp.internal \
  --san web.corp.internal --san www.corp.internal \
  --days 365 --out-cert web.pem --out-key web.key
```

Private CA credentials are encrypted at rest using Fernet — set `SSLMGR_ENCRYPTION_KEY` before running:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
export SSLMGR_ENCRYPTION_KEY=<output>
```

---

## Testing

```bash
python -m pytest tests/ -q
```

Test coverage: CA manager (create/issue/revoke/CRL), certificate parser (PEM/COSE/CWT), CT utilities, renewal router, private CA integration.

---

## Directory Structure

```
core/               Core business logic (certificate manager, parser, renewal router)
ca/                 Private CA implementation and DB-backed manager
database/           SQLAlchemy models and Alembic migrations
integrations/       CA and cloud provider integrations
helpers/            Utilities: OpenSSL, CT/SCT parsing
validators/         Certificate validation engine
notifications/      Email and SNMP notification handlers
cli/                Command line interface
web/                Flask REST API
auth/               OAuth2 / JWT authentication
config/             Configuration files
tests/              Integration test suite
scripts/            Utility and setup scripts
```
