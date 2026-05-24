#!/usr/bin/env python3
"""
SSL Certificate Manager — Setup Script
Initializes the database, creates directories, and writes a default config if needed.
"""

import json
import os
import sys
from pathlib import Path

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


# ── Default configuration ─────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "database": {
        "type": "sqlite",
        "name": str(project_root / "sslmgr.db"),
        "host": "localhost",
        "port": 5432,
        "username": "",
        "password": ""
    },
    "email": {
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "from_address": "ssl-manager@yourcompany.com",
        "use_tls": True
    },
    "snmp": {
        "enabled": False,
        "community": "public",
        "host": "localhost",
        "port": 161,
        "oid_base": "1.3.6.1.4.1.12345"
    },
    "certificate_authorities": {
        "letsencrypt": {
            "enabled": False,
            "staging": True,
            "email": ""
        },
        "digicert": {
            "enabled": False,
            "api_key": "",
            "organization_id": ""
        },
        "sectigo": {
            "enabled": False,
            "login": "",
            "password": "",
            "customer_uri": "",
            "org_id": ""
        }
    },
    "cloud_providers": {
        "aws": {
            "enabled": False,
            "access_key_id": "",
            "secret_access_key": "",
            "region": "us-east-1"
        },
        "cloudflare": {
            "enabled": False,
            "api_token": "",
            "zone_id": ""
        }
    },
    "private_ca": {
        "enabled": False,
        "key_storage_dir": str(project_root / "ca_keys"),
        "default_key_type": "rsa",
        "default_key_size": 4096
    },
    "oauth2": {
        "client_id": "",
        "client_secret": "",
        "redirect_uri": "http://localhost:5000/auth/callback",
        "authorization_url": "",
        "token_url": ""
    },
    "web": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": False,
        "secret_key": os.urandom(32).hex()
    },
    "directories": {
        "certificates": str(project_root / "certificates"),
        "cache": str(project_root / "cache"),
        "logs": str(project_root / "logs")
    },
    "notification_days": [120, 90, 60, 30, 15, 5, 2, 1]
}


def ensure_config() -> dict:
    """Load config.json, creating it from defaults if it does not exist."""
    config_file = project_root / "config" / "config.json"
    config_file.parent.mkdir(parents=True, exist_ok=True)

    if config_file.exists():
        with open(config_file) as f:
            cfg = json.load(f)
        print(f"✓ Using existing config: {config_file}")
        return cfg

    # Write defaults
    with open(config_file, 'w') as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)

    print(f"✓ Default config written to {config_file}")
    print("  → Review and update credentials before going to production.")
    return DEFAULT_CONFIG


def setup_database(config: dict) -> None:
    """Create all SQLAlchemy-managed tables (idempotent)."""
    print("Setting up database …")
    from database.models import DatabaseManager, get_database_url
    db  = DatabaseManager(get_database_url(config))
    db.create_tables()
    sess = db.get_session()
    sess.close()
    print("✓ Database tables created / verified")


def create_directories(config: dict) -> None:
    """Create required runtime directories."""
    dirs = [
        config.get('directories', {}).get('certificates', './certificates'),
        config.get('directories', {}).get('cache',        './cache'),
        config.get('directories', {}).get('logs',         './logs'),
        config.get('private_ca', {}).get('key_storage_dir', './ca_keys'),
        project_root / 'temp',
    ]
    for d in dirs:
        p = Path(d)
        if not p.is_absolute():
            p = project_root / p
        p.mkdir(parents=True, exist_ok=True)
        print(f"✓ Directory ready: {p}")


def check_encryption_key() -> None:
    """Warn if SSLMGR_ENCRYPTION_KEY is not set (needed for secret storage)."""
    if not os.environ.get('SSLMGR_ENCRYPTION_KEY'):
        print()
        print("⚠  SSLMGR_ENCRYPTION_KEY is not set.")
        print("   Generate one and add it to your environment:")
        print("   python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
        print("   export SSLMGR_ENCRYPTION_KEY=<the key above>")


def check_dependencies() -> bool:
    """Verify required Python packages are importable."""
    required = ['cryptography', 'sqlalchemy', 'flask', 'click', 'requests', 'jinja2']
    missing  = [p for p in required if not _importable(p)]
    if missing:
        print(f"✗ Missing packages: {', '.join(missing)}")
        print("  Run: pip install -r requirements.txt")
        return False
    print("✓ Core dependencies present")
    return True


def _importable(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def make_scripts_executable() -> None:
    for rel in ('cli/ssl_manager.py', 'scripts/send_notifications.py'):
        p = project_root / rel
        if p.exists():
            p.chmod(0o755)
            print(f"✓ chmod +x {p.name}")


def show_next_steps() -> None:
    print()
    print("=" * 60)
    print("Setup complete!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("1. Set SSLMGR_ENCRYPTION_KEY in your environment (see above)")
    print("2. Edit config/config.json — fill in credentials")
    print("3. Test:  python test_startup.py")
    print("4. Start: python start_web_server.py")
    print()
    print("Private CA quick-start:")
    print("  from ca import PrivateCAManager, CertificateType")
    print("  mgr  = PrivateCAManager()")
    print("  root = mgr.create_root_ca('My Root CA', organization='Acme', country='US')")
    print("  cert = mgr.issue_certificate('app.example.com', root['cert_pem'], root['key_pem'])")


def main() -> None:
    print("SSL Certificate Manager — Setup")
    print("=" * 40)

    if not check_dependencies():
        sys.exit(1)

    config = ensure_config()
    setup_database(config)
    create_directories(config)
    make_scripts_executable()
    check_encryption_key()
    show_next_steps()


if __name__ == '__main__':
    main()
