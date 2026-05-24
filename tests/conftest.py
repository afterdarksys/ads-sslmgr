"""
Shared fixtures for integration tests.
"""

import sys
import os
import pytest
import tempfile
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Minimal env for tests that need encryption
os.environ.setdefault(
    'SSLMGR_ENCRYPTION_KEY',
    'Y3NlY3JldC1rZXktZm9yLXRlc3Rpbmctb25seS10ZXN0=',  # base64-encoded 32-byte key
)

from cryptography.fernet import Fernet
# Generate a valid Fernet key for tests (override the placeholder above)
_TEST_KEY = Fernet.generate_key().decode()
os.environ['SSLMGR_ENCRYPTION_KEY'] = _TEST_KEY


@pytest.fixture(scope='session')
def tmp_dir(tmp_path_factory):
    return tmp_path_factory.mktemp('sslmgr_test')


@pytest.fixture(scope='session')
def test_config(tmp_dir):
    db_path = str(tmp_dir / 'test.db')
    key_dir = str(tmp_dir / 'ca_keys')
    return {
        'database': {'type': 'sqlite', 'name': db_path},
        'directories': {
            'certificates': str(tmp_dir / 'certs'),
            'cache': str(tmp_dir / 'cache'),
            'logs': str(tmp_dir / 'logs'),
        },
        'private_ca': {'key_storage_dir': key_dir},
        'certificate_authorities': {},
    }


@pytest.fixture(scope='session')
def db_manager(test_config):
    from database.models import DatabaseManager, get_database_url
    mgr = DatabaseManager(get_database_url(test_config))
    mgr.create_tables()
    return mgr


@pytest.fixture(scope='session')
def ca_manager(db_manager, test_config):
    from ca.ca_manager import CAManager
    return CAManager(db_manager, test_config['private_ca']['key_storage_dir'])
