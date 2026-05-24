import json
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool, create_engine

from alembic import context

# ── Project path setup ──────────────────────────────────────────────────────
# Add the project root so that database.models is importable.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from database.models import Base, get_database_url  # noqa: E402

# ── Alembic Config ──────────────────────────────────────────────────────────
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Point autogenerate at our SQLAlchemy metadata
target_metadata = Base.metadata


# ── Database URL resolution ─────────────────────────────────────────────────

def _get_url() -> str:
    """
    Resolve the database URL in order of preference:
    1. SSLMGR_DB_URL environment variable
    2. config/config.json (standard project config)
    3. alembic.ini sqlalchemy.url (fallback, for manual overrides)
    """
    if os.environ.get('SSLMGR_DB_URL'):
        return os.environ['SSLMGR_DB_URL']

    config_file = PROJECT_ROOT / 'config' / 'config.json'
    if config_file.exists():
        with open(config_file) as f:
            app_config = json.load(f)
        return get_database_url(app_config)

    # Fall back to alembic.ini value (may be the placeholder)
    url = config.get_main_option('sqlalchemy.url')
    if url and 'driver://' not in url:
        return url

    # Last resort: SQLite in project root (absolute path)
    return f"sqlite:///{PROJECT_ROOT}/sslmgr.db"


# ── Offline migrations ───────────────────────────────────────────────────────

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout)."""
    context.configure(
        url=_get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


# ── Online migrations ────────────────────────────────────────────────────────

def run_migrations_online() -> None:
    """Run migrations in 'online' mode (connect to DB and run)."""
    connectable = create_engine(_get_url(), poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
