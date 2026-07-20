"""add enrollment tokens and managed agents

Revision ID: 8c1a6f91c1e2
Revises: 2cdf566889b7
Create Date: 2026-07-19
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '8c1a6f91c1e2'
down_revision: Union[str, None] = '2cdf566889b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'enrollment_tokens',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('ca_id', sa.Integer(), sa.ForeignKey('private_cas.id'), nullable=False),
        sa.Column('cert_type', sa.String(50), nullable=False),
        sa.Column('pkinit_principal', sa.String(500)),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('max_uses', sa.Integer(), nullable=False),
        sa.Column('uses', sa.Integer(), nullable=False),
        sa.Column('is_revoked', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime()),
    )
    op.create_table(
        'managed_agents',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('uuid', sa.String(36), nullable=False, unique=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('ca_id', sa.Integer(), sa.ForeignKey('private_cas.id'), nullable=False),
        sa.Column('certificate_id', sa.Integer(), sa.ForeignKey('privately_issued_certificates.id'), nullable=False),
        sa.Column('cert_type', sa.String(50), nullable=False),
        sa.Column('pkinit_principal', sa.String(500)),
        sa.Column('certificate_fingerprint', sa.String(64), nullable=False, unique=True),
        sa.Column('is_revoked', sa.Boolean(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime()),
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
    )


def downgrade() -> None:
    op.drop_table('managed_agents')
    op.drop_table('enrollment_tokens')
