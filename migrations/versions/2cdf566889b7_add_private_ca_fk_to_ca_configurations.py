"""add_private_ca_fk_to_ca_configurations

Revision ID: 2cdf566889b7
Revises: 055f9904687d
Create Date: 2026-05-24 09:45:16.179666

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2cdf566889b7'
down_revision: Union[str, None] = '055f9904687d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The previous revision already creates both private-CA tables.  This
    # revision only links public/private CA configuration records.  Batch mode
    # keeps the migration valid on SQLite as well as PostgreSQL/MySQL.
    with op.batch_alter_table('ca_configurations') as batch_op:
        batch_op.add_column(sa.Column('private_ca_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            'fk_ca_configurations_private_ca_id', 'private_cas',
            ['private_ca_id'], ['id'])


def downgrade() -> None:
    with op.batch_alter_table('ca_configurations') as batch_op:
        batch_op.drop_constraint('fk_ca_configurations_private_ca_id', type_='foreignkey')
        batch_op.drop_column('private_ca_id')
