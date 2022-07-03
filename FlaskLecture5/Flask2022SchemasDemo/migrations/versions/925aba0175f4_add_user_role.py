"""Add user role.

Revision ID: 925aba0175f4
Revises: c525c5c58afe
Create Date: 2022-07-03 17:38:03.543499

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
from sqlalchemy.dialects import postgresql

revision = '925aba0175f4'
down_revision = 'c525c5c58afe'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    userrolesenum = postgresql.ENUM('super_admin', 'admin', 'user', name='userrolesenum')
    userrolesenum.create(op.get_bind())
    op.add_column('user', sa.Column('role', sa.Enum('super_admin', 'admin', 'user', name='userrolesenum'), nullable=False, server_default='user'))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'role')
    # ### end Alembic commands ###
