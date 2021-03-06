"""folder

Revision ID: 2a6ed9064d91
Revises: c1b35a3832ca
Create Date: 2020-03-11 01:59:47.289500

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2a6ed9064d91'
down_revision = 'c1b35a3832ca'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('folder',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('folder_id', sa.Integer(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_folder_folder_id'), 'folder', ['folder_id'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_folder_folder_id'), table_name='folder')
    op.drop_table('folder')
    # ### end Alembic commands ###
