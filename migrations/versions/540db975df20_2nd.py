"""2nd

Revision ID: 540db975df20
Revises: 52e175a9450f
Create Date: 2018-02-06 20:29:44.215630

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '540db975df20'
down_revision = '52e175a9450f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('pathologist',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('first_name', sa.String(length=255), nullable=True),
    sa.Column('last_name', sa.String(length=255), nullable=True),
    sa.Column('credentials', sa.String(length=255), nullable=True),
    sa.Column('email', sa.String(length=255), nullable=True),
    sa.Column('phone', sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.drop_table('followers')
    op.add_column('user', sa.Column('address_1', sa.String(length=255), nullable=True))
    op.add_column('user', sa.Column('address_2', sa.String(length=255), nullable=True))
    op.add_column('user', sa.Column('city', sa.String(length=255), nullable=True))
    op.add_column('user', sa.Column('first_name', sa.String(length=255), nullable=True))
    op.add_column('user', sa.Column('last_name', sa.String(length=255), nullable=True))
    op.add_column('user', sa.Column('state', sa.String(length=255), nullable=True))
    op.add_column('user', sa.Column('telephone', sa.String(length=255), nullable=True))
    op.add_column('user', sa.Column('zipcode', sa.String(length=255), nullable=True))
    op.drop_index('ix_user_username', table_name='user')
    op.drop_column('user', 'username')
    op.drop_column('user', 'about_me')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('about_me', sa.VARCHAR(length=140), nullable=True))
    op.add_column('user', sa.Column('username', sa.VARCHAR(length=64), nullable=True))
    op.create_index('ix_user_username', 'user', ['username'], unique=1)
    op.drop_column('user', 'zipcode')
    op.drop_column('user', 'telephone')
    op.drop_column('user', 'state')
    op.drop_column('user', 'last_name')
    op.drop_column('user', 'first_name')
    op.drop_column('user', 'city')
    op.drop_column('user', 'address_2')
    op.drop_column('user', 'address_1')
    op.create_table('followers',
    sa.Column('follower_id', sa.INTEGER(), nullable=True),
    sa.Column('followed_id', sa.INTEGER(), nullable=True),
    sa.ForeignKeyConstraint(['followed_id'], ['user.id'], ),
    sa.ForeignKeyConstraint(['follower_id'], ['user.id'], )
    )
    op.drop_table('pathologist')
    # ### end Alembic commands ###
