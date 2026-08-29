"""ids count upwards only

Revision ID: 8b50a162c06d
Revises: 5321c3844a71
Create Date: 2026-08-29 10:43:50.718918
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '8b50a162c06d'
down_revision: Union[str, None] = '5321c3844a71'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Written by hand: autogenerate cannot see table kwargs. Rebuilds the two
    # tables with AUTOINCREMENT so SQLite never hands an id out twice. Without
    # this, the id of a deleted account comes back with the next INSERT - and
    # any leftover row that references accounts by bare integer would hand the
    # newcomer the permissions of the deleted one. The delete endpoints clean
    # such rows up; this is the second layer underneath that.
    #
    # recreate="always" is the point: there is no column change to trigger the
    # rebuild, the table itself is the change. Existing rows keep their ids,
    # and SQLite seeds the sequence from the highest one copied over.
    with op.batch_alter_table(
        "user", recreate="always", table_kwargs={"sqlite_autoincrement": True}
    ):
        pass
    with op.batch_alter_table(
        "group", recreate="always", table_kwargs={"sqlite_autoincrement": True}
    ):
        pass


def downgrade() -> None:
    with op.batch_alter_table(
        "user", recreate="always", table_kwargs={"sqlite_autoincrement": False}
    ):
        pass
    with op.batch_alter_table(
        "group", recreate="always", table_kwargs={"sqlite_autoincrement": False}
    ):
        pass
