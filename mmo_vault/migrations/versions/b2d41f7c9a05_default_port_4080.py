"""The service listens on 4080 by default

setup() writes every setting, defaults included, so an installation set up
before this change carries server.port = 8000 in its database and would keep
it - while image, compose file and documentation now all say 4080.

Only the old default is moved. A port somebody chose deliberately stays, even
though at the time of writing there is no interface to choose one.

Revision ID: b2d41f7c9a05
Revises: a1c0de5e2100
"""

from typing import Sequence, Union

from alembic import op

revision: str = "b2d41f7c9a05"
down_revision: Union[str, None] = "a1c0de5e2100"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("UPDATE setting SET value = '4080' WHERE key = 'server.port' AND value = '8000'")


def downgrade() -> None:
    op.execute("UPDATE setting SET value = '8000' WHERE key = 'server.port' AND value = '4080'")
