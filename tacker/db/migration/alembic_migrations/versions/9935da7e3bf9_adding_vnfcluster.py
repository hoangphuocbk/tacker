# Copyright 2017 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

"""Adding vnfcluster

Revision ID: 9935da7e3bf9
Revises: e9a1e47fb0b5
Create Date: 2017-12-22 15:31:26.179064

"""

# revision identifiers, used by Alembic.
revision = '9935da7e3bf9'
down_revision = '5d490546290c'

from alembic import op
import sqlalchemy as sa
from tacker.db.types import Json


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'clusters',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=255), nullable=False),
        sa.Column('vnfd_id', sa.String(length=36), nullable=False),
        sa.Column('vip_endpoint', Json, nullable=True),
        sa.Column('role_config', Json, nullable=True),
        sa.Column('lb_info', Json, nullable=True),
        sa.ForeignKeyConstraint(['vnfd_id'], ['vnfd.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB'
    )

    op.create_table(
        'clustermembers',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('cluster_id', sa.String(length=36), nullable=False),
        sa.Column('vnf_id', sa.String(length=36), nullable=False),
        sa.Column('role', sa.String(length=255), nullable=False),
        sa.Column('mgmt_url', sa.String(length=255), nullable=True),
        sa.Column('lb_member_id', sa.String(length=36), nullable=True),
        sa.Column('vim_id', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['vnf_id'], ['vnf.id'], ),
        sa.ForeignKeyConstraint(['cluster_id'], ['clusters.id'], ),
        sa.ForeignKeyConstraint(['vim_id'], ['vims.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB'
    )
