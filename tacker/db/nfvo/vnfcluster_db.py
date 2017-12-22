# Copyright 2016 Red Hat Inc
# All Rights Reserved.
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

import sqlalchemy as sa
import time

from oslo_log import log as logging
from oslo_utils import uuidutils
from sqlalchemy import orm
from sqlalchemy.orm import exc as orm_exc

from tacker.db.common_services import common_services_db_plugin
from tacker.db import db_base
from tacker.db import model_base
from tacker.db import models_v1
from tacker.db import types
from tacker.extensions.nfvo_plugins import vnfcluster
from tacker import manager
from tacker.plugins.common import constants

LOG = logging.getLogger(__name__)


class VnfCluster(model_base.BASE, models_v1.HasId, models_v1.HasTenant):
    """VNF Cluster Data Model"""

    __tablename__ = 'clusters'
    __table_args__ = {'extend_existing': True}
    name = sa.Column(sa.String(255), nullable=False)
    description = sa.Column(sa.String(255), nullable=True)
    status = sa.Column(sa.String(255), nullable=False)
    vip_endpoint = sa.Column(types.Json, nullable=True)
    vnfd_id = sa.Column(sa.String(255), sa.ForeignKey('vnfd.id'))
    lb_info = sa.Column(types.Json, nullable=True)
    cluster_members = orm.relationship("VnfClusterMember",
                                       backref="vnfcluster")
    role_config = sa.Column(types.Json)


class VnfClusterMember(model_base.BASE, models_v1.HasId, models_v1.HasTenant):
    """VNF Cluster Member Data Model"""

    __tablename__ = 'clustermembers'
    __table_args__ = {'extend_existing': True}
    name = sa.Column(sa.String(255), nullable=False)
    cluster_id = sa.Column(sa.String(255), sa.ForeignKey('clusters.id'))
    vnf_id = sa.Column(sa.String(255), sa.ForeignKey('vnf.id'))
    role = sa.Column(sa.String(255), nullable=False)
    mgmt_url = sa.Column(sa.String(255), nullable=True)
    vim_id = sa.Column(sa.String(255))
    lb_member_id = sa.Column(sa.String(255), nullable=True)


class VnfClusterPluginDb(vnfcluster.VnfClusterPluginBase,
                         db_base.CommonDbMixin):

    def __init__(self):
        super(vnfcluster.VnfClusterPluginBase, self).__init__()
        self._cos_db_plg = common_services_db_plugin.CommonServicesPluginDb()

    def _get_resource(self, context, model, id):
        try:
            return self._get_by_id(context, model, id)
        except orm_exc.NoResultFound:
            if issubclass(model, VnfCluster):
                raise vnfcluster.ClusterNotFound(cluster_id=id)
            if issubclass(model, VnfClusterMember):
                raise vnfcluster.ClusterMemberNotFound(clustermember_id=id)
            else:
                raise

    def _create_cluster_db(self, context, cluster_config):
        cluster_dict = self._create_cluster_pre(context, cluster_config)
        LOG.debug('cluster_dict %s', cluster_dict)
        return cluster_dict

    def _get_cluster_db(self, context, cluster_id, fields=None):
        vnf_db = self._get_resource(context, VnfCluster, cluster_id)
        return self._make_cluster_dict(vnf_db, fields)

    def _get_clusters_db(self, context, filters=None, fields=None):
        return self._get_collection(context,
                                    VnfCluster,
                                    self._make_cluster_dict,
                                    filters=filters,
                                    fields=fields)

    def _delete_cluster_db(self, context, cluster_id):
        LOG.debug(('Delete cluster_id %s'), cluster_id)
        with context.session.begin(subtransactions=True):
            vnfcluster_db = self._get_resource(context, VnfCluster,
                                               cluster_id)
            context.session.delete(vnfcluster_db)

    def _create_cluster_pre(self, context, cluster_config):
        tenant_id = self._get_tenant_id_for_create(context, cluster_config)
        cluster_id = uuidutils.generate_uuid()
        name = cluster_config['name']
        description = cluster_config['description']
        vnfd_id = cluster_config['vnfd_id']
        role_config = dict()

        with context.session.begin(subtransactions=True):
            cluster_db = VnfCluster(id=cluster_id,
                                    tenant_id=tenant_id,
                                    name=name,
                                    description=description,
                                    status=constants.PENDING_CREATE,
                                    vnfd_id=vnfd_id,
                                    role_config=role_config,
                                    vip_endpoint=None)
            context.session.add(cluster_db)
        cluster_dict = self._make_cluster_dict(cluster_db)
        return cluster_dict

    def _make_cluster_dict(self, cluster_db, fields=None):
        res = dict()
        key_list = ('id', 'tenant_id', 'name', 'description',
                    'status', 'vnfd_id',
                    'lb_info', 'role_config', 'vip_endpoint')
        res.update((key, cluster_db[key]) for key in key_list)
        return self._fields(res, fields)

    def _update_cluster_attr(self, context, cluster_id, field, attr):
        with context.session.begin(subtransactions=True):
            query = (self._model_query(context, VnfCluster).
                     filter(VnfCluster.id == cluster_id))
            query.update({field: attr})
        return attr

    def get_lb_config(self, policy_info, attr_key):
        try:
            attr_dict = policy_info['properties']['load_balancer'][attr_key]
        except Exception:
            return None
        return attr_dict

    def get_role_by_vim(self, context, role_config, vim_name):
        role_by_vim = dict()
        try:
            for role, role_attr in role_config.iteritems():
                cluster_roles = [constants.CLUSTER_STANDBY,
                                 constants.CLUSTER_ACTIVE]
                if role.upper() not in cluster_roles:
                    return None
                n_node = 0
                if type(role_attr) is int:
                    # Get role_config in form: "role: number_of_nodes"
                    # Default VIM will be invoked
                    vim = self.get_vim_by_name(context, None).get('name')
                    if vim == vim_name:
                        n_node += role_attr
                else:
                    for vim, n in role_attr.iteritems():
                        if vim == vim_name:
                            n_node += n
                if n_node != 0:
                    if role not in role_by_vim:
                        role_by_vim[role] = dict()
                    role_by_vim[role][vim_name] = n_node
        except Exception:
            return None

        return role_by_vim

    def get_required_vims(self, context, role_config=None):
        vim_list = set()
        try:
            for role, role_attr in role_config.iteritems():
                if type(role_attr) is int:
                    # Get role_config in form: "role: number_of_nodes"
                    # Default VIM will be invoked
                    default_vim = \
                        self.get_vim_by_name(context, None).get('name')
                    vim_list.add(default_vim)
                else:
                    for vim_name, n in role_attr.iteritems():
                        if n > 0 and vim_name not in vim_list:
                            vim_list.add(vim_name)
        except Exception:
            LOG.error('VIM is not declared in policy file')
            raise vnfcluster.ClusterRoleConfigInvalid()
        return list(vim_list)

    def _create_cluster_member(self, context, vnfm_plugin,
                               cluster_dict, name, role, vim_id):
        vnf_member = self._create_vnf_member(context, vnfm_plugin,
                                             cluster_dict, name, vim_id)
        member_dict = self._make_member_dict_from_vnf(cluster_dict['id'],
                                                      role, vnf_member)
        self._create_member(context, member_dict)
        return member_dict

    def _create_vnf_member(self, context, vnfm_plugin,
                           cluster, name, vim_id):
        pre_vnf_dict = self._make_pre_vnf_dict(cluster, name, vim_id)
        vnf_dict = vnfm_plugin.create_vnf(context, pre_vnf_dict)
        LOG.debug('Creating %s', vnf_dict.get('name'))
        while (1):
            status = vnf_dict.get('status')
            if status == constants.ACTIVE:
                return vnf_dict
            elif status == constants.ERROR or status == constants.DEAD:
                break
            time.sleep(2)
        # Delete VNF if the deployment fail.
        vnfm_plugin.delete_vnf(context, vnf_dict.get('id'))
        raise vnfcluster.ClusterMemberCreateFailed(vnf_id=vnf_dict.get('id'))

    def _make_member_config(self, name, role, cluster_id, vnfd_id, vim_id):
        config = dict(name=name,
                      role=role,
                      cluster_id=cluster_id,
                      vim_id=vim_id,
                      vnfd_id=vnfd_id)
        member_config = dict(clustermember=config)
        return member_config

    def _make_pre_vnf_dict(self, cluster, name, vim_id):
        p = dict(description='A member of cluster ' + cluster['name'],
                 tenant_id=cluster['tenant_id'],
                 vim_id=vim_id,
                 name=name,
                 placement_attr=dict(),
                 attributes=dict(),
                 vnfd_id=cluster['vnfd_id'])
        vnf_dict = dict(vnf=p)
        LOG.debug(("_make_policy_dict p : %s"), p)
        return vnf_dict

    def _get_member_db(self, context, member_id, fields=None):
        member_db = self._get_resource(context, VnfClusterMember, member_id)
        return self._make_member_dict(member_db, fields)

    def _get_members_db(self, context, filters=None, fields=None):
        return self._get_collection(context, VnfClusterMember,
                                    self._make_member_dict,
                                    filters=filters, fields=fields)

    def _delete_member_db(self, context, member_id):
        with context.session.begin(subtransactions=True):
            member_db = self._get_resource(context, VnfClusterMember,
                                           member_id)
            context.session.delete(member_db)

    def _make_member_dict(self, member_db, fields=None):
        res = dict()
        key_list = ('id', 'tenant_id', 'name', 'cluster_id', 'role',
                    'vim_id', 'lb_member_id', 'vnf_id', 'mgmt_url')
        res.update((key, member_db[key]) for key in key_list)
        return self._fields(res, fields)

    def _create_member(self, context, member):
        member_name = member['name']
        member_id = member['id']
        tenant_id = member['tenant_id']
        cluster_id = member['cluster_id']
        role = member['role']
        vnf_id = member['vnf_id']
        mgmt_url = member['mgmt_url']
        vim_id = member['vim_id']
        with context.session.begin(subtransactions=True):
            member_db = VnfClusterMember(id=member_id,
                                         tenant_id=tenant_id,
                                         name=member_name,
                                         cluster_id=cluster_id,
                                         vim_id=vim_id,
                                         role=role,
                                         vnf_id=vnf_id,
                                         mgmt_url=mgmt_url)
            context.session.add(member_db)
        member_dict = self._make_member_dict(member_db)

        LOG.debug(('cluster_member_dict %s'), member_dict)
        return member_dict

    def _make_member_dict_from_vnf(self, cluster_id, role, vnf_info):
        member_dict = dict(id=uuidutils.generate_uuid(),
                           tenant_id=vnf_info['tenant_id'],
                           name=vnf_info['name'],
                           cluster_id=cluster_id,
                           role=role,
                           vim_id=vnf_info['vim_id'],
                           vnf_id=vnf_info['id'],
                           mgmt_url=vnf_info['mgmt_url'])
        LOG.debug(("_make_cluster_member_dict c : %s"), member_dict)
        return member_dict

    def _get_member_cp_id(self, context, vnfm_plugin, cluster, vnf_id):
        vnf_resources = vnfm_plugin.get_vnf_resources(context, vnf_id)
        cp = cluster['lb_info']['CP']
        for resource in vnf_resources:
            if resource['name'] == cp:
                member_cp_id = resource['id']
                return member_cp_id
        return None

    def get_member_by_attr(self, context, filters=None, fields=None):
        members = self._get_members_db(context, filters=filters, fields=fields)
        if members:
            return members[0]
        raise vnfcluster.ClusterMemberAttributeInvalid(mem_attr=filters)

    def update_member_role(self, context, vim_obj, lb_obj, member, new_role):
        member_id = member['id']
        cluster_id = member['cluster_id']
        cluster_dict = self.get_cluster(context, cluster_id)

        vim_name = vim_obj['name']

        # Update role_config in cluster
        role_config = cluster_dict['role_config']
        if role_config.get(new_role) is None:
            role_config[new_role] = dict()
            role_config[new_role][vim_name] = dict()
        role_config[new_role][vim_name][member_id] = member['vnf_id']

        if new_role == constants.CLUSTER_ACTIVE:
            vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']
            cp_id = \
                self._get_member_cp_id(context, vnfm_plugin,
                                       cluster_dict, member['vnf_id'])
            lb_member_id = \
                self._vim_drivers.invoke(vim_obj['type'], 'pool_member_add',
                                         net_port_id=cp_id,
                                         lb_info=lb_obj,
                                         auth_attr=vim_obj['auth_cred'])
            # add STANDBY member to lb
            self._update_member_attr(context,
                                     member_id, 'lb_member_id', lb_member_id)
            # Update from STANDBY to ACTIVE
            self._update_member_attr(context, member_id, 'role', new_role)
            del role_config[constants.CLUSTER_STANDBY][vim_name][member_id]

        elif new_role == constants.CLUSTER_STANDBY:
            lb_member_id = member['lb_member_id']
            self._vim_drivers.invoke(vim_obj['type'], 'pool_member_remove',
                                     lb_id=lb_obj['loadbalancer'],
                                     pool_id=lb_obj['pool'],
                                     member_id=lb_member_id,
                                     auth_attr=vim_obj['auth_cred'])
            # remove ACTIVE member from lb
            self._update_member_attr(context, member_id, 'lb_member_id', None)
            del role_config[constants.CLUSTER_ACTIVE][vim_name][member_id]

        # Update member database
        self._update_member_attr(context, member_id, 'role', new_role)
        self._update_cluster_attr(context, cluster_id,
                                  'role_config', role_config)

    def _update_member_attr(self, context, member_id, field, attr):
        with context.session.begin(subtransactions=True):
            query = (self._model_query(context, VnfClusterMember).
                     filter(VnfClusterMember.id == member_id))
            query.update({field: attr})
