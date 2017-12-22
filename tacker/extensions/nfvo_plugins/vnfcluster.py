# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import abc
import six

from tacker.common import exceptions
from tacker.services import service_base


@six.add_metaclass(abc.ABCMeta)
class VnfClusterPluginBase(service_base.NFVPluginBase):

    @abc.abstractmethod
    def create_cluster(self, context, cluster_config):
        pass

    @abc.abstractmethod
    def delete_cluster(self, context, cluster_id):
        pass

    @abc.abstractmethod
    def get_cluster(self, context, cluster_id, fields=None):
        pass

    @abc.abstractmethod
    def get_clusters(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_clustermember(self, context, clustermember):
        pass

    @abc.abstractmethod
    def get_clustermembers(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_clustermember(self, context, clustermember_id, fields=None):
        pass

    @abc.abstractmethod
    def delete_clustermember(self, context, clustermember_id):
        pass


class ClusterCreateFailed(exceptions.TackerException):
    message = _('Creating cluster based on %(cluster_id)s failed.')


class ClusterNotFound(exceptions.NotFound):
    message = ('Cluster %(cluster_id)s could not be found.')


class ClusterRoleConfigInvalid(exceptions.TackerException):
    message = _('Invalid cluster role configuration.')


class LoadBalancerCreateFailed(exceptions.TackerException):
    message = _('Creating Load balancer failed.')


class ClusterInUse(exceptions.InUse):
    message = _('Cluster %(cluster_id)s is still in use')


class LoadBalancerConfigAttributeNotFound(exceptions.NotFound):
    message = _('%(lb_attr)s is not found in load balancer configuration.')


class LoadBalancerResourceNotFound(exceptions.NotFound):
    message = _('Load balancer resouces are not found in %(vim)s.')


class InvalidLoadBalancerConfig(exceptions.InvalidInput):
    message = _('Invalid %(config)s in policy file.')


class ClusterMemberNotFound(exceptions.NotFound):
    message = ('Cluster member %(clustermember_id)s could not be found.')


class ClusterMemberCreateFailed(exceptions.TackerException):
    message = _('Creating cluster member based on VNF %(vnf_id)s failed.')


class ClusterMemberAttributeInvalid(exceptions.InvalidInput):
    message = _('Invalid cluster member attribute %(mem_attr)s.')


class ClusterMemberRoleInvalid(exceptions.InvalidInput):
    message = _('Invalid cluster member role %(role)s.')


class ClusterMemberCPNotFound(exceptions.NotFound):
    message = _('Cluster member connection point'
                ' could not be found in VNF resources.')


class ClusterMemberAddFailed(exceptions.TackerException):
    message = ('Cluster member %(clustermember_id)s '
               'could not be added to load balancer.')
