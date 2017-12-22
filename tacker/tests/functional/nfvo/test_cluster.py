# Copyright 2015 Brocade Communications System, Inc.
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

from oslo_config import cfg
import yaml


from tacker.tests.functional import base
from tacker.tests.utils import read_file

CONF = cfg.CONF
VNF_CIRROS_CREATE_TIMEOUT = 120


class ClusterTestCreate(base.BaseTackerTest):
    def test_create_delete_cluster(self):
        vnfd_name = 'vnfd-test'
        data = dict()
        data['tosca'] = read_file('sample-tosca-vnfd-no-monitor.yaml')
        toscal = data['tosca']
        tosca_arg = {'vnfd': {'name': vnfd_name,
                     'attributes': {'vnfd': toscal}}}

        # Create vnfd with tosca template
        vnfd_instance = self.client.create_vnfd(body=tosca_arg)
        self.assertIsNotNone(vnfd_instance)

        # Create a cluster with vnfd_id and policy file
        cluster_name = 'cluster-test'
        vnfd_id = vnfd_instance['vnfd']['id']
        policy_info = yaml.safe_load(read_file('sample-cluster-policy.yaml'))
        cluster_arg = {'cluster': {'policy_info': policy_info,
                                   'name': cluster_name,
                                   'vnfd_id': vnfd_id}}

        cluster_instance = self.client.create_cluster(body=cluster_arg)
        self.assertIsNone(cluster_instance)
