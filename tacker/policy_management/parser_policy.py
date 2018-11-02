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


import yaml

from tacker import manager
from tacker.extensions import nfvo


NS_PLACEMENT_POLICY = 'tosca.policies.tacker.Placement.ns'
VNF_PLACEMENT_POLICY = 'tosca.policies.tacker.Placement.vnf'


def get_policies(template, vim_regions, vnfds):
    defied_policies = []
    policied_vnfs = []
    grouped_vnfs = list()

    tpl_temp = "topology_template"
    pol_temp = "policies"
    policies = template[tpl_temp][pol_temp]
    for policy in policies:
        policy_obj = dict()
        policy_obj['name'] = policy.keys()[0]
        policy_value = policy.values()[0]
        policy_obj['type'] = policy_value.get('type')
        policy_obj['properties'] = dict()
        if policy_obj['type'] == NS_PLACEMENT_POLICY:

            # validate network service placement
            props = policy_value.get('properties')
            for key, value in props.items():
                policy_obj['properties'][key] = value

            # update vim regions
            if policy_value['targets']:
                policy_obj['targets'] = policy_value['targets']
            else:
                policy_obj['targets'] = vim_regions

            # validate VNFs in placement NS, which can only appear
            # in one policy
            for vnf_name in policy_obj['targets']:
                if vnf_name in policied_vnfs:
                    raise nfvo.MessageException(
                        message='The VNF already is applied by other policy')
                else:
                    policied_vnfs.append(vnf_name)
        elif policy_obj['type'] == VNF_PLACEMENT_POLICY:
            # validate network service placement
            props = policy_value.get('properties')

            for key, value in props.items():
                policy_obj['properties'][key] = value
            policy_obj['targets'] = policy_value['targets']
            if props['policy'] == 'affinity':
                grouped_vnfs.append(policy_value['targets'])

        defied_policies.append(policy_obj)
    return defied_policies, grouped_vnfs


def get_vnf_resource(context, vnfd_vnf_mapping):
    resource_mapping = dict()
    vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']
    for vnfd_name, vnf in vnfd_vnf_mapping.items():
        vnfd = vnfm_plugin.get_vnfd(context, vnfd_name)
        vnfd_template = vnfd['attributes'].get('vnfd')
        vnfd = yaml.safe_load(vnfd_template)
        resource_mapping[vnf] = dict()

        for item in ['num_cpus', 'disk_size', 'mem_size']:
            resource_mapping[vnf][item] = 0

        for node, value in vnfd['topology_template']['node_templates'].items():
            if value.get('type') == 'tosca.nodes.nfv.VDU.Tacker':
                disk_size = value['capabilities']['nfv_compute'][
                    'properties'].get('disk_size')
                mem_size = value['capabilities']['nfv_compute'][
                    'properties'].get('mem_size')
                disk_size = int(disk_size.split(" ")[0])
                mem_size = int(mem_size.split(" ")[0])
                resource_mapping[vnf]['num_cpus'] += \
                    int(value['capabilities']['nfv_compute'][
                            'properties'].get('num_cpus'))
                resource_mapping[vnf]['mem_size'] += mem_size
                resource_mapping[vnf]['disk_size'] += disk_size

            elif value.get('type') == 'tosca.nodes.BlockStorage.Tacker':
                resource_mapping[vnf]['disk_size'] += \
                    int(value['properties'].get('size'))

    return resource_mapping
