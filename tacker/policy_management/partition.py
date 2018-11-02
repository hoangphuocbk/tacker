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


from tacker.nfvo.drivers.vim import get_region_usage


NS_PLACEMENT_POLICY = 'tosca.policies.tacker.Placement.ns'


def partition_ns(nsd_dict, defied_policies, grouped_vnfs, vnfd_vnf_mapping,
                 auth_attr, vnf_resource_req):
    topo_tpl = nsd_dict.get('topology_template')
    groups = topo_tpl.get('groups')
    all_vnfs = list()
    mapping_region = dict()

    for _, value in groups.items():
        all_vnfds = value.get('properties').get('constituent_vnfs')
        for vnfd_name in all_vnfds:
            all_vnfs.append(vnfd_vnf_mapping[vnfd_name])

    modifed_groups = modified_group_vnfs(all_vnfs, grouped_vnfs)

    for policy in defied_policies:
        if policy['type'] == NS_PLACEMENT_POLICY:
            policy_type = policy['properties'].get('policy')
            policy_strategy = policy['properties'].get('strategy')

            # get information of data centers
            data_centers = policy['properties'].get('data_centers')

            # get resource usage of data centers
            data_center_infomation = get_region_usage.get_datacenters_usage(
                auth_attr, data_centers)

            if policy_type == 'load_balancing':

                if policy_strategy == 'least_loaded_first':
                    mapping_region = dict()
                    mapping_region = partition_resource_usage(
                        modifed_groups['mod_group_vnfs'], data_center_infomation,
                        vnf_resource_req, mapping_region)

                elif policy_strategy == 'round_robin':
                    mapping_region = partition_load_balancer(modifed_groups, data_centers)

    return mapping_region


def partition_load_balancer(modifed_groups, data_centers):
    mod_group_vnfs = modifed_groups['mod_group_vnfs']
    mod_group_index = modifed_groups['mod_group_index']
    mapping_region = dict()
    if len(mod_group_vnfs) <= len(data_centers):
        i = 0
        while i < len(mod_group_vnfs):
            mapping_region[data_centers[i]] = [mod_group_vnfs[i]]
            i += 1
        return mapping_region
    elif (len(mod_group_vnfs) > len(data_centers)) and \
            (len(data_centers) == 1):
        group_vnfs = list()
        for i in range(0, len(mod_group_vnfs)):
            if isinstance(mod_group_vnfs[i], list):
                group_vnfs = group_vnfs + mod_group_vnfs[i]
            elif isinstance(mod_group_vnfs[i], str):
                group_vnfs.append(mod_group_vnfs[i])
        mapping_region[data_centers[0]] = group_vnfs
        return mapping_region

    else:
        total_index = 0
        for i in range(0, len(mod_group_index)):
            total_index += mod_group_index[i]
        average_index = total_index / len(data_centers)
        index = 0
        group_vnfs = list()
        for i in range(0, len(mod_group_vnfs)):
            index += mod_group_index[i]

            if isinstance(mod_group_vnfs[i], list):
                group_vnfs = group_vnfs + mod_group_vnfs[i]
            elif isinstance(mod_group_vnfs[i], str):
                group_vnfs.append(mod_group_vnfs[i])

            del mod_group_vnfs[i]
            del mod_group_index[i]

            if index >= average_index:
                mapping_region[data_centers[0]] = group_vnfs
                del data_centers[0]
                break

        mapping_region.update(partition_load_balancer(
            modifed_groups, data_centers))
        return mapping_region


def partition_resource_usage(mod_group_vnfs, data_center_infomation,
                             vnf_resource_req, mapping_region):

    if len(mod_group_vnfs) == 0:
        return mapping_region
    else:
        checking_group = mod_group_vnfs[0]
        resource_req = 0
        group_vnfs = list()

        if isinstance(checking_group, list):
            group_vnfs = group_vnfs + checking_group
            for vnf in checking_group:
                resource_req += \
                    int(vnf_resource_req[vnf].get('mem_size')) / 1024.0
        elif isinstance(checking_group, str):
            group_vnfs.append(checking_group)
            resource_req += \
                int(vnf_resource_req[checking_group].get('mem_size')) / 1024.0

        max_resource = 0
        choosen_data_center = ''
        for data_center, dc_info in data_center_infomation.items():
            if dc_info.get('free_ram') > max_resource:
                max_resource = dc_info.get('free_ram')
                choosen_data_center = data_center

        # update data center information
        data_center_infomation[choosen_data_center]['free_ram'] -= resource_req

        if choosen_data_center not in mapping_region:
            mapping_region[choosen_data_center] = group_vnfs
        else:
            mapping_region[choosen_data_center] += group_vnfs

        del mod_group_vnfs[0]
        return partition_resource_usage(
            mod_group_vnfs, data_center_infomation, vnf_resource_req, mapping_region)


def modified_group_vnfs(all_vnfs, grouped_vnfs):
    modifed_groups = dict()
    mod_group_vnfs = list()
    mod_group_index = list()

    i = 0
    while i < len(all_vnfs):
        for grouped_vnf in grouped_vnfs:
            if all_vnfs[i] == grouped_vnf[0]:
                i += len(grouped_vnf)
                mod_group_vnfs.append(grouped_vnf)
                mod_group_index.append(len(grouped_vnf))
                break
        mod_group_vnfs.append(all_vnfs[i])
        mod_group_index.append(1)
        i += 1

    modifed_groups['mod_group_vnfs'] = mod_group_vnfs
    modifed_groups['mod_group_index'] = mod_group_index
    return modifed_groups
