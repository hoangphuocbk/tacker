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


from keystoneauth1 import identity
from keystoneauth1 import session
from novaclient import client as nova_client


def get_nova_client(auth_attr, vim_region_name):
    VERSION = '2'
    auth_cred = auth_attr.copy()
    verify = 'True' == auth_cred.pop('cert_verify', 'True') or False
    auth = identity.Password(**auth_cred)
    sess = session.Session(auth=auth, verify=verify)
    return nova_client.Client(VERSION, session=sess,
                              region_name=vim_region_name)


def get_datacenters_usage(auth_attr, data_centers):
    resource_usage = dict()
    for center in data_centers:
        resource_usage[center] = dict()
        nova_client1 = get_nova_client(auth_attr, center)
        stats = nova_client1.hypervisor_stats.statistics()
        resource_usage[center]['free_disk'] = stats.free_disk_gb
        resource_usage[center]['free_ram'] = stats.free_ram_mb / 1024.0
        resource_usage[center]['free_cpu'] = stats.vcpus - stats.vcpus_used
    return resource_usage

