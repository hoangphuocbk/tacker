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


class NovaClient(object):
    """Nova Client class for resource management"""

    def __init__(self, auth_attr):
        VERSION = '2'
        auth_cred = auth_attr.copy()
        verify = 'True' == auth_cred.pop('cert_verify', 'True') or False
        auth = identity.Password(**auth_cred)
        sess = session.Session(auth=auth, verify=verify)
        self.client = nova_client.Client(VERSION, session=sess)

    def get_vim_usage(self):
        print(self.client.servers.list())