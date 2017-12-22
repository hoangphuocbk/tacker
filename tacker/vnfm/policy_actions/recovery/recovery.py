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

from oslo_log import log as logging
from tacker import manager
from tacker.vnfm.policy_actions import abstract_action

LOG = logging.getLogger(__name__)


class ClusterActionRecovery(abstract_action.AbstractPolicyAction):
    def get_type(self):
        return 'recovery'

    def get_name(self):
        return 'recovery'

    def get_description(self):
        return 'Tacker VNF cluster Recovery policy'

    def execute_action(self, plugin, context, vnf_dict, args):
        LOG.error(('Recovery action for cluster member %s dead'),
                  vnf_dict['id'])
        nfvo_plugin = manager.TackerManager.get_service_plugins()['NFVO']
        nfvo_plugin.recovery_action(context, vnf_dict['id'])
