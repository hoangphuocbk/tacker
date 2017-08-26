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

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from tacker.db.common_services import common_services_db_plugin
from tacker.plugins.common import constants
from tacker.vnfm.policy_actions import abstract_action
from tacker.common import rpc
from tacker.common import topics
from tacker.conductor import conductorrpc
from tacker import context as t_context

LOG = logging.getLogger(__name__)


def _log_monitor_events(context, vnf_dict, evt_details):
    _cos_db_plg = common_services_db_plugin.CommonServicesPluginDb()
    _cos_db_plg.create_event(context, res_id=vnf_dict['id'],
                             res_type=constants.RES_TYPE_VNF,
                             res_state=vnf_dict['status'],
                             evt_type=constants.RES_EVT_MONITOR,
                             tstamp=timeutils.utcnow(),
                             details=evt_details)


class VNFActionNotify(abstract_action.AbstractPolicyAction):
    def get_type(self):
        return 'notify'

    def get_name(self):
        return 'notify'

    def get_description(self):
        return 'Tacker VNF notification policy'

    def execute_action(self, plugin, context, vnf_dict, args):
        # args be like actions: DEFAULT_ALARM_ACTIONS
        vnf_id = vnf_dict['id']

        def start_rpc_listeners():
            """Start the RPC loop to let the server communicate with actions."""
            self.endpoints = [self]
            self.conn = rpc.create_connection()
            self.conn.create_consumer(topics.TOPIC_ACTION_KILL,
                                      self.endpoints, fanout=False,
                                      host=vnf_id)
            return self.conn.consume_in_threads()

        def _establish_rpc(target, event_func_name):
            rpc_client = rpc.get_client(target)
            cctxt = rpc_client.prepare()
            return cctxt.call(t_context.get_admin_context_without_session(),
                              event_func_name,
                              vnf_id=vnf_id)

        def _execute_action(action):
            try:
                rpc.init_action_rpc(cfg.CONF)
                servers = start_rpc_listeners()
            except Exception:
                LOG.exception('failed to start rpc for auto-healing function')
                return 'FAILED'
            try:
                if action in constants.DEFAULT_ALARM_ACTIONS:
                    target = conductorrpc.AutoHealingRPC.AutoHealingRPC.target
                    output = _establish_rpc(target, 'vnf_respawning_event')
                    LOG.debug('RPC respawning output: %s', output)
                else:
                    target = conductorrpc.AutoScalingRPC.AutoScalingRPC.target
                    output = _establish_rpc(target, 'vnf_scaling_event')
                    LOG.debug('RPC scaling output: %s', output)
            except Exception:
                LOG.exception('failed to establish rpc call for vnf %s',
                              vnf_id)
                return 'FAILED'
            # to stop rpc connection
            for server in servers:
                try:
                    server.stop()
                except Exception:
                    LOG.exception(
                        'failed to stop rpc connection for vnf %s',
                        vnf_id)
        _execute_action(args['action'])
