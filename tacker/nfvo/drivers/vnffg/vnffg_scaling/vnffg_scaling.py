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

import uuid
from oslo_utils import timeutils

from tacker.db.common_services import common_services_db_plugin
from tacker.plugins.common import constants

from oslo_log import log as logging
from tacker.common import log
from tacker.nfvo.drivers.vnffg import absttract_vnffg_policies
from tacker import manager

LOG = logging.getLogger(__name__)


def _log_vnffg_events(context, vnffg, evt_details):
    _cos_db_plg = common_services_db_plugin.CommonServicesPluginDb()
    _cos_db_plg.create_event(context, res_id=vnffg['id'],
                             res_type=constants.RES_TYPE_VNF,
                             res_state=vnffg['status'],
                             evt_type=constants.RES_EVT_MONITOR,
                             tstamp=timeutils.utcnow(),
                             details=evt_details)


class VNFFGScaling(absttract_vnffg_policies.VnffgHaAbstractDriver):

    """Auto-scaling policy for VNFFG"""

    def __init__(self):
        super(VNFFGScaling, self).__init__()
        self._instances = set()

    def get_type(self):
        return 'vnffg_scaling'

    def get_name(self):
        return 'vnffg_scaling'

    def get_description(self):
        return 'VNFFG scaling policy'

    @log.log
    def execute_policy(self, context, vnffg, vnf_id, auth_attr=None):
        # Add event/audit function
        nfvo_plugin = manager.TackerManager.get_service_plugins()['NFVO']
        #vnffg_dict = nfvo_plugin.get_vnffg_info(context, vnffg_id)
