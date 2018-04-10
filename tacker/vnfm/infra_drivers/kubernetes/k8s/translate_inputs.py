# All Rights Reserved.
#
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
from oslo_log import log as logging
from oslo_utils import uuidutils

from tacker.common import log
from tacker.extensions import vnfm
from tacker.tosca import utils as toscautils
from tacker.vnfm.infra_drivers.kubernetes.k8s import tosca_kube_object

from toscaparser.functions import GetInput
from toscaparser import tosca_template
import toscaparser.utils.yamlparser


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

YAML_LOADER = toscaparser.utils.yamlparser.load_yaml
SCALING = 'tosca.policies.Scaling'
TACKER_CP = 'tosca.nodes.nfv.CP.Tacker'
TACKER_VL = 'tosca.nodes.nfv.VL'
COLON_CHARACTER = ':'
WHITE_SPACE_CHARACTER = ' '
NON_WHITE_SPACE_CHARACTER = ''
TOSCA_LINKS_TO = 'tosca.relationships.network.LinksTo'
TOSCA_BINDS_TO = 'tosca.relationships.network.BindsTo'

ALLOWED_KUBERNETES_OBJ_PROPS = ('namespace', 'mapping_ports', 'vnfcs',
                                'service_type', 'mgmt_driver', 'config_drive')
ALLOWED_CONTAINER_OBJ_PROPS = ('num_cpus', 'mem_size', 'image', 'config',
                               'command', 'args', 'ports')
ALLOWED_SCALING_OBJ_PROPS = ('min_instances', 'max_instances',
                             'target_cpu_utilization_percentage')
ALLOWED_SERVICE_TYPES = ('ClusterIP', 'NodePort', 'LoadBalancer')

SCALAR_UNIT_DICT = {'B': 1, 'kB': 1000, 'KiB': 1024, 'MB': 1000000,
                    'MiB': 1048576, 'GB': 1000000000,
                    'GiB': 1073741824, 'TB': 1000000000000,
                    'TiB': 1099511627776}


class Parser(object):
    """Convert TOSCA template to Tosca Kube object"""

    def __init__(self, vnfd_dict):
        self.vnfd_dict = vnfd_dict

    def loader(self):
        """Load TOSCA template and start parsing"""

        try:
            parserd_params = None
            toscautils.updateimports(self.vnfd_dict)
            tosca = tosca_template.\
                ToscaTemplate(parsed_params=parserd_params,
                              a_file=False,
                              yaml_dict_tpl=self.vnfd_dict)
        except Exception as e:
            LOG.debug("tosca-parser error: %s", str(e))
            raise vnfm.ToscaParserFailed(error_msg_details=str(e))

        # Initiate a list tosca_kube_object which are defined from VDU
        tosca_kube_objects = []
        vdus = toscautils.findvdus(tosca)

        for node_template in vdus:
            vdu_name = node_template.name
            tosca_kube_obj = self.tosca_to_kube_mapping(node_template)

            # Find network name, connection point and management values
            # in which VDU is attached
            network_name, cp_name, cp_mgmt = self.get_network_props(
                tosca, vdu_name)
            tosca_kube_obj.network_name = network_name
            tosca_kube_obj.cp_name = cp_name
            tosca_kube_obj.cp_mgmt = cp_mgmt

            # Find scaling policy that is used for this VDU, different to
            # VM-based VNF, there are no alarm policies.
            tosca_kube_obj.scaling_object = \
                self.get_scaling_policy(tosca, vdu_name)
            if tosca_kube_obj.scaling_object:
                if not tosca_kube_obj.service_type:
                    raise vnfm.MissingServiceTypeForScalingSupport
                scaling_name = tosca_kube_obj.scaling_object.scaling_name
            else:
                scaling_name = None
            tosca_kube_obj.deployment_labels = self.config_labels(
                deployment_name=tosca_kube_obj.name)
            tosca_kube_obj.service_labels = self.config_labels(
                deployment_name=tosca_kube_obj.name,
                scaling_name=scaling_name,
                network_name=network_name,
                cp_name=cp_name,
                cp_mgmt=cp_mgmt)
            if not tosca_kube_obj.service_type:
                update_labels = dict(tosca_kube_obj.deployment_labels.items() +
                                     tosca_kube_obj.service_labels.items())
                tosca_kube_obj.deployment_labels = update_labels
            tosca_kube_objects.append(tosca_kube_obj)
        return tosca_kube_objects

    @log.log
    def tosca_to_kube_mapping(self, node_template):
        """Map TOSCA template to ToscaKubeObject properties"""
        tosca_props = self.get_properties(node_template)
        self.check_unsupported_key(tosca_props, ALLOWED_KUBERNETES_OBJ_PROPS)
        tosca_kube_obj = tosca_kube_object.ToscaKubeObject()

        # tosca_kube_obj name is used for tracking Kubernetes resources
        service_name = 'svc-' + node_template.name + '-' + \
                       uuidutils.generate_uuid()
        tosca_kube_obj.name = service_name[:15].lower()
        tosca_kube_obj.namespace = tosca_props.get('namespace')
        tosca_kube_obj.service_type = tosca_props.get('service_type', '')
        if tosca_kube_obj.service_type:
            if tosca_kube_obj.service_type not in ALLOWED_SERVICE_TYPES:
                raise vnfm.InvalidKubernetesServiceType(
                    service_type=tosca_kube_obj.service_type)
        tosca_kube_obj.mapping_ports = tosca_props.get('mapping_ports', '')

        # Find config properties of VNFComponents in each VDU node
        vnfc_config_props = tosca_props.get('vnfcs')
        container_objects = self.vnfc_configurable_to_container_mapping(
            vnfc_config_props)
        tosca_kube_obj.containers = container_objects
        return tosca_kube_obj

    @log.log
    def vnfc_configurable_to_container_mapping(self, vnfc_config_properties):
        """Map VnfcConfigurableProperties to list of containers"""
        containers = list()
        for container_name, container_props in vnfc_config_properties.items():
            container = tosca_kube_object.Container()
            container.name = container_name
            self.check_unsupported_key(
                container_props, ALLOWED_CONTAINER_OBJ_PROPS)
            container.num_cpus = container_props.get('num_cpus')
            memory_size = container_props.get('mem_size')
            container.mem_size = self.process_memory(memory_size)
            container.image = container_props.get('image')
            container.config = container_props.get('config')
            container.command = container_props.get('command')
            container.args = container_props.get('args')
            container.ports = container_props.get('ports')
            containers.append(container)
        return containers

    @log.log
    def process_memory(self, mem_value):
        """Translate memory size with unit to a number of byte memory"""
        # Memory size has the pattern e.g. 512 MB, 1024 MB or 1 GB
        parser_memory = mem_value.split(WHITE_SPACE_CHARACTER)
        memory_value = parser_memory[0]
        memory_unit = parser_memory[1]
        memory_real_value = 0

        # Translate memory's byte size based on SCALAR_UNIT_DICT
        if memory_unit in SCALAR_UNIT_DICT.keys():
            memory_real_value = int(memory_value) * \
                SCALAR_UNIT_DICT[memory_unit]
        return memory_real_value

    @log.log
    def get_scaling_policy(self, tosca, vdu_name):
        """Find scaling policy which is used for VDU"""
        scaling_obj = None
        if len(tosca.policies) > 0:
            count = 0
            for policy in tosca.policies:
                if policy.type_definition.is_derived_from(SCALING) \
                        and vdu_name in policy.targets:
                    scaling_obj = tosca_kube_object.ScalingObject()
                    count = count + 1
                    policy_props = policy.properties
                    self.check_unsupported_key(
                        policy_props, ALLOWED_SCALING_OBJ_PROPS)
                    scaling_obj.scaling_name = policy.name
                    scaling_obj.target_cpu_utilization_percentage = \
                        policy_props.get('target_cpu_utilization_percentage')
                    scaling_obj.min_replicas = \
                        policy_props.get('min_instances')
                    scaling_obj.max_replicas = \
                        policy_props.get('max_instances')
            if count > 1:
                # Because in Kubernetes environment, we can attach only one
                # scaling policy to Deployment. If user provides more than one
                # policy this error will happen when count > 1
                LOG.debug("Tacker only support one scaling policy per VDU")
                raise vnfm.InvalidKubernetesScalingPolicyNumber
        return scaling_obj

    @log.log
    def get_network_props(self, tosca, vdu_name):
        """Find networks which VDU is attached based on vdu_name."""
        networks = []
        network_name_list = []
        network_name = ''
        cp_mgmt = 'False'
        cp_name = None
        for node_template in tosca.nodetemplates:
            if node_template.type_definition.is_derived_from(TACKER_CP):
                cp_name = node_template.name
                match = False
                links_to = None
                binds_to = None
                for rel, node in node_template.relationships.items():
                    if not links_to and rel.is_derived_from(TOSCA_LINKS_TO):
                        links_to = node
                    elif not binds_to and rel.is_derived_from(TOSCA_BINDS_TO):
                        binds_to = node
                        if binds_to.name == vdu_name:
                            match = True
                if match:
                    networks.append(links_to.name)
                    cp_mgmt = node_template.get_property_value('management')
        for node_template in tosca.nodetemplates:
            if node_template.type_definition.is_derived_from(TACKER_VL):
                tosca_props = self.get_properties(node_template)
                if node_template.name in networks:
                    network_name_list.append(tosca_props.get('network_name'))
        if len(network_name_list) > 1:
            # Currently, Kubernetes doesn't support multiple networks.
            # If user provides more than one network, the error will raise.
            # TODO(anyone): support Multus or multiple networking
            LOG.debug("Kubernetes feature only support one network")
            raise vnfm.InvalidKubernetesNetworkNumber
        elif len(network_name_list) == 1:
            network_name = network_name_list[0]
        return network_name, cp_name, str(cp_mgmt)

    @log.log
    def get_properties(self, node_template):
        """Return a list of property node template objects."""
        tosca_props = {}
        for prop in node_template.get_properties_objects():
            if isinstance(prop.value, GetInput):
                tosca_props[prop.name] = {'get_param': prop.value.input_name}
            else:
                tosca_props[prop.name] = prop.value
        return tosca_props

    def check_unsupported_key(self, input_values, support_key):
        """collect all unsupported keys"""
        found_keys = []
        for key in input_values:
            if key not in support_key:
                found_keys.append(key)
        if len(found_keys) > 0:
            raise vnfm.InvalidKubernetesInputParameter(found_keys=found_keys)

    # config_labels configures label
    def config_labels(self, deployment_name=None, scaling_name=None,
                      network_name=None, cp_name=None, cp_mgmt=None):
        label = dict()
        if deployment_name:
            label.update({"selector": deployment_name})
        if scaling_name:
            label.update({"scaling_name": scaling_name})
        if network_name:
            label.update({"network_name": network_name})
        if cp_name:
            label.update({"cp_name": cp_name})
        if cp_mgmt:
            label.update({"cp_mgmt": cp_mgmt})
        return label
