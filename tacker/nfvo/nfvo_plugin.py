# Copyright 2016 Brocade Communications System, Inc.
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

import copy
import os
import time
import yaml

from cryptography import fernet
import eventlet
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import strutils
from oslo_utils import uuidutils
from tempfile import mkstemp
from toscaparser.tosca_template import ToscaTemplate

from tacker._i18n import _
from tacker.common import driver_manager
from tacker.common import log
from tacker.common import utils
from tacker.db.nfvo import nfvo_db_plugin
from tacker.db.nfvo import ns_db
from tacker.db.nfvo import vnfcluster_db
from tacker.db.nfvo import vnffg_db
from tacker.extensions import common_services as cs
from tacker.extensions import nfvo
from tacker.extensions.nfvo_plugins import vnfcluster
from tacker.keymgr import API as KEYMGR_API
from tacker import manager
from tacker.nfvo.workflows.vim_monitor import vim_monitor_utils
from tacker.plugins.common import constants
from tacker.vnfm import vim_client

from tacker.tosca import utils as toscautils
from toscaparser import tosca_template

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
MISTRAL_RETRIES = 30
MISTRAL_RETRY_WAIT = 6


def config_opts():
    return [('nfvo_vim', NfvoPlugin.OPTS)]


class NfvoPlugin(nfvo_db_plugin.NfvoPluginDb, vnffg_db.VnffgPluginDbMixin,
                 ns_db.NSPluginDb, vnfcluster_db.VnfClusterPluginDb):
    """NFVO reference plugin for NFVO extension

    Implements the NFVO extension and defines public facing APIs for VIM
    operations. NFVO internally invokes the appropriate VIM driver in
    backend based on configured VIM types. Plugin also interacts with VNFM
    extension for providing the specified VIM information
    """
    supported_extension_aliases = ['nfvo']

    OPTS = [
        cfg.ListOpt(
            'vim_drivers', default=['openstack', 'kubernetes'],
            help=_('VIM driver for launching VNFs')),
        cfg.IntOpt(
            'monitor_interval', default=30,
            help=_('Interval to check for VIM health')),
    ]
    cfg.CONF.register_opts(OPTS, 'nfvo_vim')

    def __init__(self):
        super(NfvoPlugin, self).__init__()
        self._pool = eventlet.GreenPool()
        self._vim_drivers = driver_manager.DriverManager(
            'tacker.nfvo.vim.drivers',
            cfg.CONF.nfvo_vim.vim_drivers)
        self.vim_client = vim_client.VimClient()

    def get_auth_dict(self, context):
        auth = CONF.keystone_authtoken
        return {
            'auth_url': auth.auth_url + '/v3',
            'token': context.auth_token,
            'project_domain_name': auth.project_domain_name or context.domain,
            'project_name': context.tenant_name
        }

    def spawn_n(self, function, *args, **kwargs):
        self._pool.spawn_n(function, *args, **kwargs)

    @log.log
    def create_vim(self, context, vim):
        LOG.debug('Create vim called with parameters %s',
                  strutils.mask_password(vim))
        vim_obj = vim['vim']
        vim_type = vim_obj['type']
        vim_obj['id'] = uuidutils.generate_uuid()
        vim_obj['status'] = 'PENDING'
        try:
            self._vim_drivers.invoke(vim_type,
                                     'register_vim',
                                     context=context,
                                     vim_obj=vim_obj)
            res = super(NfvoPlugin, self).create_vim(context, vim_obj)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._vim_drivers.invoke(vim_type,
                                         'delete_vim_auth',
                                         context=context,
                                         vim_id=vim_obj['id'],
                                         auth=vim_obj['auth_cred'])

        try:
            self.monitor_vim(context, vim_obj)
        except Exception:
            LOG.warning("Failed to set up vim monitoring")
        return res

    def _get_vim(self, context, vim_id):
        if not self.is_vim_still_in_use(context, vim_id):
            return self.get_vim(context, vim_id, mask_password=False)

    @log.log
    def update_vim(self, context, vim_id, vim):
        vim_obj = self._get_vim(context, vim_id)
        old_vim_obj = copy.deepcopy(vim_obj)
        utils.deep_update(vim_obj, vim['vim'])
        vim_type = vim_obj['type']
        update_args = vim['vim']
        old_auth_need_delete = False
        new_auth_created = False
        try:
            # re-register the VIM only if there is a change in bearer_token,
            # username, password or bearer_token.
            # auth_url of auth_cred is from vim object which
            # is not updatable. so no need to consider it
            if 'auth_cred' in update_args:
                auth_cred = update_args['auth_cred']
                if ('username' in auth_cred) and ('password' in auth_cred)\
                        and (auth_cred['password'] is not None):
                    # update new username and password, remove bearer_token
                    # if it exists in the old vim
                    vim_obj['auth_cred']['username'] = auth_cred['username']
                    vim_obj['auth_cred']['password'] = auth_cred['password']
                    if 'bearer_token' in vim_obj['auth_cred']:
                        vim_obj['auth_cred'].pop('bearer_token')
                elif 'bearer_token' in auth_cred:
                    # update bearer_token, remove username and password
                    # if they exist in the old vim
                    vim_obj['auth_cred']['bearer_token'] =\
                        auth_cred['bearer_token']
                    if ('username' in vim_obj['auth_cred']) and\
                            ('password' in vim_obj['auth_cred']):
                        vim_obj['auth_cred'].pop('username')
                        vim_obj['auth_cred'].pop('password')
                if 'ssl_ca_cert' in auth_cred:
                    # update new ssl_ca_cert
                    vim_obj['auth_cred']['ssl_ca_cert'] =\
                        auth_cred['ssl_ca_cert']
                # Notice: vim_obj may be updated in vim driver's
                self._vim_drivers.invoke(vim_type,
                                         'register_vim',
                                         context=context,
                                         vim_obj=vim_obj)
                new_auth_created = True

                # Check whether old vim's auth need to be deleted
                old_key_type = old_vim_obj['auth_cred'].get('key_type')
                if old_key_type == 'barbican_key':
                    old_auth_need_delete = True

            vim_obj = super(NfvoPlugin, self).update_vim(
                context, vim_id, vim_obj)
            if old_auth_need_delete:
                try:
                    self._vim_drivers.invoke(vim_type,
                                             'delete_vim_auth',
                                             context=context,
                                             vim_id=old_vim_obj['id'],
                                             auth=old_vim_obj['auth_cred'])
                except Exception as ex:
                    LOG.warning("Fail to delete old auth for vim %s due to %s",
                                vim_id, ex)
            return vim_obj
        except Exception as ex:
            LOG.debug("Got exception when update_vim %s due to %s",
                      vim_id, ex)
            with excutils.save_and_reraise_exception():
                if new_auth_created:
                    # delete new-created vim auth, old auth is still used.
                    self._vim_drivers.invoke(vim_type,
                                             'delete_vim_auth',
                                             context=context,
                                             vim_id=vim_obj['id'],
                                             auth=vim_obj['auth_cred'])

    @log.log
    def delete_vim(self, context, vim_id):
        vim_obj = self._get_vim(context, vim_id)
        self._vim_drivers.invoke(vim_obj['type'],
                                 'deregister_vim',
                                 context=context,
                                 vim_obj=vim_obj)
        try:
            auth_dict = self.get_auth_dict(context)
            vim_monitor_utils.delete_vim_monitor(context, auth_dict, vim_obj)
        except Exception:
            LOG.exception("Failed to remove vim monitor")
        super(NfvoPlugin, self).delete_vim(context, vim_id)

    @log.log
    def monitor_vim(self, context, vim_obj):
        auth_dict = self.get_auth_dict(context)
        vim_monitor_utils.monitor_vim(auth_dict, vim_obj)

    @log.log
    def validate_tosca(self, template):
        if "tosca_definitions_version" not in template:
            raise nfvo.ToscaParserFailed(
                error_msg_details='tosca_definitions_version missing in '
                                  'template'
            )

        LOG.debug('template yaml: %s', template)

        toscautils.updateimports(template)

        try:
            tosca_template.ToscaTemplate(
                a_file=False, yaml_dict_tpl=template)
        except Exception as e:
            LOG.exception("tosca-parser error: %s", str(e))
            raise nfvo.ToscaParserFailed(error_msg_details=str(e))

    @log.log
    def validate_vnffgd_path(self, template):
        temp = template['vnffgd']['topology_template']
        vnffg_name = list(temp['groups'].keys())[0]
        nfp_name = temp['groups'][vnffg_name]['members'][0]
        path = self._get_nfp_attribute(template, nfp_name,
                                       'path')

        prev_element = None
        known_forwarders = set()
        for element in path:
            if element.get('forwarder') in known_forwarders:
                if prev_element is not None and element.get('forwarder') \
                        != prev_element['forwarder']:
                    raise nfvo.VnffgdDuplicateForwarderException(
                        forwarder=element.get('forwarder')
                    )
                elif prev_element is not None and element.get(
                        'capability') == prev_element['capability']:
                    raise nfvo.VnffgdDuplicateCPException(
                        cp=element.get('capability')
                    )
            else:
                known_forwarders.add(element.get('forwarder'))
            prev_element = element

    @log.log
    def validate_vnffg_properties(self, template):

        # check whether number_of_endpoints is same with connection_point
        connection_point = self._get_vnffg_property(
            template, 'connection_point')
        number_endpoint = self._get_vnffg_property(
            template, 'number_of_endpoints')

        if len(connection_point) != number_endpoint:
            raise nfvo.VnffgdWrongEndpointNumber(
                number=number_endpoint,
                cps=connection_point)

    @log.log
    def create_vnffgd(self, context, vnffgd):
        template = vnffgd['vnffgd']

        if 'template_source' in template:
            template_source = template.get('template_source')
        else:
            template_source = 'onboarded'
        vnffgd['vnffgd']['template_source'] = template_source

        if 'vnffgd' not in template.get('template'):
            raise nfvo.VnffgdInvalidTemplate(template=template.get('template'))
        else:
            self.validate_tosca(template['template']['vnffgd'])

            self.validate_vnffgd_path(template['template'])

            self.validate_vnffg_properties(template['template'])

        return super(NfvoPlugin, self).create_vnffgd(context, vnffgd)

    @log.log
    def create_vnffg(self, context, vnffg):
        vnffg_info = vnffg['vnffg']
        name = vnffg_info['name']

        if vnffg_info.get('vnffgd_template'):
            vnffgd_name = utils.generate_resource_name(name, 'inline')
            vnffgd = {'vnffgd': {'tenant_id': vnffg_info['tenant_id'],
                                 'name': vnffgd_name,
                                 'template': {
                                     'vnffgd': vnffg_info['vnffgd_template']},
                                 'template_source': 'inline',
                                 'description': vnffg_info['description']}}
            vnffg_info['vnffgd_id'] = \
                self.create_vnffgd(context, vnffgd).get('id')

        vnffg_dict = super(NfvoPlugin, self)._create_vnffg_pre(context, vnffg)
        nfp = super(NfvoPlugin, self).get_nfp(context,
                                              vnffg_dict['forwarding_paths'])
        sfc = super(NfvoPlugin, self).get_sfc(context, nfp['chain_id'])
        name_match_list = []
        for classifier_id in nfp['classifier_ids']:
            classifier_dict = super(NfvoPlugin, self).get_classifier(
                context, classifier_id, fields=['name', 'match'])
            name_match_list.append(classifier_dict)
        # grab the first VNF to check it's VIM type
        # we have already checked that all VNFs are in the same VIM
        vim_obj = self._get_vim_from_vnf(context,
                                         list(vnffg_dict[
                                              'vnf_mapping'].values())[0])
        # TODO(trozet): figure out what auth info we actually need to pass
        # to the driver.  Is it a session, or is full vim obj good enough?
        driver_type = vim_obj['type']
        try:
            fc_ids = []
            for item in name_match_list:
                fc_ids.append(self._vim_drivers.invoke(driver_type,
                                             'create_flow_classifier',
                                             name=item['name'],
                                             fc=item['match'],
                                             auth_attr=vim_obj['auth_cred']))
            sfc_id = self._vim_drivers.invoke(driver_type,
                                              'create_chain',
                                              name=vnffg_dict['name'],
                                              vnfs=sfc['chain'],
                                              fc_ids=fc_ids,
                                              symmetrical=sfc['symmetrical'],
                                              auth_attr=vim_obj['auth_cred'])
        except Exception:
            with excutils.save_and_reraise_exception():
                self.delete_vnffg(context, vnffg_id=vnffg_dict['id'])
        classifiers_map = super(NfvoPlugin, self). \
            create_classifiers_map(nfp['classifier_ids'], fc_ids)
        super(NfvoPlugin, self)._create_vnffg_post(context, sfc_id,
                                                   classifiers_map,
                                                   vnffg_dict)
        super(NfvoPlugin, self)._create_vnffg_status(context, vnffg_dict)
        return vnffg_dict

    @log.log
    def update_vnffg(self, context, vnffg_id, vnffg):
        vnffg_info = vnffg['vnffg']
        # put vnffg related objects in PENDING_UPDATE status
        vnffg_old = super(NfvoPlugin, self)._update_vnffg_status_pre(
            context, vnffg_id)
        name = vnffg_old['name']

        # create inline vnffgd if given by user
        if vnffg_info.get('vnffgd_template'):
            vnffgd_name = utils.generate_resource_name(name, 'inline')
            vnffgd = {'vnffgd': {'tenant_id': vnffg_old['tenant_id'],
                                 'name': vnffgd_name,
                                 'template': {
                                     'vnffgd': vnffg_info['vnffgd_template']},
                                 'template_source': 'inline',
                                 'description': vnffg_old['description']}}
            try:
                vnffg_info['vnffgd_id'] = \
                    self.create_vnffgd(context, vnffgd).get('id')
            except Exception:
                with excutils.save_and_reraise_exception():
                    super(NfvoPlugin, self)._update_vnffg_status_post(context,
                        vnffg_old, error=True, db_state=constants.ACTIVE)
        try:

            vnffg_dict = super(NfvoPlugin, self). \
                _update_vnffg_pre(context, vnffg, vnffg_id, vnffg_old)

        except (nfvo.VnfMappingNotFoundException,
                nfvo.VnfMappingNotValidException):
            with excutils.save_and_reraise_exception():

                if vnffg_info.get('vnffgd_template'):
                    super(NfvoPlugin, self).delete_vnffgd(
                        context, vnffg_info['vnffgd_id'])

                super(NfvoPlugin, self)._update_vnffg_status_post(
                    context, vnffg_old, error=True, db_state=constants.ACTIVE)
        except nfvo.UpdateVnffgException:
            with excutils.save_and_reraise_exception():
                super(NfvoPlugin, self).delete_vnffgd(context,
                                                      vnffg_info['vnffgd_id'])

                super(NfvoPlugin, self)._update_vnffg_status_post(context,
                                                                  vnffg_old,
                                                                  error=True)

        nfp = super(NfvoPlugin, self).get_nfp(context,
                                              vnffg_dict['forwarding_paths'])
        sfc = super(NfvoPlugin, self).get_sfc(context, nfp['chain_id'])

        classifier_dict = dict()
        classifier_update = []
        classifier_delete_ids = []
        classifier_ids = []
        for classifier_id in nfp['classifier_ids']:
            classifier_dict = super(NfvoPlugin, self).get_classifier(
                context, classifier_id, fields=['id', 'name', 'match',
                    'instance_id', 'status'])
            if classifier_dict['status'] == constants.PENDING_DELETE:
                classifier_delete_ids.append(
                    classifier_dict.pop('instance_id'))
            else:
                classifier_ids.append(classifier_dict.pop('id'))
                classifier_update.append(classifier_dict)

        # TODO(gongysh) support different vim for each vnf
        vim_obj = self._get_vim_from_vnf(context,
                                         list(vnffg_dict[
                                              'vnf_mapping'].values())[0])
        driver_type = vim_obj['type']
        try:
            fc_ids = []
            self._vim_drivers.invoke(driver_type,
                                     'remove_and_delete_flow_classifiers',
                                     chain_id=sfc['instance_id'],
                                     fc_ids=classifier_delete_ids,
                                     auth_attr=vim_obj['auth_cred'])
            for item in classifier_update:
                fc_ids.append(self._vim_drivers.invoke(driver_type,
                                         'update_flow_classifier',
                                         chain_id=sfc['instance_id'],
                                         fc=item,
                                         auth_attr=vim_obj['auth_cred']))
            n_sfc_chain_id = self._vim_drivers.invoke(
                driver_type, 'update_chain',
                vnfs=sfc['chain'], fc_ids=fc_ids,
                chain_id=sfc['instance_id'], auth_attr=vim_obj['auth_cred'])
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NfvoPlugin, self)._update_vnffg_status_post(context,
                                                             vnffg_dict,
                                                             error=True)

        classifiers_map = super(NfvoPlugin, self).create_classifiers_map(
            classifier_ids, fc_ids)
        super(NfvoPlugin, self)._update_vnffg_post(context, n_sfc_chain_id,
                                                   classifiers_map,
                                                   vnffg_dict)
        super(NfvoPlugin, self)._update_vnffg_status_post(context, vnffg_dict)
        return vnffg_dict

    @log.log
    def delete_vnffg(self, context, vnffg_id):
        vnffg_dict = super(NfvoPlugin, self)._delete_vnffg_pre(context,
                                                               vnffg_id)
        nfp = super(NfvoPlugin, self).get_nfp(context,
                                              vnffg_dict['forwarding_paths'])
        sfc = super(NfvoPlugin, self).get_sfc(context, nfp['chain_id'])

        classifiers = [super(NfvoPlugin, self).
            get_classifier(context, classifier_id)
            for classifier_id in nfp['classifier_ids']]
        vim_obj = self._get_vim_from_vnf(context,
                                         list(vnffg_dict[
                                              'vnf_mapping'].values())[0])
        driver_type = vim_obj['type']
        try:
            if sfc['instance_id'] is not None:
                self._vim_drivers.invoke(driver_type, 'delete_chain',
                                         chain_id=sfc['instance_id'],
                                         auth_attr=vim_obj['auth_cred'])
            for classifier in classifiers:
                if classifier['instance_id'] is not None:
                    self._vim_drivers.invoke(driver_type,
                                             'delete_flow_classifier',
                                             fc_id=classifier['instance_id'],
                                             auth_attr=vim_obj['auth_cred'])
        except Exception:
            with excutils.save_and_reraise_exception():
                vnffg_dict['status'] = constants.ERROR
                super(NfvoPlugin, self)._delete_vnffg_post(context, vnffg_id,
                                                           True)
        super(NfvoPlugin, self)._delete_vnffg_post(context, vnffg_id, False)
        return vnffg_dict

    def _get_vim_from_vnf(self, context, vnf_id):
        """Figures out VIM based on a VNF

        :param context: SQL Session Context
        :param vnf_id: VNF ID
        :return: VIM or VIM properties if fields are provided
        """
        vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']
        vim_id = vnfm_plugin.get_vnf(context, vnf_id, fields=['vim_id'])
        vim_obj = self.get_vim(context, vim_id['vim_id'], mask_password=False)
        if vim_obj is None:
            raise nfvo.VimFromVnfNotFoundException(vnf_id=vnf_id)
        self._build_vim_auth(context, vim_obj)
        return vim_obj

    def _build_vim_auth(self, context, vim_info):
        LOG.debug('VIM ID is %s', vim_info['id'])
        vim_auth = vim_info['auth_cred']
        vim_auth['password'] = self._decode_vim_auth(context,
                                                     vim_info['id'],
                                                     vim_auth)
        vim_auth['auth_url'] = vim_info['auth_url']

        # These attributes are needless for authentication
        # from keystone, so we remove them.
        needless_attrs = ['key_type', 'secret_uuid']
        for attr in needless_attrs:
            if attr in vim_auth:
                vim_auth.pop(attr, None)
        return vim_auth

    def _decode_vim_auth(self, context, vim_id, auth):
        """Decode Vim credentials

        Decrypt VIM cred, get fernet Key from local_file_system or
        barbican.
        """
        cred = auth['password'].encode('utf-8')
        if auth.get('key_type') == 'barbican_key':
            keystone_conf = CONF.keystone_authtoken
            secret_uuid = auth['secret_uuid']
            keymgr_api = KEYMGR_API(keystone_conf.auth_url)
            secret_obj = keymgr_api.get(context, secret_uuid)
            vim_key = secret_obj.payload
        else:
            vim_key = self._find_vim_key(vim_id)

        f = fernet.Fernet(vim_key)
        if not f:
            LOG.warning('Unable to decode VIM auth')
            raise nfvo.VimNotFoundException(
                'Unable to decode VIM auth key')
        return f.decrypt(cred)

    @staticmethod
    def _find_vim_key(vim_id):
        key_file = os.path.join(CONF.vim_keys.openstack, vim_id)
        LOG.debug('Attempting to open key file for vim id %s', vim_id)
        with open(key_file, 'r') as f:
            return f.read()
        LOG.warning('VIM id invalid or key not found for  %s', vim_id)

    def _vim_resource_name_to_id(self, context, resource, name, vnf_id):
        """Converts a VIM resource name to its ID

        :param resource: resource type to find (network, subnet, etc)
        :param name: name of the resource to find its ID
        :param vnf_id: A VNF instance ID that is part of the chain to which
               the classifier will apply to
        :return: ID of the resource name
        """
        vim_obj = self._get_vim_from_vnf(context, vnf_id)
        driver_type = vim_obj['type']
        return self._vim_drivers.invoke(driver_type,
                                        'get_vim_resource_id',
                                        vim_obj=vim_obj,
                                        resource_type=resource,
                                        resource_name=name)

    @log.log
    def create_nsd(self, context, nsd):
        nsd_data = nsd['nsd']
        template = nsd_data['attributes'].get('nsd')
        if isinstance(template, dict):
            nsd_data['attributes']['nsd'] = yaml.safe_dump(
                template)
        LOG.debug('nsd %s', nsd_data)

        if 'template_source' in nsd_data:
            template_source = nsd_data.get('template_source')
        else:
            template_source = "onboarded"
        nsd['nsd']['template_source'] = template_source

        self._parse_template_input(context, nsd)
        return super(NfvoPlugin, self).create_nsd(
            context, nsd)

    def _parse_template_input(self, context, nsd):
        nsd_dict = nsd['nsd']
        nsd_yaml = nsd_dict['attributes'].get('nsd')
        inner_nsd_dict = yaml.safe_load(nsd_yaml)
        nsd['vnfds'] = dict()
        LOG.debug('nsd_dict: %s', inner_nsd_dict)

        vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']
        vnfd_imports = inner_nsd_dict['imports']
        inner_nsd_dict['imports'] = []
        new_files = []
        for vnfd_name in vnfd_imports:
            vnfd = vnfm_plugin.get_vnfd(context, vnfd_name)
            # Copy VNF types and VNF names
            sm_dict = yaml.safe_load(vnfd['attributes']['vnfd'])[
                'topology_template'][
                'substitution_mappings']
            nsd['vnfds'][sm_dict['node_type']] = vnfd['name']
            # Ugly Hack to validate the child templates
            # TODO(tbh): add support in tosca-parser to pass child
            # templates as dict
            fd, temp_path = mkstemp()
            with open(temp_path, 'w') as fp:
                fp.write(vnfd['attributes']['vnfd'])
            os.close(fd)
            new_files.append(temp_path)
            inner_nsd_dict['imports'].append(temp_path)
        # Prepend the tacker_defs.yaml import file with the full
        # path to the file
        toscautils.updateimports(inner_nsd_dict)

        try:
            ToscaTemplate(a_file=False,
                          yaml_dict_tpl=inner_nsd_dict)
        except Exception as e:
            LOG.exception("tosca-parser error: %s", str(e))
            raise nfvo.ToscaParserFailed(error_msg_details=str(e))
        finally:
            for file_path in new_files:
                os.remove(file_path)
            inner_nsd_dict['imports'] = vnfd_imports

        if ('description' not in nsd_dict or
                nsd_dict['description'] == ''):
            nsd_dict['description'] = inner_nsd_dict.get(
                'description', '')
        if (('name' not in nsd_dict or
                not len(nsd_dict['name'])) and
                'metadata' in inner_nsd_dict):
            nsd_dict['name'] = inner_nsd_dict['metadata'].get(
                'template_name', '')

        LOG.debug('nsd %s', nsd)

    def _get_vnfd_id(self, vnfd_name, onboarded_vnfds):
        for vnfd in onboarded_vnfds:
            if vnfd_name == vnfd['name']:
                return vnfd['id']

    @log.log
    def create_ns(self, context, ns):
        """Create NS and corresponding VNFs.

        :param ns: ns dict which contains nsd_id and attributes
        This method has 3 steps:
        step-1: substitute all get_input params to its corresponding values
        step-2: Build params dict for substitution mappings case through which
        VNFs will actually substitute their requirements.
        step-3: Create mistral workflow and execute the workflow
        """
        ns_info = ns['ns']
        name = ns_info['name']

        if ns_info.get('nsd_template'):
            nsd_name = utils.generate_resource_name(name, 'inline')
            nsd = {'nsd': {
                'attributes': {'nsd': ns_info['nsd_template']},
                'description': ns_info['description'],
                'name': nsd_name,
                'template_source': 'inline',
                'tenant_id': ns_info['tenant_id']}}
            ns_info['nsd_id'] = self.create_nsd(context, nsd).get('id')

        nsd = self.get_nsd(context, ns['ns']['nsd_id'])
        nsd_dict = yaml.safe_load(nsd['attributes']['nsd'])
        vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']
        onboarded_vnfds = vnfm_plugin.get_vnfds(context, [])
        region_name = ns.setdefault('placement_attr', {}).get(
            'region_name', None)
        vim_res = self.vim_client.get_vim(context, ns['ns']['vim_id'],
                                          region_name)
        driver_type = vim_res['vim_type']
        if not ns['ns']['vim_id']:
            ns['ns']['vim_id'] = vim_res['vim_id']

        # Step-1
        param_values = ns['ns']['attributes'].get('param_values', {})
        if 'get_input' in str(nsd_dict):
            self._process_parameterized_input(ns['ns']['attributes'],
                                              nsd_dict)
        # Step-2
        vnfds = nsd['vnfds']
        # vnfd_dict is used while generating workflow
        vnfd_dict = dict()
        for node_name, node_val in \
                (nsd_dict['topology_template']['node_templates']).items():
            if node_val.get('type') not in vnfds.keys():
                continue
            vnfd_name = vnfds[node_val.get('type')]
            if not vnfd_dict.get(vnfd_name):
                vnfd_dict[vnfd_name] = {
                    'id': self._get_vnfd_id(vnfd_name, onboarded_vnfds),
                    'instances': [node_name]
                }
            else:
                vnfd_dict[vnfd_name]['instances'].append(node_name)
            if not node_val.get('requirements'):
                continue
            if not param_values.get(vnfd_name):
                param_values[vnfd_name] = {}
            param_values[vnfd_name]['substitution_mappings'] = dict()
            req_dict = dict()
            requirements = node_val.get('requirements')
            for requirement in requirements:
                req_name = list(requirement.keys())[0]
                req_val = list(requirement.values())[0]
                res_name = req_val + ns['ns']['nsd_id'][:11]
                req_dict[req_name] = res_name
                if req_val in nsd_dict['topology_template']['node_templates']:
                    param_values[vnfd_name]['substitution_mappings'][
                        res_name] = nsd_dict['topology_template'][
                        'node_templates'][req_val]

            param_values[vnfd_name]['substitution_mappings'][
                'requirements'] = req_dict
        ns['vnfd_details'] = vnfd_dict
        # Step-3
        kwargs = {'ns': ns, 'params': param_values}

        # NOTE NoTasksException is raised if no tasks.
        workflow = self._vim_drivers.invoke(
            driver_type,
            'prepare_and_create_workflow',
            resource='vnf',
            action='create',
            auth_dict=self.get_auth_dict(context),
            kwargs=kwargs)
        try:
            mistral_execution = self._vim_drivers.invoke(
                driver_type,
                'execute_workflow',
                workflow=workflow,
                auth_dict=self.get_auth_dict(context))
        except Exception as ex:
            LOG.error('Error while executing workflow: %s', ex)
            self._vim_drivers.invoke(driver_type,
                                     'delete_workflow',
                                     workflow_id=workflow['id'],
                                     auth_dict=self.get_auth_dict(context))
            raise ex
        ns_dict = super(NfvoPlugin, self).create_ns(context, ns)

        def _create_ns_wait(self_obj, ns_id, execution_id):
            exec_state = "RUNNING"
            mistral_retries = MISTRAL_RETRIES
            while exec_state == "RUNNING" and mistral_retries > 0:
                time.sleep(MISTRAL_RETRY_WAIT)
                exec_state = self._vim_drivers.invoke(
                    driver_type,
                    'get_execution',
                    execution_id=execution_id,
                    auth_dict=self.get_auth_dict(context)).state
                LOG.debug('status: %s', exec_state)
                if exec_state == 'SUCCESS' or exec_state == 'ERROR':
                    break
                mistral_retries = mistral_retries - 1
            error_reason = None
            if mistral_retries == 0 and exec_state == 'RUNNING':
                error_reason = _(
                    "NS creation is not completed within"
                    " {wait} seconds as creation of mistral"
                    " execution {mistral} is not completed").format(
                    wait=MISTRAL_RETRIES * MISTRAL_RETRY_WAIT,
                    mistral=execution_id)
            exec_obj = self._vim_drivers.invoke(
                driver_type,
                'get_execution',
                execution_id=execution_id,
                auth_dict=self.get_auth_dict(context))
            self._vim_drivers.invoke(driver_type,
                                     'delete_execution',
                                     execution_id=execution_id,
                                     auth_dict=self.get_auth_dict(context))
            self._vim_drivers.invoke(driver_type,
                                     'delete_workflow',
                                     workflow_id=workflow['id'],
                                     auth_dict=self.get_auth_dict(context))
            super(NfvoPlugin, self).create_ns_post(context, ns_id, exec_obj,
                                                   vnfd_dict, error_reason)

        self.spawn_n(_create_ns_wait, self, ns_dict['id'],
                     mistral_execution.id)
        return ns_dict

    @log.log
    def _update_params(self, original, paramvalues):
        for key, value in (original).items():
            if not isinstance(value, dict) or 'get_input' not in str(value):
                pass
            elif isinstance(value, dict):
                if 'get_input' in value:
                    if value['get_input'] in paramvalues:
                        original[key] = paramvalues[value['get_input']]
                    else:
                        LOG.debug('Key missing Value: %s', key)
                        raise cs.InputValuesMissing(key=key)
                else:
                    self._update_params(value, paramvalues)

    @log.log
    def _process_parameterized_input(self, attrs, nsd_dict):
        param_vattrs_dict = attrs.pop('param_values', None)
        if param_vattrs_dict:
            for node in \
                    nsd_dict['topology_template']['node_templates'].values():
                if 'get_input' in str(node):
                    self._update_params(node, param_vattrs_dict['nsd'])
        else:
            raise cs.ParamYAMLInputMissing()

    @log.log
    def delete_ns(self, context, ns_id):
        ns = super(NfvoPlugin, self).get_ns(context, ns_id)
        vim_res = self.vim_client.get_vim(context, ns['vim_id'])
        super(NfvoPlugin, self).delete_ns_pre(context, ns_id)
        driver_type = vim_res['vim_type']
        workflow = None
        try:
            if ns['vnf_ids']:
                workflow = self._vim_drivers.invoke(
                    driver_type,
                    'prepare_and_create_workflow',
                    resource='vnf',
                    action='delete',
                    auth_dict=self.get_auth_dict(context),
                    kwargs={
                        'ns': ns})
        except nfvo.NoTasksException:
            LOG.warning("No VNF deletion task(s).")
        if workflow:
            try:
                mistral_execution = self._vim_drivers.invoke(
                    driver_type,
                    'execute_workflow',
                    workflow=workflow,
                    auth_dict=self.get_auth_dict(context))

            except Exception as ex:
                LOG.error('Error while executing workflow: %s', ex)
                self._vim_drivers.invoke(driver_type,
                                         'delete_workflow',
                                         workflow_id=workflow['id'],
                                         auth_dict=self.get_auth_dict(context))

                raise ex

        def _delete_ns_wait(ns_id, execution_id):
            exec_state = "RUNNING"
            mistral_retries = MISTRAL_RETRIES
            while exec_state == "RUNNING" and mistral_retries > 0:
                time.sleep(MISTRAL_RETRY_WAIT)
                exec_state = self._vim_drivers.invoke(
                    driver_type,
                    'get_execution',
                    execution_id=execution_id,
                    auth_dict=self.get_auth_dict(context)).state
                LOG.debug('status: %s', exec_state)
                if exec_state == 'SUCCESS' or exec_state == 'ERROR':
                    break
                mistral_retries -= 1
            error_reason = None
            if mistral_retries == 0 and exec_state == 'RUNNING':
                error_reason = _(
                    "NS deletion is not completed within"
                    " {wait} seconds as deletion of mistral"
                    " execution {mistral} is not completed").format(
                    wait=MISTRAL_RETRIES * MISTRAL_RETRY_WAIT,
                    mistral=execution_id)
            exec_obj = self._vim_drivers.invoke(
                driver_type,
                'get_execution',
                execution_id=execution_id,
                auth_dict=self.get_auth_dict(context))
            self._vim_drivers.invoke(driver_type,
                                     'delete_execution',
                                     execution_id=execution_id,
                                     auth_dict=self.get_auth_dict(context))
            self._vim_drivers.invoke(driver_type,
                                     'delete_workflow',
                                     workflow_id=workflow['id'],
                                     auth_dict=self.get_auth_dict(context))
            super(NfvoPlugin, self).delete_ns_post(context, ns_id, exec_obj,
                                                   error_reason)

        if workflow:
            self.spawn_n(_delete_ns_wait, ns['id'], mistral_execution.id)
        else:
            super(NfvoPlugin, self).delete_ns_post(
                context, ns_id, None, None)
        return ns['id']

    @log.log
    def create_cluster(self, context, cluster, reconfig=None):
        # 1. Create Cluster
        cluster_config = cluster.get('cluster')
        policy_info = cluster_config.get('policy_info')

        if not reconfig:
            role_config = policy_info['properties']['role']
            vim_list = self.get_required_vims(context, role_config)
            cluster_dict = self._create_cluster_db(context, cluster_config)
            cluster_dict['lb_info'] = dict()
            cluster_dict['vip_endpoint'] = dict()
        else:
            role_config = reconfig.get('role_config')
            vim_list = reconfig.get('vim_name')
            cluster_dict = reconfig.get('cluster_dict')

        # Get cluster_id from deployed cluster
        cluster_id = cluster_dict.get('id')

        # Muliple VIM name scenario processing
        if len(vim_list) > 1:
            # Multiple VIMs are specified in role_config
            for vim_name in vim_list:
                role_by_vim = \
                    self.get_role_by_vim(context, role_config, vim_name)
                if len(role_by_vim) > 0:
                    reconfig = dict(vim_name=[vim_name],
                                    role_config=role_by_vim,
                                    cluster_dict=cluster_dict)
                    cluster_result = \
                        self.create_cluster(context, cluster,
                                            reconfig=reconfig)
                    if not cluster_result:
                        self._update_cluster_attr(context, cluster_id,
                                                  'status', constants.ERROR)
                        raise vnfcluster.\
                            ClusterCreateFailed(cluster_id=cluster_id)
            return cluster_result

        elif len(vim_list) == 1:
            # Single VIM is specified in role_config
            vim_name = vim_list[0]
            vim_obj = self.get_vim_by_name(context, vim_name)
            vim_id = vim_obj.get('id')
            role_config = self.get_role_by_vim(context, role_config, vim_name)
            if not role_config:
                self._update_cluster_attr(context, cluster_id,
                                          'status', constants.ERROR)
                raise vnfcluster.ClusterRoleConfigInvalid()

        # 2. Deploy Neutron Load-balancer for created cluster members
        lb_pool = self.get_lb_config(policy_info, 'pool')
        lb_vip = self.get_lb_config(policy_info, 'vip')
        lb_listener = self.get_lb_config(policy_info, 'listener')
        lb_timeout = self.get_lb_config(policy_info,
                                        'lb_deployment_timeout')
        invalid_config = None
        if not lb_vip:
            invalid_config = 'load_balancer:vip'
        elif not lb_vip.get('subnet'):
            invalid_config = 'load_balancer:vip:subnet'
        if invalid_config:
            self._update_cluster_attr(context, cluster_id,
                                      'status', constants.ERROR)
            raise vnfcluster.InvalidLoadBalancerConfig(config=invalid_config)

        lb_info = self._vim_drivers.\
            invoke(vim_obj['type'], 'create_loadbalancer',
                   lb_pool=lb_pool, lb_vip=lb_vip,
                   lb_listener=lb_listener,
                   lb_deployment_timeout=lb_timeout,
                   auth_attr=vim_obj['auth_cred'])
        if not lb_info:
            LOG.error('Creating Load balancer failed.')
            cluster_dict['status'] = self._update_cluster_attr(context,
                                                               cluster_id,
                                                               'status',
                                                               constants.ERROR)
            raise vnfcluster.LoadBalancerCreateFailed()

        # Update lb_info
        cluster_dict['lb_info'][vim_name] = lb_info
        cluster_dict['lb_info']['CP'] = \
            self.get_lb_config(policy_info, 'target')
        self._update_cluster_attr(context, cluster_id,
                                  'lb_info', cluster_dict['lb_info'])

        # Update vip_endpoint
        vip_endpoint = {lb_info.get('vip_address'):
                        lb_info.get('protocol_port')}
        if not reconfig:
            cluster_dict['vip_endpoint'] = vip_endpoint
        else:
            cluster_dict['vip_endpoint'][vim_name] = vip_endpoint
        self._update_cluster_attr(context, cluster_id,
                                  'vip_endpoint', cluster_dict['vip_endpoint'])

        # 3. Create cluster member by role
        for role in role_config:
            n_members = role_config[role].get(vim_name)
            role = role.upper()
            if n_members > 0:
                for i in range(n_members):
                    member_name = role + '-' + uuidutils.generate_uuid()
                    member_config = \
                        self._make_member_config(member_name, role, cluster_id,
                                                 cluster_dict['vnfd_id'],
                                                 vim_id)
                    self.create_clustermember(context, member_config)

        cluster_dict['role_config'] = \
            self._get_cluster_db(context, cluster_id).get('role_config')
        cluster_dict['status'] = \
            self._update_cluster_attr(context, cluster_id,
                                      'status', constants.ACTIVE)
        return cluster_dict

    @log.log
    def recovery_action(self, context, vnf_id):
        fault_vnf_id = vnf_id
        LOG.warning(("Handling recovery_action for the fault vnf_id : %s"),
                    fault_vnf_id)
        fault_member_dict = \
            self.get_member_by_attr(context, dict(vnf_id=[fault_vnf_id]))
        fault_member_id = fault_member_dict.get('id')

        cluster_id = fault_member_dict.get('cluster_id')
        cluster_dict = self.get_cluster(context, cluster_id)
        self._update_cluster_attr(context, cluster_id,
                                  'status', constants.PENDING_UPDATE)

        # Get vim_obj
        vim_id = fault_member_dict.get('vim_id')
        vim_obj = self.get_vim(context, vim_id, mask_password=False)
        self._build_vim_auth(context, vim_obj)
        vim_name = vim_obj.get('name')

        lb_info = cluster_dict['lb_info'].get(vim_name)

        role_config = cluster_dict.get('role_config')
        fault_member_role = fault_member_dict.get('role')

        # 1. Remove the fault member
        self.delete_clustermember(context, fault_member_id)
        LOG.debug('Remove the failure member %s from deployed cluster',
                  fault_member_id)

        if fault_member_role == constants.CLUSTER_ACTIVE:
            n_standby = 0
            if constants.CLUSTER_STANDBY in role_config:
                standby_list = \
                    role_config[constants.CLUSTER_STANDBY].get(vim_name)
                if standby_list is not None:
                    n_standby = len(standby_list)

            if n_standby == 0:
                # 2a. Pointing out that a new member will be ACTIVE member
                new_member_role = constants.CLUSTER_ACTIVE

            elif n_standby > 0:
                # 2b. Update STANDBY member to ACTIVE member,
                # and a new member will be STANDBY member
                filters = dict(cluster_id=[cluster_id],
                               role=[constants.CLUSTER_STANDBY],
                               vim_id=[vim_id])
                alter_member = self.get_member_by_attr(context, filters)
                self.update_member_role(context, vim_obj, lb_info,
                                        alter_member,
                                        constants.CLUSTER_ACTIVE)
                new_member_role = constants.CLUSTER_STANDBY

        elif fault_member_role == constants.CLUSTER_STANDBY:
            # 2c. In the case of STANDBY member down,
            # we just need to deploy a new STANDBY member
            new_member_role = constants.CLUSTER_STANDBY

        # 3. Create an alternative cluster member
        LOG.debug(_('Create an additional %s cluster member'), new_member_role)
        member_name = new_member_role + '-' + uuidutils.generate_uuid()
        member_config = self._make_member_config(member_name,
                                                 new_member_role,
                                                 cluster_id,
                                                 cluster_dict['vnfd_id'],
                                                 vim_id)
        new_member = self.create_clustermember(context, member_config)
        LOG.debug('Recovery with a new member: %s', new_member['id'])

        self._update_cluster_attr(context, cluster_id,
                                  'status', constants.ACTIVE)
        LOG.warning("Recovery action has finished.")

    @log.log
    def get_cluster(self, context, cluster_id, fields=None):
        return self._get_cluster_db(context, cluster_id, fields)

    @log.log
    def get_clusters(self, context, filters=None, fields=None):
        return self._get_clusters_db(context, filters, fields)

    @log.log
    def delete_cluster(self, context, cluster_id):
        cluster_dict = self.get_cluster(context, cluster_id)
        # Delete member from cluster
        self._update_cluster_attr(context, cluster_id, 'status',
                                  constants.PENDING_DELETE)

        member_list = self.get_clustermembers(context,
                                              dict(cluster_id=[cluster_id]))
        for mem in member_list:
            self.delete_clustermember(context, mem['id'])

        lb_info = cluster_dict['lb_info']
        # Delete load balancer
        try:
            for vim in lb_info:
                if vim == 'CP':
                    continue
                lb_by_vim = cluster_dict['lb_info'].get(vim)
                vim_dict = self.get_vim_by_name(context, vim)
                self._vim_drivers.invoke(vim_dict['type'],
                                         'delete_loadbalancer',
                                         lb_id=lb_by_vim['lb_id'],
                                         pool_id=lb_by_vim['pool_id'],
                                         listener_id=lb_by_vim['listener_id'],
                                         auth_attr=vim_dict['auth_cred'])
        except Exception:
            LOG.warning('Load balancer resources could not be found')

        self._delete_cluster_db(context, cluster_id)

    @log.log
    def create_clustermember(self, context, clustermember):
        vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']

        LOG.debug('Adding a new cluster member: %s', clustermember)
        param_dict = clustermember['clustermember']
        name = param_dict['name']
        role = param_dict['role']
        cluster_id = param_dict['cluster_id']
        vim_id = param_dict['vim_id']

        roles = [constants.CLUSTER_ACTIVE, constants.CLUSTER_STANDBY]
        if role not in roles:
            raise vnfcluster.ClusterMemberRoleInvalid(role=role)

        cluster_dict = self.get_cluster(context, cluster_id)

        if not vim_id:
            vim_obj = self.get_default_vim(context)
        else:
            vim_obj = self.get_vim(context, vim_id, mask_password=False)
        self._build_vim_auth(context, vim_obj)
        vim_name = vim_obj['name']

        # Check and update cluster status
        if cluster_dict['status'] == constants.ACTIVE:
            cluster_dict['status'] = \
                self._update_cluster_attr(context, cluster_id,
                                          'status', constants.PENDING_UPDATE)

        member_dict = self._create_cluster_member(context, vnfm_plugin,
                                                  cluster_dict,
                                                  name, role, vim_id)
        # Update role_config in cluster
        role_config = cluster_dict['role_config']
        if not role_config.get(role):
            role_config[role] = dict()
        if not role_config[role].get(vim_name):
            role_config[role][vim_name] = dict()
        role_config[role][vim_name][member_dict['id']] = member_dict['vnf_id']
        self._update_cluster_attr(context, cluster_id,
                                  'role_config', role_config)

        # Attach ACTIVE cluster member in deployed load balancer
        if role == constants.CLUSTER_ACTIVE:
            lb_obj = cluster_dict['lb_info'].get(vim_name)
            if not lb_obj:
                self._update_cluster_attr(context, cluster_id,
                                          'status', constants.ERROR)
                raise vnfcluster.LoadBalancerResourceNotFound(vim=vim_name)
            cp_id = self._get_member_cp_id(context, vnfm_plugin,
                                           cluster_dict,
                                           member_dict['vnf_id'])
            if not cp_id:
                self._update_cluster_attr(context, cluster_id,
                                          'status', constants.ERROR)
                raise vnfcluster.ClusterMemberCPNotFound()

            lb_member_id = \
                self._vim_drivers.invoke(vim_obj['type'],
                                         'pool_member_add',
                                         net_port_id=cp_id,
                                         lb_info=lb_obj,
                                         auth_attr=vim_obj['auth_cred'])
            if not lb_member_id:
                self._update_cluster_attr(context, cluster_id,
                                          'status', constants.ERROR)
                raise vnfcluster.\
                    ClusterMemberAddFailed(clustermember_id=member_dict['id'])

            LOG.debug(("create lb_member_result : %s"), lb_member_id)
            self._update_member_attr(context,
                                     member_dict['id'],
                                     'lb_member_id',
                                     lb_member_id)

        if cluster_dict['status'] is constants.PENDING_UPDATE:
            cluster_dict['status'] = \
                self._update_cluster_attr(context, cluster_id,
                                          'status', constants.ACTIVE)
        return member_dict

    @log.log
    def get_clustermember(self, context, clustermember_id,
                          filters=None, fields=None):
        return self._get_member_db(context, clustermember_id, fields)

    @log.log
    def get_clustermembers(self, context, filters=None, fields=None):
        return self._get_members_db(context, filters, fields)

    @log.log
    def delete_clustermember(self, context, cluster_member_id):

        vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']
        member_id = cluster_member_id
        try:
            member = self.get_clustermember(context, member_id)
        except Exception:
            LOG.error('Cannot get resources from cluster member %s', member_id)
            raise vnfcluster.ClusterMemberNotFound(clustermember_id=member_id)

        role = member.get('role')

        vim_id = member.get('vim_id')
        vim_obj = self.get_vim(context, vim_id, mask_password=False)
        self._build_vim_auth(context, vim_obj)
        vim_name = vim_obj.get('name')

        # Check cluster deployment status
        cluster_id = member.get('cluster_id')
        cluster_dict = self.get_cluster(context, cluster_id)
        if cluster_dict['status'] == constants.ACTIVE:
            cluster_dict['status'] = \
                self._update_cluster_attr(context, cluster_id,
                                          'status', constants.PENDING_UPDATE)

        if role == constants.CLUSTER_ACTIVE:
            try:
                lb_member_id = member['lb_member_id']
                cluster_id = member['cluster_id']
                lb_info = self.get_cluster(context, cluster_id,
                                           'lb_info')['lb_info'][vim_name]
                LOG.debug('Get load balancer information: %s', lb_info)
                self._vim_drivers.invoke(vim_obj['type'],
                                         'pool_member_remove',
                                         lb_id=lb_info['lb_id'],
                                         pool_id=lb_info['pool_id'],
                                         member_id=lb_member_id,
                                         auth_attr=vim_obj['auth_cred'])
            except Exception:
                LOG.error('Load balancer resources could not be found.')

        # Update role_config in cluster
        role_config = cluster_dict.get('role_config')
        try:
            LOG.debug('Delete member %s from cluster %s',
                      member_id, cluster_id)
            del role_config[role][vim_name][member_id]
            self._update_cluster_attr(context, cluster_id,
                                      'role_config', role_config)
        except Exception:
            LOG.warning('member_id %s could not be found in role_config.',
                        member_id)

        self._delete_member_db(context, member_id)
        vnfm_plugin.delete_vnf(context, member['vnf_id'])

        if cluster_dict['status'] == constants.PENDING_UPDATE:
            cluster_dict['status'] = \
                self._update_cluster_attr(context, cluster_id,
                                          'status', constants.ACTIVE)
