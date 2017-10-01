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

import os
import six
import yaml

from tacker.mistral import mistral_client
from tacker.common.container import  kubernetes_utils

from oslo_config import cfg
from oslo_log import log as logging

from tacker._i18n import _
from tacker.common import log
from tacker.extensions import nfvo
from tacker.keymgr import API as KEYMGR_API
from tacker.nfvo.drivers.vim import abstract_vim_driver
from tacker.nfvo.drivers.workflow import workflow_generator
from tacker.vnfm import keystone


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

KUBERNETES_OPTS = [
    cfg.StrOpt('api_url', default='https://127.0.0.1:6443',
               help=('API endpoint of Kubernetes daemon')),
    cfg.StrOpt('kubernetes_fernet_path', default='/etc/tacker/vim/kubernetes/fernet_keys',
               help='Dir.path to store fernet keys.'),
    cfg.BoolOpt('use_barbican', default=False,
                help=_('Use barbican to encrypt vim password if True, '
                       'save vim credentials in local file system '
                       'if False'))
]
cfg.CONF.register_opts(KUBERNETES_OPTS, 'k8s_vim')

def config_opts():
    return [('k8s_vim', KUBERNETES_OPTS)]

class Kubernetes_Driver(abstract_vim_driver.VimAbstractDriver):
    """Driver for Kubernetes VIM

    """

    def __init__(self):
        self.kubernetes = kubernetes_utils.KubernetesHTTPAPI()
        self.kubernetes.create_key_dir(CONF.k8s_vim.kubernetes_fernet_path)

    def get_type(self):
        return 'kubernetes'

    def get_name(self):
        return 'Kubernetes VIM Driver'

    def get_description(self):
        return 'Kubernetes VIM Driver'

    def authenticate_vim(self, vim_obj):
        """Validate VIM auth attributes

        Initialize CoreApiClient with provided authentication attributes.
        """
        auth_cred = self._get_auth_creds(vim_obj)
        return self._initialize_k8s_coreClient(auth_cred)

    def _get_auth_creds(self, vim_obj):
        auth_cred = vim_obj['auth_cred']
        auth_cred['auth_url'] = vim_obj['auth_url']
        return auth_cred

    def _initialize_k8s_extensionClient(self, auth):
        k8s_extensionClient = self.kubernetes.initialize_ExtensionApiClient(**auth)
        return k8s_extensionClient

    def _initialize_k8s_coreClient(self, auth):
        try:
            k8s_coreClient = self.kubernetes.initialize_CoreApiClient(**auth)
            k8s_info = k8s_coreClient.get_api_versions()
            LOG.info(k8s_info)
        except Exception as e:
            LOG.error(e)

    def _initialize_k8s_coreV1Client(self, auth):
        k8s_coreV1Client = self.kubernetes.initialize_CoreApiV1Client(**auth)
        return k8s_coreV1Client

    @log.log
    def register_vim(self, context, vim_obj):
        """Validate Kubernetes VIM."""

        if 'key_type' in vim_obj['auth_cred']:
            vim_obj['auth_cred'].pop(u'key_type')
        if 'secret_uuid' in vim_obj['auth_cred']:
            vim_obj['auth_cred'].pop(u'secret_uuid')

        self.authenticate_vim(vim_obj)
        self.encode_vim_auth(context, vim_obj['id'], vim_obj['auth_cred'])
        LOG.debug('VIM registration completed for %s', vim_obj)

    @log.log
    def deregister_vim(self, context, vim_obj):
        """Deregister Kubernetes VIM from NFVO

        Delete VIM keys from file system
        """
        self.delete_vim_auth(context, vim_obj['id'], vim_obj['auth_cred'])

    @log.log
    def delete_vim_auth(self, context, vim_id, auth):
        """Delete kubernetes vim information

        Delete vim key stored in file system
        """
        LOG.debug('Attempting to delete key for vim id %s', vim_id)

        if auth.get('key_type') == 'barbican_key':
            try:
                keystone_conf = CONF.keystone_authtoken
                secret_uuid = auth['secret_uuid']
                keymgr_api = KEYMGR_API(keystone_conf.auth_url)
                keymgr_api.delete(context, secret_uuid)
                LOG.debug('VIM key deleted successfully for vim %s',
                          vim_id)
            except Exception as ex:
                LOG.warning('VIM key deletion failed for vim %s due to %s',
                            vim_id,
                            ex)
                raise
        else:
            key_file = os.path.join(CONF.k8s_vim.kubernetes_fernet_path, vim_id)
            try:
                os.remove(key_file)
                LOG.debug('VIM key deleted successfully for vim %s',
                          vim_id)
            except OSError:
                LOG.warning('VIM key deletion failed for vim %s',
                            vim_id)

    @log.log
    def encode_vim_auth(self, context, vim_id, auth):
        """Encode VIM credentials

         Store VIM auth using fernet key encryption
         """
        fernet_key, fernet_obj = self.kubernetes.create_fernet_key()
        if 'password' in auth:
            encoded_auth = fernet_obj.encrypt(auth['password'].encode('utf-8'))
            auth['password'] = encoded_auth
        elif 'bearer_token' in auth:
            encoded_auth = fernet_obj.encrypt(auth['bearer_token'].encode('utf-8'))
            auth['bearer_token'] = encoded_auth

        if CONF.k8s_vim.use_barbican:
            try:
                keystone_conf = CONF.keystone_authtoken
                keymgr_api = KEYMGR_API(keystone_conf.auth_url)
                secret_uuid = keymgr_api.store(context, fernet_key)

                auth['key_type'] = 'barbican_key'
                auth['secret_uuid'] = secret_uuid
                LOG.debug('VIM auth successfully stored for vim %s',
                          vim_id)
            except Exception as ex:
                LOG.warning('VIM key creation failed for vim %s due to %s',
                            vim_id,
                            ex)
                raise

        else:
            auth['key_type'] = 'fernet_key'
            key_file = os.path.join(CONF.k8s_vim.kubernetes_fernet_path, vim_id)
            try:
                with open(key_file, 'w') as f:
                    if six.PY2:
                        f.write(fernet_key.decode('utf-8'))
                    else:
                        f.write(fernet_key)
                    LOG.debug('VIM auth successfully stored for vim %s',
                              vim_id)
            except IOError:
                raise nfvo.VimKeyNotFoundException(vim_id=vim_id)

    def get_mistral_client(self, auth_dict):
        if not auth_dict:
            LOG.warning("auth dict required to instantiate mistral client")
            raise EnvironmentError('auth dict required for'
                                   ' mistral workflow driver')
        return mistral_client.MistralClient(
            keystone.Keystone().initialize_client('2', **auth_dict),
            auth_dict['token']).get_client()

    def prepare_and_create_workflow(self, resource, action,
                                    kwargs, auth_dict=None):
        mistral_client = self.get_mistral_client(auth_dict)
        wg = workflow_generator.WorkflowGenerator(resource, action)
        wg.task(**kwargs)
        if not wg.get_tasks():
            raise nfvo.NoTasksException(resource=resource, action=action)
        definition_yaml = yaml.safe_dump(wg.definition)
        workflow = mistral_client.workflows.create(definition_yaml)
        return {'id': workflow[0].id, 'input': wg.get_input_dict()}

    def execute_workflow(self, workflow, auth_dict=None):
        return self.get_mistral_client(auth_dict)\
            .executions.create(
                workflow_identifier=workflow['id'],
                workflow_input=workflow['input'],
                wf_params={})

    def get_execution(self, execution_id, auth_dict=None):
        return self.get_mistral_client(auth_dict)\
            .executions.get(execution_id)

    def delete_execution(self, execution_id, auth_dict=None):
        return self.get_mistral_client(auth_dict).executions\
            .delete(execution_id)

    def delete_workflow(self, workflow_id, auth_dict=None):
        return self.get_mistral_client(auth_dict)\
            .workflows.delete(workflow_id)
