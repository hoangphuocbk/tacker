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

from cryptography import fernet
from oslo_config import cfg
from oslo_log import log as logging
from kubernetes import client
from kubernetes.client import api_client

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

class KubernetesHTTPAPI(object):

    # TODO: Phuoc - will remove __init__()
    def __init__(self, k8sAPI_url=None,
                 username=None,
                 password=None,
                 bearer_token=None,
                 ca_cert=None):

        print("bearer token:", bearer_token)

        config = client.ConfigurationObject()
        config.host = k8sAPI_url
        if username and password:
            config.username = username
            config.password = password
        else:
            config.api_key_prefix['authorization'] = 'Bearer'
            config.api_key['authorization'] = bearer_token
            if ca_cert:
                config.ssl_ca_cert = ca_cert
                config.verify_ssl = True
            else:
                config.verify_ssl = False
        self.k8s_client = api_client.ApiClient(config=config)

    def get_k8sClient(self, auth_plugin):
        config = client.ConfigurationObject()
        config.host = auth_plugin['auth_url']
        if ('username' in auth_plugin) and ('password' in auth_plugin):
            config.username = auth_plugin['username']
            config.password = auth_plugin['password']
        else:
            config.api_key_prefix['authorization'] = 'Bearer'
            config.api_key['authorization'] = auth_plugin['bearer_token']
            if auth_plugin['ssl_ca_cert'] is not None:
                config.ssl_ca_cert = auth_plugin['ssl_ca_cert']
                config.verify_ssl = True
            else:
                config.verify_ssl = False
        k8s_client = api_client.ApiClient(config=config)
        return k8s_client

    def initialize_ExtensionApiClient(self, **kwargs):
        k8s_client = self.get_k8sClient(**kwargs)
        return client.ExtensionsV1beta1Api(api_client=k8s_client)

    def initialize_CoreApiV1Client(self, **kwargs):
        k8s_client = self.get_k8sClient(**kwargs)
        return client.CoreV1Api(api_client=k8s_client)

    def initialize_CoreApiClient(self, **kwargs):
        k8s_client = self.get_k8sClient(**kwargs)
        return client.CoreApi(api_client=k8s_client)

    @staticmethod
    def create_key_dir(path):
        if not os.access(path, os.F_OK):
            LOG.info('[fernet_tokens] key_repository does not appear to '
                     'exist; attempting to create it')
            try:
                os.makedirs(path, 0o700)
            except OSError:
                LOG.error(
                    'Failed to create [fernet_tokens] key_repository: either'
                    'it already exists or you don\'t have sufficient'
                    'permissions to create it')

    def create_fernet_key(self):
        fernet_key = fernet.Fernet.generate_key()
        fernet_obj = fernet.Fernet(fernet_key)
        return fernet_key, fernet_obj


    # TODO: Phuoc will remove 4 functions bellow
    def getExtensionApi(self):
        extensionApi_client = client.ExtensionsV1beta1Api(api_client=self.k8s_client)
        return extensionApi_client

    def getCoreV1Api(self):
        coreApi_client = client.CoreV1Api(api_client=self.k8s_client)
        return coreApi_client

    def getCoreApi(self):
        return client.CoreApi(api_client=self.k8s_client)

    def getK8sVersion(self):
        version = self.getCoreApi().get_api_versions().versions
        return version


def main():
    TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4taHMzY2IiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjBkNjUwNTUwLWE0NmMtMTFlNy04OGU4LTQwOGQ1Y2Q0ZmJmMSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.rFjDe3HrqXTRcf0v3nVjtTq78Hm7ltlcwiWLyQVtC4FK4QwLEoXFYZYo0k2v97bSE3030jHZaaihYsOjFHGKEZC3_K2SqkfoRywia6awkVc58TfWf45herj6IklQgEj9CA_ZPlLscO2jG1sdFZrzgyDZiONa-9jBqKhiuiq_aearwLka-mVanq6x__c2fug-LNgNTR4K7bwHnZ7kmb_G3wHTF9-kdmsij18yNQofnL2_krqLj0Mq-xBfS7C5uOpRCwrpgvWBEcAWydG4SwtQS3Ov0Ol8UDeRqkx9wlUpX85rxGcDnMuUJQXwIIHyRGI1nvIjxESQmvYQsqP68_nBrg"
    print("Gotcha")
    client1 = KubernetesHTTPAPI(k8sAPI_url='https://127.0.0.1:6443', bearer_token=TOKEN)
    print("Gotcha")
    k8s_api = client1.getCoreApi()
    print("Gotcha")
    print("K8s version:", k8s_api.get_api_versions())

if __name__ == '__main__':
    main()
