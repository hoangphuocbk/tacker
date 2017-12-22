..
  Licensed under the Apache License, Version 2.0 (the "License"); you may
  not use this file except in compliance with the License. You may obtain
  a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
  License for the specific language governing permissions and limitations
  under the License.

======================
VNF Clustering service
======================

This document describes how to use clustering service in Tacker.

Sample configuration templates for cluster deployment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example shows cluster deployment using VNFD and policy template.
The target in this example need to be the cluster deployment with pre-defined
cluster nodes. Besides, the cluster nodes should be recovered in the event of
failure.
The VNFD with *recovery* action that is described firstly in
**tosca-vnfd-cluster.yaml** file like other TOSCA templates in Tacker.

.. code-block:: yaml

    tosca_definitions_version: tosca_simple_profile_for_nfv_1_0_0

    description: Demo example for VNF cluster deployment
    metadata:
      template_name: sample-tosca-vnfd-cluster

    topology_template:
      node_templates:
        VDU1:
          type: tosca.nodes.nfv.VDU.Tacker
          capabilities:
            nfv_compute:
              properties:
                num_cpus: 1
                mem_size: 256 MB
                disk_size: 1 GB
          properties:
            image: cirros-0.3.5-x86_64-disk
            availability_zone: nova
            mgmt_driver: noop
            monitoring_policy:
              name: ping
              parameters:
                monitoring_delay: 45
                count: 3
                interval: 1
                timeout: 2
              actions:
                failure: recovery
            config: |
              param0: key1
              param1: key2

        CP1:
          type: tosca.nodes.nfv.CP.Tacker
          properties:
            management: true
            order: 0
            anti_spoofing_protection: true
          requirements:
            - virtualLink:
                node: VL1
            - virtualBinding:
                node: VDU1
        CP2:
          type: tosca.nodes.nfv.CP.Tacker
          properties:
            order: 1
            anti_spoofing_protection: true
          requirements:
            - virtualLink:
                node: VL2
            - virtualBinding:
                node: VDU1
        VL1:
          type: tosca.nodes.nfv.VL
          properties:
            network_name: net_mgmt
            vendor: Tacker
        VL2:
          type: tosca.nodes.nfv.VL
          properties:
            network_name: net0
            vendor: Tacker

Monitoring driver already supported the some default backend actions like
**scaling, respawn, log, and log_and_kill**. However, these mentioned actions
only useful with the individual deployed VNFs. In this work, we implement a
new action name **recovery** with the purpose of enabling high availability for
VNFs in deployed cluster. **recovery** action will be triggered in the event of
disconnection of cluster nodes from VNFM.

On the other hand, Tacker users need to figure out how many cluster nodes
will be deployed and which role they should be assigned during deployment.
Those kinds of configuration are shown in **cluster_policy_sample.yaml** file
as bellow:

.. code-block:: yaml

    properties:
      role:
        active:
          VIM0: 1
        standby: 1
      load_balancer:
        vip:
          subnet: subnet0
          vip_address: 10.10.0.100
        listener:
          connection_litmit: 10
          protocol: HTTP
          protocol_port: 80
        pool:
          lb_algorithm: ROUND_ROBIN
        target: CP2
        lb_deployment_timeout: 200

* The aboved sample is an encapsulation of role and load_balancer configuration
  that figure out how many cluster member will be included and how LBaaS v2
  service are configured to distribute the network load evenly among members in
  a pool:

 * In role configuration, the mentioned **VIM0** is configured as default VIM.
   If the VIM is not specified for active or standby, the default VIM will be
   used.
 * Normally, users are  not stay on top of the details of load balancer
   implementation, but they still have a requirement of features provided by
   LBaaS service. Then this template also include load_balancer configuration
   that follows the interface and properties provided by the LBaaS v2 service.
   Tacker will pass these configuration to Neutron client in order to deploy load
   balancer. A sample of load_balancer policy is shown as above. There are many
   configuration and most of them have already set with reseanable default
   values, except the following few:

  * **load_balancer.vip.subnet**: the name or ID of the subnet for the port on
    which the virtual IP is allocated.
  * **load_balancer.pool.subnet**: the name or ID of the subnet for the port on
    which VNFs can be connected.
  * **load_balancer.target**: The name of connection point that VNF will use to
    connect to load balancer. Note that, **target** must match with the name of
    connection point from included VNFs, this connection point wil be used to
    attach cluster nodes to neutron load balancer during cluster deployment. In
    this example, **CP2** will be used to attach created VNFs into load
    balancer.

The following describe properties and general rules on using the predefined
parameter. Note that this patch is not support load balancer creation and
configuration by yourself. Load balancer will be deployed automatically via
load_balancer property in this template and you no longer have to manage the
load balancer lifecycle, and you no need to update load balancer configuration
whenever cluster membership updates.

 * **load_balancer.vip**: is the IP address visible from client side. Clients
   also use this address to access service from clustering member.

  * subnet: the name or ID of the subnet for the port on which the virtual IP
    is allocated. You have to specify the vip.subnet property even though the
    actual vip.vip_address is obmitted.
  * vip_address: If you want to assign a specify VIP address to use, you will
    need to declare this address in this parameter. In the case of vip_address
    is obmitted, the LBaaS service will randomize an address from the assigned
    subnet.

 * **load_balancer.listener**:

  * connection_litmit: This is a feature provided by the LBaaS service that
    check the maximum number of connections per VIP, per second. By default,
    this limitation will be set to -1 which means there is no upper threshold
    for the number of connections.
  * protocol: Each load balancer is configured to use the same protocol. By
    default, the listener.protocol is set to **HTTP** which could be changed to
    **TCP** or **HTTPS** or **TERMINATED_HTTPS**.
  * protocol_port: Each load balancer is configured to use the same port number
    for load balancing. The default listener.protocol_port is **80**, which
    also could be changes to match with your running service configuration.

 * **load_balancer.pool**:

  * lb_algorithm: LBaaS service is capable of load balance among members in
    different ways which are specified in lb_algorithm. There are some valid
    configuration for this property:

   * ROUND_ROBIN: The workload is distributed base on a round-robim basis.
     Each member gets an equal pressure to handle incomming workloads.
   * LEAST_CONNECTIONS: The member with the lowest nunber of connections will
     be chosen by load balancer.
   * SOURCE_IP: The IP address of client and server are stored in form of
     hash value for routing. This ensures the request from the same client
     always go to the same server.

 * **load_balancer.lb_deployment_timeout**: The creation of load balancers,
   updating load balancer configuration all take considerable time. In some
   environment, it might take several minutes to make load balancer become
   operative again. You are expected to set this value based on some careful
   dry-runs. The default value is 200 seconds.

The deployment of VNF cluster in Tacker could be done with the following steps

* Ensure that **VIM0** is registerd VIM in Tacker. Tacker user could check a
  list of registerd VIMs by using:

 .. code-block:: console

    tacker vim-list

* VNFD creation from **tosca-vnfd-cluster.yaml** file

 .. code-block:: console

    tacker vnfd-create --vnfd-file tosca-vnfd-cluster.yaml vnfd-cluster

* Cluster deployment from **vnfd-cluster** and **cluster_policy_sample.yaml**

 .. code-block:: console

    tacker cluster-create --vnfd-name vnfd-cluster --policy-file cluster_policy_sample.yaml cluster-sample

* Cluster deployment results

 .. code-block:: console

    tacker cluster-list
    +--------------------------------------+----------------+--------------------------------------+--------+---------------------+
    | id                                   | name           | vnfd_id                              | status | vip_endpoint        |
    +--------------------------------------+----------------+--------------------------------------+--------+---------------------+
    | 075ec909-20ca-4bba-a350-53026d01d886 | cluster-sample | ea4e01db-4511-4273-b22c-9e6e59af97e6 | ACTIVE | {u'10.10.0.12': 80} |
    +--------------------------------------+----------------+--------------------------------------+--------+---------------------+

 .. code-block:: console

    tacker cluster-member-list --cluster-id 075ec909-20ca-4bba-a350-53026d01d886
    +--------------------------------------+----------------------------------------------+--------------------------------------+---------+--------------------------------------+--------------------------------------+----------------------------+--------------------------------------+
    | id                                   | name                                         | cluster_id                           | role    | vnf_id                               | vim_id                               | mgmt_url                   | lb_member_id                         |
    +--------------------------------------+----------------------------------------------+--------------------------------------+---------+--------------------------------------+--------------------------------------+----------------------------+--------------------------------------+
    | 2a64ba4c-3c8b-481e-9aff-b131ff6eedd2 | STANDBY-d1802a60-00f1-4529-8cf3-db0f649d5f40 | 075ec909-20ca-4bba-a350-53026d01d886 | STANDBY | 2b909422-0378-4945-bf65-974b28a2061f | 6b9225a0-ad7e-4b3a-8171-c4b4e0249cd9 | {"VDU1": "192.168.120.13"} |                                      |
    | 84fc60c0-c8d9-4196-bfb8-45fa766cea0c | ACTIVE-8a3b296d-c289-472e-9e3d-1c3bfebd399d  | 075ec909-20ca-4bba-a350-53026d01d886 | ACTIVE  | 1e7d490b-5a70-4cee-b3bd-6304117a7d0a | 6b9225a0-ad7e-4b3a-8171-c4b4e0249cd9 | {"VDU1": "192.168.120.10"} | b0d02426-1991-4f0c-a93e-93721dc25782 |
    +--------------------------------------+----------------------------------------------+--------------------------------------+---------+--------------------------------------+--------------------------------------+----------------------------+--------------------------------------+

* Add a new ACTIVE node into cluster **cluster-sample**. This command will:

 * Deploy a new VNF from VNFD **vnfd-cluster**
 * Attach a new VNF to cluster in form of ACTIVE node

 .. code-block:: console

    tacker cluster-member-add --vnfd-name vnfd-cluster --role active --cluster-name cluster-sample new-active

* Add a new STANDBY node into cluster **cluster-sample**. This command will:

 * Deploy a new VNF from VNFD **vnfd-cluster**
 * Attach a new VNF to cluster in form of STANDBY node

 .. code-block:: console

    tacker cluster-member-add --vnfd-name vnfd-cluster --role standby --cluster-name cluster-sample new-standby

The deletion of VNF cluster in Tacker could be done with the following

 .. code-block:: console

    tacker cluster-delete cluster-sample

How to setup environment
~~~~~~~~~~~~~~~~~~~~~~~~

If Devstack is used to test clustering service in Tacker, neutron-lbaas and
octavia plugins will need to be enabled in local.conf:

 .. code-block:: ini

    enable_plugin neutron-lbaas https://github.com/openstack/neutron-lbaas.git master
    enable_plugin octavia https://github.com/openstack/octavia.git master
    ENABLED_SERVICES+=,q-lbaasv2
    ENABLED_SERVICES+=,octavia,o-cw,o-hk,o-hm,o-api

    [[post-config|/$NOVA_CONF]]
    [libvirt]
    hw_machine_type = "x86_64=pc-i440fx-xenial,i686=pc-i440fx-xenial"

    [[post-config|/$NOVA_CPU_CONF]]
    [libvirt]
    hw_machine_type = "x86_64=pc-i440fx-xenial,i686=pc-i440fx-xenial"

To make ensure that load balancing service is working well in your system.
You could check the following doc for more detail:

 .. code-block:: console

    https://docs.openstack.org/octavia/latest/contributor/guides/dev-quick-start.html

How to recovery cluster node with recovery action
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All of cluster nodes are monitored under the monitoring driver that is declared
in VNFD. In this case, **ping** has been choosen as monitoring driver. Hence,
if we want to trigger **recovery** action, we just need to disconnect VNF from
VNFM. In particular, we delete a neutron-port from VNF.

Then, in order to trigger **recovery** action in deployed cluster, Tacker users
could use CLI. In the following example, we show how to trigger **recovery**
action from **ACTIVE** node in cluster **cluster-sample**

* To get the cluster deployment information

 .. code-block:: console

    #Set cluster name and role of member is **ACTIVE**
    cluster_name=cluster-sample
    member_role=ACTIVE

    #Get cluster_id from a lits of deployed cluster
    cluster_id=$(tacker cluster-list | grep $cluster_name | grep ACTIVE | awk '{print $2}')

* To delete neutron-port from VM that associate with **ACTIVE** node

 .. code-block:: console

    #Get management IP of cluster-member whose role is ACTIVE
    mgmt_ip=$(tacker cluster-member-list -c mgmt_url -c cluster_id -c role | grep $cluster_id | grep $member_role | awk -F'\"' '{print $4}')

    #Get openstack port ID of cluster-member
    port_id=$(openstack port list | grep $mgmt_ip | awk '{print $2}')

    #Delete openstack port
    openstack port set $port_id --device-owner none
    openstack port delete $port_id

**NOTE**:Another way could be used to trigger **recovery** action is:

* Tacker users login the VNF with user/password or SSH
* Turn off the network interface that associated with mgmt_url in Tacker

Then, users can use **tacker cluster-member-list** to know if cluster node is
recovered.

 .. code-block:: console

    tacker cluster-member-list --cluster-id 075ec909-20ca-4bba-a350-53026d01d886
    +--------------------------------------+----------------------------------------------+--------------------------------------+---------+--------------------------------------+--------------------------------------+----------------------------+--------------------------------------+
    | id                                   | name                                         | cluster_id                           | role    | vnf_id                               | vim_id                               | mgmt_url                   | lb_member_id                         |
    +--------------------------------------+----------------------------------------------+--------------------------------------+---------+--------------------------------------+--------------------------------------+----------------------------+--------------------------------------+
    | 2a64ba4c-3c8b-481e-9aff-b131ff6eedd2 | STANDBY-d1802a60-00f1-4529-8cf3-db0f649d5f40 | 075ec909-20ca-4bba-a350-53026d01d886 | ACTIVE  | 2b909422-0378-4945-bf65-974b28a2061f | 6b9225a0-ad7e-4b3a-8171-c4b4e0249cd9 | {"VDU1": "192.168.120.13"} | c7051124-004d-4936-b0cb-0398f1c1c873 |
    | 59b88800-edde-4308-b6f6-f261ca9a1d78 | STANDBY-bbd0c481-9883-40bf-a5d0-d9bb9dfe3a6b | 075ec909-20ca-4bba-a350-53026d01d886 | STANDBY | 37a99680-0506-4f30-b693-b34f46b6d5bd | 6b9225a0-ad7e-4b3a-8171-c4b4e0249cd9 | {"VDU1": "192.168.120.14"} |                                      |
    +--------------------------------------+----------------------------------------------+--------------------------------------+---------+--------------------------------------+--------------------------------------+----------------------------+--------------------------------------+

From the **tacker cluster-member-list** result, it is easy to observe that

* **STANDBY-d1802a60-00f1-4529-8cf3-db0f649d5f40** has changed to **ACTIVE**

* Tacker deployed **STANDBY-bbd0c481-9883-40bf-a5d0-d9bb9dfe3a6b** as a new
  **STANDBY**

* **ACTIVE-8a3b296d-c289-472e-9e3d-1c3bfebd399d** has been deleted after
  disconnecting from VNFM.

Known Issues and Limitations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Only suport cluster deployment onto single VIM. Multi-vim based deployment
  is not statble now.

* Currently, recovery_action is only triggred if and only if the deployed VNF
  is disconnected from monitoring drivrer. There is no manual recovery
  interface for the end users

* In current state, when Tacker users request add a new node into cluster,
  Tacker will request to deploy a new VNF from vnfd. Tacker is not support
  to add an existing VNF in to created cluster
