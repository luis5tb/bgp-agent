# Copyright 2021 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import sys
import time

from oslo_concurrency import processutils
import pyroute2
from pyroute2.netlink.rtnl import ndmsg

from bgp_agent import constants
from bgp_agent.utils import ovn
from bgp_agent.utils import ovs
from bgp_agent.events import osp_events

# import logging
# LOG = logging.getLogger(__name__)
# LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)


def start():
    """Main method for listening to VM adverticing events.
    """
    # set to True to also add ip rules, which avoids the need for
    # learning bgp routes on the compute nodes
    use_rules = True
    # expose tenant networks is only supported if use_rules is enabled
    expose_tenant_networks = True
    agt = BGPAgent()
    agt.start(use_rules, expose_tenant_networks)


class BGPAgent(object):

    def start(self, use_rules=False, expose_tenant_networks=True):
        print("Starting BGP Agent...")
        self._use_rules = use_rules
        self._expose_tenant_networks = expose_tenant_networks
        self.ovn_routing_tables = {}  # {'br-ex': 200}
        self.ovn_bridge_mappings = {}  # {'public': 'br-ex'}
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = []

        self.ovs_idl = ovs.OvsIdl().start(constants.OVS_CONNECTION_STRING)
        self._load_config()

        tables = ('Port_Binding', 'Datapath_Binding', 'SB_Global',
                  'Chassis')
        if self._expose_tenant_networks:
            events = (osp_events.PortBindingChassisCreatedEvent(self),
                    osp_events.PortBindingChassisDeletedEvent(self),
                    osp_events.FIPSetEvent(self),
                    osp_events.FIPUnsetEvent(self),
                    osp_events.SubnetRouterAttachedEvent(self),
                    osp_events.SubnetRouterDetachedEvent(self),
                    osp_events.TenantPortCreatedEvent(self),
                    osp_events.TenantPortDeletedEvent(self))
        else:
            events = (osp_events.PortBindingChassisCreatedEvent(self),
                      osp_events.PortBindingChassisDeletedEvent(self),
                      osp_events.FIPSetEvent(self),
                      osp_events.FIPUnsetEvent(self))

        self.has_chassis_private = False
        try:
            self.sb_idl = ovn.OvnSbIdl(
                self.ovn_remote,
                chassis=self.chassis,
                tables=tables + ('Chassis_Private', ),
                events=events + (osp_events.ChassisPrivateCreateEvent(self), )).start()
            self.has_chassis_private = True
        except AssertionError:
            self.sb_idl = ovn.OvnSbIdl(
                self.ovn_remote,
                chassis=self.chassis,
                tables=tables,
                events=events + (osp_events.ChassisCreateEvent(self), )).start()

        print("BGP Agent Started...")
        # Do the initial sync.
        self.sync()

        while True:
            time.sleep(1)

    def _load_config(self):
        self.chassis = self._get_own_chassis_name()
        self.ovn_remote = self._get_ovn_remote()
        print("Loaded chassis {}.".format(self.chassis))

    def _get_own_chassis_name(self):
        """Return the external_ids:system-id value of the Open_vSwitch table.

        As long as ovn-controller is running on this node, the key is
        guaranteed to exist and will include the chassis name.
        """
        ext_ids = self.ovs_idl.db_get(
            'Open_vSwitch', '.', 'external_ids').execute()
        return ext_ids['system-id']

    def _get_ovn_remote(self):
        """Return the external_ids:ovn-remote value of the Open_vSwitch table.

        """
        ext_ids = self.ovs_idl.db_get(
            'Open_vSwitch', '.', 'external_ids').execute()
        return ext_ids['ovn-remote']

    def _get_ovn_bridge_mappings(self):
        """Return the external_ids:ovn-bridge-mappings value of the Open_vSwitch table.

        """
        ext_ids = self.ovs_idl.db_get(
            'Open_vSwitch', '.', 'external_ids').execute()
        return ext_ids['ovn-bridge-mappings'].split(",")

    def _ovs_cmd(self, command, args, timeout=None):
        full_args = [command]
        if timeout is not None:
            full_args += ['--timeout=%s' % timeout]
        full_args += args
        try:
            return processutils.execute(*full_args, run_as_root=True)
        except Exception as e:
            print("Unable to execute {} {}. Exception: {}".format(
                command, full_args, e))
            raise

    def _ensure_vrf(self, vrf_name, vrf_table):
        ipdb = pyroute2.IPDB()
        try:
            with ipdb.interfaces[vrf_name] as vrf:
                if vrf.state != "up":
                    vrf.up()
        except KeyError:
            with ipdb.create(kind="vrf",
                             ifname=vrf_name,
                             vrf_table=vrf_table) as vrf:
                vrf.up()

    def _ensure_ovn_device(self, ovn_ifname, vrf_name):
        ipdb = pyroute2.IPDB()
        ip = pyroute2.IPRoute()
        try:
            with ipdb.interfaces[ovn_ifname] as iface:
                if iface.state != "up":
                    iface.up()
        except KeyError:
            with ipdb.create(kind="dummy",
                             ifname=ovn_ifname) as iface:
                iface.up()
        # Associate device to VRF
        ovn_nic_index = ip.link_lookup(ifname=ovn_ifname)[0]
        ovn_nic = ip.link("get", index=ovn_nic_index)[0]
        # Check if already associated to a vrf, and associate it if not
        if not ovn_nic.get_attr("IFLA_MASTER"):
            with ipdb.interfaces[vrf_name] as vrf:
                vrf.add_port(ovn_nic_index)

    def _ensure_routing_table_for_bridge(self, bridge):
        # check a routing table with the bridge name exists on
        # /etc/iproute2/rt_tables
        regex = '^[0-9]*[\s]*{}$'.format(bridge)
        matching_table = [line.replace('\t', ' ')
                            for line in open('/etc/iproute2/rt_tables')
                            if re.findall(regex, line)]
        if matching_table:
            table_info = matching_table[0].strip().split()
            self.ovn_routing_tables[table_info[1]] = int(table_info[0])
            print("Found routing table for {} with: {}".format(bridge,
                    table_info))
        # if not raise configuration error and exit
        else:
            print(("Routing table for bridge {} must be configure "
                    "at /etc/iproute2/rt_tables").format(bridge))
            sys.exit()

        # add default route on that table if it does not exist
        ipdb = pyroute2.IPDB()
        try:
            table_route = ipdb.routes.tables[
                self.ovn_routing_tables[bridge]]
        except KeyError:  # if there is no rules, ipdb returns KeyError
            ipdb.routes.add(dst='default',
                            oif=ipdb.interfaces[bridge].index,
                            table=self.ovn_routing_tables[bridge]
                            ).commit()
        else:
            rule_missing = True
            for rule in table_route:
                if (rule['dst'] == 'default' and
                        ipdb.interfaces[rule['oif']].ifname == bridge):
                    rule_missing = False
                else:
                    with rule as r:
                        r.remove()
            if rule_missing:
                ipdb.routes.add(dst='default',
                                oif=ipdb.interfaces[bridge].index,
                                table=self.ovn_routing_tables[bridge]
                                ).commit()

    def sync(self):
        ipdb = pyroute2.IPDB()
        ip = pyroute2.IPRoute()
        print("Ensuring VRF configuration for advertising routes")
        # Create VRF
        self._ensure_vrf(constants.OVN_BGP_VRF, constants.OVN_BGP_VRF_TABLE)
        # Create OVN dummy device
        self._ensure_ovn_device(constants.OVN_BGP_NIC, constants.OVN_BGP_VRF)

        print("Configuring br-ex default rule and routing tables for each "
              "provider network")
        flows_info = {}
        # 1) Get bridge mappings: xxxx:br-ex,yyyy:br-ex2
        bridge_mappings = self._get_ovn_bridge_mappings()
        # 2) Get macs for bridge mappings
        for bridge_mapping in bridge_mappings:
            network = bridge_mapping.split(":")[0]
            bridge = bridge_mapping.split(":")[1]
            self.ovn_bridge_mappings[network] = bridge
            if self._use_rules:
                self._ensure_routing_table_for_bridge(bridge)

            with ipdb.interfaces[bridge] as iface:
                flows_info[bridge] = {'mac': iface.address}
            # 3) Get in_port for bridge mappings (br-ex, br-ex2)
            ovs_port = self._ovs_cmd('ovs-vsctl',
                                     ['list-ports', bridge])[0].rstrip()
            if ovs_port:
                ovs_ofport = self._ovs_cmd(
                    'ovs-vsctl',
                    ['get', 'Interface', ovs_port, 'ofport'])[0].rstrip()
                flows_info[bridge]['in_port'] = ovs_ofport
        # 4) Add flows for each bridge mappings
        for bridge, info in flows_info.items():
            if info.get('in_port'):
                flow = ("cookie={},priority=1000,ip,in_port={},"
                        "actions=mod_dl_dst:{},NORMAL".format(
                           constants.OVS_RULE_COOKIE, info['in_port'],
                           info['mac']))
                self._ovs_cmd('ovs-ofctl', ['add-flow', bridge, flow])

        print("Sync current routes.")
        # get all the ips on ovn dev
        exposed_ips = []
        with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
            exposed_ips = [ip[0] for ip in iface.ipaddr
                           if ip[1] == 32 or ip[1] == 128]
        # get the rules pointing to ovn bridges
        created_ip_rules = {}
        if self._use_rules:
            for table in self.ovn_routing_tables.values():
                for rule in ip.get_rules(table=table):
                    dst = rule.get_attrs('FRA_DST')[0]
                    mask = rule['dst_len']
                    created_ip_rules[dst] = {'table': table, 'mask': mask}

        # add missing routes/ips for fips/provider VMs
        ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        for port in ports:
            if port.type not in constants.OVN_VIF_PORT_TYPES:
                continue
            if (len(port.mac[0].split(' ')) != 2 and
                    len(port.mac[0].split(' ')) != 3):
                continue
            port_ip = port.mac[0].split(' ')[1]
            ip_address = port_ip.split("/")[0]
            self.add_bgp_route(port_ip, port)
            if ip_address in exposed_ips:
                # remove each ip to add from the list of current ips on dev OVN
                exposed_ips.remove(ip_address)
            if (ip_address in created_ip_rules.keys() and
                    self._use_rules):
                del created_ip_rules[ip_address]
        # add missing route/ips for tenant network VMs
        if self._use_rules and self._expose_tenant_networks:
            for cr_lrp_info in self.ovn_local_cr_lrps.values():
                lrp_ports = self.sb_idl.get_lrp_ports_for_router(
                    cr_lrp_info['router_datapath'])
                for lrp in lrp_ports:
                    if lrp.chassis:
                        continue
                    try:
                        lrp_ip = lrp.mac[0].split(' ')[1]
                    except IndexError:
                        continue
                    if lrp_ip.split('/')[0] == cr_lrp_info['ip']:
                        continue
                    self.ovn_local_lrps.append(lrp)
                    self._add_ip_rule(lrp_ip,
                                      cr_lrp_info['provider_datapath'])
                    lrp_network = self.sb_idl.get_port_datapath(
                        lrp.options['peer'])
                    if lrp_network:
                        network_ports = self.sb_idl.get_ports_on_datapath(
                            lrp_network)
                        for port in network_ports:
                            if port.type != "":
                                continue
                            try:
                                ip_address = port.mac[0].split(' ')[1]
                            except IndexError:
                                continue
                            with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
                                iface.add_ip('%s/%s' % (ip_address, 32))
                            if ip_address in exposed_ips:
                                exposed_ips.remove(ip_address)
                            if ip_address in created_ip_rules.keys():
                                del created_ip_rules[ip_address]

        # remove extra routes/ips
        # remove all the leftovers on the list of current ips on dev OVN
        with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
            for ip in exposed_ips:
                # TODO: add ipv6 support
                iface.del_ip(ip, 32)
        # remove all the leftovers on the list of current ip rules for ovn
        # bridges
        for rule_ip, rule_info in created_ip_rules.items():
            rule = {'dst': '{}/{}'.format(rule_ip, rule_info['mask']),
                    'table': rule_info['table']}
            ip.rule('del', **rule)

    def add_bgp_route(self, ip_address, row):
        '''Advertice BGP route by adding IP to device.

        This methods ensures BGP advertises the IP of the VM in the provider
        network, or the FIP associated to a VM in a tenant networks.

        It relies on Zebra, which creates and advertises a route when an IP
        is added to a local interface.

        This method assumes a device named self.ovn_decice exists (inside a
        VRF), and adds the IP of either:
        - VM IP on the provider network,
        - VM FIP, or
        - CR-LRP OVN port
        '''
        # TODO: add ipv6 support
        if row.type == "" and self.sb_idl.is_provider_network(row.datapath):
            print("Add BGP route for logical port with ip {}".format(
                  ip_address))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
                iface.add_ip('%s/%s' % (ip_address, 32))
            if self._use_rules:
                self._add_ip_rule(ip_address, row.datapath)

        # VM with FIP
        elif row.type == "":
            fip_address, fip_datapath = self.sb_idl.get_fip_associated(
                row.logical_port)
            if fip_address:
                print("Add BGP route for FIP with ip {}".format(fip_address))
                ipdb = pyroute2.IPDB()
                with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
                    iface.add_ip('%s/%s' % (fip_address, 32))
                if self._use_rules:
                    self._add_ip_rule(fip_address, fip_datapath)

        # CR-LRP Port
        elif (row.type == "chassisredirect" and
              row.logical_port.startswith('cr-')):
            cr_lrp_address, cr_lrp_datapath = self.sb_idl.get_fip_associated(
                row.logical_port)
            if cr_lrp_address:
                print("Add BGP route for CR-LRP Port {}".format(
                    ip_address.split("/")[0]))
                # Keeping information about the associated network for
                # tenant network advertisement
                self.ovn_local_cr_lrps[row.logical_port] = {
                    'router_datapath': row.datapath,
                    'provider_datapath': cr_lrp_datapath,
                    'ip': cr_lrp_address
                }
                ipdb = pyroute2.IPDB()
                with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
                    iface.add_ip('%s/%s' % (cr_lrp_address, 32))
                if self._use_rules:
                    self._add_ip_rule(cr_lrp_address, cr_lrp_datapath,
                                      lladdr=row.mac[0].split(' ')[0])

    def delete_bgp_route(self, ip_address, row):
        '''Withdraw BGP route by removing IP from device.

        This methods ensures BGP withdraw an advertised IP of a VM, either
        in the provider network, or the FIP associated to a VM in a tenant
        networks.

        It relies on Zebra, which withdraws the advertisement as soon as the
        IP is deleted from the local interface.

        This method assumes a device named self.ovn_decice exists (inside a
        VRF), and removes the IP of either:
        - VM IP on the provider network,
        - VM FIP, or
        - CR-LRP OVN port
        '''
        if row.type == "" and self.sb_idl.is_provider_network(row.datapath):
            print("Delete BGP route for logical port with ip {}".format(
                  ip_address))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
                iface.del_ip('%s/%s' % (ip_address, 32))
            if self._use_rules:
                self._del_ip_rule(ip_address, row.datapath)
        # VM with FIP
        elif row.type == "":
            fip_address, fip_datapath = self.sb_idl.get_fip_associated(
                row.logical_port)
            if fip_address:
                print("Delete BGP route for FIP with ip {}".format(
                      fip_address))
                ipdb = pyroute2.IPDB()
                with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
                    iface.del_ip('%s/%s' % (fip_address, 32))
                if self._use_rules:
                    self._del_ip_rule(fip_address, fip_datapath)
        elif (row.type == "chassisredirect" and
              row.logical_port.startswith('cr-')):
            cr_lrp_ip = '{}/32'.format(ip_address.split("/")[0])
            cr_lrp_datapath = self.ovn_local_cr_lrps.get(
                row.logical_port, {}).get('provider_datapath')
            if cr_lrp_datapath:
                print("Delete BGP route for CR-LRP Port {}".format(
                    cr_lrp_ip))
                # Removing information about the associated network for
                # tenant network advertisement
                del self.ovn_local_cr_lrps[row.logical_port]
                ipdb = pyroute2.IPDB()
                with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
                    iface.del_ip(cr_lrp_ip)
                if self._use_rules:
                    self._del_ip_rule(cr_lrp_ip, cr_lrp_datapath,
                                      lladdr=row.mac[0].split(' ')[0])

    def add_bgp_fip_route(self, nat, datapath):
        # NOTE: Works the same as add_bgp_route. However as there is an option
        # associate/disassociate FIPs from VMs, and that won't trigger a
        # PortBinding event, we need to handled it with a different notifier
        # and check if the VM is in the local chassis where the agent is run,
        # e.g:"fa:16:3e:70:ad:b1 172.24.4.176
        # is_chassis_resident(\"0c60373b-b770-4946-8bb4-38b5dce99308\")"
        port = nat.split(" ")[2].split("\"")[1]
        if self.sb_idl.is_port_on_chasis(port, self.chassis):
            fip_address = nat.split(" ")[1]
            print("Add BGP route for FIP with ip {}".format(fip_address))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
                iface.add_ip('%s/%s' % (fip_address, 32))

            if self._use_rules:
                self._add_ip_rule(fip_address, datapath)

    def delete_bgp_fip_route(self, nat, datapath):
        # example: "fa:16:3e:70:ad:b1 172.24.4.176
        # is_chassis_resident(\"0c60373b-b770-4946-8bb4-38b5dce99308\")"
        port = nat.split(" ")[2].split("\"")[1]
        if self.sb_idl.is_port_on_chasis(port, self.chassis):
            fip_address = nat.split(" ")[1]
            print("Delete BGP route for FIP with ip {}".format(fip_address))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
                iface.del_ip('%s/%s' % (fip_address, 32))

            if self._use_rules:
                self._del_ip_rule(fip_address, datapath)

    def add_subnet_bgp_route(self, ip_address, datapath):
        port_lrp = self.sb_idl.get_lrp_port_for_datapath(datapath)
        if port_lrp in self.ovn_local_lrps:
            print("Add BGP route for tenant IP {} on chassis {}".format(
                ip_address, self.chassis))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
                iface.add_ip('%s/%s' % (ip_address, 32))

    def del_subnet_bgp_route(self, ip_address, datapath):
        port_lrp = self.sb_idl.get_lrp_port_for_datapath(datapath)
        if port_lrp in self.ovn_local_lrps:
            print("Delete BGP route for tenant IP {} on chassis {}".format(
                ip_address, self.chassis))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[constants.OVN_BGP_NIC] as iface:
                iface.del_ip('%s/%s' % (ip_address, 32))

    def add_subnet_rules(self, ip_address, logical_port, datapath):
        cr_lrp = self.sb_idl.is_router_gateway_chassis(datapath,
                                                       self.chassis)
        if cr_lrp:
            print("Add IP Rules for network {} on chassis {}".format(
                ip_address, self.chassis))
            self.ovn_local_lrps.append(logical_port)
            cr_lrp_datapath = self.ovn_local_cr_lrps.get(cr_lrp, {}).get(
                'provider_datapath')
            if cr_lrp_datapath and self._use_rules:
                self._add_ip_rule(ip_address, cr_lrp_datapath)

    def del_subnet_rules(self, ip_address, logical_port, datapath):
        cr_lrp = self.sb_idl.is_router_gateway_chassis(datapath,
                                                       self.chassis)
        if cr_lrp:
            print("Delete IP Rules for network {} on chassis {}".format(
                ip_address, self.chassis))
            if logical_port in self.ovn_local_lrps:
                self.ovn_local_lrps.remove(logical_port)
            cr_lrp_datapath = self.ovn_local_cr_lrps.get(cr_lrp, {}).get(
                'provider_datapath')
            if cr_lrp_datapath and self._use_rules:
                self._del_ip_rule(ip_address, cr_lrp_datapath)

    def _add_ip_rule(self, ip, datapath, lladdr=None):
        network_name = self.sb_idl.get_network_name(datapath)
        if network_name:
            network_bridge = self.ovn_bridge_mappings[network_name]
            rule = {'dst': ip,
                    'table': self.ovn_routing_tables[network_bridge]}
            # REMOVEME: due to a problem with pyroute, look for the rule too
            # without the mask
            rule_aux = {'dst': ip.split("/")[0],
                        'table': self.ovn_routing_tables[network_bridge]}
            iproute = pyroute2.IPRoute()
            if (not iproute.get_rules(**rule) and
                    not iproute.get_rules(**rule_aux)):
                iproute.rule('add', **rule)
            if lladdr:
                # This is doing something like:
                # sudo ip nei replace 172.24.4.69
                # lladdr fa:16:3e:d3:5d:7b dev br-ex nud permanent
                network_bridge_if = iproute.link_lookup(
                    ifname=network_bridge)[0]
                iproute.neigh('set',
                              dst=ip,
                              lladdr=lladdr,
                              ifindex=network_bridge_if,
                              state=ndmsg.states['permanent'])

    def _del_ip_rule(self, ip, datapath, lladdr=None):
        network_name = self.sb_idl.get_network_name(datapath)
        if network_name:
            network_bridge = self.ovn_bridge_mappings[network_name]
            rule = {'dst': ip,
                    'table': self.ovn_routing_tables[network_bridge]}
            # REMOVEME: due to a problem with pyroute, look for the rule too
            # without the mask
            rule_aux = {'dst': ip.split("/")[0],
                        'table': self.ovn_routing_tables[network_bridge]}
            iproute = pyroute2.IPRoute()
            if iproute.get_rules(**rule) or iproute.get_rules(**rule_aux):
                iproute.rule('del', **rule)
            if lladdr:
                # This is doing something like:
                # sudo ip nei del 172.24.4.69
                # lladdr fa:16:3e:d3:5d:7b dev br-ex nud permanent
                network_bridge_if = iproute.link_lookup(
                    ifname=network_bridge)[0]
                iproute.neigh('del',
                              dst=ip.split("/")[0],
                              lladdr=lladdr,
                              ifindex=network_bridge_if,
                              state=ndmsg.states['permanent'])
