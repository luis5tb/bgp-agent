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

import collections
import ipaddress
import pyroute2

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from bgp_agent import constants
from bgp_agent.platform import driver_api
from bgp_agent.platform.osp.utils import ovs
from bgp_agent.platform.osp.utils import ovn
from bgp_agent.platform.utils import linux_net
from bgp_agent.utils import utils

from bgp_agent.platform.osp import watcher


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
# LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)

class OSPOVNDriver(driver_api.AgentDriverBase):

    def __init__(self):
        self._expose_tenant_networks = True
        self.ovn_routing_tables = {}  # {'br-ex': 200}
        self.ovn_bridge_mappings = {}  # {'public': 'br-ex'}
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = set([])
        # {'br-ex': [route1, route2]}
        self.ovn_routing_tables_routes = collections.defaultdict()

        self.ovs_idl = ovs.OvsIdl()
        self.ovs_idl.start(constants.OVS_CONNECTION_STRING)
        self.chassis = self.ovs_idl.get_own_chassis_name()
        self.ovn_remote = self.ovs_idl.get_ovn_remote()
        LOG.debug("Loaded chassis {}.".format(self.chassis))

        self._tables = tuple(CONF.watcher_tables)
        events = ()
        for event in CONF.watcher_events:
            event_class = getattr(watcher, event)
            events += (event_class(self),)

        self._sb_idl = ovn.OvnSbIdl(
            self.ovn_remote,
            chassis=self.chassis,
            tables=self._tables,
            events=events)

    def start(self):
        # start the subscriptions to the OSP events. This ensures the watcher
        # calls the relevant driver methods upon registered events
        self.sb_idl = self._sb_idl.start()

    @lockutils.synchronized('bgp')
    def sync(self):
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = set([])
        self.ovn_routing_tables_routes = collections.defaultdict()

        LOG.debug("Ensuring VRF configuration for advertising routes")
        # Create VRF
        linux_net.ensure_vrf(constants.OVN_BGP_VRF,
                             constants.OVN_BGP_VRF_TABLE)                      
        # Create OVN dummy device
        linux_net.ensure_ovn_device(constants.OVN_BGP_NIC,
                                    constants.OVN_BGP_VRF)

        LOG.debug("Configuring br-ex default rule and routing tables for "
                  "each provider network")
        flows_info = {}
        # 1) Get bridge mappings: xxxx:br-ex,yyyy:br-ex2
        bridge_mappings = self.ovs_idl.get_ovn_bridge_mappings()
        # 2) Get macs for bridge mappings
        extra_routes = {}
        for bridge_mapping in bridge_mappings:
            network = bridge_mapping.split(":")[0]
            bridge = bridge_mapping.split(":")[1]
            self.ovn_bridge_mappings[network] = bridge
            if not extra_routes.get(bridge):
                extra_routes[bridge] = (
                    linux_net.ensure_routing_table_for_bridge(
                        self.ovn_routing_tables, bridge))
            vlan_tag = self.sb_idl.get_network_vlan_tag_by_network_name(
                network)
            if vlan_tag:
                linux_net.ensure_vlan_device_for_network(bridge,
                                                            vlan_tag)

            if flows_info.get(bridge):
                continue
            with pyroute2.IPDB().interfaces[bridge] as iface:
                flows_info[bridge] = {'mac': iface.address}
                flows_info[bridge]['in_port'] = set([])
            # 3) Get in_port for bridge mappings (br-ex, br-ex2)
            ovs.get_ovs_flows(bridge, flows_info)
        # 4) Add/Remove flows for each bridge mappings
        ovs.remove_extra_ovs_flows(flows_info)

        LOG.debug("Syncing current routes.")
        exposed_ips = linux_net.get_exposed_ips(constants.OVN_BGP_NIC)
        # get the rules pointing to ovn bridges
        ovn_ip_rules = linux_net.get_ovn_ip_rules(
            self.ovn_routing_tables.values())

        # add missing routes/ips for fips/provider VMs
        ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        for port in ports:
            self._ensure_port_exposed(port, exposed_ips, ovn_ip_rules)

        # add missing route/ips for tenant network VMs
        if self._expose_tenant_networks:
            for cr_lrp_info in self.ovn_local_cr_lrps.values():
                lrp_ports = self.sb_idl.get_lrp_ports_for_router(
                    cr_lrp_info['router_datapath'])
                for lrp in lrp_ports:
                    if lrp.chassis:
                        continue
                    self._ensure_network_exposed(
                        lrp, cr_lrp_info, exposed_ips, ovn_ip_rules)

        # remove extra routes/ips
        # remove all the leftovers on the list of current ips on dev OVN
        linux_net.delete_exposed_ips(exposed_ips, constants.OVN_BGP_NIC)
        # remove all the leftovers on the list of current ip rules for ovn
        # bridges
        linux_net.delete_ip_rules(ovn_ip_rules)

        # remove all the extra rules not needed
        linux_net.delete_bridge_ip_routes(self.ovn_routing_tables,
                                          self.ovn_routing_tables_routes,
                                          extra_routes)

    def _ensure_port_exposed(self, port, exposed_ips, ovn_ip_rules):
        if port.type not in constants.OVN_VIF_PORT_TYPES:
            return
        if (len(port.mac[0].split(' ')) != 2 and
                len(port.mac[0].split(' ')) != 3):
            return
        port_ips = [port.mac[0].split(' ')[1]]
        if len(port.mac[0].split(' ')) == 3:
            port_ips.append(port.mac[0].split(' ')[2])

        fip = self._expose_IP(port_ips, port)
        if fip:
            if fip in exposed_ips:
                exposed_ips.remove(fip)
            if fip in ovn_ip_rules.keys():
                del ovn_ip_rules[fip]

        for port_ip in port_ips:
            ip_address = port_ip.split("/")[0]
            if ip_address in exposed_ips:
                # remove each ip to add from the list of current ips on dev OVN
                exposed_ips.remove(ip_address)
            if ip_address in ovn_ip_rules.keys():
                del ovn_ip_rules[ip_address]

    def _ensure_network_exposed(self, router_port, gateway, exposed_ips=[],
                                ovn_ip_rules={}):
        gateway_ips = [ip.split('/')[0] for ip in gateway['ips']]
        try:
            router_port_ip = router_port.mac[0].split(' ')[1]
        except IndexError:
            return
        router_ip = router_port_ip.split('/')[0]
        if router_ip in gateway_ips:
            return
        self.ovn_local_lrps.add(router_port.logical_port)
        rule_bridge, vlan_tag = self._get_bridge_for_datapath(
            gateway['provider_datapath'])

        linux_net.add_ip_rule(router_port_ip,
                              self.ovn_routing_tables[rule_bridge],
                              rule_bridge)
        if router_ip in ovn_ip_rules.keys():
            del ovn_ip_rules[router_ip]

        router_port_ip_version = utils.get_ip_version(router_port_ip)
        for gateway_ip in gateway_ips:
            if utils.get_ip_version(gateway_ip) == router_port_ip_version:
                linux_net.add_ip_route(
                    self.ovn_routing_tables_routes,
                    router_ip,
                    self.ovn_routing_tables[rule_bridge],
                    rule_bridge,
                    vlan=vlan_tag,
                    mask=router_port_ip.split("/")[1],
                    via=gateway_ip)
                break

        network_port_datapath = self.sb_idl.get_port_datapath(
            router_port.options['peer'])
        if network_port_datapath:
            ports = self.sb_idl.get_ports_on_datapath(
                network_port_datapath)
            for port in ports:
                if port.type != "":
                    continue
                try:
                    port_ips = [port.mac[0].split(' ')[1]]
                except IndexError:
                    continue
                if len(port.mac[0].split(' ')) == 3:
                    port_ips.append(port.mac[0].split(' ')[2])

                ip_version = utils.get_ip_version(router_port_ip)
                for port_ip in port_ips:
                    # Only adding the port ips that match the lrp
                    # IP version
                    port_ip_version = utils.get_ip_version(port_ip)
                    if port_ip_version == ip_version:
                        linux_net.add_ips_to_dev(
                            constants.OVN_BGP_NIC, [port_ip])
                        if port_ip in exposed_ips:
                            exposed_ips.remove(port_ip)
                        if port_ip in ovn_ip_rules.keys():
                            del ovn_ip_rules[port_ip]

    def _remove_network_exposed(self, router_port, gateway, exposed_ips=[],
                                ovn_ip_rules={}):
        gateway_ips = [ip.split('/')[0] for ip in gateway['ips']]
        try:
            router_port_ip = router_port.mac[0].split(' ')[1]
        except IndexError:
            return
        router_ip = router_port_ip.split('/')[0]
        if router_ip in gateway_ips:
            return

        if router_port.logical_port in self.ovn_local_lrps:
            self.ovn_local_lrps.remove(router_port.logical_port)
        rule_bridge, vlan_tag = self._get_bridge_for_datapath(
            gateway['provider_datapath'])

        linux_net.del_ip_rule(router_port_ip,
                              self.ovn_routing_tables[rule_bridge],
                              rule_bridge)            

        router_port_ip_version = utils.get_ip_version(router_port_ip)
        for gateway_ip in gateway_ips:
            if utils.get_ip_version(gateway_ip) == router_port_ip_version:
                linux_net.del_ip_route(
                    self.ovn_routing_tables_routes,
                    router_ip,
                    self.ovn_routing_tables[rule_bridge],
                    rule_bridge,
                    vlan=vlan_tag,
                    mask=router_port_ip.split("/")[1],
                    via=gateway_ip)
                if utils.get_ip_version(gateway_ip) == constants.IP_VERSION_6:
                    net = ipaddress.IPv6Network(router_port_ip, strict=False)
                else:
                    net = ipaddress.IPv4Network(router_port_ip, strict=False)    
                break
        # Check if there are VMs on the network
        # and if so withdraw the routes
        vms_on_net = linux_net.get_exposed_ips_on_network(
            constants.OVN_BGP_NIC, net)
        linux_net.delete_exposed_ips(vms_on_net, constants.OVN_BGP_NIC)

    def _get_bridge_for_datapath(self, datapath):
        network_name, network_tag = self.sb_idl.get_network_name_and_tag(
            datapath, self.ovn_bridge_mappings.keys())
        if network_name:
            if network_tag:
                return self.ovn_bridge_mappings[network_name], network_tag[0]
            return self.ovn_bridge_mappings[network_name], None

    @lockutils.synchronized('bgp')
    def expose_IP(self, ips, row, associated_port=None, caller=None):
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
        LOG.info("XXXXX EXPOSE IP EVENT FOR ROW: {}".format(ips))
        LOG.info("XXXXX EXPOSE IP EVENT CALLED BY: {}".format(caller))
        self._expose_IP(ips, row, associated_port)

    def _expose_IP(self, ips, row, associated_port=None):
        LOG.info("YYYYYY INTERNAL EXPOSE IP EVENT CALLED")
        # VM on provider Network
        if row.type == "" and self.sb_idl.is_provider_network(row.datapath):
            LOG.info("Add BGP route for logical port with ip {}".format(ips))
            linux_net.add_ips_to_dev(constants.OVN_BGP_NIC, ips)

            rule_bridge, vlan_tag = self._get_bridge_for_datapath(row.datapath)
            for ip in ips:
                linux_net.add_ip_rule(ip,
                                      self.ovn_routing_tables[rule_bridge],
                                      rule_bridge)
                linux_net.add_ip_route(
                    self.ovn_routing_tables_routes, ip,
                    self.ovn_routing_tables[rule_bridge], rule_bridge,
                    vlan=vlan_tag)

        # VM with FIP
        elif row.type == "":
            # FIPs are only supported with IPv4
            fip_address, fip_datapath = self.sb_idl.get_fip_associated(
                row.logical_port)
            if fip_address:
                LOG.info("Add BGP route for FIP with ip {}".format(fip_address))
                linux_net.add_ips_to_dev(constants.OVN_BGP_NIC,
                                         [fip_address])

                rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                    fip_datapath)
                linux_net.add_ip_rule(fip_address,
                                      self.ovn_routing_tables[rule_bridge],
                                      rule_bridge)
                linux_net.add_ip_route(
                    self.ovn_routing_tables_routes, fip_address,
                    self.ovn_routing_tables[rule_bridge], rule_bridge,
                    vlan=vlan_tag)
                return fip_address
            else:
                ovs.ensure_bridge_ovs_flows(self.ovn_bridge_mappings.values())
        
        # FIP association to VM
        elif row.type == "patch":
            if (associated_port and self.sb_idl.is_port_on_chassis(
                    associated_port, self.chassis)):
                LOG.info("Add BGP route for FIP with ip {}".format(ips))
                linux_net.add_ips_to_dev(constants.OVN_BGP_NIC, ips)

                rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                    row.datapath)
                for ip in ips:
                    linux_net.add_ip_rule(ip,
                                          self.ovn_routing_tables[rule_bridge],
                                          rule_bridge)
                    linux_net.add_ip_route(
                        self.ovn_routing_tables_routes, ip,
                        self.ovn_routing_tables[rule_bridge], rule_bridge,
                        vlan=vlan_tag)                

        # CR-LRP Port
        elif (row.type == "chassisredirect" and
              row.logical_port.startswith('cr-')):
            _, cr_lrp_datapath = self.sb_idl.get_fip_associated(
                row.logical_port)
            if cr_lrp_datapath:
                LOG.info("Add BGP route for CR-LRP Port {}".format(ips))
                # Keeping information about the associated network for
                # tenant network advertisement
                self.ovn_local_cr_lrps[row.logical_port] = {
                    'router_datapath': row.datapath,
                    'provider_datapath': cr_lrp_datapath,
                    'ips': ips
                }
                ips_without_mask = [ip.split("/")[0] for ip in ips]
                linux_net.add_ips_to_dev(constants.OVN_BGP_NIC,
                                         ips_without_mask)

                rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                    cr_lrp_datapath)

                for ip in ips:
                    ip_without_mask = ip.split("/")[0]
                    linux_net.add_ip_rule(
                        ip_without_mask, self.ovn_routing_tables[rule_bridge],
                        rule_bridge, lladdr=row.mac[0].split(' ')[0])
                    linux_net.add_ip_route(
                        self.ovn_routing_tables_routes, ip_without_mask,
                        self.ovn_routing_tables[rule_bridge], rule_bridge,
                        vlan=vlan_tag)
                    # add proxy ndp config for ipv6
                    if (utils.get_ip_version(ip_without_mask) ==
                            constants.IP_VERSION_6):
                        linux_net.add_ndp_proxy(ip, rule_bridge)

                # Check if there are networks attached to the router,
                # and if so, add the needed routes/rules
                lrp_ports = self.sb_idl.get_lrp_ports_for_router(
                    row.datapath)
                for lrp in lrp_ports:
                    if lrp.chassis:
                        continue
                    self._ensure_network_exposed(
                        lrp, self.ovn_local_cr_lrps[row.logical_port])

    @lockutils.synchronized('bgp')
    def withdraw_IP(self, ips, row, associated_port=None, caller=None):
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
        LOG.info("XXXXX WITHDRAW IP EVENT FOR ROW: {}".format(ips))
        LOG.info("XXXXX WITHDRAW IP EVENT CALLED BY: {}".format(caller))

        # VM on provider Network
        if row.type == "" and self.sb_idl.is_provider_network(row.datapath):
            LOG.info("Delete BGP route for logical port with ip {}".format(ips))
            linux_net.del_ips_from_dev(constants.OVN_BGP_NIC, ips)

            rule_bridge, vlan_tag = self._get_bridge_for_datapath(row.datapath)
            for ip in ips:
                linux_net.del_ip_rule(ip,
                                      self.ovn_routing_tables[rule_bridge],
                                      rule_bridge)
                linux_net.del_ip_route(
                    self.ovn_routing_tables_routes, ip,
                    self.ovn_routing_tables[rule_bridge], rule_bridge,
                    vlan=vlan_tag)

        # VM with FIP
        elif row.type == "":
            # FIPs are only supported with IPv4
            fip_address, fip_datapath = self.sb_idl.get_fip_associated(
                row.logical_port)
            if fip_address:
                LOG.info("Delete BGP route for FIP with ip {}".format(
                      fip_address))
                linux_net.del_ips_from_dev(constants.OVN_BGP_NIC,
                                           [fip_address])

                rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                    fip_datapath)
                linux_net.del_ip_rule(fip_address,
                                      self.ovn_routing_tables[rule_bridge],
                                      rule_bridge)
                linux_net.del_ip_route(
                    self.ovn_routing_tables_routes, fip_address,
                    self.ovn_routing_tables[rule_bridge], rule_bridge,
                    vlan=vlan_tag)

        # FIP association to VM
        elif row.type == "patch":
            if (associated_port and (
                    self.sb_idl.is_port_on_chassis(
                        associated_port, self.chassis) or
                    self.sb_idl.is_port_deleted(associated_port))):
                LOG.info("Delete BGP route for FIP with ip {}".format(ips))
                linux_net.del_ips_from_dev(constants.OVN_BGP_NIC, ips)

                rule_bridge, vlan_tag = self._get_bridge_for_datapath(row.datapath)
                for ip in ips:
                    linux_net.del_ip_rule(ip,
                                          self.ovn_routing_tables[rule_bridge],
                                          rule_bridge)
                    linux_net.del_ip_route(
                        self.ovn_routing_tables_routes, ip,
                        self.ovn_routing_tables[rule_bridge], rule_bridge,
                        vlan=vlan_tag) 

        # CR-LRP Port
        elif (row.type == "chassisredirect" and
              row.logical_port.startswith('cr-')):
            cr_lrp_datapath = self.ovn_local_cr_lrps.get(
                row.logical_port, {}).get('provider_datapath')
            if cr_lrp_datapath:
                LOG.info("Delete BGP route for CR-LRP Port {}".format(ips))
                # Removing information about the associated network for
                # tenant network advertisement
                ips_without_mask = [ip.split("/")[0] for ip in ips]
                linux_net.del_ips_from_dev(constants.OVN_BGP_NIC,
                                           ips_without_mask)

                rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                    cr_lrp_datapath)

                for ip in ips_without_mask:
                    if utils.get_ip_version(ip) == constants.IP_VERSION_6:
                        cr_lrp_ip = '{}/128'.format(ip)
                    else:
                        cr_lrp_ip = '{}/32'.format(ip)
                    linux_net.del_ip_rule(
                        cr_lrp_ip, self.ovn_routing_tables[rule_bridge],
                        rule_bridge, lladdr=row.mac[0].split(' ')[0])
                    linux_net.del_ip_route(
                        self.ovn_routing_tables_routes, ip,
                        self.ovn_routing_tables[rule_bridge], rule_bridge,
                        vlan=vlan_tag)
                    # del proxy ndp config for ipv6
                    if utils.get_ip_version(ip) == constants.IP_VERSION_6:
                        linux_net.del_ndp_proxy(ip, rule_bridge)

                # Check if there are networks attached to the router,
                # and if so, delete the needed routes/rules
                lrp_ports = self.sb_idl.get_lrp_ports_for_router(
                    row.datapath)
                for lrp in lrp_ports:
                    if lrp.chassis:
                        continue
                    local_cr_lrp_info = self.ovn_local_cr_lrps.get(
                        row.logical_port)
                    if local_cr_lrp_info:
                        self._remove_network_exposed(lrp, local_cr_lrp_info)
                try:
                    del self.ovn_local_cr_lrps[row.logical_port]
                except KeyError:
                    LOG.debug("Gateway port already cleanup from the agent")

    @lockutils.synchronized('bgp')
    def expose_remote_IP(self, ips, row):
        if self.sb_idl.is_provider_network(row.datapath):
            return
        port_lrp = self.sb_idl.get_lrp_port_for_datapath(row.datapath)
        if port_lrp in self.ovn_local_lrps:
            LOG.info("Add BGP route for tenant IP {} on chassis {}".format(
                     ips, self.chassis))
            linux_net.add_ips_to_dev(constants.OVN_BGP_NIC, ips)

    @lockutils.synchronized('bgp')
    def withdraw_remote_IP(self, ips, row):
        if self.sb_idl.is_provider_network(row.datapath):
            return
        port_lrp = self.sb_idl.get_lrp_port_for_datapath(row.datapath)
        if port_lrp in self.ovn_local_lrps:
            LOG.info("Delete BGP route for tenant IP {} on chassis {}".format(
                     ips, self.chassis))
            linux_net.del_ips_from_dev(constants.OVN_BGP_NIC, ips)

    @lockutils.synchronized('bgp')
    def expose_subnet(self, ip, row):
        cr_lrp = self.sb_idl.is_router_gateway_on_chassis(row.datapath,
                                                          self.chassis)
        if cr_lrp:
            LOG.info("Add IP Rules for network {} on chassis {}".format(
                ip, self.chassis))
            self.ovn_local_lrps.add(row.logical_port)
            cr_lrp_info = self.ovn_local_cr_lrps.get(cr_lrp, {})
            cr_lrp_datapath = cr_lrp_info.get('provider_datapath')
            if cr_lrp_datapath:
                cr_lrp_ips = [ip_address.split('/')[0]
                              for ip_address in cr_lrp_info.get('ips', [])]
                rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                    cr_lrp_datapath)
                linux_net.add_ip_rule(ip,
                                      self.ovn_routing_tables[rule_bridge],
                                      rule_bridge)

                ip_version = utils.get_ip_version(ip)
                for cr_lrp_ip in cr_lrp_ips:
                    if utils.get_ip_version(cr_lrp_ip) == ip_version:
                        linux_net.add_ip_route(
                            self.ovn_routing_tables_routes,
                            ip.split("/")[0],
                            self.ovn_routing_tables[rule_bridge],
                            rule_bridge,
                            vlan=vlan_tag,
                            mask=ip.split("/")[1],
                            via=cr_lrp_ip)
                        break

                # Check if there are VMs on the network
                # and if so expose the route
                network_port_datapath = self.sb_idl.get_port_datapath(
                    row.options['peer'])
                if network_port_datapath:
                    ports = self.sb_idl.get_ports_on_datapath(
                        network_port_datapath)
                    for port in ports:
                        if port.type != "":
                            continue
                        try:
                            port_ips = [port.mac[0].split(' ')[1]]
                        except IndexError:
                            continue
                        if len(port.mac[0].split(' ')) == 3:
                            port_ips.append(port.mac[0].split(' ')[2])

                        ip_version = utils.get_ip_version(ip)
                        for port_ip in port_ips:
                            # Only adding the port ips that match the lrp
                            # IP version
                            port_ip_version = utils.get_ip_version(port_ip)
                            if port_ip_version == ip_version:
                                linux_net.add_ips_to_dev(
                                    constants.OVN_BGP_NIC, [port_ip])

    @lockutils.synchronized('bgp')
    def withdraw_subnet(self, ip, row):
        cr_lrp = self.sb_idl.is_router_gateway_on_chassis(row.datapath,
                                                          self.chassis)
        if cr_lrp:
            LOG.info("Delete IP Rules for network {} on chassis {}".format(
                ip, self.chassis))
            if row.logical_port in self.ovn_local_lrps:
                self.ovn_local_lrps.remove(row.logical_port)
            cr_lrp_info = self.ovn_local_cr_lrps.get(cr_lrp, {})
            cr_lrp_datapath = cr_lrp_info.get('provider_datapath')

            if cr_lrp_datapath:
                cr_lrp_ips = [ip_address.split('/')[0]
                              for ip_address in cr_lrp_info.get('ips', [])]
                rule_bridge, vlan_tag = self._get_bridge_for_datapath(
                    cr_lrp_datapath)
                linux_net.del_ip_rule(ip,
                                      self.ovn_routing_tables[rule_bridge],
                                      rule_bridge)    

                ip_version = utils.get_ip_version(ip)
                for cr_lrp_ip in cr_lrp_ips:
                    if utils.get_ip_version(cr_lrp_ip) == ip_version:
                        linux_net.del_ip_route(
                            self.ovn_routing_tables_routes,
                            ip.split("/")[0],
                            self.ovn_routing_tables[rule_bridge],
                            rule_bridge,
                            vlan=vlan_tag,
                            mask=ip.split("/")[1],
                            via=cr_lrp_ip)
                        if utils.get_ip_version(cr_lrp_ip) == constants.IP_VERSION_6:
                            net = ipaddress.IPv6Network(ip, strict=False)
                        else:
                            net = ipaddress.IPv4Network(ip, strict=False)
                        break

                # Check if there are VMs on the network
                # and if so withdraw the routes
                vms_on_net = linux_net.get_exposed_ips_on_network(
                    constants.OVN_BGP_NIC, net)
                linux_net.delete_exposed_ips(vms_on_net,
                                             constants.OVN_BGP_NIC)