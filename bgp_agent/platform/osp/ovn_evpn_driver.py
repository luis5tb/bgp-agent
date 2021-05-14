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

from bgp_agent.platform.osp.watchers import evpn_watcher as watcher


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
# LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)

OVN_TABLES = ("Port_Binding", "Chassis", "Datapath_Binding")


class OSPOVNEVPNDriver(driver_api.AgentDriverBase):

    def __init__(self):
        self.ovn_bridge_mappings = {}  # {'public': 'br-ex'}
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = {}
        # {'br-ex': [route1, route2]}
        self._ovn_routing_tables_routes = collections.defaultdict()
        self._ovn_exposed_evpn_ips = collections.defaultdict()

        self.ovs_idl = ovs.OvsIdl()
        self.ovs_idl.start(constants.OVS_CONNECTION_STRING)
        self.chassis = self.ovs_idl.get_own_chassis_name()
        self.ovn_remote = self.ovs_idl.get_ovn_remote()
        LOG.debug("Loaded chassis {}.".format(self.chassis))

        events = ()
        for event in self._get_events():
            event_class = getattr(watcher, event)
            events += (event_class(self),)

        self._sb_idl = ovn.OvnSbIdl(
            self.ovn_remote,
            chassis=self.chassis,
            tables=OVN_TABLES,
            events=events)

    def start(self):
        # start the subscriptions to the OSP events. This ensures the watcher
        # calls the relevant driver methods upon registered events
        self.sb_idl = self._sb_idl.start()

    def _get_events(self):
        events = set(["PortBindingChassisCreatedEvent",
                      "PortBindingChassisDeletedEvent",
                      "SubnetRouterAttachedEvent",
                      "SubnetRouterDetachedEvent",
                      "TenantPortCreatedEvent",
                      "TenantPortDeletedEvent",
                      "ChassisCreateEvent"])
        return events

    @lockutils.synchronized('evpn')
    def sync(self):
        self.ovn_local_cr_lrps = {}
        self.ovn_local_lrps = {}
        self._ovn_routing_tables_routes = collections.defaultdict()
        self._ovn_exposed_evpn_ips = collections.defaultdict()

        # 1) Get bridge mappings: xxxx:br-ex,yyyy:br-ex2
        bridge_mappings = self.ovs_idl.get_ovn_bridge_mappings()
        # 2) Get macs for bridge mappings
        for bridge_mapping in bridge_mappings:
            network = bridge_mapping.split(":")[0]
            bridge = bridge_mapping.split(":")[1]
            self.ovn_bridge_mappings[network] = bridge

        # TO DO
        # add missing routes/ips for fips/provider VMs
        ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        for port in ports:
            if port.type != 'chassisredirect':
                continue
            self._expose_IP(port, cr_lrp=True)

        self._remove_extra_exposed_ips()
        self._remove_extra_routes()
        self._remove_extra_ovs_flows()
        self._remove_extra_vrfs()

    def _ensure_network_exposed(self, router_port, gateway):
        evpn_info = self.sb_idl.get_evpn_info_from_lrp_port_name(
            router_port.logical_port)
        if not evpn_info:
            LOG.debug("No EVPN information for LRP Port {}. "
                      "Not exposing it.".format(router_port))
            return

        gateway_ips = [ip.split('/')[0] for ip in gateway['ips']]
        try:
            router_port_ip = router_port.mac[0].split(' ')[1]
        except IndexError:
            return
        router_ip = router_port_ip.split('/')[0]
        if router_ip in gateway_ips:
            return
        self.ovn_local_lrps[router_port.logical_port] = {
            'datapath': router_port.datapath,
            'ip': router_port_ip
            }
        datapath_bridge, vlan_tag = self._get_bridge_for_datapath(
            gateway['provider_datapath'])

        router_port_ip_version = utils.get_ip_version(router_port_ip)
        for gateway_ip in gateway_ips:
            if utils.get_ip_version(gateway_ip) == router_port_ip_version:
                linux_net.add_ip_route(
                    self._ovn_routing_tables_routes,
                    router_ip,
                    gateway['vni'],
                    datapath_bridge,
                    vlan=vlan_tag,
                    mask=router_port_ip.split("/")[1],
                    via=gateway_ip)
                break

        if router_port_ip_version == constants.IP_VERSION_6:
            net_ip = '{}'.format(ipaddress.IPv6Network(
                router_port_ip, strict=False))
        else:
            net_ip = '{}'.format(ipaddress.IPv4Network(
                router_port_ip, strict=False))

        ovs.ensure_evpn_ovs_flow(datapath_bridge,
                                 constants.OVS_VRF_RULE_COOKIE,
                                 gateway['mac'],
                                 gateway['vrf'],
                                 net_ip)

        network_port_datapath = self.sb_idl.get_port_datapath(
            router_port.options['peer'])
        if not network_port_datapath:
            return
        ports = self.sb_idl.get_ports_on_datapath(
            network_port_datapath)
        for port in ports:
            if port.type != "" and port.type != "virtual":
                continue
            try:
                port_ips = [port.mac[0].split(' ')[1]]
            except IndexError:
                continue
            if len(port.mac[0].split(' ')) == 3:
                port_ips.append(port.mac[0].split(' ')[2])

            for port_ip in port_ips:
                # Only adding the port ips that match the lrp
                # IP version
                port_ip_version = utils.get_ip_version(port_ip)
                if port_ip_version == router_port_ip_version:
                    linux_net.add_ips_to_dev(
                        gateway['lo'], [port_ip],
                        clear_local_route_at_table=gateway['vni'])
                    self._ovn_exposed_evpn_ips.setdefault(
                         gateway['lo'], []).extend([port_ip])

    def _get_bridge_for_datapath(self, datapath):
        network_name, network_tag = self.sb_idl.get_network_name_and_tag(
            datapath, self.ovn_bridge_mappings.keys())
        if network_name:
            if network_tag:
                return self.ovn_bridge_mappings[network_name], network_tag[0]
            return self.ovn_bridge_mappings[network_name], None
        return None, None

    @lockutils.synchronized('evpn')
    def expose_IP(self, row, cr_lrp=False):
        '''Advertice BGP route through EVPN.

        This methods ensures BGP advertises the IP through the required
        VRF/Tenant by using the specified VNI/VXLAN id.

        It relies on Zebra, which creates and advertises a route when an IP
        is added to a interface in the related VRF.
        '''
        self._expose_IP(row, cr_lrp)

    def _expose_IP(self, row, cr_lrp=False):
        if cr_lrp:
            cr_lrp_port_name = row.logical_port
            cr_lrp_port = row
        else:
            cr_lrp_port_name = 'cr-lrp-' + row.logical_port
            cr_lrp_port = self.sb_idl.get_port_if_local_chassis(
                cr_lrp_port_name, self.chassis)
            if not cr_lrp_port:
                # Not in local chassis, no need to proccess
                return

        _, cr_lrp_datapath = self.sb_idl.get_fip_associated(
            cr_lrp_port_name)
        if not cr_lrp_datapath:
            return

        if (len(cr_lrp_port.mac[0].split(' ')) != 2 and
                len(cr_lrp_port.mac[0].split(' ')) != 3):
            return
        ips = [cr_lrp_port.mac[0].split(' ')[1]]
        # for dual-stack
        if len(cr_lrp_port.mac[0].split(' ')) == 3:
            ips.append(cr_lrp_port.mac[0].split(' ')[2])

        if cr_lrp:
            evpn_info = self.sb_idl.get_evpn_info_from_crlrp_port_name(
                cr_lrp_port_name)
        else:
            evpn_info = self.sb_idl.get_evpn_info_from_port(row)
        if not evpn_info:
            LOG.debug("No EVPN information for CR-LRP Port with IPs {}. "
                      "Not exposing it.".format(ips))
            return

        LOG.info("Adding BGP route for CR-LRP Port {} on RT {} and "
                 "VNI {}".format(ips, evpn_info['rt'], evpn_info['vni']))
        vrf, lo, bridge, vxlan = self._ensure_evpn_devices(evpn_info['vni'])
        if not vrf or not lo:
            return

        self.ovn_local_cr_lrps[cr_lrp_port_name] = {
            'router_datapath': cr_lrp_port.datapath,
            'provider_datapath': cr_lrp_datapath,
            'ips': ips,
            'mac': cr_lrp_port.mac[0].split(' ')[0],
            'vni': int(evpn_info['vni']),
            'rt': evpn_info['rt'],
            'lo': lo,
            'bridge': bridge,
            'vxlan': vxlan,
            'vrf': vrf
        }

        self._reconfigure_FRR(evpn_info)

        datapath_bridge, vlan_tag = self._get_bridge_for_datapath(
            cr_lrp_datapath)
        self._connect_evpn_to_ovn(vrf, ips, datapath_bridge, evpn_info['vni'],
                                  vlan_tag)

        ips_without_mask = [ip.split("/")[0] for ip in ips]
        linux_net.add_ips_to_dev(lo, ips_without_mask,
                                 clear_local_route_at_table=evpn_info['vni'])
        self._ovn_exposed_evpn_ips.setdefault(
                         lo, []).extend(ips_without_mask)

        # Check if there are networks attached to the router,
        # and if so, add the needed routes/rules
        lrp_ports = self.sb_idl.get_lrp_ports_for_router(
            cr_lrp_port.datapath)
        for lrp in lrp_ports:
            if lrp.chassis:
                continue
            self._ensure_network_exposed(
                lrp, self.ovn_local_cr_lrps[cr_lrp_port_name])

    @lockutils.synchronized('evpn')
    def withdraw_IP(self, row, cr_lrp=False):
        '''Withdraw BGP route through EVPN.

        This methods ensures BGP withdraw the IP advertised through the
        required VRF/Tenant by using the specified VNI/VXLAN id.

        It relies on Zebra, which cwithdraws the advertisement as son as the
        IP is deleted from the interface in the related VRF.
        '''
        if cr_lrp:
            cr_lrp_port_name = row.logical_port
        else:
            cr_lrp_port_name = 'cr-lrp-' + row.logical_port

        cr_lrp_info = self.ovn_local_cr_lrps.get(cr_lrp_port_name, {})
        if not cr_lrp_info:
            # This means it is in a different chassis
            return
        cr_lrp_datapath = cr_lrp_info.get('provider_datapath')
        if not cr_lrp_datapath:
            return

        ips = cr_lrp_info.get('ips')
        evpn_vni = cr_lrp_info.get('vni')
        if not evpn_vni:
            LOG.debug("No EVPN information for CR-LRP Port with IPs {}. "
                      "No need to withdraw it.".format(ips))
            return

        LOG.info("Delete BGP route for CR-LRP Port {} on VNI {}".format(
            ips,  evpn_vni))
        datapath_bridge, vlan_tag = self._get_bridge_for_datapath(
            cr_lrp_datapath)

        self._disconnect_evpn_to_ovn(evpn_vni, datapath_bridge)
        self._remove_evpn_devices(evpn_vni)
        ovs.remove_evpn_router_ovs_flows(datapath_bridge,
                                         constants.OVS_VRF_RULE_COOKIE,
                                         cr_lrp_info.get('mac'))

        evpn_info = {'vni': evpn_vni, 'rt': cr_lrp_info.get('rt')}
        self._reconfigure_FRR(evpn_info)

        try:
            del self.ovn_local_cr_lrps[cr_lrp_port_name]
        except KeyError:
            LOG.debug("Gateway port already cleanup from the agent")

    @lockutils.synchronized('evpn')
    def expose_remote_IP(self, ips, row):
        if self.sb_idl.is_provider_network(row.datapath):
            return
        port_lrp = self.sb_idl.get_lrp_port_for_datapath(row.datapath)
        if port_lrp in self.ovn_local_lrps.keys():
            evpn_info = self.sb_idl.get_evpn_info_from_lrp_port_name(port_lrp)
            if not evpn_info:
                LOG.debug("No EVPN information for LRP Port {}. "
                          "Not exposing IPs: {}.".format(port_lrp, ips))
                return
            LOG.info("Add BGP route for tenant IP {} on chassis {}".format(
                     ips, self.chassis))
            lo_name = constants.OVN_EVPN_LO_PREFIX + str(evpn_info['vni'])
            linux_net.add_ips_to_dev(
                lo_name, ips, clear_local_route_at_table=evpn_info['vni'])
            self._ovn_exposed_evpn_ips.setdefault(
                lo_name, []).extend(ips)

    @lockutils.synchronized('evpn')
    def withdraw_remote_IP(self, ips, row):
        if self.sb_idl.is_provider_network(row.datapath):
            return
        port_lrp = self.sb_idl.get_lrp_port_for_datapath(row.datapath)
        if port_lrp in self.ovn_local_lrps.keys():
            evpn_info = self.sb_idl.get_evpn_info_from_lrp_port_name(port_lrp)
            if not evpn_info:
                LOG.debug("No EVPN information for LRP Port {}. "
                          "Not withdrawing IPs: {}.".format(port_lrp, ips))
                return
            LOG.info("Delete BGP route for tenant IP {} on chassis {}".format(
                     ips, self.chassis))
            lo_name = constants.OVN_EVPN_LO_PREFIX + str(evpn_info['vni'])
            linux_net.del_ips_from_dev(lo_name, ips)

    @lockutils.synchronized('evpn')
    def expose_subnet(self, row):
        evpn_info = self.sb_idl.get_evpn_info_from_port(row)
        ip = self.sb_idl.get_ip_from_port_peer(row)
        if not evpn_info:
            LOG.debug("No EVPN information for LRP Port {}. "
                      "Not exposing IPs: {}.".format(row.logical_port, ip))
            return

        lrp_logical_port = 'lrp-' + row.logical_port
        lrp_datapath = self.sb_idl.get_port_datapath(lrp_logical_port)

        cr_lrp = self.sb_idl.is_router_gateway_on_chassis(lrp_datapath,
                                                          self.chassis)
        if not cr_lrp:
            return

        LOG.info("Add IP Routes for network {} on chassis {}".format(
            ip, self.chassis))
        self.ovn_local_lrps[lrp_logical_port] = {
            'datapath': lrp_datapath,
            'ip': ip
            }

        cr_lrp_info = self.ovn_local_cr_lrps.get(cr_lrp, {})
        cr_lrp_datapath = cr_lrp_info.get('provider_datapath')
        if not cr_lrp_datapath:
            LOG.info("Subnet not connected to the provider network. "
                     "No need to expose it through EVPN")
            return

        cr_lrp_ips = [ip_address.split('/')[0]
                      for ip_address in cr_lrp_info.get('ips', [])]
        datapath_bridge, vlan_tag = self._get_bridge_for_datapath(
            cr_lrp_datapath)

        ip_version = utils.get_ip_version(ip)
        for cr_lrp_ip in cr_lrp_ips:
            if utils.get_ip_version(cr_lrp_ip) == ip_version:
                linux_net.add_ip_route(
                    self._ovn_routing_tables_routes,
                    ip.split("/")[0],
                    evpn_info['vni'],
                    datapath_bridge,
                    vlan=vlan_tag,
                    mask=ip.split("/")[1],
                    via=cr_lrp_ip)
                break

        if ip_version == constants.IP_VERSION_6:
            net_ip = '{}'.format(ipaddress.IPv6Network(
                ip, strict=False))
        else:
            net_ip = '{}'.format(ipaddress.IPv4Network(
                ip, strict=False))

        ovs.ensure_evpn_ovs_flow(datapath_bridge,
                                 constants.OVS_VRF_RULE_COOKIE,
                                 cr_lrp_info['mac'],
                                 cr_lrp_info['vrf'],
                                 net_ip)

        # Check if there are VMs on the network
        # and if so expose the route
        network_port_datapath = row.datapath
        if not network_port_datapath:
            return
        ports = self.sb_idl.get_ports_on_datapath(
            network_port_datapath)
        for port in ports:
            if port.type != "" and port.type != "virtual":
                continue
            try:
                port_ips = [port.mac[0].split(' ')[1]]
            except IndexError:
                continue
            if len(port.mac[0].split(' ')) == 3:
                port_ips.append(port.mac[0].split(' ')[2])

            for port_ip in port_ips:
                # Only adding the port ips that match the lrp
                # IP version
                port_ip_version = utils.get_ip_version(port_ip)
                if port_ip_version == ip_version:
                    linux_net.add_ips_to_dev(
                        cr_lrp_info['lo'], [port_ip],
                        clear_local_route_at_table=evpn_info['vni'])
                    self._ovn_exposed_evpn_ips.setdefault(
                        cr_lrp_info['lo'], []).extend([port_ip])

    @lockutils.synchronized('evpn')
    def withdraw_subnet(self, row):
        lrp_logical_port = 'lrp-' + row.logical_port
        lrp_datapath = self.ovn_local_lrps[lrp_logical_port].get('datapath')
        ip = self.ovn_local_lrps[lrp_logical_port].get('ip')
        if not lrp_datapath:
            return

        cr_lrp = self.sb_idl.is_router_gateway_on_chassis(lrp_datapath,
                                                          self.chassis)
        if not cr_lrp:
            return

        LOG.info("Delete IP Routes for network {} on chassis {}".format(
            ip, self.chassis))

        cr_lrp_info = self.ovn_local_cr_lrps.get(cr_lrp, {})
        cr_lrp_datapath = cr_lrp_info.get('provider_datapath')
        if not cr_lrp_datapath:
            LOG.info("Subnet not connected to the provider network. "
                     "No need to withdraw it from EVPN")
            return
        cr_lrp_ips = [ip_address.split('/')[0]
                      for ip_address in cr_lrp_info.get('ips', [])]
        datapath_bridge, vlan_tag = self._get_bridge_for_datapath(
            cr_lrp_datapath)

        ip_version = utils.get_ip_version(ip)
        for cr_lrp_ip in cr_lrp_ips:
            if utils.get_ip_version(cr_lrp_ip) == ip_version:
                linux_net.del_ip_route(
                    self._ovn_routing_tables_routes,
                    ip.split("/")[0],
                    cr_lrp_info['vni'],
                    datapath_bridge,
                    vlan=vlan_tag,
                    mask=ip.split("/")[1],
                    via=cr_lrp_ip)
                if utils.get_ip_version(cr_lrp_ip) == constants.IP_VERSION_6:
                    net = ipaddress.IPv6Network(ip, strict=False)
                else:
                    net = ipaddress.IPv4Network(ip, strict=False)
                break

        ovs.remove_evpn_network_ovs_flow(datapath_bridge,
                                         constants.OVS_VRF_RULE_COOKIE,
                                         cr_lrp_info['mac'],
                                         '{}'.format(net))

        # Check if there are VMs on the network
        # and if so withdraw the routes
        vms_on_net = linux_net.get_exposed_ips_on_network(
            cr_lrp_info['lo'], net)
        linux_net.delete_exposed_ips(vms_on_net,
                                     cr_lrp_info['lo'])

        try:
            del self.ovn_local_lrps[lrp_logical_port]
        except KeyError:
            LOG.debug("Router Interface port already cleanup from the agent")

    def _ensure_evpn_devices(self, vni):
        # ensure vrf device.
        # NOTE: It uses vni id as table number
        vrf_name = constants.OVN_EVPN_VRF_PREFIX + str(vni)
        linux_net.ensure_vrf(vrf_name, vni)

        # ensure bridge device
        bridge_name = constants.OVN_EVPN_BRIDGE_PREFIX + str(vni)
        linux_net.ensure_bridge(bridge_name)
        # connect bridge to vrf
        linux_net.set_master_for_device(bridge_name, vrf_name)

        # ensure vxlan device
        vxlan_name = constants.OVN_EVPN_VXLAN_PREFIX + str(vni)
        # NOTE: assuming only 1 IP on the loopback device with /32 prefix
        lo_ip = linux_net.get_nic_ip('lo',
                                     ip_version=constants.IP_VERSION_4)[0]
        if not lo_ip:
            LOG.error("Loopback IP must have a /32 IP associated for the "
                      "EVPN local ip")
            return None, None
        linux_net.ensure_vxlan(vxlan_name, vni, lo_ip)
        # connect vxlan to bridge
        linux_net.set_master_for_device(vxlan_name, bridge_name)

        # ensure dummy lo interface
        lo_name = constants.OVN_EVPN_LO_PREFIX + str(vni)
        linux_net.ensure_dummy_device(lo_name)
        # connect dummy to vrf
        linux_net.set_master_for_device(lo_name, vrf_name)

        return vrf_name, lo_name, bridge_name, vxlan_name

    def _remove_evpn_devices(self, vni):
        vrf_name = constants.OVN_EVPN_VRF_PREFIX + str(vni)
        bridge_name = constants.OVN_EVPN_BRIDGE_PREFIX + str(vni)
        vxlan_name = constants.OVN_EVPN_VXLAN_PREFIX + str(vni)
        lo_name = constants.OVN_EVPN_LO_PREFIX + str(vni)

        for device in [lo_name, vrf_name, bridge_name, vxlan_name]:
            linux_net.delete_device(device)

    def _connect_evpn_to_ovn(self, vrf, ips, datapath_bridge, vni, vlan_tag):
        # add vrf to ovs bridge
        ovs.add_device_to_ovs_bridge(vrf, datapath_bridge)

        # add route for ip to ovs provider bridge (at the vrf routing table)
        for ip in ips:
            ip_without_mask = ip.split("/")[0]
            linux_net.add_ip_route(
                self._ovn_routing_tables_routes, ip_without_mask,
                vni, datapath_bridge, vlan=vlan_tag)

            # add proxy ndp config for ipv6
            if (utils.get_ip_version(ip_without_mask) ==
                    constants.IP_VERSION_6):
                linux_net.add_ndp_proxy(ip, datapath_bridge, vlan_tag)

        # add unreachable route to vrf
        linux_net.add_unreachable_route(vrf)

    def _disconnect_evpn_to_ovn(self, vni, datapath_bridge):
        vrf = constants.OVN_EVPN_VRF_PREFIX + str(vni)
        # remove vrf from ovs bridge
        ovs.del_device_from_ovs_bridge(vrf, datapath_bridge)

        linux_net.delete_routes_from_table(vni)

    def _reconfigure_FRR(self, evpn_info):
        # TO DO
        LOG.info("FRR CONFIGURATION AUTOMATION NEEDED. "
                 "FOR MANUAL TESTING ADD FRR CONFIG FOR: {}", evpn_info)

    def _remove_extra_vrfs(self):
        vrfs, los, bridges, vxlans = ([], [], [], [])
        for cr_lrp_info in self.ovn_local_cr_lrps.values():
            vrfs.append(cr_lrp_info['vrf'])
            los.append(cr_lrp_info['lo'])
            bridges.append(cr_lrp_info['bridge'])
            vxlans.append(cr_lrp_info['vxlan'])

        interfaces = linux_net.get_interfaces()
        for interface in interfaces:
            if (interface.startswith(constants.OVN_EVPN_VRF_PREFIX) and
                    interface not in vrfs):
                linux_net.delete_device(interface)
                ovs.del_device_from_ovs_bridge(interface)
            elif (interface.startswith(constants.OVN_EVPN_LO_PREFIX) and
                    interface not in los):
                linux_net.delete_device(interface)
            elif (interface.startswith(constants.OVN_EVPN_BRIDGE_PREFIX) and
                    (interface not in bridges and
                     interface != constants.OVN_INTEGRATION_BRIDGE and
                     interface not in set(self.ovn_bridge_mappings.values()))):
                linux_net.delete_device(interface)
            elif (interface.startswith(constants.OVN_EVPN_VXLAN_PREFIX) and
                    interface not in vxlans):
                linux_net.delete_device(interface)

    def _remove_extra_routes(self):
        table_ids = self._get_table_ids()
        with pyroute2.NDB() as ndb:
            vrf_routes = set([r for r in ndb.routes.summary()
                              if r.table in table_ids])
            if not vrf_routes:
                return
            for bridge, routes_info in self._ovn_routing_tables_routes.items():
                for route_info in routes_info:
                    oif = ndb.interfaces[bridge]['index']
                    if route_info['vlan']:
                        vlan_device_name = '{}.{}'.format(bridge,
                                                          route_info['vlan'])
                        oif = ndb.interfaces[vlan_device_name]['index']
                    if 'gateway' in route_info['route'].keys():  # subnet route
                        possible_matchings = [
                            r for r in vrf_routes
                            if (r['dst'] == route_info['route']['dst'] and
                                r['dst_len'] == route_info['route']['dst_len'] and
                                r['gateway'] == route_info['route']['gateway'] and
                                r['table'] == route_info['route']['table'])]
                    else:  # cr-lrp
                        possible_matchings = [
                            r for r in vrf_routes
                            if (r['dst'] == route_info['route']['dst'] and
                                r['dst_len'] == route_info['route']['dst_len'] and
                                r['oif'] == oif and
                                r['table'] == route_info['route']['table'])]
                    for r in possible_matchings:
                        vrf_routes.remove(r)
            for route in vrf_routes:
                r_info = {'dst': route['dst'],
                          'dst_len': route['dst_len'],
                          'family': route['family'],
                          'oif': route['oif'],
                          'gateway': route['gateway'],
                          'table': route['table']}
                try:
                    with ndb.routes[r_info] as r:
                        r.remove()
                except KeyError:
                    LOG.debug("Route already deleted: {}".format(route))

    def _remove_extra_ovs_flows(self):
        cr_lrp_mac_vrf_mappings = self._get_cr_lrp_mac_vrf_mapping()
        for bridge in set(self.ovn_bridge_mappings.values()):
            current_flows = ovs.get_bridge_flows_by_cookie(
                bridge, constants.OVS_VRF_RULE_COOKIE)
            for flow in current_flows:
                flow_info = ovs.get_flow_info(flow)
                if not flow_info.get('mac'):
                    ovs.del_flow(flow, bridge, constants.OVS_VRF_RULE_COOKIE)
                elif flow_info['mac'] not in cr_lrp_mac_vrf_mappings.keys():
                    ovs.del_flow(flow, bridge, constants.OVS_VRF_RULE_COOKIE)
                elif flow_info['port']:
                    if (not flow_info.get('nw_src') and not
                            flow_info.get('ipv6_src')):
                        ovs.del_flow(flow, bridge,
                                     constants.OVS_VRF_RULE_COOKIE)
                    else:
                        device = cr_lrp_mac_vrf_mappings[flow_info['mac']]
                        vrf_port = ovs.get_device_port_at_ovs(device)
                        if vrf_port != flow_info['port']:
                            ovs.del_flow(flow, bridge,
                                         constants.OVS_VRF_RULE_COOKIE)
                        nw_src_ip = nw_src_mask = None
                        matching_dst = False
                        if flow_info.get('nw_src'):
                            nw_src_ip = flow_info['nw_src'].split('/')[0]
                            nw_src_mask = int(
                                flow_info['nw_src'].split('/')[1])
                        elif flow_info.get('ipv6_src'):
                            nw_src_ip = flow_info['ipv6_src'].split('/')[0]
                            nw_src_mask = int(
                                flow_info['ipv6_src'].split('/')[1])

                        for route_info in self._ovn_routing_tables_routes[
                                bridge]:
                            if (route_info['route']['dst'] == nw_src_ip and
                                    route_info['route'][
                                        'dst_len'] == nw_src_mask):
                                matching_dst = True
                        if not matching_dst:
                            ovs.del_flow(flow, bridge,
                                         constants.OVS_VRF_RULE_COOKIE)

    def _remove_extra_exposed_ips(self):
        for lo, ips in self._ovn_exposed_evpn_ips.items():
            exposed_ips_on_device = linux_net.get_exposed_ips(lo)
            for ip in exposed_ips_on_device:
                if ip not in ips:
                    linux_net.del_ips_from_dev(lo, [ip])

    def _get_table_ids(self):
        table_ids = []
        for cr_lrp_info in self.ovn_local_cr_lrps.values():
            table_ids.append(cr_lrp_info['vni'])
        return table_ids

    def _get_cr_lrp_mac_vrf_mapping(self):
        mac_vrf_mappings = {}
        for cr_lrp_info in self.ovn_local_cr_lrps.values():
            mac_vrf_mappings[cr_lrp_info['mac']] = cr_lrp_info['vrf']
        return mac_vrf_mappings
