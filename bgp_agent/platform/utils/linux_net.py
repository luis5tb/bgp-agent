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

import ipaddress
import pyroute2
import re
import sys

from pyroute2.netlink.rtnl import ndmsg
from socket import AF_INET6

from oslo_concurrency import processutils
from oslo_log import log as logging

from bgp_agent import constants
from bgp_agent.utils import utils

LOG = logging.getLogger(__name__)


def ensure_vrf(vrf_name, vrf_table):
    with pyroute2.IPDB() as ipdb:
        try:
            with ipdb.interfaces[vrf_name] as vrf:
                if vrf.state != "up":
                    vrf.up()
        except KeyError:
            with ipdb.create(kind="vrf",
                                ifname=vrf_name,
                                vrf_table=vrf_table) as vrf:
                vrf.up()


def ensure_ovn_device(ovn_ifname, vrf_name):
    with pyroute2.IPDB() as ipdb:
        try:
            with ipdb.interfaces[ovn_ifname] as iface:
                if iface.state != "up":
                    iface.up()
        except KeyError:
            with ipdb.create(kind="dummy",
                             ifname=ovn_ifname) as iface:
                iface.up()

        with pyroute2.IPRoute() as ip:
            # Associate device to VRF
            ovn_nic_index = ip.link_lookup(ifname=ovn_ifname)[0]
            ovn_nic = ip.link("get", index=ovn_nic_index)[0]

        # Check if already associated to a vrf, and associate it if not
        if not ovn_nic.get_attr("IFLA_MASTER"):
            with ipdb.interfaces[vrf_name] as vrf:
                vrf.add_port(ovn_nic_index)


def ensure_routing_table_for_bridge(ovn_routing_tables, bridge):
    # check a routing table with the bridge name exists on
    # /etc/iproute2/rt_tables
    regex = '^[0-9]*[\s]*{}$'.format(bridge)
    matching_table = [line.replace('\t', ' ')
                        for line in open('/etc/iproute2/rt_tables')
                        if re.findall(regex, line)]
    if matching_table:
        table_info = matching_table[0].strip().split()
        ovn_routing_tables[table_info[1]] = int(table_info[0])
        LOG.debug("Found routing table for {} with: {}".format(bridge,
                  table_info))
    # if not raise configuration error and exit
    else:
        LOG.error(("Routing table for bridge {} must be configure "
                   "at /etc/iproute2/rt_tables").format(bridge))
        sys.exit()

    # add default route on that table if it does not exist
    extra_routes = []
    with pyroute2.IPDB() as ipdb:
        try:
            table_route = ipdb.routes.tables[
                ovn_routing_tables[bridge]]
        except KeyError:  # if there is no rules, ipdb returns KeyError
            ipdb.routes.add(dst='default',
                            oif=ipdb.interfaces[bridge].index,
                            table=ovn_routing_tables[bridge],
                            scope=253,
                            proto=3
                            ).commit()
            ipdb.routes.add(dst='default',
                            oif=ipdb.interfaces[bridge].index,
                            table=ovn_routing_tables[bridge],
                            family=AF_INET6,
                            proto=3
                            ).commit()
        else:
            route_missing = True
            route6_missing = True
            for route in table_route:
                if (route['dst'] == 'default' and
                        ipdb.interfaces[route['oif']].ifname == bridge):
                    if route['family'] == AF_INET6:
                        route6_missing = False
                    else:
                        route_missing = False
                else:
                    extra_routes.append(route)
            if route_missing:
                ipdb.routes.add(dst='default',
                                oif=ipdb.interfaces[bridge].index,
                                table=ovn_routing_tables[bridge],
                                scope=253,
                                proto=3
                                ).commit()
            if route6_missing:
                ipdb.routes.add(dst='default',
                                oif=ipdb.interfaces[bridge].index,
                                table=ovn_routing_tables[bridge],
                                family=AF_INET6,
                                proto=3
                                ).commit()
    return extra_routes


def ensure_vlan_device_for_network(bridge, vlan_tag):
    vlan_tag = vlan_tag[0]
    vlan_device_name = '{}.{}'.format(bridge, vlan_tag)

    with pyroute2.IPDB() as ipdb:
        try:
            with ipdb.interfaces[vlan_device_name] as iface:
                if iface.state != "up":
                    iface.up()
        except KeyError:
            with ipdb.create(kind="vlan",
                             ifname=vlan_device_name,
                             vlan_id=vlan_tag,
                             link=ipdb.interfaces[bridge].index) as iface:
                iface.up()

    ipv4_flag = "net.ipv4.conf.{}/{}.proxy_arp".format(bridge, vlan_tag)
    _set_kernel_flag(ipv4_flag, 1)
    ipv6_flag = "net.ipv6.conf.{}/{}.proxy_ndp".format(bridge, vlan_tag)
    _set_kernel_flag(ipv6_flag, 1)


def _set_kernel_flag(flag, value):
    command = ["sysctl", "-w", "{}={}".format(flag, value)]
    try:
        return processutils.execute(*command, run_as_root=True)
    except Exception as e:
        LOG.error("Unable to execute {}. Exception: {}".format(
                  command, e))
        raise


def get_exposed_ips(nic):
    exposed_ips = []
    with pyroute2.IPDB() as ipdb:
        with ipdb.interfaces[nic] as iface:
            exposed_ips = [ip[0] for ip in iface.ipaddr
                        if ip[1] == 32 or ip[1] == 128]
    return exposed_ips


def get_exposed_ips_on_network(nic, network):
    exposed_ips = []
    with pyroute2.IPDB() as ipdb:
        with ipdb.interfaces[nic] as iface:
            exposed_ips = [ip[0] for ip in iface.ipaddr
                           if ((ip[1] == 32 or ip[1] == 128) and
                               ipaddress.ip_address(ip[0]) in network)]
    return exposed_ips


def get_ovn_ip_rules(routing_table):
    # get the rules pointing to ovn bridges
    ovn_ip_rules = {}
    with pyroute2.IPRoute() as ip:
        for table in routing_table:
            for rule in ip.get_rules(table=table):
                dst = rule.get_attrs('FRA_DST')[0]
                mask = rule['dst_len']
                ovn_ip_rules[dst] = {'table': table, 'mask': mask}
            for rule in ip.get_rules(table=table, family=AF_INET6):
                dst = rule.get_attrs('FRA_DST')[0]
                mask = rule['dst_len']
                ovn_ip_rules[dst] = {'table': table, 'mask': mask}
    return ovn_ip_rules


def delete_exposed_ips(ips, nic):
    with pyroute2.IPDB() as ipdb:
        with ipdb.interfaces[nic] as iface:
            for ip in ips:
                if utils.get_ip_version(ip) == constants.IP_VERSION_6:
                    iface.del_ip(ip, 128)
                else:
                    iface.del_ip(ip, 32)


def delete_ip_rules(ip_rules):
    with pyroute2.IPRoute() as ip:
        for rule_ip, rule_info in ip_rules.items():
            rule = {'dst': '{}/{}'.format(rule_ip, rule_info['mask']),
                    'table': rule_info['table']}
            if utils.get_ip_version(rule_ip) == constants.IP_VERSION_6:
                rule['family'] = AF_INET6
            ip.rule('del', **rule)


def delete_bridge_ip_routes(routing_tables, routing_tables_routes,
                            extra_routes): 
    with pyroute2.IPDB() as ipdb:
        for bridge, routes_info in routing_tables_routes.items():
            if not extra_routes[bridge]:
                continue
            for route_info in routes_info:
                oif = ipdb.interfaces[bridge].index
                if route_info['vlan']:
                    vlan_device_name = '{}.{}'.format(bridge,
                                                      route_info['vlan'])
                    oif = ipdb.interfaces[vlan_device_name].index

                if 'gateway' in route_info['route'].keys():  # subnet route
                    possible_matchings = [
                        r for r in extra_routes[bridge]
                        if (r['dst'] == route_info['route']['dst'] and
                            r['oif'] == oif and
                            r['gateway'] == route_info['route']['gateway'])]
                else:  # cr-lrp
                    possible_matchings = [
                        r for r in extra_routes[bridge]
                        if (r['dst'] == route_info['route']['dst'] and
                            r['oif'] == oif)]
                for r in possible_matchings:
                    extra_routes[bridge].remove(r)

        for bridge, routes in extra_routes.items():
            routing_table = routing_tables[bridge]
            for route in routes:
                try:
                    with ipdb.routes.tables[routing_table][route] as r:
                        r.remove()
                except KeyError:
                    LOG.debug("Route already deleted: {}".format(route))


def add_ndp_proxy(ip, dev, vlan=None):
    # FIXME(ltomasbo): This should use pyroute instead but I didn't find
    # out how
    net_ip = str(ipaddress.IPv6Network(ip, strict=False).network_address)
    dev_name = dev
    if vlan:
        dev_name = "{}.{}".format(dev, vlan)
    command = ["ip", "-6", "nei", "add", "proxy", net_ip, "dev", dev_name]
    try:
        return processutils.execute(*command, run_as_root=True)
    except Exception as e:
        LOG.error("Unable to execute {}. Exception: {}".format(
                  command, e))
        raise


def del_ndp_proxy(ip, dev, vlan=None):
    # FIXME(ltomasbo): This should use pyroute instead but I didn't find
    # out how
    net_ip = str(ipaddress.IPv6Network(ip, strict=False).network_address)
    dev_name = dev
    if vlan:
        dev_name = "{}.{}".format(dev, vlan)
    command = ["ip", "-6", "nei", "del", "proxy", net_ip, "dev", dev_name]
    try:
        return processutils.execute(*command, run_as_root=True)
    except Exception as e:
        if "No such file or directory" in e.stderr:
            # Already deleted
            return
        LOG.error("Unable to execute {}. Exception: {}".format(
                  command, e))
        raise


def add_ips_to_dev(nic, ips):
    with pyroute2.IPDB() as ipdb:
        with ipdb.interfaces[nic] as iface:
            for ip in ips:
                if utils.get_ip_version(ip) == constants.IP_VERSION_6:
                    iface.add_ip('%s/%s' % (ip, 128))
                else:
                    iface.add_ip('%s/%s' % (ip, 32))


def del_ips_from_dev(nic, ips):
    with pyroute2.IPDB() as ipdb:
        with ipdb.interfaces[nic] as iface:
            for ip in ips:
                if utils.get_ip_version(ip) == constants.IP_VERSION_6:
                    iface.del_ip('%s/%s' % (ip, 128))
                else:
                    iface.del_ip('%s/%s' % (ip, 32))


def add_ip_rule(ip, table, dev=None, lladdr=None):
    ip_version = utils.get_ip_version(ip)
    rule = {'dst': ip, 'table': table}
    # REMOVEME: due to a problem with pyroute, look for the rule too
    # without the mask
    rule_aux = {'dst': ip.split("/")[0], 'table': table}
    if ip_version == constants.IP_VERSION_6:
        rule['family'] = AF_INET6
        rule_aux['family'] = AF_INET6

    with pyroute2.IPRoute() as iproute:
        if (not iproute.get_rules(**rule) and
                not iproute.get_rules(**rule_aux)):
            iproute.rule('add', **rule)
        if lladdr:
            # This is doing something like:
            # sudo ip nei replace 172.24.4.69
            # lladdr fa:16:3e:d3:5d:7b dev br-ex nud permanent
            network_bridge_if = iproute.link_lookup(ifname=dev)[0]
            if ip_version == constants.IP_VERSION_6:
                iproute.neigh('set',
                              dst=ip,
                              lladdr=lladdr,
                              family=AF_INET6,
                              ifindex=network_bridge_if,
                              state=ndmsg.states['permanent'])
            else:
                iproute.neigh('set',
                              dst=ip,
                              lladdr=lladdr,
                              ifindex=network_bridge_if,
                              state=ndmsg.states['permanent'])


def del_ip_rule(ip, table, dev=None, lladdr=None):
    ip_version = utils.get_ip_version(ip)
    rule = {'dst': ip, 'table': table}
    # REMOVEME: due to a problem with pyroute, look for the rule too
    # without the mask
    rule_aux = {'dst': ip.split("/")[0], 'table': table}
    if ip_version == constants.IP_VERSION_6:
        rule['family'] = AF_INET6
        rule_aux['family'] = AF_INET6
    with pyroute2.IPRoute() as iproute:
        if iproute.get_rules(**rule) or iproute.get_rules(**rule_aux):
            iproute.rule('del', **rule)
        if lladdr:
            # This is doing something like:
            # sudo ip nei del 172.24.4.69
            # lladdr fa:16:3e:d3:5d:7b dev br-ex nud permanent
            network_bridge_if = iproute.link_lookup(
                ifname=dev)[0]
            if ip_version == constants.IP_VERSION_6:
                iproute.neigh('del',
                              dst=ip.split("/")[0],
                              lladdr=lladdr,
                              family=AF_INET6,
                              ifindex=network_bridge_if,
                              state=ndmsg.states['permanent'])
            else:
                iproute.neigh('del',
                              dst=ip.split("/")[0],
                              lladdr=lladdr,
                              ifindex=network_bridge_if,
                              state=ndmsg.states['permanent'])


def add_ip_route(ovn_routing_tables_routes, ip_address, rule_table, dev,
                  vlan=None, mask=None, via=None):
    if not mask:  # default /32 or /128
        if utils.get_ip_version(ip_address) == constants.IP_VERSION_6:
            ip = '{}/{}'.format(ip_address, 128)
        else:
            ip = '{}/{}'.format(ip_address, 32)
    else:
        ip = '{}/{}'.format(ip_address, mask)
        if utils.get_ip_version(ip_address) == constants.IP_VERSION_6:
            net_ip = ipaddress.IPv6Network(ip,
                                            strict=False).network_address
            ip = '{}/{}'.format(net_ip, mask)
        else:
            net_ip = ipaddress.IPv4Network(ip,
                                            strict=False).network_address
            ip = '{}/{}'.format(net_ip, mask)

    if via:
        route = {'dst': ip, 'gateway': via, 'table': rule_table,
                 'proto': 3, 'scope': 0}
    else:
        with pyroute2.IPRoute() as iproute:
            if vlan:
                oif_name = '{}.{}'.format(dev, vlan)
                oif = iproute.link_lookup(ifname=oif_name)[0]
            else:
                oif = iproute.link_lookup(ifname=dev)[0]
        route = {'dst': ip, 'oif': oif, 'table': rule_table, 'proto': 3,
                 'scope': 253}
    if utils.get_ip_version(ip) == constants.IP_VERSION_6:
        route['family'] = AF_INET6
        del route['scope']
    with pyroute2.IPDB() as ipdb:
        try:
            ipdb.routes.tables[rule_table][route]
            LOG.debug("Route already existing: {}".format(route))
        except KeyError:
            ipdb.routes.add(route).commit()
            LOG.debug("Route created at table {}: {}".format(rule_table,
                                                             route))
    route_info = {'vlan': vlan, 'route': route}
    ovn_routing_tables_routes.setdefault(dev, []).append(route_info)


def del_ip_route(ovn_routing_tables_routes, ip_address, rule_table, dev,
                  vlan=None, mask=None, via=None):
    if not mask:  # default /32 or /128
        if utils.get_ip_version(ip_address) == constants.IP_VERSION_6:
            ip = '{}/{}'.format(ip_address, 128)
        else:
            ip = '{}/{}'.format(ip_address, 32)
    else:
        ip = '{}/{}'.format(ip_address, mask)
        if utils.get_ip_version(ip_address) == constants.IP_VERSION_6:
            net_ip = ipaddress.IPv6Network(ip,
                                            strict=False).network_address
            ip = '{}/{}'.format(net_ip, mask)
        else:
            net_ip = ipaddress.IPv4Network(ip,
                                            strict=False).network_address
            ip = '{}/{}'.format(net_ip, mask)

    if via:
        route = {'dst': ip, 'gateway': via, 'table': rule_table,
                 'proto': 3, 'scope': 0}
    else:
        with pyroute2.IPRoute() as iproute:
            if vlan:
                oif_name = '{}.{}'.format(dev, vlan)
                oif = iproute.link_lookup(ifname=oif_name)[0]
            else:
                oif = iproute.link_lookup(ifname=dev)[0]
        route = {'dst': ip, 'oif': oif, 'table': rule_table, 'proto': 3,
                 'scope': 253}
    if utils.get_ip_version(ip) == constants.IP_VERSION_6:
        route['family'] = AF_INET6
        del route['scope']
    with pyroute2.IPDB() as ipdb:
        try:
            with ipdb.routes.tables[rule_table][route] as r:
                r.remove()
            LOG.debug("Route deleted at table {}: {}".format(rule_table,
                                                             route))
            route_info = {'vlan': vlan, 'route': route}
            ovn_routing_tables_routes[dev].remove(route_info)
        except KeyError:
            LOG.debug("Route already deleted: {}".format(route))