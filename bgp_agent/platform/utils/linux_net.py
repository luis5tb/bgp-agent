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
import random
import re
import sys

from pyroute2.netlink.rtnl import ndmsg
from socket import AF_INET
from socket import AF_INET6

from oslo_concurrency import processutils
from oslo_log import log as logging

from bgp_agent import constants
from bgp_agent.utils import utils

LOG = logging.getLogger(__name__)


def ensure_vrf(vrf_name, vrf_table):
    with pyroute2.NDB() as ndb:
        try:
            with ndb.interfaces[vrf_name] as vrf:
                if vrf['state'] != "up":
                    vrf['state'] = 'up'
        except KeyError:
            ndb.interfaces.create(
                kind="vrf", ifname=vrf_name, vrf_table=vrf_table).set(
                    'state', 'up').commit()


def ensure_ovn_device(ovn_ifname, vrf_name):
    with pyroute2.NDB() as ndb:
        try:
            with ndb.interfaces[ovn_ifname] as iface:
                if iface['state'] != "up":
                    iface['state'] = 'up'
        except KeyError:
            ndb.interfaces.create(
                kind="dummy", ifname=ovn_ifname).set('state', 'up').commit()

        # Check if already associated to a vrf, and associate it if not
        if not ndb.interfaces[ovn_ifname].get('master'):
            with ndb.interfaces[ovn_ifname] as iface:
                iface.set('master', ndb.interfaces[vrf_name]['index'])


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
    # if not configured, add random number for the table
    else:
        LOG.debug(("Routing table for bridge {} not configured "
                   "at /etc/iproute2/rt_tables").format(bridge))
        regex = '^[0-9]+[\s]*'
        existing_routes = [int(line.replace('\t', ' ').split(' ')[0])
                           for line in open('/etc/iproute2/rt_tables')
                           if re.findall(regex, line)]
        # pick a number between 1 and 252
        try:
            table_number = random.choice(
                [x for x in range(1, 253) if x not in existing_routes])
        except IndexError:
            LOG.error(("No more routing tables available for bridge {} "
                       "at /etc/iproute2/rt_tables").format(bridge))
            sys.exit()

        with open('/etc/iproute2/rt_tables', 'a') as rt_tables:
            rt_tables.write('{} {}\n'.format(table_number, bridge))

        ovn_routing_tables[bridge] = int(table_number)
        LOG.debug("Added routing table for {} with number: {}".format(bridge,
                  table_number))

    # add default route on that table if it does not exist
    extra_routes = []

    with pyroute2.NDB() as ndb:
        table_route_dsts = set([r.dst for r in ndb.routes.summary()
                                if r.table == ovn_routing_tables[bridge]])
        if not table_route_dsts:
            ndb.routes.create(dst='default',
                              oif=ndb.interfaces[bridge]['index'],
                              table=ovn_routing_tables[bridge],
                              scope=253,
                              proto=3).commit()
            ndb.routes.create(dst='default',
                              oif=ndb.interfaces[bridge]['index'],
                              table=ovn_routing_tables[bridge],
                              family=AF_INET6,
                              proto=3).commit()
        else:
            route_missing = True
            route6_missing = True
            for dst in table_route_dsts:
                if not dst:  # default route
                    try:
                        route =  ndb.routes[
                            {'table': ovn_routing_tables[bridge],
                             'dst': '',
                             'family': AF_INET}]
                        if (ndb.interfaces[{'index': route['oif']}]['ifname']
                                == bridge):
                            route_missing = False
                        else:
                            extra_routes.append(route)
                    except KeyError:
                        pass  # no ipv4 default rule
                    try:
                        route_6 =  ndb.routes[
                            {'table': ovn_routing_tables[bridge],
                             'dst': '',
                             'family': AF_INET6}]
                        if (ndb.interfaces[{'index': route_6['oif']}]['ifname']
                                == bridge):
                            route6_missing = False
                        else:
                            extra_routes.append(route_6)
                    except KeyError:
                        pass  # no ipv6 default rule
                else:
                    extra_routes.append(
                        ndb.routes[{'table': ovn_routing_tables[bridge],
                                    'dst': dst}]
                    )

            if route_missing:
                ndb.routes.create(dst='default',
                                  oif=ndb.interfaces[bridge]['index'],
                                  table=ovn_routing_tables[bridge],
                                  scope=253,
                                  proto=3).commit()
            if route6_missing:
                ndb.routes.create(dst='default',
                                  oif=ndb.interfaces[bridge]['index'],
                                  table=ovn_routing_tables[bridge],
                                  family=AF_INET6,
                                  proto=3).commit()
    return extra_routes


def ensure_vlan_device_for_network(bridge, vlan_tag):
    vlan_tag = vlan_tag[0]
    vlan_device_name = '{}.{}'.format(bridge, vlan_tag)

    with pyroute2.NDB() as ndb:
        try:
            with ndb.interfaces[vlan_device_name] as iface:
                if iface['state'] != "up":
                    iface['state'] = 'up'
        except KeyError:
            ndb.interfaces.create(kind="vlan", ifname=vlan_device_name,
                vlan_id=vlan_tag, link=ndb.interfaces[bridge]['index']).set(
                    'state', 'up').commit()

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
    with pyroute2.NDB() as ndb:
        exposed_ips = [ip.address
                       for ip in ndb.interfaces[nic].ipaddr.summary()
                       if ip.prefixlen == 32 or ip.prefixlen == 128]
    return exposed_ips


def get_exposed_ips_on_network(nic, network):
    exposed_ips = []
    with pyroute2.NDB() as ndb:
        exposed_ips = [ip.address
                       for ip in ndb.interfaces[nic].ipaddr.summary()
                       if (ip.prefixlen == 32 or ip.prefixlen == 128 and
                           ipaddress.ip_address(ip.address) in network)]
    return exposed_ips


def get_ovn_ip_rules(routing_table):
    # get the rules pointing to ovn bridges
    ovn_ip_rules = {}
    with pyroute2.NDB() as ndb:
        rules_info = [(rule.table, "{}/{}".format(rule.dst, rule.dst_len), rule.family) for rule in ndb.rules.dump()
                      if rule.table in routing_table]
        for table, dst, family in rules_info:
            ovn_ip_rules[dst] = {'table': table, 'family': family}
    return ovn_ip_rules


def delete_exposed_ips(ips, nic):
    with pyroute2.NDB() as ndb:
        for ip in ips:
            address = '{}/32'.format(ip)
            if utils.get_ip_version(ip) == constants.IP_VERSION_6:
                address = '{}/128'.format(ip)
            try:
                ndb.interfaces[nic].ipaddr[address].remove().commit()
            except KeyError:
                LOG.debug("IP address {} already removed from nic {}.".format(
                    ip, nic))


def delete_ip_rules(ip_rules):
    with pyroute2.NDB() as ndb:
        for rule_ip, rule_info in ip_rules.items():
            rule = {'dst': rule_ip.split("/")[0],
                    'dst_len': rule_ip.split("/")[1],
                    'table': rule_info['table'],
                    'family': rule_info['family']}
            try:
                with ndb.rules[rule] as r:
                    r.remove()
            except KeyError:
                LOG.debug("Rule {} already deleted".format(rule))
            except pyroute2.netlink.exceptions.NetlinkError:
                # FIXME: There is a issue with NDB and ip rules deletion:
                # https://github.com/svinota/pyroute2/issues/771
                LOG.debug("This should not happen, skipping")


def delete_bridge_ip_routes(routing_tables, routing_tables_routes,
                            extra_routes): 
    with pyroute2.NDB() as ndb:
        for bridge, routes_info in routing_tables_routes.items():
            if not extra_routes[bridge]:
                continue
            for route_info in routes_info:
                oif = ndb.interfaces[bridge]['index']
                if route_info['vlan']:
                    vlan_device_name = '{}.{}'.format(bridge,
                                                      route_info['vlan'])
                    oif = ndb.interfaces[vlan_device_name]['index']
                if 'gateway' in route_info['route'].keys():  # subnet route
                    possible_matchings = [
                        r for r in extra_routes[bridge]
                        if (r['dst'] == route_info['route']['dst'] and
                            r['dst_len'] == route_info['route']['dst_len'] and
                            r['gateway'] == route_info['route']['gateway'])]
                else:  # cr-lrp
                    possible_matchings = [
                        r for r in extra_routes[bridge]
                        if (r['dst'] == route_info['route']['dst'] and
                            r['dst_len'] == route_info['route']['dst_len'] and
                            r['oif'] == oif)]
                for r in possible_matchings:
                    extra_routes[bridge].remove(r)

        for bridge, routes in extra_routes.items():
            for route in routes:
                r_info = {'dst': route['dst'],
                          'dst_len': route['dst_len'],
                          'family': route['family'],
                          'oif': route['oif'],
                          'gateway': route['gateway'],
                          'table': routing_tables[bridge]}
                try:
                    with ndb.routes[r_info] as r:
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
    with pyroute2.NDB() as ndb:
        try:
            with ndb.interfaces[nic] as iface:
                for ip in ips:
                    address = '{}/32'.format(ip)
                    if utils.get_ip_version(ip) == constants.IP_VERSION_6:
                        address = '{}/128'.format(ip)
                    iface.add_ip(address)
        except KeyError:
            # NDB raises KeyError: 'object exists'
            # if the ip is already added
            pass


def del_ips_from_dev(nic, ips):
    with pyroute2.NDB() as ndb:
        with ndb.interfaces[nic] as iface:
            for ip in ips:
                address = '{}/32'.format(ip)
                if utils.get_ip_version(ip) == constants.IP_VERSION_6:
                    address = '{}/128'.format(ip)
                iface.del_ip(address)


def add_ip_rule(ip, table, dev=None, lladdr=None):
    ip_version = utils.get_ip_version(ip)
    ip_info = ip.split("/")

    if len(ip_info) == 1:
        rule = {'dst': ip_info[0], 'table': table, 'dst_len': 32}
        if ip_version == constants.IP_VERSION_6:
            rule['dst_len'] = 128
            rule['family'] = AF_INET6
    elif len(ip_info) == 2:
        rule = {'dst': ip_info[0], 'table': table, 'dst_len': int(ip_info[1])}
        if ip_version == constants.IP_VERSION_6:
            rule['family'] = AF_INET6
    else:
        LOG.error("Invalid ip: {}".format(ip))
        return

    with pyroute2.NDB() as ndb:
        try:
            ndb.rules[rule]
        except KeyError:
            LOG.debug("Creating ip rule with: {}".format(rule))
            ndb.rules.create(rule).commit()

    # FIXME: There is no support for creating neighbours in NDB
    # So we are using iproute here
    if lladdr:
        ip_version = utils.get_ip_version(ip)
        with pyroute2.IPRoute() as iproute:
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
    ip_info = ip.split("/")

    if len(ip_info) == 1:
        rule = {'dst': ip_info[0], 'table': table, 'dst_len': 32}
        if ip_version == constants.IP_VERSION_6:
            rule['dst_len'] = 128
            rule['family'] = AF_INET6
    elif len(ip_info) == 2:
        rule = {'dst': ip_info[0], 'table': table, 'dst_len': int(ip_info[1])}
        if ip_version == constants.IP_VERSION_6:
            rule['family'] = AF_INET6
    else:
        LOG.error("Invalid ip: {}".format(ip))
        return
    with pyroute2.NDB() as ndb:
        try:
            ndb.rules[rule].remove().commit()
            LOG.debug("Deleting ip rule with: {}".format(rule))
        except KeyError:
            LOG.debug("Rule already deleted: {}".format(rule))

    # FIXME: There is no support for deleting neighbours in NDB
    # So we are using iproute here
    if lladdr:
        ip_version = utils.get_ip_version(ip)
        with pyroute2.IPRoute() as iproute:
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
    net_ip = ip_address
    if not mask:  # default /32 or /128   
        if utils.get_ip_version(ip_address) == constants.IP_VERSION_6:
            mask = 128
        else:
            mask = 32
    else:
        ip = '{}/{}'.format(ip_address, mask)
        if utils.get_ip_version(ip_address) == constants.IP_VERSION_6:
            net_ip = '{}'.format(ipaddress.IPv6Network(
                ip, strict=False).network_address)
        else:
            net_ip = '{}'.format(ipaddress.IPv4Network(
                ip, strict=False).network_address)

    with pyroute2.NDB() as ndb:
        if vlan:
            oif_name = '{}.{}'.format(dev, vlan)
            oif = ndb.interfaces[oif_name]['index']
        else:
            oif = ndb.interfaces[dev]['index']

    route = {'dst': net_ip, 'dst_len': int(mask), 'oif': oif,
             'table': rule_table, 'proto': 3}
    if via:
        route['gateway'] = via
        route['scope'] = 0
    else:
        route['scope'] = 253
    if utils.get_ip_version(net_ip) == constants.IP_VERSION_6:
        route['family'] = AF_INET6
        del route['scope']


    with pyroute2.NDB() as ndb:
        try:
            with ndb.routes[route] as r:
                LOG.debug("Route already existing: {}".format(r))
        except KeyError:
            ndb.routes.create(route).commit()
            LOG.debug("Route created at table {}: {}".format(rule_table,
                                                             route))
    route_info = {'vlan': vlan, 'route': route}
    ovn_routing_tables_routes.setdefault(dev, []).append(route_info)


def del_ip_route(ovn_routing_tables_routes, ip_address, rule_table, dev,
                  vlan=None, mask=None, via=None):
    net_ip = ip_address
    if not mask:  # default /32 or /128   
        if utils.get_ip_version(ip_address) == constants.IP_VERSION_6:
            mask = 128
        else:
            mask = 32
    else:
        ip = '{}/{}'.format(ip_address, mask)
        if utils.get_ip_version(ip_address) == constants.IP_VERSION_6:
            net_ip = '{}'.format(ipaddress.IPv6Network(
                ip, strict=False).network_address)
        else:
            net_ip = '{}'.format(ipaddress.IPv4Network(
                ip, strict=False).network_address)

    with pyroute2.NDB() as ndb:
        if vlan:
            oif_name = '{}.{}'.format(dev, vlan)
            oif = ndb.interfaces[oif_name]['index']
        else:
            oif = ndb.interfaces[dev]['index']

    route = {'dst': net_ip, 'dst_len': int(mask), 'oif': oif,
             'table': rule_table, 'proto': 3}
    if via:
        route['gateway'] = via
        route['scope'] = 0
    else:
        route['scope'] = 253
    if utils.get_ip_version(net_ip) == constants.IP_VERSION_6:
        route['family'] = AF_INET6

    with pyroute2.NDB() as ndb:
        try:
            with ndb.routes[route] as r:
                r.remove()
            LOG.debug("Route deleted at table {}: {}".format(rule_table,
                                                             route))
            route_info = {'vlan': vlan, 'route': route}
            ovn_routing_tables_routes[dev].remove(route_info)
        except (KeyError, ValueError):
            LOG.debug("Route already deleted: {}".format(route))