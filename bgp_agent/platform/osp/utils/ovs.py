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

import pyroute2

from ovs.db import idl
from oslo_concurrency import processutils

from bgp_agent import constants

from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.schema.open_vswitch import impl_idl as idl_ovs


def ovs_cmd(command, args, timeout=None):
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


def get_ovs_flows(bridge, flows_info):
    ovs_ports = ovs_cmd('ovs-vsctl',
                        ['list-ports', bridge])[0].rstrip()
    if not ovs_ports:
        flow = ("cookie={}/-1").format(constants.OVS_RULE_COOKIE)
        ovs_cmd('ovs-ofctl', ['del-flows', bridge, flow])
        return
    for ovs_port in ovs_ports.split("\n"):
        ovs_ofport = ovs_cmd(
            'ovs-vsctl',
            ['get', 'Interface', ovs_port, 'ofport'])[0].rstrip()
        flows_info[bridge]['in_port'].add(ovs_ofport)


def remove_extra_ovs_flows(flows_info):
    for bridge, info in flows_info.items():
        for in_port in info.get('in_port'):
            flow = ("cookie={},priority=1000,ip,in_port={},"
                    "actions=mod_dl_dst:{},NORMAL".format(
                        constants.OVS_RULE_COOKIE, in_port,
                        info['mac']))
            flow_v6 = ("cookie={},priority=1000,ipv6,in_port={},"
                        "actions=mod_dl_dst:{},NORMAL".format(
                            constants.OVS_RULE_COOKIE, in_port,
                            info['mac']))
            ovs_cmd('ovs-ofctl', ['add-flow', bridge, flow])
            ovs_cmd('ovs-ofctl', ['add-flow', bridge, flow_v6])

            cookie = ("cookie={}/-1").format(constants.OVS_RULE_COOKIE)
            current_flows = ovs_cmd(
                'ovs-ofctl', ['dump-flows', bridge, cookie]
                )[0].split('\n')[1:-1]
            for flow in current_flows:
                agent_flow = False
                for port in info.get('in_port'):
                    in_port = 'in_port={}'.format(port)
                    if in_port in flow:
                        agent_flow = True
                        break
                if agent_flow:
                    continue
                in_port = flow.split("in_port=")[1].split(" ")[0]
                del_flow = ('{},in_port={}').format(cookie, in_port)
                ovs_cmd('ovs-ofctl', ['del-flows', bridge, del_flow])


def ensure_bridge_ovs_flows(ovn_bridge_mappings):
    cookie = ("cookie={}/-1").format(constants.OVS_RULE_COOKIE)
    for bridge in ovn_bridge_mappings:
        mac = None
        with pyroute2.NDB().interfaces[bridge] as iface:
            mac = iface['address']
        ovs_port = ovs_cmd('ovs-vsctl', ['list-ports', bridge])[0].rstrip()
        if not ovs_port:
            continue
        ovs_ofport = ovs_cmd(
            'ovs-vsctl', ['get', 'Interface', ovs_port, 'ofport']
            )[0].rstrip()
        flow_filter = ('{},in_port={}').format(cookie, ovs_ofport)
        current_flows = ovs_cmd(
            'ovs-ofctl', ['dump-flows', bridge, flow_filter]
            )[0].split('\n')[1:-1]
        if len(current_flows) == 1:
            # assume the rule is the right one as it has the right cookie
            # and in_port
            continue

        flow = ("cookie={},priority=1000,ip,in_port={},"
                "actions=mod_dl_dst:{},NORMAL".format(
                constants.OVS_RULE_COOKIE, ovs_ofport, mac))
        ovs_cmd('ovs-ofctl', ['add-flow', bridge, flow])

        # Remove unneeded flows
        cookie = ("cookie={}/-1").format(constants.OVS_RULE_COOKIE)
        port = 'in_port={}'.format(ovs_ofport)
        current_flows = ovs_cmd(
                'ovs-ofctl', ['dump-flows', bridge, cookie]
                )[0].split('\n')[1:-1]
        for flow in current_flows:
            if not flow or port in flow:
                continue
            in_port = flow.split("in_port=")[1].split(" ")[0]
            del_flow = ('{},in_port={}').format(cookie, in_port)
            ovs_cmd('ovs-ofctl', ['del-flows', bridge, del_flow])

class OvsIdl(object):
    def start(self, connection_string):
        helper = idlutils.get_schema_helper(connection_string,
                                            'Open_vSwitch')
        tables = ('Open_vSwitch', 'Bridge', 'Port', 'Interface')
        for table in tables:
            helper.register_table(table)
        ovs_idl = idl.Idl(connection_string, helper)
        ovs_idl._session.reconnect.set_probe_interval(60000)
        conn = connection.Connection(
            ovs_idl, timeout=180)
        self.idl_ovs = idl_ovs.OvsdbIdl(conn)

    def get_own_chassis_name(self):
        """Return the external_ids:system-id value of the Open_vSwitch table.

        As long as ovn-controller is running on this node, the key is
        guaranteed to exist and will include the chassis name.
        """
        ext_ids = self.idl_ovs.db_get(
            'Open_vSwitch', '.', 'external_ids').execute()
        return ext_ids['system-id']

    def get_ovn_remote(self):
        """Return the external_ids:ovn-remote value of the Open_vSwitch table.

        """
        ext_ids = self.idl_ovs.db_get(
            'Open_vSwitch', '.', 'external_ids').execute()
        return ext_ids['ovn-remote']

    def get_ovn_bridge_mappings(self):
        """Return the external_ids:ovn-bridge-mappings value of the Open_vSwitch table.

        """
        ext_ids = self.idl_ovs.db_get(
            'Open_vSwitch', '.', 'external_ids').execute()
        try:
            return ext_ids['ovn-bridge-mappings'].split(",")
        except KeyError:
            return []