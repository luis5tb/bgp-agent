import abc
import re
import sys
import time

import pyroute2
from pyroute2.ipdb import exceptions as ipdb_exc
from pyroute2.netlink.rtnl import ndmsg

from ovs.db import idl
from ovsdbapp.backend import ovs_idl
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import event as row_event
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp import event

from ovsdbapp.schema.open_vswitch import impl_idl as idl_ovs
from ovsdbapp.schema.ovn_southbound import impl_idl as sb_impl_idl

from oslo_concurrency import lockutils
from oslo_concurrency import processutils


OVN_VIF_PORT_TYPES = ("", "chassisredirect", )
_SYNC_STATE_LOCK = lockutils.ReaderWriterLock()
OVN_BGP_NIC = "ovn"
OVN_BGP_VRF = "ovn-bgp-vrf"
OVN_BGP_VRF_TABLE = 10
OVS_CONNECTION_STRING = "unix:/usr/local/var/run/openvswitch/db.sock"
OVS_RULE_COOKIE = "999"


class PortBindingChassisEvent(row_event.RowEvent):
    def __init__(self, bgp_agent, events):
        self.agent = bgp_agent
        table = 'Port_Binding'
        super(PortBindingChassisEvent, self).__init__(
            events, table, None)
        self.event_name = self.__class__.__name__


class PortBindingChassisCreatedEvent(PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(PortBindingChassisCreatedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if (len(row.mac[0].split(' ')) != 2 and 
                len(row.mac[0].split(' ')) != 3): 
                return False
            return (row.chassis[0].name == self.agent.chassis and
                    not old.chassis)
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type not in OVN_VIF_PORT_TYPES:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ip_address = row.mac[0].split(' ')[1]
            self.agent.add_bgp_route(ip_address, row)


class PortBindingChassisDeletedEvent(PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE)
        super(PortBindingChassisDeletedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if (len(row.mac[0].split(' ')) != 2 and 
                len(row.mac[0].split(' ')) != 3): 
                return False
            if event == self.ROW_UPDATE:
                return (old.chassis[0].name == self.agent.chassis and
                        not row.chassis)
            else:
                if row.chassis[0].name == self.agent.chassis:
                    return True
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type not in OVN_VIF_PORT_TYPES:
            return
        with _SYNC_STATE_LOCK.read_lock():
            ip_address = row.mac[0].split(' ')[1]
            self.agent.delete_bgp_route(ip_address, row)


class FIPSetEvent(PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(FIPSetEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            return (not row.chassis and row.nat_addresses != old.nat_addresses)
        except (AttributeError):
            return False

    def run(self, event, row, old):
        if row.type != 'patch':
            return
        with _SYNC_STATE_LOCK.read_lock():
            for nat in row.nat_addresses:
                if nat not in old.nat_addresses:
                    self.agent.add_bgp_fip_route(nat, row.datapath)


class FIPUnsetEvent(PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(FIPUnsetEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            return (not row.chassis and row.nat_addresses != old.nat_addresses)
        except (AttributeError):
            return False

    def run(self, event, row, old):
        if row.type != 'patch':
            return
        with _SYNC_STATE_LOCK.read_lock():
            for nat in old.nat_addresses:
                if nat not in row.nat_addresses:
                    self.agent.delete_bgp_fip_route(nat, old.datapath)


class ChassisCreateEventBase(row_event.RowEvent):
    table = None

    def __init__(self, bgp_agent):
        self.agent = bgp_agent
        self.first_time = True
        events = (self.ROW_CREATE,)
        super(ChassisCreateEventBase, self).__init__(
            events, self.table, (('name', '=', self.agent.chassis),))
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        if self.first_time:
            self.first_time = False
        else:
            print("Connection to OVSDB established, doing a full sync")
            self.agent.sync()


class ChassisCreateEvent(ChassisCreateEventBase):
    table = 'Chassis'


class ChassisPrivateCreateEvent(ChassisCreateEventBase):
    table = 'Chassis_Private'


class Backend(ovs_idl.Backend):
    lookup_table = {}
    ovsdb_connection = None

    def __init__(self, connection):
        self.ovsdb_connection = connection
        super(Backend, self).__init__(connection)

    @property
    def idl(self):
        return self.ovsdb_connection.idl

    @property
    def tables(self):
        return self.idl.tables


class OvsdbSbOvnIdl(sb_impl_idl.OvnSbApiIdlImpl, Backend):
    def __init__(self, connection):
        super(OvsdbSbOvnIdl, self).__init__(connection)
        self.idl._session.reconnect.set_probe_interval(60000)

    def is_provider_network(self, datapath):
        cmd = self.db_find_rows('Port_Binding', ('datapath', '=', datapath),
                                ('type', '=', 'localnet'))
        return next(iter(cmd.execute(check_error=True)), None)
        
    def get_fip_associated(self, port):
        cmd = self.db_find_rows('Port_Binding', ('type', '=', 'patch'))
        for row in cmd.execute(check_error=True):
            for fip in row.nat_addresses:
                if port in fip:
                    return fip.split(" ")[1], row.datapath
        return None, None
    
    def is_port_on_chasis(self, port, chassis):
        cmd = self.db_find_rows('Port_Binding', ('logical_port', '=', port))
        port_info = cmd.execute(check_error=True)
        try:
            if port_info and port_info[0].type == "" and port_info[0].chassis[0].name == chassis:
                return True
        except IndexError:
            pass
        return False

    def get_ports_on_chassis(self, chassis):
        rows = self.db_list_rows('Port_Binding').execute(check_error=True)
        return [r for r in rows if r.chassis and r.chassis[0].name == chassis]

    def get_network_name(self, datapath):
        cmd = self.db_find_rows('Port_Binding', ('datapath', '=', datapath),
                                ('type', '=', 'localnet'))
        for row in cmd.execute(cheeck_error=True):
            if row.options:
                return row.options.get('network_name')
        return None


class OvnDbNotifyHandler(event.RowEventHandler):
    def __init__(self, driver):
        super(OvnDbNotifyHandler, self).__init__()
        self.driver = driver


class OvnIdl(connection.OvsdbIdl):
    def __init__(self, driver, remote, schema):
        super(OvnIdl, self).__init__(remote, schema)
        self.driver = driver
        self.notify_handler = OvnDbNotifyHandler(driver)
        self.event_lock_name = "neutron_ovn_event_lock"

    def notify(self, event, row, updates=None):
        if self.is_lock_contended:
            return
        self.notify_handler.notify(event, row, updates)


class OvnSbIdl(OvnIdl):
    SCHEMA = 'OVN_Southbound'

    def __init__(self, connection_string, chassis=None, events=None, tables=None):
        helper = self._get_ovsdb_helper(connection_string)
        if tables is None:
            tables = ('Chassis', 'Encap', 'Port_Binding', 'Datapath_Binding',
                      'SB_Global')
        for table in tables:
            helper.register_table(table)
        super(OvnSbIdl, self).__init__(
            None, connection_string, helper)
        if chassis:
            table = ('Chassis_Private' if 'Chassis_Private' in tables
                     else 'Chassis')
            self.tables[table].condition = [['name', '==', chassis]]
        if events:
            self.notify_handler.watch_events(events)

    def _get_ovsdb_helper(self, connection_string):
        return idlutils.get_schema_helper(connection_string, self.SCHEMA)

    def start(self):
        conn = connection.Connection(
            self, timeout=180)
        return OvsdbSbOvnIdl(conn)


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
        return idl_ovs.OvsdbIdl(conn)


class BGPAgent(object):
    def _load_config(self):
        self.ovn_device = OVN_BGP_NIC
        self.ovn_vrf = OVN_BGP_VRF
        self.ovn_vrf_table = OVN_BGP_VRF_TABLE
        self.ovn_routing_tables = {} # {'br-ex': 200}
        self.ovn_bridge_mappings = {} # {'public': 'br-ex'}

        self.chassis = self._get_own_chassis_name()
        self.ovn_remote = self._get_ovn_remote()
        print("Loaded chassis {}.".format(self.chassis))

    def start(self, use_rules=False):
        print("Starting BGP Agent...")
        self.ovs_idl = OvsIdl().start(OVS_CONNECTION_STRING)
        self._use_rules = use_rules
        self._load_config()

        tables = ('Port_Binding', 'Datapath_Binding', 'SB_Global',
                  'Chassis')
        events = (PortBindingChassisCreatedEvent(self),
                  PortBindingChassisDeletedEvent(self),
                  FIPSetEvent(self),
                  FIPUnsetEvent(self))

        self.has_chassis_private = False
        try:
            self.sb_idl = OvnSbIdl(self.ovn_remote,
                chassis=self.chassis, tables=tables + ('Chassis_Private', ),
                events=events + (ChassisPrivateCreateEvent(self), )).start()
            self.has_chassis_private = True
        except AssertionError:
            self.sb_idl = OvnSbIdl(self.ovn_remote,
                chassis=self.chassis, tables=tables,
                events=events + (ChassisCreateEvent(self), )).start()

        print("BGP Agent Started...")
        # Do the initial sync.
        self.sync()

        while True:
            time.sleep(1)

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
            with ipdb.interfaces[self.ovn_device] as iface:
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
                with ipdb.interfaces[self.ovn_device] as iface:
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
                ipdb = pyroute2.IPDB()
                with ipdb.interfaces[self.ovn_device] as iface:
                    iface.add_ip('%s/%s' % (cr_lrp_address, 32))
                if self._use_rules:
                    self._add_ip_rule(cr_lrp_address, cr_lrp_datapath,
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
            with ipdb.interfaces[self.ovn_device] as iface:
                iface.add_ip('%s/%s' % (fip_address, 32))

            if self._use_rules:
                self._add_ip_rule(fip_address, datapath)

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
            print("Delete BGP route for logical port with ip {}".format(ip_address))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[self.ovn_device] as iface:
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
                with ipdb.interfaces[self.ovn_device] as iface:
                    iface.del_ip('%s/%s' % (fip_address, 32))
                if self._use_rules:
                    self._del_ip_rule(fip_address, fip_datapath)
        elif (row.type == "chassisredirect" and
              row.logical_port.startswith('cr-')):
            cr_lrp_address, cr_lrp_datapath = self.sb_idl.get_fip_associated(
                row.logical_port)
            if cr_lrp_address:
                print("Delete BGP route for CR-LRP Port {}".format(
                    ip_address.split("/")[0]))
                ipdb = pyroute2.IPDB()
                with ipdb.interfaces[self.ovn_device] as iface:
                    iface.del_ip('%s/%s' % (ip_address.split("/")[0], 32))
                if self._use_rules:
                    self._del_ip_rule(cr_lrp_address, cr_lrp_datapath,
                                      lladdr=row.mac[0].split(' ')[0])

    def delete_bgp_fip_route(self, nat, datapath):
        # example: "fa:16:3e:70:ad:b1 172.24.4.176 is_chassis_resident(\"0c60373b-b770-4946-8bb4-38b5dce99308\")"
        port = nat.split(" ")[2].split("\"")[1]
        if self.sb_idl.is_port_on_chasis(port, self.chassis):
            fip_address = nat.split(" ")[1]
            print("Delete BGP route for FIP with ip {}".format(fip_address))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[self.ovn_device] as iface:
                iface.del_ip('%s/%s' % (fip_address, 32))

            if self._use_rules:
                self._del_ip_rule(fip_address, datapath)

    def _add_ip_rule(self, ip, datapath, lladdr=None):
        network_name = self.sb_idl.get_network_name(datapath)
        if network_name:
            network_bridge = self.ovn_bridge_mappings[network_name]
            rule = {'dst': ip,
                    'table': self.ovn_routing_tables[network_bridge]}
            iproute = pyroute2.IPRoute()
            if not iproute.get_rules(**rule):
                iproute.rule('add', **rule)
            if lladdr:
                # This is doing something like:
                # sudo ip nei replace 172.24.4.69
                # lladdr fa:16:3e:d3:5d:7b dev br-ex nud permanent
                network_bridge_if = iproute.link_lookup(ifname=network_bridge)[0]
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
            iproute = pyroute2.IPRoute()
            if iproute.get_rules(**rule):
                iproute.rule('del', **rule)
            if lladdr:
                # This is doing something like:
                # sudo ip nei del 172.24.4.69
                # lladdr fa:16:3e:d3:5d:7b dev br-ex nud permanent
                network_bridge_if = iproute.link_lookup(ifname=network_bridge)[0]
                iproute.neigh('del',
                              dst=ip,
                              lladdr=lladdr,
                              ifindex=network_bridge_if,
                              state=ndmsg.states['permanent'])

    def sync(self):
        ipdb = pyroute2.IPDB()
        ip = pyroute2.IPRoute()
        print("Ensuring VRF configuration for advertising routes")
        # Create VRF
        try:
            with ipdb.interfaces[self.ovn_vrf] as vrf:
                if vrf.state != "up":
                    vrf.up()
        except KeyError:
            with ipdb.create(kind="vrf",
                             ifname=self.ovn_vrf,
                             vrf_table=self.ovn_vrf_table) as vrf:
                vrf.up()
        # Create device
        try:
            with ipdb.interfaces[self.ovn_device] as iface:
                if iface.state != "up":
                    iface.up()
        except KeyError:
            with ipdb.create(kind="dummy",
                             ifname=self.ovn_device) as iface:
                iface.up()
        # Associate device to VRF
        ovn_nic_index=ip.link_lookup(ifname=self.ovn_device)[0]
        ovn_nic = ip.link("get", index=ovn_nic_index)[0]
        # Check if already associated to a vrf, and associate it if not
        if not ovn_nic.get_attr("IFLA_MASTER"):
            with ipdb.interfaces[self.ovn_vrf] as vrf:
                        vrf.add_port(ovn_nic_index)

        print("Configuring br-ex default rule and routing tables for each provider network")
        flows_info = {}
        # 1) Get bridge mappings: xxxx:br-ex,yyyy:br-ex2
        bridge_mappings = self._get_ovn_bridge_mappings()
        # 2) Get macs for bridge mappings
        for bridge_mapping in bridge_mappings:
            network = bridge_mapping.split(":")[0]
            bridge = bridge_mapping.split(":")[1]
            self.ovn_bridge_mappings[network] = bridge
            if self._use_rules:
                # check a routing table with the bridge name exists on
                # /etc/iproute2/rt_tables
                regex = '^[0-9]*[\s]*{}$'.format(bridge)
                matching_table = [line.replace('\t', ' ')
                                  for line in open('/etc/iproute2/rt_tables')
                                  if re.findall(regex, line)]
                if matching_table:
                    table_info = matching_table[0].strip().split()
                    self.ovn_routing_tables[table_info[1]] = int(table_info[0])
                    print("Found routing table for {} with: {}".format(bridge, table_info))
                # if not raise configuration error and exit
                else:
                    print(("Routing table for bridge {} must be configure "
                           "at /etc/iproute2/rt_tables").format(bridge))
                    sys.exit()
                # add default route on that table if it does not exist
                try:
                    table_route = ipdb.routes.tables[
                        self.ovn_routing_tables[bridge]]
                except KeyError: # if there is no rules, ipdb returns KeyError
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
            with ipdb.interfaces[bridge] as iface:
                flows_info[bridge] = {'mac': iface.address}
            # 3) Get in_port for bridge mappings (br-ex, br-ex2)
            ovs_port = self._ovs_cmd('ovs-vsctl', ['list-ports', bridge])[0].rstrip()
            ovs_ofport = self._ovs_cmd('ovs-vsctl', ['get', 'Interface', ovs_port, 'ofport'])[0].rstrip()
            flows_info[bridge]['in_port'] = ovs_ofport
        # 4) Add flows for each bridge mappings
        for bridge, info in flows_info.items():
            flow = "cookie={},priority=1000,ip,in_port={},actions=mod_dl_dst:{},NORMAL".format(OVS_RULE_COOKIE, info['in_port'], info['mac'])
            self._ovs_cmd('ovs-ofctl', ['add-flow', bridge, flow])

        print("Sync current routes...")
        # get all the ips on ovn dev
        exposed_ips = []
        with ipdb.interfaces[self.ovn_device] as iface:
            exposed_ips = [ip[0] for ip in iface.ipaddr if ip[1] == 32 or ip[1] == 128]
        # add missing routes/ips
        ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        for port in ports:
            if port.type not in OVN_VIF_PORT_TYPES:
                continue
            if (len(port.mac[0].split(' ')) != 2 and
                len(port.mac[0].split(' ')) != 3):
                continue
            ip_address = port.mac[0].split(' ')[1]
            self.add_bgp_route(ip_address, port)
            if ip_address in exposed_ips:
                # remove each ip to add from the list of current ips on dev OVN
                exposed_ips.remove(ip_address)
        # remove extra routes/ips
        # remove all the leftovers on the list of current ips on dev OVN
        with ipdb.interfaces[self.ovn_device] as iface:
            for ip in exposed_ips:
                # TODO: add ipv6 support
                iface.del_ip(ip, 32)

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

def main():
    """Main method for listening to VM adverticing events.
    """
    # set to True to also add ip rules, which avoids the need for
    # learning bgp routes on the compute nodes
    use_rules = True
    agt = BGPAgent()
    agt.start(use_rules)

if __name__ == "__main__":
    main()