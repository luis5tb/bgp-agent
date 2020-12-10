import abc
import time

import pyroute2

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
                    self.agent.add_bgp_fip_route(nat)


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
                    self.agent.delete_bgp_fip_route(nat)


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
                    return fip.split(" ")[1]
        return False
    
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
        self.ovn_device = "ovn"
        self.ovn_vrf = "ovn-bgp-vrf"
        self.chassis = self._get_own_chassis_name()
        self.ovn_remote = self._get_ovn_remote()
        print("Loaded chassis {}.".format(self.chassis))

    def start(self):
        print("Starting BGP Agent...")
        ovs_connection_string = 'unix:/usr/local/var/run/openvswitch/db.sock'
        self.ovs_idl = OvsIdl().start(ovs_connection_string)
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
        if row.type == "" and self.sb_idl.is_provider_network(row.datapath):
            print("Add BGP route for logical port with ip {}".format(ip_address))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[self.ovn_device] as iface:
                iface.add_ip('%s/%s' % (ip_address, 32))
        # VM with FIP
        elif row.type == "":
            fip_address = self.sb_idl.get_fip_associated(row.logical_port)
            if fip_address:
                print("Add BGP route for FIP with ip {}".format(fip_address))
                ipdb = pyroute2.IPDB()
                with ipdb.interfaces[self.ovn_device] as iface:
                    iface.add_ip('%s/%s' % (fip_address, 32))
        # CR-LRP Port
        elif row.type == "chassisredirect" and row.logical_port.startswith('cr-'):
            print("Add BGP route for CR-LRP Port {}".format(ip_address.split("/")[0]))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[self.ovn_device] as iface:
                iface.add_ip('%s/%s' % (ip_address.split("/")[0], 32))

    def add_bgp_fip_route(self, nat):
        # example: "fa:16:3e:70:ad:b1 172.24.4.176 is_chassis_resident(\"0c60373b-b770-4946-8bb4-38b5dce99308\")"
        port = nat.split(" ")[2].split("\"")[1]
        if self.sb_idl.is_port_on_chasis(port, self.chassis):
            fip_address = nat.split(" ")[1]
            print("Add BGP route for FIP with ip {}".format(fip_address))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[self.ovn_device] as iface:
                iface.add_ip('%s/%s' % (fip_address, 32))


    def delete_bgp_route(self, ip_address, row):
        if row.type == "" and self.sb_idl.is_provider_network(row.datapath):
            print("Delete BGP route for logical port with ip {}".format(ip_address))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[self.ovn_device] as iface:
                iface.del_ip('%s/%s' % (ip_address, 32))
        # VM with FIP
        elif row.type == "":
            fip_address = self.sb_idl.get_fip_associated(row.logical_port)
            if fip_address:
                print("Delete BGP route for FIP with ip {}".format(fip_address))
                ipdb = pyroute2.IPDB()
                with ipdb.interfaces[self.ovn_device] as iface:
                    iface.del_ip('%s/%s' % (fip_address, 32))
        elif row.type == "chassisredirect" and row.logical_port.startswith('cr-'):
            print("Delete BGP route for CR-LRP Port {}".format(ip_address.split("/")[0]))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[self.ovn_device] as iface:
                iface.del_ip('%s/%s' % (ip_address.split("/")[0], 32))

    def delete_bgp_fip_route(self, nat):
        # example: "fa:16:3e:70:ad:b1 172.24.4.176 is_chassis_resident(\"0c60373b-b770-4946-8bb4-38b5dce99308\")"
        port = nat.split(" ")[2].split("\"")[1]
        if self.sb_idl.is_port_on_chasis(port, self.chassis):
            fip_address = nat.split(" ")[1]
            print("Delete BGP route for FIP with ip {}".format(fip_address))
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[self.ovn_device] as iface:
                iface.del_ip('%s/%s' % (fip_address, 32))

    def sync(self):
        print("Configuring br-ex default rule")
        flows_info = {}
        # 1) Get bridge mappings: xxxx:br-ex,yyyy:br-ex2
        bridge_mappings = self._get_ovn_bridge_mappings()
        # 2) Get macs for bridge mappings
        for bridge_mapping in bridge_mappings:
            bridge = bridge_mapping.split(":")[1]
            ipdb = pyroute2.IPDB()
            with ipdb.interfaces[bridge] as iface:
                flows_info[bridge] = {'mac': iface.address}
            # 3) Get in_port for bridge mappings (br-ex, br-ex2)
            ovs_port = self._ovs_cmd('ovs-vsctl', ['list-ports', bridge])[0].rstrip()
            ovs_ofport = self._ovs_cmd('ovs-vsctl', ['get', 'Interface', ovs_port, 'ofport'])[0].rstrip()
            flows_info[bridge]['in_port'] = ovs_ofport
        # 4) Add flows for each bridge mappings
        for bridge, info in flows_info.items():
            flow = "cookie=999,priority=1000,ip,in_port={},actions=mod_dl_dst:{},NORMAL".format(info['in_port'], info['mac'])
            self._ovs_cmd('ovs-ofctl', ['add-flow', bridge, flow])

        print("Sync current routes...")
        # get all the ips on ovn dev
        exposed_ips = []
        ipdb = pyroute2.IPDB()
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
                # TODO: adapt to ipv6
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
    agt = BGPAgent()
    agt.start()

if __name__ == "__main__":
    main()