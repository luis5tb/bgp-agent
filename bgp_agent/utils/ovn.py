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

from ovsdbapp.backend import ovs_idl
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp import event
from ovsdbapp.schema.ovn_southbound import impl_idl as sb_impl_idl


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


class OvnDbNotifyHandler(event.RowEventHandler):
    def __init__(self, driver):
        super(OvnDbNotifyHandler, self).__init__()
        self.driver = driver


class OvnSbIdl(OvnIdl):
    SCHEMA = 'OVN_Southbound'

    def __init__(self, connection_string, chassis=None, events=None,
                 tables=None):
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

    def _get_port_by_name(self, port):
        cmd = self.db_find_rows('Port_Binding', ('logical_port', '=', port))
        port_info = cmd.execute(check_error=True)
        if port_info:
            return port_info[0]
        return []

    def _get_ports_by_datapath(self, datapath, port_type=None):
        if port_type:
            cmd = self.db_find_rows('Port_Binding',
                                    ('datapath', '=', datapath),
                                    ('type', '=', port_type))
        else:
            cmd = self.db_find_rows('Port_Binding',
                                    ('datapath', '=', datapath))
        return cmd.execute(check_error=True)

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

    def is_port_on_chassis(self, port_name, chassis):
        port_info = self._get_port_by_name(port_name)
        try:
            if (port_info and port_info[0].type == "" and
                    port_info.chassis[0].name == chassis):
                return True
        except IndexError:
            pass
        return False

    def get_ports_on_chassis(self, chassis):
        rows = self.db_list_rows('Port_Binding').execute(check_error=True)
        return [r for r in rows if r.chassis and r.chassis[0].name == chassis]

    def get_network_name(self, datapath):
        for row in self._get_ports_by_datapath(datapath, 'localnet'):
            if row.options:
                return row.options.get('network_name')
        return None

    def is_router_gateway_chassis(self, datapath, chassis):
        port_info = self._get_ports_by_datapath(datapath, 'chassisredirect')
        try:
            if port_info and port_info[0].chassis[0].name == chassis:
                return port_info[0].logical_port
        except IndexError:
            pass
        return None

    def get_lrp_port_for_datapath(self, datapath):
        for row in self._get_ports_by_datapath(datapath, 'patch'):
            if row.options:
                return row.options['peer']
        return None

    def get_lrp_ports_for_router(self, datapath):
        return self._get_ports_by_datapath(datapath, 'patch')

    def get_port_datapath(self, port_name):
        port_info = self._get_port_by_name(port_name)
        if port_info:
            return port_info.datapath
        return None

    def get_ports_on_datapath(self, datapath):
        return self._get_ports_by_datapath(datapath)