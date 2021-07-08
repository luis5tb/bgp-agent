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

from bgp_agent import constants

from ovsdbapp.backend.ovs_idl import event as row_event

from oslo_concurrency import lockutils

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
            if row.type != 'chassisredirect':
                return False
            if (len(row.mac[0].split(' ')) != 2 and
                    len(row.mac[0].split(' ')) != 3):
                return False
            return (row.chassis[0].name == self.agent.chassis and
                    not old.chassis)
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type != 'chassisredirect':
            return
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.expose_IP(row, cr_lrp=True)


class PortBindingChassisDeletedEvent(PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(PortBindingChassisDeletedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            if row.type != 'chassisredirect':
                return False
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
        if row.type != 'chassisredirect':
            return
        with _SYNC_STATE_LOCK.read_lock():
            self.agent.withdraw_IP(row, cr_lrp=True)


class SubnetRouterAttachedEvent(PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_CREATE,)
        super(SubnetRouterAttachedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            if event == self.ROW_UPDATE:
                return (not row.chassis and
                        not row.logical_port.startswith('lrp-') and
                        row.external_ids[constants.OVN_EVPN_VNI_EXT_ID_KEY] and
                        row.external_ids[constants.OVN_EVPN_AS_EXT_ID_KEY] and
                        (not old.external_ids.get(
                            constants.OVN_EVPN_VNI_EXT_ID_KEY) or
                         not old.external_ids.get(
                             constants.constants.OVN_EVPN_AS_EXT_ID_KEY)))
            else:
                return (not row.chassis and
                        not row.logical_port.startswith('lrp-') and
                        row.external_ids[constants.OVN_EVPN_VNI_EXT_ID_KEY] and
                        row.external_ids[constants.OVN_EVPN_AS_EXT_ID_KEY])
        except (IndexError, AttributeError, KeyError):
            return False

    def run(self, event, row, old):
        if row.type != 'patch':
            return
        with _SYNC_STATE_LOCK.read_lock():
            if row.nat_addresses:
                self.agent.expose_IP(row)
            else:
                self.agent.expose_subnet(row)


class SubnetRouterDetachedEvent(PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE,)
        super(SubnetRouterDetachedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            if event == self.ROW_UPDATE:
                return (not row.chassis and
                        not row.logical_port.startswith('lrp-') and
                        old.external_ids[constants.OVN_EVPN_VNI_EXT_ID_KEY] and
                        old.external_ids[constants.OVN_EVPN_AS_EXT_ID_KEY] and
                        (not row.external_ids.get(
                            constants.OVN_EVPN_VNI_EXT_ID_KEY) or
                         not row.external_ids.get(
                             constants.OVN_EVPN_AS_EXT_ID_KEY)))
            else:
                return (not row.chassis and
                        not row.logical_port.startswith('lrp-') and
                        row.external_ids[constants.OVN_EVPN_VNI_EXT_ID_KEY] and
                        row.external_ids[constants.OVN_EVPN_AS_EXT_ID_KEY])
        except (IndexError, AttributeError, KeyError):
            return False

    def run(self, event, row, old):
        if row.type != 'patch':
            return
        with _SYNC_STATE_LOCK.read_lock():
            if row.nat_addresses:
                self.agent.withdraw_IP(row)
            else:
                self.agent.withdraw_subnet(row)


class TenantPortCreatedEvent(PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_UPDATE,)
        super(TenantPortCreatedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if (len(row.mac[0].split(' ')) != 2 and
                    len(row.mac[0].split(' ')) != 3):
                return False
            return (not old.chassis and row.chassis and
                    self.agent.ovn_local_lrps != [])
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type != "" and row.type != "virtual":
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = [row.mac[0].split(' ')[1]]
            # for dual-stack
            if len(row.mac[0].split(' ')) == 3:
                ips.append(row.mac[0].split(' ')[2])
            self.agent.expose_remote_IP(ips, row)


class TenantPortDeletedEvent(PortBindingChassisEvent):
    def __init__(self, bgp_agent):
        events = (self.ROW_DELETE, self.ROW_UPDATE,)
        super(TenantPortDeletedEvent, self).__init__(
            bgp_agent, events)

    def match_fn(self, event, row, old):
        try:
            # single and dual-stack format
            if (len(row.mac[0].split(' ')) != 2 and
                    len(row.mac[0].split(' ')) != 3):
                return False
            if event == self.ROW_UPDATE:
                return (old.chassis and not row.chassis and
                        self.agent.ovn_local_lrps != [])
            else:
                return (self.agent.ovn_local_lrps != [])
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        if row.type != "" and row.type != "virtual":
            return
        with _SYNC_STATE_LOCK.read_lock():
            ips = [row.mac[0].split(' ')[1]]
            # for dual-stack
            if len(row.mac[0].split(' ')) == 3:
                ips.append(row.mac[0].split(' ')[2])
            self.agent.withdraw_remote_IP(ips, row)


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
