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

OVN_VIF_PORT_TYPES = ("", "chassisredirect", "virtual")

OVN_BGP_NIC = "ovn"
OVN_BGP_VRF = "ovn-bgp-vrf"
OVN_BGP_VRF_TABLE = 10
OVS_CONNECTION_STRING = "unix:/var/run/openvswitch/db.sock"
OVS_RULE_COOKIE = "999"
OVS_VRF_RULE_COOKIE = "998"

IP_VERSION_6 = 6
IP_VERSION_4 = 4

BGP_MODE='BGP'
EVPN_MODE='EVPN'

OVN_EVPN_VNI_EXT_ID_KEY = 'neutron_bgpvpn:vni'
OVN_EVPN_RT_EXT_ID_KEY = 'neutron_bgpvpn:rt'
OVN_EVPN_VRF_PREFIX = "vrf-"
OVN_EVPN_BRIDGE_PREFIX = "br-"
OVN_EVPN_VXLAN_PREFIX = "vxlan-"
OVN_EVPN_LO_PREFIX = "lo-"
OVN_INTEGRATION_BRIDGE = 'br-int'
