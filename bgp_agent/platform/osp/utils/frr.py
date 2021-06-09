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

from jinja2 import Template

from oslo_concurrency import processutils
from oslo_log import log as logging

from bgp_agent import constants

LOG = logging.getLogger(__name__)

ADD_VRF_TEMPLATE = '''
vrf {{ vrf_name }}
  vni {{ vni }}                      
 
router bgp {{ rt }} vrf {{ vrf_name }}
  address-family ipv4 unicast
    redistribute connected        
  exit-address-family                              
  address-family l2vpn evpn
    advertise ipv4 unicast
  exit-address-family  
  
'''

DEL_VRF_TEMPLATE = '''
no vrf {{ vrf_name }}
no router bgp {{ rt }} vrf {{ vrf_name }}

'''


def frr_reconfigure(evpn_info, action):
    LOG.info("FRR reconfiguration (action = {}) for evpn: {}".format(
             action, evpn_info))
    frr_config_file = None
    if action == "add-vrf":
        vrf_template = Template(ADD_VRF_TEMPLATE)
        vrf_config = vrf_template.render(
            vrf_name="{}{}".format(constants.OVN_EVPN_VRF_PREFIX,
                                   evpn_info['vni']),
            rt=evpn_info['rt'],
            vni=evpn_info['vni'])
        frr_config_file = "frr-config-add-vrf-{}".format(evpn_info['vni'])
    elif action == "del-vrf":
        vrf_template = Template(DEL_VRF_TEMPLATE)
        vrf_config = vrf_template.render(
            vrf_name="{}{}".format(constants.OVN_EVPN_VRF_PREFIX,
                                   evpn_info['vni']),
            rt=evpn_info['rt'])
        frr_config_file = "frr-config-del-vrf-{}".format(evpn_info['vni'])
    else:
        LOG.error("Unknown FRR reconfiguration action: %s", action)
        return
    with open(frr_config_file, 'w') as vrf_config_file:
        vrf_config_file.write(vrf_config)
    vtysh_command = "copy {} running-config".format(frr_config_file)
    full_args = ['/usr/bin/vtysh', '--vty_socket', constants.FRR_SOCKET_PATH,
                 '-c', vtysh_command]
    try:
        return processutils.execute(*full_args, run_as_root=True)
    except Exception as e:
        print("Unable to execute vtysh with {}. Exception: {}".format(
            full_args, e))
        raise