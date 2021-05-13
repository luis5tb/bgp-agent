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

from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

agent_opts = [
    cfg.IntOpt('reconcile_interval',
               help='Time between re-sync actions.',
               default=120),
    cfg.BoolOpt('expose_tenant_networks',
               help='Expose VM IPs on tenant networks',
               default=True),
    cfg.StrOpt('watcher_handler',
               help='Watcher handler to be used',
               default='osp_watcher'),
    cfg.ListOpt('mode',
                help="Agent mode options to enable ('BGP', 'EVPN', 'BGP,EVPN')",
                default=["BGP",
                         "EVPN"]),
    cfg.StrOpt('driver',
               help='Driver to be used',
               default='osp_ovn_driver'),
    cfg.StrOpt('ovn_sb_private_key',
               default='/etc/pki/tls/private/ovn_controller.key',
               help='The PEM file with private key for SSL connection to '
                    'OVN-SB-DB'),
    cfg.StrOpt('ovn_sb_certificate',
               default='/etc/pki/tls/certs/ovn_controller.crt',
               help='The PEM file with certificate that certifies the '
                    'private key specified in ovn_sb_private_key'),
    cfg.StrOpt('ovn_sb_ca_cert',
               default='/etc/ipa/ca.crt',
               help='The PEM file with CA certificate that OVN should use to'
                    ' verify certificates presented to it by SSL peers'),
]

CONF = cfg.CONF
CONF.register_opts(agent_opts)

logging.register_options(CONF)


def init(args, **kwargs):
    CONF(args=args, project='bgp-agent', **kwargs)


def setup_logging():
    logging.setup(CONF, 'bgp-agent')
    logging.set_defaults(default_log_levels=logging.get_default_log_levels())
    LOG.info("Logging enabled!")
