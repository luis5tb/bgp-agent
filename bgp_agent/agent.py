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

import functools
import sys

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import periodic_task
from oslo_service import service

from bgp_agent import config
from bgp_agent.platform import driver_api


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class BGPAgentMeta(type(service.Service),
                   type(periodic_task.PeriodicTasks)):
    pass


class BGPAgent(service.Service, periodic_task.PeriodicTasks,
               metaclass=BGPAgentMeta):
    """Kuryr-Kubernetes controller Service."""

    def __init__(self):
        super(BGPAgent, self).__init__()
        periodic_task.PeriodicTasks.__init__(self, CONF)

        self.agent_driver = driver_api.AgentDriverBase.get_instance(
            CONF.driver)

    def start(self):
        LOG.info("Service '%s' starting", self.__class__.__name__)
        super(BGPAgent, self).start()
        self.agent_driver.start()

        LOG.info("Service '%s' started", self.__class__.__name__)
        f = functools.partial(self.run_periodic_tasks, None)
        self.tg.add_timer(1, f)

    @periodic_task.periodic_task(spacing=CONF.reconcile_interval,
                                 run_immediately=True)
    def sync(self, context):
        LOG.info("Running reconciliation loop to ensure routes/rules are "
                 "in place.")
        self.agent_driver.sync()

    def wait(self):
        super(BGPAgent, self).wait()
        LOG.info("Service '%s' stopped", self.__class__.__name__)

    def stop(self, graceful=False):
        LOG.info("Service '%s' stopping", self.__class__.__name__)
        super(BGPAgent, self).stop(graceful)


def start():
    config.init(sys.argv[1:])
    config.setup_logging()

    bgp_agent_launcher = service.launch(config.CONF, BGPAgent())
    bgp_agent_launcher.wait()