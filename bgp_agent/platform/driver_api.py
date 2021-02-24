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

import abc
from stevedore import driver as stevedore_driver

class AgentDriverBase(object, metaclass=abc.ABCMeta):
    """Base class for agent drivers.

    """

    @classmethod
    def get_instance(cls, specific_driver):
        agent_driver = stevedore_driver.DriverManager(
            namespace='bgp_agent.platform',
            name=specific_driver,
            invoke_on_load=True
        ).driver

        return agent_driver

    @abc.abstractmethod
    def expose_IP(self, ip_address):
        raise NotImplementedError()

    @abc.abstractmethod
    def withdraw_IP(self, ip_address):
        raise NotImplementedError()

    @abc.abstractmethod
    def expose_remote_IP(self, ip_address):
        raise NotImplementedError()

    @abc.abstractmethod
    def withdraw_remote_IP(self, ip_address):
        raise NotImplementedError()

    @abc.abstractmethod
    def expose_subnet(self, subnet):
        raise NotImplementedError()

    @abc.abstractmethod
    def withdraw_subnet(self, subnet):
        raise NotImplementedError()