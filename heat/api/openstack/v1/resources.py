# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import itertools

from heat.api.openstack.v1 import util
from heat.common import wsgi
from heat.rpc import api as engine_api
from heat.common import identifier
from heat.rpc import client as rpc_client


def format_resource(req, res, keys=[]):
    include_key = lambda k: k in keys if keys else True

    def transform(key, value):
        if not include_key(key):
            return

        if key == engine_api.RES_ID:
            identity = identifier.ResourceIdentifier(**value)
            yield ('links', [util.make_link(req, identity),
                             util.make_link(req, identity.stack(), 'stack')])
        elif (key == engine_api.RES_STACK_NAME or
              key == engine_api.RES_STACK_ID or
              key == engine_api.RES_ACTION):
            return
        elif (key == engine_api.RES_METADATA):
            return
        elif (key == engine_api.RES_STATUS and engine_api.RES_ACTION in res):
            # To avoid breaking API compatibility, we join RES_ACTION
            # and RES_STATUS, so the API format doesn't expose the
            # internal split of state into action/status
            yield (key, '_'.join((res[engine_api.RES_ACTION], value)))
        else:
            yield (key, value)

    return dict(itertools.chain.from_iterable(
        transform(k, v) for k, v in res.items()))


class ResourceController(object):
    """
    WSGI controller for Resources in Heat v1 API
    Implements the API actions
    """

    def __init__(self, options):
        self.options = options
        self.engine = rpc_client.EngineClient()

    @util.identified_stack
    def index(self, req, identity):
        """
        Lists summary information for all resources
        """

        res_list = self.engine.list_stack_resources(req.context,
                                                    identity)

        return {'resources': [format_resource(req, res) for res in res_list]}

    @util.identified_stack
    def show(self, req, identity, resource_name):
        """
        Gets detailed information for a stack
        """

        res = self.engine.describe_stack_resource(req.context,
                                                  identity,
                                                  resource_name)

        return {'resource': format_resource(req, res)}

    @util.identified_stack
    def metadata(self, req, identity, resource_name):
        """
        Gets detailed information for a stack
        """

        res = self.engine.describe_stack_resource(req.context,
                                                  identity,
                                                  resource_name)

        return {engine_api.RES_METADATA: res[engine_api.RES_METADATA]}


def create_resource(options):
    """
    Resources resource factory method.
    """
    # TODO(zaneb) handle XML based on Content-type/Accepts
    deserializer = wsgi.JSONRequestDeserializer()
    serializer = wsgi.JSONResponseSerializer()
    return wsgi.Resource(ResourceController(options), deserializer, serializer)
