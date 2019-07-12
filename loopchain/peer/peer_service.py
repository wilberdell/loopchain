# Copyright 2018 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""loopchain main peer service.
It has secure outer service for p2p consensus and status monitoring.
And also has insecure inner service for inner process modules."""

import getpass
import json
import multiprocessing
import signal
import timeit
from functools import partial

from loopchain.baseservice import CommonSubprocess, RestStubManager
# FIXME : import directly
from loopchain.blockchain import *
from loopchain.container import RestService
from loopchain.crypto.signature import Signer
from loopchain.p2p.p2p_service import P2PService, get_radio_station_stub
from loopchain.peer import PeerInnerService
from loopchain.utils import loggers, command_arguments
from loopchain.utils.message_queue import StubCollection


class PeerService:
    """Peer Service
    p2p networking with P2PService(outer) and inter process communication with rabbitMQ(inner)
    """
    def __init__(self, radio_station_target=None, node_type=None):
        """Peer는 Radio Station 에 접속하여 leader 및 다른 Peer에 대한 접속 정보를 전달 받는다.

        :param radio_station_target: IP:Port of Radio Station
        :param node_type: CommunityNode or CitizenNode
        :return:
        """
        node_type = node_type or conf.NodeType.CommunityNode

        self.is_support_node_function = \
            partial(conf.NodeType.is_support_node_function, node_type=node_type)

        utils.logger.spam(f"Your Peer Service runs on debugging MODE!")
        utils.logger.spam(f"You can see many terrible garbage logs just for debugging, DO U Really want it?")

        self._node_type = node_type

        self._radio_station_target = radio_station_target
        logging.info("Set Radio Station target is " + self._radio_station_target)

        self._radio_station_stub = None
        self._peer_id = None
        self._node_key = bytes()
        self.p2p_service: P2PService = None
        self._channel_infos = None

        # peer status cache for channel
        self.status_cache = {}  # {channel:status}

        self._peer_target = None
        self._rest_target = None
        self._peer_port = 0

        # gRPC service for Peer
        self._inner_service: PeerInnerService = None

        self._channel_services = {}
        self._rest_service = None

        ObjectManager().peer_service = self

    @property
    def inner_service(self):
        return self._inner_service

    @property
    def peer_target(self):
        return self._peer_target

    @property
    def rest_target(self):
        return self._rest_target

    @property
    def channel_infos(self):
        return self._channel_infos

    @property
    def node_type(self):
        return self._node_type

    @property
    def radio_station_target(self):
        return self._radio_station_target

    @property
    def stub_to_radiostation(self):
        if self._radio_station_stub is None:
            if self.is_support_node_function(conf.NodeFunction.Vote):
                self._radio_station_stub = get_radio_station_stub(self._radio_station_target)
            else:
                self._radio_station_stub = RestStubManager(self._radio_station_target)

        return self._radio_station_stub

    @property
    def peer_port(self):
        return self._peer_port

    @property
    def peer_id(self):
        return self._peer_id

    @property
    def node_key(self):
        return self._node_key

    def _get_channel_infos(self):
        # util.logger.spam(f"__get_channel_infos:node_type::{self.__node_type}")
        if self.is_support_node_function(conf.NodeFunction.Vote):
            if conf.ENABLE_REP_RADIO_STATION:
                response = self.p2p_service.call_and_retry(
                    self.stub_to_radiostation,
                    self._peer_id,
                    self._peer_target
                )
                # util.logger.spam(f"__get_channel_infos:response::{response}")

                if not response:
                    return None
                logging.info(f"Connect to channels({utils.pretty_json(response.channel_infos)})")
                channels = json.loads(response.channel_infos)
            else:
                channels = utils.load_json_data(conf.CHANNEL_MANAGE_DATA_PATH)
        else:
            response = self.stub_to_radiostation.call_in_times(method_name="GetChannelInfos")
            channels = {channel: value for channel, value in response["channel_infos"].items()}

        return channels

    def _init_port(self, port):
        # service 초기화 작업
        target_ip = utils.get_private_ip()
        self._peer_target = f"{target_ip}:{port}"
        self._peer_port = int(port)

        rest_port = int(port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER
        self._rest_target = f"{target_ip}:{rest_port}"

        logging.info("Start Peer Service at port: " + str(port))

    def _run_rest_services(self, port):
        if conf.ENABLE_REST_SERVICE and conf.RUN_ICON_IN_LAUNCHER:
            logging.debug(f'Launch Sanic RESTful server. '
                          f'Port = {int(port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER}')
            self._rest_service = RestService(int(port))

    def _init_node_key(self):
        prikey_file = conf.PRIVATE_PATH

        if conf.PRIVATE_PASSWORD:
            password = conf.PRIVATE_PASSWORD
        else:
            password = getpass.getpass(f"Input your keystore password: ")
        signer = Signer.from_prikey_file(prikey_file, password)
        self._make_peer_id(signer.address)
        self._node_key = signer.private_key.private_key

    def _make_peer_id(self, address):
        self._peer_id = address

        logger_preset = loggers.get_preset()
        logger_preset.peer_id = self.peer_id
        logger_preset.update_logger()

        logging.info(f"run peer_id : {self._peer_id}")

    @staticmethod
    def _get_use_kms():
        if conf.GRPC_SSL_KEY_LOAD_TYPE == conf.KeyLoadType.KMS_LOAD:
            return True
        for value in conf.CHANNEL_OPTION.values():
            if value["key_load_type"] == conf.KeyLoadType.KMS_LOAD:
                return True
        return False

    def _init_kms_helper(self, agent_pin):
        if self._get_use_kms():
            from loopchain.tools.kms_helper import KmsHelper
            KmsHelper().set_agent_pin(agent_pin)

    def _close_kms_helper(self):
        if self._get_use_kms():
            from loopchain.tools.kms_helper import KmsHelper
            KmsHelper().remove_agent_pin()

    def start_p2p_server(self):
        self.p2p_service.start_server()

    def stop_p2p_server(self):
        self.p2p_service.stop_server()

    def serve(self,
              port,
              agent_pin: str=None,
              amqp_target: str=None,
              amqp_key: str=None,
              event_for_init: multiprocessing.Event=None):
        """start func of Peer Service ===================================================================

        :param port:
        :param agent_pin: kms agent pin
        :param amqp_target: rabbitmq host target
        :param amqp_key: sharing queue key
        :param event_for_init: set when peer initiates
        """

        amqp_target = amqp_target or conf.AMQP_TARGET
        amqp_key = amqp_key or conf.AMQP_KEY

        stopwatch_start = timeit.default_timer()

        self._init_kms_helper(agent_pin)
        self._init_port(port)
        self._init_node_key()

        StubCollection().amqp_target = amqp_target
        StubCollection().amqp_key = amqp_key

        peer_queue_name = conf.PEER_QUEUE_NAME_FORMAT.format(amqp_key=amqp_key)
        self._inner_service = PeerInnerService(
            amqp_target, peer_queue_name, conf.AMQP_USERNAME, conf.AMQP_PASSWORD, peer_service=self)

        self._reset_channel_infos()

        self._run_rest_services(port)

        self.p2p_service = P2PService(self.__peer_port)
        self.start_p2p_server()

        self._close_kms_helper()

        stopwatch_duration = timeit.default_timer() - stopwatch_start
        logging.info(f"Start Peer Service at port: {port} start duration({stopwatch_duration})")

        async def _serve():
            await self.ready_tasks()
            await self._inner_service.connect(conf.AMQP_CONNECTION_ATTEMPTS, conf.AMQP_RETRY_DELAY, exclusive=True)

            if conf.CHANNEL_BUILTIN:
                await self.serve_channels()

            if event_for_init is not None:
                event_for_init.set()

            logging.info(f'peer_service: init complete peer: {self.peer_id}')

        loop = self._inner_service.loop
        loop.create_task(_serve())
        loop.add_signal_handler(signal.SIGINT, self.close)
        loop.add_signal_handler(signal.SIGTERM, self.close)

        try:
            loop.run_forever()
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

        # process monitor must stop monitoring before any subprocess stop
        # Monitor().stop()

        logging.info("Peer Service Ended.")
        if self._rest_service is not None:
            self._rest_service.stop()

    def close(self):
        async def _close():
            for channel_stub in StubCollection().channel_stubs.values():
                await channel_stub.async_task().stop("Close")

            self.stop_p2p_server()
            loop.stop()

        loop = self._inner_service.loop
        loop.create_task(_close())

    async def serve_channels(self):
        for i, channel_name in enumerate(self._channel_infos.keys()):
            score_port = self._peer_port + conf.PORT_DIFF_SCORE_CONTAINER + conf.PORT_DIFF_BETWEEN_SCORE_CONTAINER * i

            args = ['python3', '-m', 'loopchain', 'channel']
            args += ['-p', str(score_port)]
            args += ['--channel', str(channel_name)]
            args += command_arguments.get_raw_commands_by_filter(
                command_arguments.Type.Develop,
                command_arguments.Type.AMQPTarget,
                command_arguments.Type.AMQPKey,
                command_arguments.Type.ConfigurationFilePath,
                command_arguments.Type.RadioStationTarget
            )

            service = CommonSubprocess(args)

            channel_stub = StubCollection().channel_stubs[channel_name]
            await channel_stub.async_task().hello()

            self._channel_services[channel_name] = service

    async def ready_tasks(self):
        await StubCollection().create_peer_stub()  # for getting status info

        for channel_name, channel_info in self._channel_infos.items():
            await StubCollection().create_channel_stub(channel_name)
            await StubCollection().create_channel_tx_receiver_stub(channel_name)

            await StubCollection().create_icon_score_stub(channel_name)

    def _reset_channel_infos(self):
        self._channel_infos = self._get_channel_infos()
        if not self._channel_infos:
            utils.exit_and_msg("There is no peer_list, initial network is not allowed without RS!")

    async def change_node_type(self, node_type):
        if self._node_type.value == node_type:
            utils.logger.warning(f"Does not change node type because new note type equals current node type")
            return

        self._node_type = conf.NodeType(node_type)
        self.is_support_node_function = \
            partial(conf.NodeType.is_support_node_function, node_type=node_type)

        self._radio_station_stub = None

        self._reset_channel_infos()
