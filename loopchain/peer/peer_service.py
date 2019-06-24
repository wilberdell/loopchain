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

import asyncio
import getpass
import datetime
import json
import multiprocessing
import signal
import timeit
from functools import partial
from typing import Dict, Tuple

from loopchain.baseservice import CommonSubprocess, RestStubManager, TimerService
# FIXME : import directly
from loopchain.blockchain import *
from loopchain.container import RestService
from loopchain.crypto.signature import Signer
from loopchain.p2p.bridge import PeerBridgeBase
from loopchain.p2p.p2p_service import P2PService, get_radio_station_stub
from loopchain.peer import PeerInnerService
from loopchain.peer.state_borg import PeerState
from loopchain.utils import loggers, command_arguments
from loopchain.utils.message_queue import StubCollection


class PeerInnerBridge(PeerBridgeBase):
    """ Implementation of PeerBridgeBase
    P2PService call function of ChannelService and using PeerState by this PeerBridge interface
    """

    def __init__(self, inner_service):
        self._inner_service = inner_service
        self._peer_state = PeerState()
        self._status_cache_update_time = {}

    def _status_update(self, channel_name, future):
        # update peer outer status cache by channel
        utils.logger.spam(f"status_update channel({channel_name}) result({future.result()})")
        self._status_cache_update_time[channel_name] = datetime.datetime.now()
        self._peer_state.status_cache[channel_name] = future.result()

    def _get_status_from_cache(self, channel: str) -> Dict:
        if channel in self._peer_state.status_cache:
            if channel in self._status_cache_update_time:
                diff = utils.datetime_diff_in_mins(self._status_cache_update_time[channel])
                if diff > conf.ALLOW_STATUS_CACHE_LAST_UPDATE_IN_MINUTES:
                    return {}
            status_data = self._peer_state.status_cache[channel]
        else:
            channel_stub = StubCollection().channel_stubs[channel]
            status_data = asyncio.run_coroutine_threadsafe(
                channel_stub.async_task().get_status(),
                self._inner_service.loop
            ).result()
            self._peer_state.status_cache[channel] = status_data

        return status_data

    def channel_reset_timer(self, channel_name):
        channel_stub = StubCollection().channel_stubs[channel_name]
        channel_stub.sync_task().reset_timer(TimerService.TIMER_KEY_CONNECT_PEER)

    def channel_get_status_data(self, channel_name: str) -> Dict:
        channel_stub = StubCollection().channel_stubs[channel_name]

        try:
            future = asyncio.run_coroutine_threadsafe(
                channel_stub.async_task().get_status(),
                self._inner_service.loop
            )

            callback = partial(self._status_update, channel_name)
            future.add_done_callback(callback)
        except BaseException as e:
            logging.error(f"Peer GetStatus Exception : {e}")

        status_data = self._get_status_from_cache(channel_name)
        if not status_data:
            from loopchain.blockchain import ChannelStatusError
            raise ChannelStatusError(f"Fail get status data from channel({channel_name})")

        return status_data

    def channel_get_peer_status_data(self, channel_name: str) -> Dict:
        status_cache = self.channel_get_status_data(channel_name)
        return {
                'state': status_cache['state'],
                'peer_type': status_cache['peer_type'],
                'block_height': status_cache['block_height'],
                'peer_count': status_cache['peer_count'],
                'leader': status_cache['leader']
            }

    def channel_get_peer_list(self, channel_name) -> Tuple:
        channel_stub = StubCollection().channel_stubs[channel_name]
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().get_peer_list(),
            self._inner_service.loop
        )
        return future.result()

    def channel_get_tx_by_address(self, channel_name, address, index) -> Tuple:
        channel_stub = StubCollection().channel_stubs[channel_name]
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().get_tx_by_address(address, index),
            self._inner_service.loop
        )
        return future.result()

    def channel_mq_status_data(self, channel_name) -> Dict:
        stubs = {
            "peer": StubCollection().peer_stub,
            "channel": StubCollection().channel_stubs.get(channel_name),
            "score": StubCollection().icon_score_stubs.get(channel_name)
        }

        mq_status_data = {}
        for key, stub in stubs.items():
            message_count = -1
            message_error = None
            try:
                mq_info = stub.sync_info().queue_info()
                message_count = mq_info.method.message_count
            except AttributeError:
                message_error = "Stub is not initialized."
            except Exception as e:
                message_error = f"{type(e).__name__}, {e}"

            mq_status_data[key] = {}
            mq_status_data[key]["message_count"] = message_count
            if message_error:
                mq_status_data[key]["error"] = message_error

        return mq_status_data

    def channel_get_score_status(self, channel_name):
        channel_stub = StubCollection().channel_stubs[channel_name]
        return channel_stub.sync_task().get_score_status()

    def channel_complain_leader(self, channel_name, complain_vote):
        channel_stub = StubCollection().channel_stubs[channel_name]
        asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().complain_leader(vote_dumped=complain_vote),
            self._inner_service.loop
        )

    def channel_create_tx(self, channel_name, data):
        channel_stub = StubCollection().channel_stubs[channel_name]
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().create_tx(data),
            self._inner_service.loop
        )
        return future.result()

    def channel_add_tx(self, channel_name, request):
        StubCollection().channel_stubs[channel_name].sync_task().add_tx(request)

    def channel_tx_receiver_add_tx_list(self, channel_name, request):
        StubCollection().channel_tx_receiver_stubs[channel_name].sync_task().add_tx_list(request)

    def channel_get_tx(self, channel_name, tx_hash):
        channel_stub = StubCollection().channel_stubs[channel_name]
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().get_tx(tx_hash),
            self._inner_service.loop
        )
        return future.result()

    def channel_get_block(self, channel_name, block_height, block_hash, block_data_filter, tx_data_filter):
        channel_stub = StubCollection().channel_stubs[channel_name]
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().get_block(
                block_height=block_height,
                block_hash=block_hash,
                block_data_filter=block_data_filter,
                tx_data_filter=tx_data_filter
            ), self._inner_service.loop
        )

        return future.result()

    def channel_get_precommit_block(self, channel_name, last_block_height) -> Tuple:
        channel_stub = StubCollection().channel_stubs[channel_name]
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().get_precommit_block(last_block_height=last_block_height),
            self._inner_service.loop
        )
        return future.result()

    def channel_get_invoke_result(self, channel_name, tx_hash) -> Tuple:
        channel_stub = StubCollection().channel_stubs[channel_name]
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().get_invoke_result(tx_hash),
            self._inner_service.loop
        )
        return future.result()

    def channel_announce_unconfirmed_block(self, channel_name, block):
        channel_stub = StubCollection().channel_stubs[channel_name]
        asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().announce_unconfirmed_block(block),
            self._inner_service.loop
        )

    def channel_block_sync(self, channel_name, block_hash, block_height) -> Tuple:
        channel_stub = StubCollection().channel_stubs[channel_name]
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().block_sync(block_hash, block_height),
            self._inner_service.loop
        )
        return future.result()

    def channel_add_audience(self, channel_name, peer_target):
        channel_stub = StubCollection().channel_stubs[channel_name]
        asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().add_audience(peer_target=peer_target),
            self._inner_service.loop
        )

    def channel_remove_audience(self, channel_name, peer_target):
        channel_stub = StubCollection().channel_stubs[channel_name]
        asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().remove_audience(peer_target=peer_target),
            self._inner_service.loop
        )

    def channel_vote_unconfirmed_block(self, channel_name, vote_dumped):
        channel_stub = StubCollection().channel_stubs[channel_name]
        asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().vote_unconfirmed_block(vote_dumped),
            self._inner_service.loop
        )

    def peer_get_channel_infos(self):
        return self._peer_state.channel_infos


class PeerService:
    """Peer Service
    p2p networking with P2PService(outer) and inter process communication with rabbitMQ(inner)
    """
    def __init__(self, radio_station_target=None, node_type=None):
        """
        :param radio_station_target: IP:Port of Radio Station
        :param node_type: CommunityNode or CitizenNode
        :return:
        """
        node_type = node_type or conf.NodeType.CommunityNode

        self.is_support_node_function = \
            partial(conf.NodeType.is_support_node_function, node_type=node_type)

        utils.logger.spam(f"Your Peer Service runs on debugging MODE!")
        utils.logger.spam(f"You can see many terrible garbage logs just for debugging, DO U Really want it?")

        self._peer_state = PeerState()
        self._peer_state.radio_station_target = radio_station_target

        logging.info("Set Radio Station target is " + self._peer_state.radio_station_target)

        self._radio_station_stub = None
        self.p2p_service: P2PService = None
        self._channel_infos = None

        self._peer_state.peer_id = None
        self._peer_state.peer_port = 0
        self._peer_state.peer_target = None
        self._peer_state.rest_target = None
        self._peer_state.channel_infos = {}
        self._peer_state.node_type = node_type
        self._peer_state.node_keys = bytes()
        # peer status cache for channel
        self._peer_state.status_cache = {}

        # gRPC service for Peer
        self._inner_service: PeerInnerService = None

        self._channel_services = {}
        self._rest_service = None

        ObjectManager().peer_service = self

    @property
    def peer_target(self):
        return self._peer_state.peer_target

    @property
    def rest_target(self):
        return self._peer_state.reset_target

    @property
    def channel_infos(self):
        return self._peer_state.channel_infos

    @property
    def node_type(self):
        return self._peer_state.node_type

    @property
    def radio_station_target(self):
        return self._peer_state.radio_station_target

    @property
    def stub_to_radiostation(self):
        if self._radio_station_stub is None:
            if self.is_support_node_function(conf.NodeFunction.Vote):
                self._radio_station_stub = get_radio_station_stub(self._peer_state.radio_station_target)
            else:
                self._radio_station_stub = RestStubManager(self._peer_state.radio_station_target)

        return self._radio_station_stub

    @property
    def peer_port(self):
        return self._peer_state.peer_port

    @property
    def peer_id(self):
        return self._peer_state.peer_id

    @property
    def node_key(self):
        return self._peer_state.node_key

    def _get_channel_infos(self):
        # util.logger.spam(f"__get_channel_infos:node_type::{self.__node_type}")
        if self.is_support_node_function(conf.NodeFunction.Vote):
            if conf.ENABLE_REP_RADIO_STATION:
                response = self.p2p_service.call_and_retry(
                    self.stub_to_radiostation,
                    self.peer_id,
                    self.peer_target
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
        self._peer_state.peer_target = f"{target_ip}:{port}"
        self._peer_state.peer_port = int(port)

        rest_port = int(port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER
        self._peer_state.rest_target = f"{target_ip}:{rest_port}"

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
        # self._node_key = signer.private_key.private_key
        self._peer_state.node_key = signer.private_key.private_key

    def _make_peer_id(self, address):
        self._peer_state.peer_id = address

        logger_preset = loggers.get_preset()
        logger_preset.peer_id = self.peer_id
        logger_preset.update_logger()

        logging.info(f"run peer_id : {self._peer_state.peer_id}")

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
              agent_pin: str = None,
              amqp_target: str = None,
              amqp_key: str = None,
              event_for_init: multiprocessing.Event = None):
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
            amqp_target, peer_queue_name, conf.AMQP_USERNAME, conf.AMQP_PASSWORD)

        self._reset_channel_infos()

        self._run_rest_services(port)

        self.p2p_service = P2PService(self._peer_state.peer_port, PeerInnerBridge(self._inner_service))
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
        for i, channel_name in enumerate(self.channel_infos.keys()):
            score_port = (self._peer_state.peer_port
                          + conf.PORT_DIFF_SCORE_CONTAINER
                          + conf.PORT_DIFF_BETWEEN_SCORE_CONTAINER * i)

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

        for channel_name, channel_info in self.channel_infos.items():
            await StubCollection().create_channel_stub(channel_name)
            await StubCollection().create_channel_tx_receiver_stub(channel_name)

            await StubCollection().create_icon_score_stub(channel_name)

    def _reset_channel_infos(self):
        self._peer_state.channel_infos = self._get_channel_infos()
        if not self.channel_infos:
            utils.exit_and_msg("There is no peer_list, initial network is not allowed without RS!")

    async def change_node_type(self, node_type):
        if self.node_type.value == node_type:
            utils.logger.warning(f"Does not change node type because new note type equals current node type")
            return

        self._peer_state.node_type = conf.NodeType(node_type)
        self.is_support_node_function = \
            partial(conf.NodeType.is_support_node_function, node_type=node_type)

        self._radio_station_stub = None

        self._reset_channel_infos()
