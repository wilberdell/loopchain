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
"""broadcast scheduler"""

import abc
import logging
import multiprocessing as mp
import os
import queue
import signal
import threading
import time
from concurrent import futures
from functools import partial

from loopchain import configure as conf, utils
from loopchain.baseservice import CommonThread, BroadcastCommand, TimerService, Timer
from loopchain.baseservice.module_process import ModuleProcess, ModuleProcessProperties
from loopchain.baseservice.tx_item_helper import *
from loopchain.p2p.broadcaster import Broadcaster


class BroadcastHandler:
    """ handle broadcast command for each channel
    """

    def __init__(self, channel: str, self_target: str = None):
        self.__channel = channel

        self.__handler_map = {
            BroadcastCommand.CREATE_TX: self.__handler_create_tx,
            BroadcastCommand.SUBSCRIBE: self.__handler_subscribe,
            BroadcastCommand.UNSUBSCRIBE: self.__handler_unsubscribe,
            BroadcastCommand.BROADCAST: self.__handler_broadcast
        }

        self.__broadcaster = Broadcaster(channel=channel, self_target=self_target)

        # FIXME : move timer service to somewhere
        self.__timer_service = TimerService()

    @property
    def is_running(self):
        return self.__timer_service.is_run()

    def start(self):
        self.__timer_service.start()

    def stop(self):
        if self.__timer_service.is_run():
            self.__timer_service.stop()
            self.__timer_service.wait()

    def handle_command(self, command, params):
        logging.warning(f"handle_command: {command}")
        func = self.__handler_map[command]
        func(params)

    def __handler_subscribe(self, audience_target):
        utils.logger.debug(f"BroadcastHandler received subscribe command peer_target: {audience_target}")
        self.__broadcaster.subscribe(audience_target)

    def __handler_unsubscribe(self, audience_target):
        utils.logging.debug(f"BroadcastHandler received unsubscribe command peer_target: {audience_target}")
        self.__broadcaster.unsubscribe(audience_target)

    def __handler_broadcast(self, broadcast_param):
        # logging.debug("BroadcastThread received broadcast command")
        broadcast_method_name = broadcast_param[0]
        broadcast_method_param = broadcast_param[1]
        broadcast_method_kwparam = broadcast_param[2]
        # logging.debug("BroadcastThread method name: " + broadcast_method_name)
        # logging.debug("BroadcastThread method param: " + str(broadcast_method_param))

        self.__broadcaster.broadcast(broadcast_method_name, broadcast_method_param, broadcast_method_kwparam)

    def __handler_create_tx(self, create_tx_param):
        # logging.debug(f"Broadcast create_tx....")
        try:
            tx_item = TxItem.create_tx_item(create_tx_param, self.__channel)
        except Exception as e:
            logging.warning(f"tx in channel({self.__channel})")
            logging.warning(f"__handler_create_tx: meta({create_tx_param})")
            logging.warning(f"tx dumps fail ({e})")
            return

        self.__broadcaster.add_tx_item(tx_item)
        self.__send_tx_in_timer(conf.SEND_TX_LIST_DURATION)

    def __send_tx_by_timer(self, **kwargs):
        # utils.logger.spam(f"broadcast_scheduler:__send_tx_by_timer")

        # Send single tx for test
        # stored_tx_item = self.stored_tx.get()
        # self.__broadcast_run("AddTx", stored_tx_item.get_tx_message())

        # Send multiple tx
        remains = self.__broadcaster.send_tx_list()
        if remains:
            self.__send_tx_in_timer()

    def __send_tx_in_timer(self, duration: int = 0):
        # utils.logger.spam(f"broadcast_scheduler:__send_tx_in_timer")

        if TimerService.TIMER_KEY_ADD_TX not in self.__timer_service.timer_list:
            self.__timer_service.add_timer(
                TimerService.TIMER_KEY_ADD_TX,
                Timer(
                    target=TimerService.TIMER_KEY_ADD_TX,
                    duration=duration,
                    callback=self.__send_tx_by_timer,
                    callback_kwargs={}
                )
            )


class BroadcastScheduler(metaclass=abc.ABCMeta):
    def __init__(self):
        self.__schedule_listeners = dict()

    @abc.abstractmethod
    def start(self):
        raise NotImplementedError("start function is interface method")

    @abc.abstractmethod
    def stop(self):
        raise NotImplementedError("stop function is interface method")

    @abc.abstractmethod
    def wait(self):
        raise NotImplementedError("stop function is interface method")

    @abc.abstractmethod
    def _put_command(self, command, params, block=False, block_timeout=None):
        raise NotImplementedError("_put_command function is interface method")

    def add_schedule_listener(self, callback, commands: tuple):
        if not commands:
            raise ValueError("commands parameter is required")

        for cmd in commands:
            callbacks = self.__schedule_listeners.get(cmd)
            if callbacks is None:
                callbacks = []
                self.__schedule_listeners[cmd] = callbacks
            elif callback in callbacks:
                raise ValueError("callback is already in callbacks")
            callbacks.append(callback)

    def remove_schedule_listener(self, callback):
        removed = False
        for cmd in list(self.__schedule_listeners):
            callbacks = self.__schedule_listeners[cmd]
            try:
                callbacks.remove(callback)
                removed = True
                if len(callbacks):
                    del self.__schedule_listeners[cmd]
            except ValueError:
                pass
        if not removed:
            raise ValueError("callback is not in overserver callbacks")

    def __perform_schedule_listener(self, command, params):
        callbacks = self.__schedule_listeners.get(command)
        if callbacks:
            for cb in callbacks:
                cb(command, params)

    def schedule_job(self, command, params, block=False, block_timeout=None):
        self._put_command(command, params, block=block, block_timeout=block_timeout)
        self.__perform_schedule_listener(command, params)

    def schedule_broadcast(self, method_name, method_param, *, retry_times=None, timeout=None):
        kwargs = {}
        if retry_times is not None:
            kwargs['retry_times'] = retry_times
        if timeout is not None:
            kwargs['timeout'] = timeout
        self.schedule_job(BroadcastCommand.BROADCAST, (method_name, method_param, kwargs))


class _BroadcastThread(CommonThread):
    """
    TODO : consider broadcastThread change to coroutine
    TODO : queue.priorityQueue to asyncio.PriorityQueue
    """

    def __init__(self, channel: str, self_target: str=None):
        super().__init__()
        self.broadcast_queue = queue.PriorityQueue()
        self.__broadcast_pool = futures.ThreadPoolExecutor(conf.MAX_BROADCAST_WORKERS, "BroadcastThread")
        self.__broadcast_handler = BroadcastHandler(channel, self_target)

    def stop(self):
        super().stop()
        self.broadcast_queue.put((None, None, None, None))
        self.__broadcast_pool.shutdown(False)

    def run(self, event: threading.Event):
        event.set()
        self.__broadcast_handler.start()

        def _callback(curr_future: futures.Future, executor_future: futures.Future):
            if executor_future.exception():
                curr_future.set_exception(executor_future.exception())
                logging.error(executor_future.exception())
            else:
                curr_future.set_result(executor_future.result())

        while self.is_run():
            priority, command, params, future = self.broadcast_queue.get()
            if command is None:
                break

            return_future = self.__broadcast_pool.submit(self.__broadcast_handler.handle_command, command, params)
            if future is not None:
                return_future.add_done_callback(partial(_callback, future))


class _BroadcastSchedulerThread(BroadcastScheduler):
    def __init__(self, channel: str, self_target: str=None):
        super().__init__()

        self.__broadcast_thread = _BroadcastThread(channel, self_target=self_target)

    def start(self):
        self.__broadcast_thread.start()

    def stop(self):
        self.__broadcast_thread.stop()

    def wait(self):
        self.__broadcast_thread.wait()

    def _put_command(self, command, params, block=False, block_timeout=None):
        if command == BroadcastCommand.CREATE_TX:
            priority = (10, time.time())
        elif isinstance(params, tuple) and params[0] == "AddTx":
            priority = (10, time.time())
        else:
            priority = (0, time.time())

        future = futures.Future() if block else None
        self.__broadcast_thread.broadcast_queue.put((priority, command, params, future))
        if future is not None:
            future.result(block_timeout)


class _BroadcastSchedulerMp(BroadcastScheduler):
    def __init__(self, channel: str, self_target: str=None):
        super().__init__()

        self.__channel = channel
        self.__self_target = self_target

        self.__process = ModuleProcess()

        self.__broadcast_queue = self.__process.Queue()
        self.__broadcast_queue.cancel_join_thread()

    @staticmethod
    def _main(broadcast_queue: mp.Queue, channel: str, self_target: str, properties: ModuleProcessProperties=None):
        if properties is not None:
            ModuleProcess.load_properties(properties, f"{channel}_broadcast")

        logging.info(f"BroadcastScheduler process({channel}) start")

        broadcast_queue.cancel_join_thread()

        broadcast_handler = BroadcastHandler(channel, self_target)
        broadcast_handler.start()

        original_sigterm_handler = signal.getsignal(signal.SIGTERM)
        original_sigint_handler = signal.getsignal(signal.SIGINT)

        def _signal_handler(signal_num, frame):
            signal.signal(signal.SIGTERM, original_sigterm_handler)
            signal.signal(signal.SIGINT, original_sigint_handler)
            logging.error(f"BroadcastScheduler process({channel}) has been received signal({signal_num})")
            broadcast_queue.put((None, None))
            broadcast_handler.stop()

        signal.signal(signal.SIGTERM, _signal_handler)
        signal.signal(signal.SIGINT, _signal_handler)

        while True:
            command, params = broadcast_queue.get()
            if not broadcast_handler.is_running or command is None:
                break
            broadcast_handler.handle_command(command, params)

        while not broadcast_queue.empty():
            broadcast_queue.get()

        logging.info(f"BroadcastScheduler process({channel}) end")

    def start(self):
        def crash_callback_in_join_thread(process: ModuleProcess):
            os.kill(os.getpid(), signal.SIGTERM)

        args = (self.__broadcast_queue, self.__channel, self.__self_target)
        self.__process.start(target=_BroadcastSchedulerMp._main,
                             args=args,
                             crash_callback_in_join_thread=crash_callback_in_join_thread)

    def stop(self):
        logging.info(f"Terminate BroadcastScheduler process({self})")
        self.__process.terminate()

    def wait(self):
        self.__process.join()

    def _put_command(self, command, params, block=False, block_timeout=None):
        self.__broadcast_queue.put((command, params))


class BroadcastSchedulerFactory:
    @staticmethod
    def new(channel: str, self_target: str=None, is_multiprocessing: bool=None) -> BroadcastScheduler:
        if is_multiprocessing is None:
            is_multiprocessing = conf.IS_BROADCAST_MULTIPROCESSING

        if is_multiprocessing:
            return _BroadcastSchedulerMp(channel, self_target=self_target)
        else:
            return _BroadcastSchedulerThread(channel, self_target=self_target)
