#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
"""Test timer service"""

import asyncio
import datetime

import pytest
from freezegun import freeze_time

from loopchain.baseservice.timer_service import Timer, TimerService, OffType

TEST_TIMER_KEY = "test_timer_key"
TEST_INVALID_TIMER_KEY = "not_exist_key"
TEST_DURATIONS = [0.1, 0.5, 1, 2]


@pytest.fixture
def timer_service():
    ts = TimerService()
    ts.start()

    yield ts

    ts.stop()


class TestTimer:
    @pytest.mark.parametrize("duration", TEST_DURATIONS)
    def test_timeout_after_duration_sec_passed(self, duration):
        timer = Timer(duration=duration)
        assert not timer.is_timeout()

        with freeze_time(datetime.datetime.now() + datetime.timedelta(seconds=duration)):
            assert timer.is_timeout()

    def test_start_time_reset_after_reset_timer(self):
        attr_start_time = "_Timer__start_time"

        timer = Timer()
        start_time = getattr(timer, attr_start_time)
        timer.reset()
        new_start_time = getattr(timer, attr_start_time)

        assert new_start_time > start_time

    @pytest.mark.parametrize("duration", TEST_DURATIONS)
    def test_remain_time_returns_correct(self, duration):
        timer = Timer(duration=duration)

        remain_time = timer.remain_time()
        assert remain_time < duration

        with freeze_time(datetime.datetime.now() + datetime.timedelta(seconds=duration)):
            remain_time = timer.remain_time()

            assert remain_time == 0

    def test_timer_on(self):
        """Timer.on do nothing!!!"""
        timer = Timer()
        timer.on()

    def test_timer_off_triggers_blocking_func(self, mocker):
        blocking_callback = mocker.MagicMock()

        timer = Timer(callback=blocking_callback)
        assert not blocking_callback.called

        timer.off(OffType.time_out)
        assert blocking_callback.called

    def test_timer_off_triggers_coroutine_func(self, mocker):
        coro_call_checker = mocker.MagicMock()

        async def coro_callback(**kwargs):
            coro_call_checker()

        timer = Timer(callback=coro_callback)

        timer.off(OffType.time_out)
        asyncio.get_event_loop().run_until_complete(asyncio.sleep(0))  # Give a chance for coroutine to run

        assert coro_call_checker.called

    def test_timer_off_and_exception_in_blocking_func_does_not_break_process(self, mocker):
        blocking_callback = mocker.MagicMock()
        blocking_callback.side_effect = RuntimeError("Call is back!!")
        timer = Timer(callback=blocking_callback)
        assert not blocking_callback.called

        timer.off(OffType.time_out)
        assert blocking_callback.called

    def test_timer_off_and_exception_in_coroutine_func_does_not_break_process(self, mocker):
        coro_call_checker = mocker.MagicMock()
        coro_call_checker.side_effect = RuntimeError("Call is back!!")

        async def coro_callback(**kwargs):
            coro_call_checker()

        timer = Timer(callback=coro_callback)

        timer.off(OffType.time_out)
        asyncio.get_event_loop().run_until_complete(asyncio.sleep(0))  # Give a chance for coroutine to run

        assert coro_call_checker.called


class TestTimerService:
    def test_add_timer_adds_timer_key(self, timer_service: TimerService):
        timer = Timer(duration=1)

        timer_service.add_timer(TEST_TIMER_KEY, timer)
        assert len(timer_service.timer_list) == 1
        assert timer_service.get_timer(TEST_TIMER_KEY)

    def test_add_timer_with_is_run_at_start(self, timer_service: TimerService, mocker):
        timer = Timer(duration=1, is_run_at_start=True)

        mock_run = mocker.MagicMock()
        mock_run_immediate = mocker.MagicMock()
        timer_service._TimerService__run = mock_run
        timer_service._TimerService__run_immediate = mock_run_immediate

        with mocker.patch.object(asyncio, "run_coroutine_threadsafe"):
            timer_service.add_timer(TEST_TIMER_KEY, timer)
            assert mock_run_immediate.called
            assert not mock_run.called

    def test_add_timer_without_is_run_at_start(self, timer_service: TimerService, mocker):
        timer = Timer(duration=1)

        mock_run = mocker.MagicMock()
        mock_run_immediate = mocker.MagicMock()
        timer_service._TimerService__run = mock_run
        timer_service._TimerService__run_immediate = mock_run_immediate

        with mocker.patch.object(asyncio, "run_coroutine_threadsafe"):
            timer_service.add_timer(TEST_TIMER_KEY, timer)
            assert not mock_run_immediate.called
            assert mock_run.called

    def test_add_timer_convenient_adds_timer_key(self, timer_service: TimerService):
        assert len(timer_service.timer_list) == 0

        timer_service.add_timer_convenient(TEST_TIMER_KEY, duration=1)
        assert len(timer_service.timer_list) == 1

    def test_add_timer_convenient_with_duplicated_timer_key(self, timer_service: TimerService):
        assert len(timer_service.timer_list) == 0

        timer_service.add_timer_convenient(TEST_TIMER_KEY, duration=1)
        assert len(timer_service.timer_list) == 1

        assert TEST_TIMER_KEY in timer_service.timer_list
        timer_service.add_timer_convenient(TEST_TIMER_KEY, duration=2)
        assert len(timer_service.timer_list) == 1

    def test_remove_timer_deletes_timer_key(self, timer_service: TimerService):
        timer = Timer(duration=1)
        timer_service.add_timer(TEST_TIMER_KEY, timer)

        timer_service.remove_timer(TEST_TIMER_KEY)
        assert len(timer_service.timer_list) == 0
        assert not timer_service.get_timer(TEST_TIMER_KEY)

    def test_remove_timer_with_invalid_key(self, timer_service: TimerService):
        timer = Timer(duration=1)
        timer_service.add_timer(TEST_TIMER_KEY, timer)

        assert not timer_service.remove_timer(TEST_INVALID_TIMER_KEY)
        assert TEST_TIMER_KEY in timer_service.timer_list

    def test_reset_timer_calls_timer_reset(self, timer_service: TimerService, mocker):
        with mocker.patch.object(Timer, "reset") as mock_timer_reset:
            timer = Timer(duration=1)
            timer.reset = mock_timer_reset
            timer_service.add_timer(TEST_TIMER_KEY, timer)

            timer_service.reset_timer(TEST_TIMER_KEY)
            assert mock_timer_reset.called

    def test_reset_timer_with_invalid_key(self, timer_service: TimerService, mocker):
        with mocker.patch.object(Timer, "reset") as mock_timer_reset:
            timer = Timer(duration=1)
            timer.reset = mock_timer_reset
            timer_service.add_timer(TEST_TIMER_KEY, timer)

            timer_service.reset_timer(TEST_INVALID_TIMER_KEY)
            assert not mock_timer_reset.called

    def test_restart_timer_turnoff_timer_and_reset(self, timer_service: TimerService, mocker):
        mock_timer_off = mocker.MagicMock()
        mock_timer_reset = mocker.MagicMock()

        timer = Timer(duration=1)
        timer.off = mock_timer_off
        timer.reset = mock_timer_reset

        timer_service.add_timer(TEST_TIMER_KEY, timer)
        timer_service.restart_timer(TEST_TIMER_KEY)

        assert mock_timer_off.called
        assert mock_timer_reset.called

    def test_restart_timer_with_invalid_key(self, timer_service: TimerService, mocker):
        mock_timer_off = mocker.MagicMock()
        mock_timer_reset = mocker.MagicMock()

        timer = Timer(duration=1)
        timer.off = mock_timer_off
        timer.reset = mock_timer_reset

        timer_service.add_timer(TEST_TIMER_KEY, timer)
        timer_service.restart_timer(TEST_INVALID_TIMER_KEY)

        assert not mock_timer_off.called
        assert not mock_timer_reset.called

    def test_stop_timer_calls_timer_off_and_remove(self, timer_service: TimerService, mocker):
        mock_timer_off = mocker.MagicMock()

        timer = Timer(duration=1)
        timer.off = mock_timer_off

        timer_service.add_timer(TEST_TIMER_KEY, timer)
        assert TEST_TIMER_KEY in timer_service.timer_list

        timer_service.stop_timer(TEST_TIMER_KEY, OffType.normal)
        assert TEST_TIMER_KEY not in timer_service.timer_list
        assert mock_timer_off.called

    def test_stop_timer_with_invalid_key(self, timer_service: TimerService, mocker):
        mock_timer_off = mocker.MagicMock()

        timer = Timer(duration=1)
        timer.off = mock_timer_off

        timer_service.add_timer(TEST_TIMER_KEY, timer)
        assert TEST_TIMER_KEY in timer_service.timer_list

        timer_service.stop_timer(TEST_INVALID_TIMER_KEY, OffType.normal)
        assert TEST_TIMER_KEY in timer_service.timer_list
        assert not mock_timer_off.called

    def test_clean(self, timer_service: TimerService):
        timer = Timer(duration=1)
        timer_service.add_timer(TEST_TIMER_KEY, timer)
        assert len(timer_service.timer_list) == 1

        timer_service.clean()
        assert not timer_service.timer_list


@pytest.mark.asyncio
class TestTimerServiceRun:
    @pytest.fixture
    def mocked_timer_service(self, timer_service, mocker):
        mock_restart_timer = mocker.MagicMock()
        mock_stop_timer = mocker.MagicMock()
        timer_service.restart_timer = mock_restart_timer
        timer_service.stop_timer = mock_stop_timer

        return timer_service

    async def test_timer_triggered_if_timeout(self, timer_service: TimerService, mocker):
        timer = Timer()
        mock_is_timeout = mocker.MagicMock(return_value=True)
        timer.is_timeout = mock_is_timeout

        mock_run_immediate = mocker.MagicMock()
        timer_service._TimerService__run_immediate = mock_run_immediate
        timer_service.add_timer(TEST_TIMER_KEY, timer)

        await asyncio.sleep(0.1)
        assert mock_run_immediate.called

    async def test_repeated_timer_run_again_if_timeout(self, mocked_timer_service: TimerService, mocker):
        timer = Timer(is_repeat=True)
        mock_is_timeout = mocker.MagicMock(return_value=True)
        timer.is_timeout = mock_is_timeout

        mocked_timer_service.add_timer(TEST_TIMER_KEY, timer)

        await asyncio.sleep(0.1)
        assert mocked_timer_service.restart_timer.called

    async def test_not_repeated_timer_stopped_if_timeout(self, mocked_timer_service: TimerService, mocker):
        burn_out_timer = Timer(is_repeat=False)
        mock_is_timeout = mocker.MagicMock(return_value=True)
        burn_out_timer.is_timeout = mock_is_timeout

        mocked_timer_service.add_timer(TEST_TIMER_KEY, burn_out_timer)

        await asyncio.sleep(0.1)
        assert not mocked_timer_service.restart_timer.called
        assert mocked_timer_service.stop_timer.called
