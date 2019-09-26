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

import os

import pytest

from loopchain.blockchain.blocks import BlockBuilder, Block
from loopchain.blockchain.blocks import v0_1a
from loopchain.blockchain.blocks import v0_3
from loopchain.blockchain.types import ExternalAddress, Hash32, BloomFilter
from loopchain.blockchain.types import Signature


@pytest.mark.parametrize("module", [v0_1a, v0_3])
class TestBlockBuilderBase:
    def test_builder_version_check(self, block_builder_factory_base, module):
        block_builder: BlockBuilder = block_builder_factory_base(block_version=module.version)

        assert isinstance(block_builder, module.BlockBuilder)

    # @pytest.mark.skip(reason="What is the most meaningful case to test this?")
    def test_size_check(self, block_builder_factory_base, module):
        block_builder: BlockBuilder = block_builder_factory_base(block_version=module.version)

        assert isinstance(block_builder.size(), int)

    def test_build_peer_id_returns_its_peer_id_if_exists(self, block_builder_factory_base, module):
        block_builder: BlockBuilder = block_builder_factory_base(block_version=module.version)
        expected_peer_id = ExternalAddress(os.urandom(ExternalAddress.size))
        block_builder.peer_id = expected_peer_id

        built_peer_id = block_builder.build_peer_id()
        assert built_peer_id == expected_peer_id

    def test_build_peer_id_raises_exc_if_signer_not_exists(self, block_builder_factory_base, module):
        block_builder: BlockBuilder = block_builder_factory_base(block_version=module.version)
        assert not block_builder.peer_id

        block_builder.signer = None

        with pytest.raises(RuntimeError):
            assert block_builder.build_peer_id()

    def test_sign_returns_its_signature_if_exists(self, block_builder_factory_base, module):
        block_builder: BlockBuilder = block_builder_factory_base(block_version=module.version)
        expected_signature = Signature(os.urandom(Signature.size))
        block_builder.signature = expected_signature

        signature = block_builder.sign()

        assert signature == expected_signature

    def test_sign_raises_exc_if_hash_not_exists(self, block_builder_factory_base, module):
        block_builder: BlockBuilder = block_builder_factory_base(block_version=module.version)
        assert not block_builder.signature
        assert not block_builder.hash

        with pytest.raises(RuntimeError):
            assert block_builder.sign()

    def test_sign_generates_signature(self, block_builder_factory_base, module):
        block_builder: BlockBuilder = block_builder_factory_base(block_version=module.version)
        block_builder.hash = Hash32(os.urandom(Hash32.size))
        assert not block_builder.signature

        block_builder.sign()
        assert block_builder.signature

    def test_reset_cache_removes_base_target_members(self, block_builder_factory_base, module):
        block_builder: BlockBuilder = block_builder_factory_base(block_version=module.version)

        block_builder.block = "block "
        block_builder.hash = "hash"
        block_builder.signature = "signature"
        block_builder.peer_id = "peer_id"

        block_builder.reset_cache()

        assert not block_builder.block
        assert not block_builder.hash
        assert not block_builder.signature
        assert not block_builder.peer_id

    def test_build(self, block_builder_factory_base, module):
        block_builder: BlockBuilder = block_builder_factory_base(block_version=module.version)
        block_builder.build()

    # @pytest.mark.skip(reason="What is the most meaningful case to test this?")
    def test_block_builder_from_block_functionally(self, block_builder_factory_base, module):
        block_builder: BlockBuilder = block_builder_factory_base(block_version=module.version)
        block: Block = block_builder.build()

        block_builder.from_(block=block)


class TestBlockBuilderV0_1:
    BLOCK_VERSION = v0_1a.version

    @pytest.fixture
    def block_builder_factory_v0_1(self, block_builder_factory_base):
        block_builder = block_builder_factory_base(block_version=TestBlockBuilderV0_1.BLOCK_VERSION)
        assert isinstance(block_builder, v0_1a.BlockBuilder)

        return block_builder

    def test_reset_cache_removes_target_members(self, block_builder_factory_v0_1):
        block_builder_factory_v0_1.merkle_tree_root_hash = "merkle_tree_root_hash"
        block_builder_factory_v0_1.commit_state = "commit_state"
        block_builder_factory_v0_1._timestamp = "timestamp"

        block_builder_factory_v0_1.reset_cache()

        assert not block_builder_factory_v0_1.merkle_tree_root_hash
        assert not block_builder_factory_v0_1.commit_state
        assert not block_builder_factory_v0_1._timestamp

    def test_build_merkle_tree_root_hash_returns_its_hash_if_exists(self, block_builder_factory_v0_1):
        expected_merkle_tree_root_hash = Hash32(os.urandom(Hash32.size))
        block_builder_factory_v0_1.merkle_tree_root_hash = expected_merkle_tree_root_hash

        merkle_tree_root_hash = block_builder_factory_v0_1.build_merkle_tree_root_hash()

        assert merkle_tree_root_hash == expected_merkle_tree_root_hash

    def test_build_merkle_tree_root_hash(self, block_builder_factory_v0_1):
        assert not block_builder_factory_v0_1.merkle_tree_root_hash

        block_builder_factory_v0_1.build_merkle_tree_root_hash()
        assert block_builder_factory_v0_1.merkle_tree_root_hash


class TestBlockBuilderV0_3:
    BLOCK_VERSION = v0_3.version

    @pytest.fixture
    def block_builder_factory_v0_3(self, block_builder_factory_base):
        block_builder = block_builder_factory_base(block_version=TestBlockBuilderV0_3.BLOCK_VERSION)
        assert isinstance(block_builder, v0_3.BlockBuilder)

        return block_builder

    def test_reset_cache_removes_target_members(self, block_builder_factory_v0_3):
        block_builder_factory_v0_3.transactions_hash = "transactions_hash"
        block_builder_factory_v0_3.receipts_hash = "receipts_hash"
        block_builder_factory_v0_3.reps_hash = "reps_hash"
        block_builder_factory_v0_3.leader_votes_hash = "leader_votes_hash"
        block_builder_factory_v0_3.prev_votes_hash = "prev_votes_hash"
        block_builder_factory_v0_3.logs_bloom = "logs_bloom"
        block_builder_factory_v0_3._timestamp = "_timestamp"

        block_builder_factory_v0_3.reset_cache()

        assert not block_builder_factory_v0_3.transactions_hash
        assert not block_builder_factory_v0_3.receipts_hash
        assert not block_builder_factory_v0_3.reps_hash
        assert not block_builder_factory_v0_3.leader_votes_hash
        assert not block_builder_factory_v0_3.prev_votes_hash
        assert not block_builder_factory_v0_3.logs_bloom
        assert not block_builder_factory_v0_3._timestamp

    @pytest.mark.skip(reason="What is the most meaningful case to test this?")
    def test_set_receipts_(self, block_builder_factory_v0_3):
        assert False

    def test_set_receipts_raises_exc_if_set_wrong_number_of_receipts(self, block_builder_factory_v0_3):
        assert not block_builder_factory_v0_3.receipts
        txs = block_builder_factory_v0_3.transactions
        tx_count = len(txs)

        receipts = {f"dummy{i}": i for i in range(tx_count + 1)}

        with pytest.raises(RuntimeError, match="not matched"):
            block_builder_factory_v0_3.receipts = receipts

    def test_build_transactions_hash_returns_its_hash_if_exists(self, block_builder_factory_v0_3):
        expected_transactions_hash = Hash32(os.urandom(Hash32.size))
        block_builder_factory_v0_3.transactions_hash = expected_transactions_hash

        transactions_hash = block_builder_factory_v0_3.build_transactions_hash()

        assert transactions_hash == expected_transactions_hash

    def test_build_transactions_hash_returns_empty_if_no_transactions_exists(self, block_builder_factory_v0_3):
        block_builder_factory_v0_3.transactions = []
        assert not block_builder_factory_v0_3.transactions
        assert not block_builder_factory_v0_3.transactions_hash

        transactions_hash = block_builder_factory_v0_3.build_transactions_hash()

        assert transactions_hash == Hash32.empty()

    @pytest.mark.skip(reason="BlockProver dependencies")
    def test_build_transactions_with_prover(self, block_builder_factory_v0_3):
        assert False

    def test_build_receipts_hash_returns_its_hash_if_exists(self, block_builder_factory_v0_3):
        expected_receipts_hash = Hash32(os.urandom(Hash32.size))
        block_builder_factory_v0_3.receipts_hash = expected_receipts_hash

        receipts_hash = block_builder_factory_v0_3.build_receipts_hash()

        assert receipts_hash == expected_receipts_hash

    def test_build_receipts_hash_returns_empty_if_no_receipts_exists(self, block_builder_factory_v0_3):
        assert not block_builder_factory_v0_3.receipts
        assert not block_builder_factory_v0_3.receipts_hash

        receipts_hash = block_builder_factory_v0_3.build_receipts_hash()

        assert receipts_hash == Hash32.empty()

    @pytest.mark.skip(reason="BlockProver dependencies")
    def test_build_receipts_hash_with_prover(self, block_builder_factory_v0_3):
        assert False

    def test_build_reps_hash_returns_its_hash_if_exists(self, block_builder_factory_v0_3):
        expected_reps_hash = Hash32(os.urandom(Hash32.size))
        block_builder_factory_v0_3.reps_hash = expected_reps_hash

        reps_hash = block_builder_factory_v0_3.build_reps_hash()

        assert reps_hash == expected_reps_hash

    def test_build_reps_hash_generate_next_reps_hash_if_not_exists(self, block_builder_factory_v0_3):
        block_builder_factory_v0_3.next_reps_hash = None
        assert not block_builder_factory_v0_3.next_reps_hash
        assert not block_builder_factory_v0_3.reps_hash

        block_builder_factory_v0_3.build_reps_hash()

        reps_hash = block_builder_factory_v0_3.reps_hash
        next_reps_hash = block_builder_factory_v0_3.next_reps_hash
        assert reps_hash
        assert next_reps_hash
        assert reps_hash == next_reps_hash

    @pytest.mark.skip(reason="BlockProver dependencies")
    def test_build_reps_hash_with_prover(self, block_builder_factory_v0_3):
        assert False

    def test_build_leader_votes_hash_returns_its_hash_if_exists(self, block_builder_factory_v0_3):
        expected_leader_votes_hash = Hash32(os.urandom(Hash32.size))
        block_builder_factory_v0_3.leader_votes_hash = expected_leader_votes_hash

        leader_votes_hash = block_builder_factory_v0_3.build_leader_votes_hash()

        assert leader_votes_hash == expected_leader_votes_hash

    def test_build_leader_votes_hash(self, block_builder_factory_v0_3):
        assert not block_builder_factory_v0_3.leader_votes_hash

        block_builder_factory_v0_3.build_leader_votes_hash()
        assert block_builder_factory_v0_3.leader_votes_hash

    def test_build_prev_votes_hash_returns_its_hash_if_exists(self, block_builder_factory_v0_3):
        expected_prev_votes_hash = Hash32(os.urandom(Hash32.size))
        block_builder_factory_v0_3.prev_votes_hash = expected_prev_votes_hash

        prev_votes_hash = block_builder_factory_v0_3.build_prev_votes_hash()

        assert prev_votes_hash == expected_prev_votes_hash

    # @pytest.mark.skip(reason="BlockVote dependencies")
    def test_build_prev_votes_hash_returns_empty_if_no_prev_votes_exist(self, block_builder_factory_v0_3):
        assert not block_builder_factory_v0_3.prev_votes
        assert not block_builder_factory_v0_3.prev_votes_hash

        prev_votes_hash = block_builder_factory_v0_3.build_prev_votes_hash()
        assert prev_votes_hash == Hash32.empty()

    def test_build_logs_bloom_returns_its_data_if_exists(self, block_builder_factory_v0_3):
        expected_logs_bloom = BloomFilter(os.urandom(BloomFilter.size))
        block_builder_factory_v0_3.logs_bloom = expected_logs_bloom

        logs_bloom = block_builder_factory_v0_3.build_logs_bloom()

        assert logs_bloom == expected_logs_bloom

    def test_build_logs_bloom_returns_empty_its_if_no_receipts(self, block_builder_factory_v0_3):
        assert not block_builder_factory_v0_3.receipts
        assert not block_builder_factory_v0_3.logs_bloom

        logs_bloom = block_builder_factory_v0_3.build_logs_bloom()

        assert logs_bloom == BloomFilter.empty()

    def test_build_hash_returns_its_hash_if_exists(self, block_builder_factory_v0_3):
        expected_hash = Hash32(os.urandom(Hash32.size))
        block_builder_factory_v0_3.hash = expected_hash

        hash_ = block_builder_factory_v0_3.build_hash()

        assert hash_ == expected_hash

    def test_build_hash_raises_exc_if_has_no_prev_hash(self, block_builder_factory_v0_3):
        block_builder_factory_v0_3.height = 1
        block_builder_factory_v0_3.prev_hash = None

        with pytest.raises(RuntimeError):
            block_builder_factory_v0_3.build_hash()

    def test_build_hash_set_timestamp_as_fixed_timestamp_if_exists(self, block_builder_factory_v0_3):
        assert not block_builder_factory_v0_3._timestamp

        expected_timestamp = 1111
        block_builder_factory_v0_3.fixed_timestamp = expected_timestamp

        block_builder_factory_v0_3._build_hash()

        assert block_builder_factory_v0_3._timestamp == expected_timestamp

    def test_build_hash_set_timestamp_as_current_time_if_no_fixed_timestamp(self, block_builder_factory_v0_3):
        from freezegun import freeze_time
        import datetime

        assert not block_builder_factory_v0_3.fixed_timestamp
        assert not block_builder_factory_v0_3._timestamp

        everlasting_time = datetime.datetime(2019, 9, 28, 2, 11, 11, microsecond=123123, tzinfo=datetime.timezone.utc)
        with freeze_time(everlasting_time):
            block_builder_factory_v0_3._build_hash()

        expected_timestamp = everlasting_time.timestamp()
        timestamp = block_builder_factory_v0_3._timestamp / 1_000_000

        assert timestamp == expected_timestamp
