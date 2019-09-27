import functools
import os
from typing import List

import pytest

from loopchain.blockchain.blocks import BlockBuilder, v0_1a, v0_3
from loopchain.blockchain.transactions import Transaction
from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.blockchain.types import Address
from loopchain.blockchain.types import ExternalAddress, Hash32, BloomFilter
from loopchain.blockchain.votes.v0_3 import BlockVote, LeaderVote
from loopchain.crypto.signature import Signer


# @pytest.fixture
# def block_header_factory():
#     def _block_header_factory(version):
#
#         return BlockHeader(hash=,
#                            prev_hash=,
#                            height=,
#                            timestamp=,
#                            peer_id=,
#                            signature=
#                            )
#
#     return _block_header_factory
#
#
# @pytest.fixture
# def block_body():
#     return
#


@pytest.fixture
def block_builder_factory_base(tx_builder_factory, tx_version="0x3", tx_count=5):
    def _block_builder_factory(block_version: str, _tx_builder_factory, _tx_version, _tx_count):
        """Note that assign variables to only required member vars!"""
        block_builder: BlockBuilder = BlockBuilder.new(version=block_version, tx_versioner=TransactionVersioner())

        # Attributes that must be assigned
        block_builder.height: int = 1
        block_builder.prev_hash: Hash32 = Hash32(os.urandom(Hash32.size))
        block_builder.signer: Signer = Signer.new()

        if block_version == v0_1a.version:
            # Attributes to be assigned(optional)
            block_builder.next_leader: Address = Address(os.urandom(Address.size))
            block_builder.confirm_prev_block = True
            block_builder.fixed_timestamp: int = 0

            # Attributes to be generated
            block_builder.commit_state: dict = None
            block_builder.merkle_tree_root_hash: 'Hash32' = None

            block_builder._timestamp: int = None

        if block_version == v0_3.version:
            # Attributes that must be assigned
            def generate_rep() -> ExternalAddress:
                return ExternalAddress(os.urandom(ExternalAddress.size))

            reps_count = 4
            block_builder.reps: List[ExternalAddress] = [generate_rep() for _ in range(reps_count)]
            block_builder.next_reps_hash: Hash32 = Hash32(os.urandom(Hash32.size))
            block_builder.leader_votes: List[LeaderVote] = []
            block_builder.prev_votes: List[BlockVote] = None
            block_builder.next_leader: 'ExternalAddress' = generate_rep()

            # Attributes to be assigned(optional)
            block_builder.fixed_timestamp: int = None
            block_builder.state_hash: 'Hash32' = None

            # Attributes to be generated
            block_builder.transactions_hash: 'Hash32' = None
            block_builder.receipts_hash: 'Hash32' = None
            block_builder.reps_hash: 'Hash32' = None
            block_builder.leader_votes_hash: 'Hash32' = None
            block_builder.prev_votes_hash: 'Hash32' = None
            block_builder.logs_bloom: 'BloomFilter' = None
            block_builder._timestamp: int = None
            block_builder._receipts: list = None

        for i in range(_tx_count):
            tx: Transaction = _tx_builder_factory(version=_tx_version).build()
            block_builder.transactions[tx.hash] = tx

        return block_builder

    return functools.partial(_block_builder_factory, _tx_builder_factory=tx_builder_factory, _tx_version=tx_version, _tx_count=tx_count)


