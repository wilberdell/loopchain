import os
import random

import pytest

from loopchain.blockchain.transactions import TransactionBuilder, TransactionVersioner
from loopchain.blockchain.transactions import TransactionVerifier
from loopchain.blockchain.transactions import genesis
from loopchain.blockchain.transactions import v2
from loopchain.blockchain.transactions import v3
from loopchain.blockchain.transactions import v3_issue
from loopchain.blockchain.types import ExternalAddress
from loopchain.crypto.signature import Signer


class TestTransactionVerifier:
    versions = (
        v2.version,
        v3.version,
        v3_issue.version,
    )

    @pytest.fixture
    def transaction_builder(self):
        """Transaction fixture"""
        def _tx(version) -> TransactionBuilder:
            tb = TransactionBuilder.new(version=version, type_="base", versioner=TransactionVersioner())
            tb.step_limit = 1000000
            tb.value = 100000
            tb.signer = Signer.new()
            tb.to_address = ExternalAddress(os.urandom(20))
            tb.nid = 3
            tb.nonce = random.randint(0, 100000)
            tb.data = "test"
            tb.data_type = "message"

            return tb

        return _tx

    @pytest.mark.parametrize("version", versions + (genesis.version, ))
    def test_init(self, version):
        tv = TransactionVerifier.new(version=version, type_="base", versioner=TransactionVersioner())

        assert tv

    @pytest.mark.parametrize("version", versions)
    def test_pre_verify(self, version, transaction_builder):
        tb = transaction_builder(version)
        tx = tb.build()

        tv = TransactionVerifier.new(version=tx.version, type_=tx.type(), versioner=TransactionVersioner())
        tv.pre_verify(tx, nid=3)
