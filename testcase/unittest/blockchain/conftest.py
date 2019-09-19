import functools
import os

import pytest

from loopchain.blockchain.transactions import TransactionBuilder, TransactionVersioner
from loopchain.blockchain.transactions import genesis, v2, v3
from loopchain.blockchain.types import Hash32, Signature, ExternalAddress, Address
from loopchain.crypto.signature import Signer


@pytest.fixture
def tx_builder_factory():
    def _tx_builder_factory(version: str):
        tx_builder: TransactionBuilder = TransactionBuilder.new(version=version, type_=None, versioner=TransactionVersioner())

        # Attributes that must be assigned
        tx_builder.signer = Signer.new()

        # Attributes to be generated
        tx_builder.from_address = ExternalAddress(os.urandom(ExternalAddress.size))
        tx_builder.hash = Hash32(os.urandom(Hash32.size))
        tx_builder.signature = Signature(Signature.size)
        tx_builder.origin_data = {"test": "origin_data"}
        tx_builder.raw_data = {"test": "origin_data"}

        if version == genesis.version:
            # Attributes that must be assigned
            tx_builder.accounts = ["accounts"]
            tx_builder.message = "message"

            # Attributes to be assigned(optional)
            tx_builder.nid = 3

        if version == v2.version:
            # Attributes that must be assigned
            tx_builder.to_address = Address(os.urandom(Address.size))
            tx_builder.value: int = 10000
            tx_builder.nonce: int = 10000

        if version == v3.version:
            # Attributes that must be assigned
            tx_builder.to_address = Address(os.urandom(Address.size))
            tx_builder.value = 10000
            tx_builder.step_limit = 10000
            tx_builder.nid = 3
            tx_builder.nonce: int = 10000

        return tx_builder

    return _tx_builder_factory


@pytest.fixture
def tx_factory(tx_builder_factory):
    def _tx_factory(_tx_builder_factory, version):
        tx_builder: TransactionBuilder = _tx_builder_factory(version=version)
        transaction = tx_builder.build()

        return transaction

    return functools.partial(_tx_factory, _tx_builder_factory=tx_builder_factory)


