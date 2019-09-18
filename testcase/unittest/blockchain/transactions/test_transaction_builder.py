import os

import pytest

from loopchain.blockchain.transactions import TransactionBuilder
from loopchain.blockchain.transactions import genesis, v2, v3
from loopchain.blockchain.types import Hash32, Signature
from loopchain.crypto.signature import Signer


@pytest.mark.parametrize("version", [genesis.version, v2.version, v3.version])
class TestTransactionBuilderBase:
    def test_builder_version_check(self, tx_builder_factory, version):
        # TODO: v3_issue builder is ignored
        tx_builder = tx_builder_factory(version=version)

        if version == genesis.version:
            assert isinstance(tx_builder, genesis.TransactionBuilder)

        if version == v2.version:
            assert isinstance(tx_builder, v2.TransactionBuilder)

        if version == v3.version:
            assert isinstance(tx_builder, v3.TransactionBuilder)

    def test_build_hash_returns_valid_hash_form(self, tx_builder_factory, version):
        tx_builder = tx_builder_factory(version=version)
        hash_ = tx_builder.build_hash()

        assert isinstance(hash_, Hash32)

    def test_build_hash_fails_if_origin_data_is_not_exist(self, tx_builder_factory, version):
        tx_builder = tx_builder_factory(version=version)
        tx_builder.origin_data = None

        with pytest.raises(RuntimeError, match="origin data is required"):
            assert tx_builder.build_hash()

    def test_sign_creates_signature(self, tx_builder_factory, version, mocker):
        tx_builder: TransactionBuilder = tx_builder_factory(version=version)

        tx_builder.signature = None
        assert not tx_builder.signature

        with mocker.patch.object(Signer, "sign_hash", return_value=os.urandom(Signature.size)):
            tx_builder.sign()
            assert isinstance(tx_builder.signature, Signature)

    def test_reset_cache_cleanse_members(self, tx_builder_factory, version):
        tx_builder = tx_builder_factory(version=version)
        assert tx_builder.from_address
        assert tx_builder.hash
        assert tx_builder.signature
        assert tx_builder.origin_data
        assert tx_builder.raw_data

        tx_builder.reset_cache()
        assert not tx_builder.from_address
        assert not tx_builder.hash
        assert not tx_builder.signature
        assert not tx_builder.origin_data
        assert not tx_builder.raw_data

        if version == genesis.version:
            assert not tx_builder.nid_generated

        if version == v2.version:
            assert not tx_builder._timestamp

        if version == v3.version:
            assert not tx_builder._timestamp

    def test_from_address_returns_its_addr_if_exists(self, tx_builder_factory, version):
        tx_builder = tx_builder_factory(version=version)
        origin_addr = tx_builder.from_address
        built_addr = tx_builder.build_from_address()

        assert origin_addr == built_addr

    def test_from_address_raise_exc_if_no_addr_and_no_signer(self, tx_builder_factory, version):
        tx_builder = tx_builder_factory(version=version)
        tx_builder.reset_cache()
        tx_builder.signer = None

        with pytest.raises(RuntimeError):
            assert tx_builder.build_from_address()

    def test_from_address_generate_addr_if_no_addr_but_signer(self, tx_builder_factory, version):
        tx_builder = tx_builder_factory(version=version)
        tx_builder.reset_cache()

        assert tx_builder.build_from_address()

    def test_build_raw_data(self, tx_builder_factory, version):
        tx_builder = tx_builder_factory(version=version)
        raw_data = tx_builder.build_raw_data()

        assert raw_data

    def test_build_transaction(self, tx_builder_factory, version):
        tx_builder = tx_builder_factory(version=version)
        tx = tx_builder.build()

        if version == genesis.version:
            assert isinstance(tx, genesis.Transaction)

        if version == v2.version:
            assert isinstance(tx, v2.Transaction)

        if version == v3.version:
            assert isinstance(tx, v3.Transaction)

    @pytest.mark.skip(reason="How to test signed transaction?")
    def test_sign_transaction(self, version):
        pass


class TestTransactionBuilderGenesis:
    @pytest.fixture
    def tx_builder_factory_genesis(self, tx_builder_factory):
        tx_builder: genesis.TransactionBuilder = tx_builder_factory(version=genesis.version)

        return tx_builder

    def test_build_nid_raises_exc_if_hash_not_exists(self, tx_builder_factory_genesis):
        tx_builder_factory_genesis.reset_cache()

        with pytest.raises(RuntimeError):
            assert tx_builder_factory_genesis.build_nid()

    def test_build_nid_returns_its_nid_if_exists(self, tx_builder_factory_genesis):
        origin_nid = tx_builder_factory_genesis.nid
        built_nid = tx_builder_factory_genesis.build_nid()

        assert origin_nid == built_nid

    @pytest.mark.parametrize("hash_, expected_nid", [
        (genesis.NTxHash.mainnet, genesis.NID.mainnet),
        (genesis.NTxHash.testnet, genesis.NID.testnet),
    ])
    def test_build_nid_with_specific_hash_matches_expected_nid(self, tx_builder_factory_genesis, hash_, expected_nid):
        tx_builder_factory_genesis.nid = None
        tx_builder_factory_genesis.hash = hash_.value
        built_nid = tx_builder_factory_genesis.build_nid()

        assert built_nid == expected_nid.value

    def test_build_nid_returns_unknown_nid_when_unexpected_hash_exists(self, tx_builder_factory_genesis):
        tx_builder_factory_genesis.nid = None
        nid_generated = tx_builder_factory_genesis.build_nid()

        assert nid_generated == genesis.NID.unknown.value
