import pytest

from loopchain.blockchain.transactions import TransactionSerializer
from loopchain.blockchain.transactions import genesis
from loopchain.blockchain.transactions import v2
from loopchain.blockchain.transactions import v3
from loopchain.blockchain.transactions import v3_issue
from loopchain.blockchain.transactions import TransactionVersioner


@pytest.fixture
def ts_factory():
    def _transaction_serializer(version: str, type_=None):
        serializer = TransactionSerializer.new(version=version, type_=type_, versioner=TransactionVersioner())

        return serializer

    return _transaction_serializer


@pytest.mark.parametrize("version", [genesis.version, v2.version, v3.version])
class TestTransactionSerializerBase:
    tx_data_genesis = {
        "nid": "0x3",
        "accounts": [
            {
                "name": "god",
                "address": "hx54f7853dc6481b670caf69c5a27c7c8fe5be8269",
                "balance": "0x2961fff8ca4a62327800000"
            },
            {
                "name": "treasury",
                "address": "hx1000000000000000000000000000000000000000",
                "balance": "0x0"
            }
        ],
        "message": "A rhizome has no beginning or end; it is always in the middle, between things, interbeing, intermezzo. The tree is filiation, but the rhizome is alliance, uniquely alliance. The tree imposes the verb \"to be\" but the fabric of the rhizome is the conjunction, \"and ... and ...and...\"This conjunction carries enough force to shake and uproot the verb \"to be.\" Where are you going? Where are you coming from? What are you heading for? These are totally useless questions.\n\n - Mille Plateaux, Gilles Deleuze & Felix Guattari\n\n\"Hyperconnect the world\""
    }
    tx_data_v2 = {
        "from": "hx63fac3fc777ad647d2c3a72cf0fc42d420a2ba81",
        "to": "hx5f8bfd603f1712ccd335d7648fbc989f63251354",
        "value": "0xde0b6b3a7640000",
        "fee": "0x2386f26fc10000",
        "nonce": "0x3",
        "tx_hash": "fabc1884932cf52f657475b6d62adcbce5661754ff1a9d50f13f0c49c7d48c0c",
        "signature": "cpSevyvPKC4OpAyywnoNyf0gamHylHOeuSPnLjkyILl1n9Xo4ygezzxda8LpcQ6K1rmo4JU+mXdh+Beh+/mhBgA=",
        "method": "icx_sendTransaction"
    }
    tx_data_v3 = {
        "from": "hx5a05b58a25a1e5ea0f1d5715e1f655dffc1fb30a",
        "nid": "0x3",
        "nonce": "0x626c647430626f356d3369706f66637531687230",
        "signature": "MBRcb88rvnaSlDv8CC6+QUeajiDWwjRrE2i0klgNKCAkBYLnPGGBzhgbVgNKufJifeTAcpxNzDTCaVmHD7HDgwE=",
        "stepLimit": "0x50000000",
        "timestamp": "0x5908a356183ca",
        "to": "hx670e692ffd3d5587c36c3a9d8442f6d2a8fcc795",
        "value": "0x3328b944c4000",
        "version": "0x3",
        "txHash": "0x7b309fea7a1e1f760ff6b5c192875180c816e5680631d45e32f651321a833df4"
    }

    def test_serializer_version_check(self, ts_factory, version):
        # TODO: Any idea to test v3_issue?
        ts = ts_factory(version=version)

        if version == genesis.version:
            assert isinstance(ts, genesis.TransactionSerializer)

        if version == v2.version:
            assert isinstance(ts, v2.TransactionSerializer)

        if version == v3.version:
            assert isinstance(ts, v3.TransactionSerializer)

    def test_to_raw_data_returns_dict(self, ts_factory, tx_factory, version):
        ts = ts_factory(version=version)
        tx = tx_factory(version=version)

        raw_data = ts.to_raw_data(tx)

        assert isinstance(raw_data, dict)

    def test_to_full_data_returns_dict(self, ts_factory, tx_factory, version):
        ts = ts_factory(version=version)
        tx = tx_factory(version=version)

        full_data = ts.to_full_data(tx)

        assert isinstance(full_data, dict)

    def test_to_db_data_returns_dict(self, ts_factory, tx_factory, version):
        ts = ts_factory(version=version)
        tx = tx_factory(version=version)

        db_data = ts.to_db_data(tx)

        assert isinstance(db_data, dict)



class TestTransactionSerializerGenesis:
    def test_to_origin_data_has_valid_form(self, ts_factory, tx_factory):
        version = genesis.version

        ts: genesis.TransactionSerializer = ts_factory(version=version)
        tx: genesis.Transaction = tx_factory(version=version)

        origin_data = ts.to_origin_data(tx)

        assert origin_data == tx.raw_data


class TestTransactionSerializerV2:
    def test_to_origin_data_has_valid_form(self, ts_factory, tx_factory):
        version = v2.version

        ts: v2.TransactionSerializer = ts_factory(version=version)
        tx: v2.Transaction = tx_factory(version=version)

        origin_data = ts.to_origin_data(tx)

        assert isinstance(origin_data, dict)
        assert not hasattr(origin_data, "tx_hash")
        assert not hasattr(origin_data, "signature")
        assert not hasattr(origin_data, "method")


class TestTransactionSerializerV3:
    def test_to_origin_data_has_valid_form(self, ts_factory, tx_factory):
        version = v3.version

        ts: v3.TransactionSerializer = ts_factory(version=version)
        tx: v3.Transaction = tx_factory(version=version)

        origin_data = ts.to_origin_data(tx)

        assert isinstance(origin_data, dict)
        assert not hasattr(origin_data, "signature")

    # @pytest.mark.parametrize("version, _type, tx_data", [
    #     (genesis.version, "base", tx_data_genesis),
    #     (v2.version, "base", tx_data_v2),
    #     (v3.version, "base", tx_data_v3),
    #     (v3_issue.version, "base", tx_data_v3)
    # ])
    # def test_from_tx_data_to_tx_obj(self, version, _type, tx_data):
    #     ts = TransactionSerializer.new(version=version, type_=_type, versioner=TransactionVersioner())
    #     tx = ts.from_(tx_data)
    #
    #     assert tx
