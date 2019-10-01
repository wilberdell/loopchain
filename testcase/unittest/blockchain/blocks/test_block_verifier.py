import datetime
import functools
import os

import pytest
from freezegun import freeze_time

from loopchain import configure as conf
from loopchain import utils
from loopchain.blockchain.blocks import v0_1a, v0_3, Block, BlockBuilder
from loopchain.blockchain.blocks.block_verifier import BlockVerifier
from loopchain.blockchain.exception import BlockVersionNotMatch, NotInReps, ScoreInvokeError, ScoreInvokeResultError
from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.blockchain.types import Hash32, ExternalAddress
from loopchain.jsonrpc.exception import GenericJsonRpcServerError


@pytest.fixture(scope="module", autouse=True)
def time_stopper():
    tzinfo = datetime.timezone.utc
    everlasting_time = datetime.datetime(2019, 9, 28, 2, 11, 11, microsecond=123123, tzinfo=tzinfo)

    freezer = freeze_time(everlasting_time)
    freezer.start()
    assert datetime.datetime.now(tz=tzinfo).timestamp() == everlasting_time.timestamp()

    yield

    freezer.stop()


@pytest.fixture
def block_verifier_base():
    def _block_verifier_factory(version, raise_exceptions: bool = True):
        return BlockVerifier.new(version=version,
                                 tx_versioner=TransactionVersioner(),
                                 raise_exceptions=raise_exceptions)

    return _block_verifier_factory


@pytest.fixture
def two_blocks_factory(block_builder_factory_base):
    def _mocked_current_and_prev_blocks_factory(block_version, _block_builder_factory_base):
        block_builder: BlockBuilder = block_builder_factory_base(block_version=block_version)
        current_block: Block = block_builder.build()
        prev_block: Block = block_builder.build()

        object.__setattr__(current_block.header, "timestamp", None)
        object.__setattr__(current_block.header, "height", prev_block.header.height + 1)
        object.__setattr__(current_block.header, "prev_hash", prev_block.header.hash)
        object.__setattr__(current_block.header, "timestamp", utils.get_time_stamp() + conf.TIMESTAMP_BUFFER_IN_VERIFIER/2)
        object.__setattr__(prev_block.header, "timestamp", utils.get_time_stamp())

        if block_version == v0_1a.version:
            object.__setattr__(current_block.header, "peer_id", prev_block.header.next_leader)

        if block_version == v0_3.version:
            pass

        return current_block, prev_block

    return functools.partial(_mocked_current_and_prev_blocks_factory, _block_builder_factory_base=block_builder_factory_base)


@pytest.mark.parametrize("block_module", [v0_1a, v0_3])
class TestBlockVerifierBase:
    def test_constructor_version_check(self, block_module, block_verifier_base):
        bv = block_verifier_base(version=block_module.version)

        assert isinstance(bv, block_module.BlockVerifier)

    def test_verify_calls_verify_tx_and_common(self, block_module, mocker, block_verifier_base, two_blocks_factory):
        bv = block_verifier_base(version=block_module.version)

        mock_verify_tx = mocker.MagicMock()
        mock_verify_common = mocker.MagicMock()
        bv.verify_transactions = mock_verify_tx
        bv.verify_common = mock_verify_common

        current_block, prev_block = two_blocks_factory(block_version=block_module.version)
        bv.verify(current_block, prev_block)

        assert bv.verify_transactions.called
        assert bv.verify_common.called

    def test_verify_loosely_calls_verify_tx_loosely_and_common(self, block_module, mocker, block_verifier_base, two_blocks_factory):
        bv = block_verifier_base(version=block_module.version)

        mock_verify_tx_loosely = mocker.MagicMock()
        mock_verify_common = mocker.MagicMock()
        bv.verify_transactions_loosely = mock_verify_tx_loosely
        bv.verify_common = mock_verify_common

        current_block, prev_block = two_blocks_factory(block_version=block_module.version)
        bv.verify_loosely(current_block, prev_block)

        assert bv.verify_transactions_loosely.called
        assert bv.verify_common.called

    @pytest.mark.parametrize("block_verify_func, tx_verify_func", [
        ("verify_transactions", "verify"),
        ("verify_transactions_loosely", "verify_loosely")
    ])
    def test_verify_transactions_calls_tx_verify(self, block_module, mocker, block_verify_func, tx_verify_func, monkeypatch, block_verifier_base, block_builder_factory_base):
        bv = block_verifier_base(version=block_module.version)
        block_builder: BlockBuilder = block_builder_factory_base(block_version=block_module.version)
        block: Block = block_builder.build()

        mock_block_verify_func = mocker.MagicMock()
        transaction_version_names = ["genesis", "v2", "v3", "v3_issue"]
        for tx_version in transaction_version_names:
            monkeypatch.setattr(f"loopchain.blockchain.transactions.{tx_version}.TransactionVerifier.{tx_verify_func}",
                                mock_block_verify_func)

        getattr(bv, block_verify_func)(block)
        assert mock_block_verify_func.called

    def test_verify_signature_check(self, block_module, block_verifier_base, block_builder_factory_base):
        bv = block_verifier_base(version=block_module.version)
        block_builder: BlockBuilder = block_builder_factory_base(block_version=block_module.version)
        block: Block = block_builder.build()

        bv.verify_signature(block)

    def test_verify_generator_check(self, block_module, block_verifier_base, block_builder_factory_base):
        # TODO: Check that there's no difference in verify_generator between v0.1a and v0.3
        bv = block_verifier_base(version=block_module.version)
        block_builder: BlockBuilder = block_builder_factory_base(block_version=block_module.version)
        block: Block = block_builder.build()

        bv.verify_generator(block, generator=block.header.peer_id)


@pytest.mark.parametrize("block_module", [v0_1a, v0_3])
@pytest.mark.parametrize("raise_exc", [True, False])
class TestExceptionsForBlockVerifierBase:
    def test_verify_common_with_no_timestamp(self, block_module, raise_exc, monkeypatch, block_verifier_base, two_blocks_factory):
        bv = block_verifier_base(version=block_module.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=block_module.version)

        object.__setattr__(current_block.header, "timestamp", None)

        if raise_exc:
            with pytest.raises(RuntimeError, match="timestamp"):
                bv.verify_common(current_block, prev_block)
        else:
            assert not bv.exceptions
            # Avoid raising rest of exceptions!
            with pytest.raises(Exception):
                bv.verify_common(current_block, prev_block)

            with pytest.raises(RuntimeError, match="timestamp"):
                raise bv.exceptions[0]

    def test_verify_common_with_no_prev_hash(self, block_module, raise_exc, monkeypatch, block_verifier_base, two_blocks_factory):
        bv = block_verifier_base(version=block_module.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=block_module.version)

        object.__setattr__(current_block.header, "height", 1)
        object.__setattr__(current_block.header, "prev_hash", None)

        if raise_exc:
            with pytest.raises(RuntimeError, match="prev_hash"):
                bv.verify_common(current_block, prev_block)
        else:
            assert not bv.exceptions
            # Avoid raising rest of exceptions!
            with pytest.raises(Exception):
                bv.verify_common(current_block, prev_block)

            with pytest.raises(RuntimeError, match="prev_hash"):
                raise bv.exceptions[0]

    def test_verify_version_with_wrong_version(self, block_module, raise_exc, block_verifier_base, block_builder_factory_base):
        bv = block_verifier_base(version=block_module.version, raise_exceptions=raise_exc)
        block_builder: BlockBuilder = block_builder_factory_base(block_version=block_module.version)
        block: Block = block_builder.build()

        object.__setattr__(block.header, "version", "wrong_block_version")

        if raise_exc:
            with pytest.raises(BlockVersionNotMatch):
                bv.verify_version(block)
        else:
            assert not bv.exceptions
            bv.verify_version(block)

            assert bv.exceptions

    def test_verify_prev_block_with_wrong_prev_height(self, block_module, raise_exc, block_verifier_base, two_blocks_factory):
        bv = block_verifier_base(version=block_module.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=block_module.version)

        object.__setattr__(current_block.header, "height", prev_block.header.height + 2)

        if raise_exc:
            with pytest.raises(RuntimeError, match="Height"):
                bv.verify_prev_block(current_block, prev_block)
        else:
            assert not bv.exceptions
            bv.verify_prev_block(current_block, prev_block)

            with pytest.raises(RuntimeError, match="Height"):
                raise bv.exceptions[0]

    def test_verify_prev_block_with_invalid_hash(self, block_module, raise_exc, block_verifier_base, two_blocks_factory):
        bv = block_verifier_base(version=block_module.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=block_module.version)

        object.__setattr__(current_block.header, "prev_hash", Hash32.new())

        if raise_exc:
            with pytest.raises(RuntimeError, match="PrevHash"):
                bv.verify_prev_block(current_block, prev_block)
        else:
            assert not bv.exceptions
            bv.verify_prev_block(current_block, prev_block)

            with pytest.raises(RuntimeError, match="PrevHash"):
                raise bv.exceptions[0]

    def test_verify_prev_block_with_invalid_timestamp(self, block_module, raise_exc, block_verifier_base, two_blocks_factory):
        bv = block_verifier_base(version=block_module.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=block_module.version)

        time_over = conf.TIMESTAMP_BUFFER_IN_VERIFIER * 2
        object.__setattr__(current_block.header, "timestamp", utils.get_time_stamp() + time_over)
        object.__setattr__(prev_block.header, "timestamp", utils.get_time_stamp())

        if raise_exc:
            with pytest.raises(RuntimeError, match="timestamp"):
                bv.verify_prev_block(current_block, prev_block)
        else:
            assert not bv.exceptions
            bv.verify_prev_block(current_block, prev_block)

            with pytest.raises(RuntimeError, match="timestamp"):
                raise bv.exceptions[0]

    def test_verifiy_signature_with_wrong_signature(self, block_module, raise_exc, block_verifier_base, block_builder_factory_base):
        bv = block_verifier_base(version=block_module.version, raise_exceptions=raise_exc)
        block_builder: BlockBuilder = block_builder_factory_base(block_version=block_module.version)
        block: Block = block_builder.build()

        object.__setattr__(block.header, "signature", Hash32(os.urandom(Hash32.size)))

        if raise_exc:
            with pytest.raises(RuntimeError, match="Invalid Signature"):
                bv.verify_signature(block)
        else:
            assert not bv.exceptions
            bv.verify_signature(block)

            with pytest.raises(RuntimeError, match="Invalid Signature"):
                raise bv.exceptions[0]

    def test_verify_generator_with_wrong_generator(self, block_module, raise_exc, block_verifier_base, block_builder_factory_base):
        # TODO: Check that abstract verify_generator is not used at all!
        bv = block_verifier_base(version=block_module.version, raise_exceptions=raise_exc)
        block_builder: BlockBuilder = block_builder_factory_base(block_version=block_module.version)
        block: Block = block_builder.build()

        if raise_exc:
            with pytest.raises(RuntimeError, match="Generator"):
                bv.verify_generator(block, generator=ExternalAddress(os.urandom(ExternalAddress.size)))
        else:
            assert not bv.exceptions
            bv.verify_generator(block, generator=ExternalAddress(os.urandom(ExternalAddress.size)))

            with pytest.raises(RuntimeError, match="Generator"):
                raise bv.exceptions[0]


@pytest.mark.parametrize("raise_exc", [True, False])
class TestBlockVerifierV0_1a:
    block_builder = BlockBuilder.new(version=v0_1a.version, tx_versioner=TransactionVersioner())

    @pytest.mark.parametrize("side_effect, expected_exc", [
        (GenericJsonRpcServerError(code=1, message="Failed to invoke a block.", http_status=400), ScoreInvokeError),
        (RuntimeError, RuntimeError),
        (ValueError, ValueError),
    ])
    def test_verify_invoke_exc_in_invoke_func(self, mocker, raise_exc, side_effect, expected_exc, block_verifier_base, two_blocks_factory):
        block_verifier_v0_1a: v0_1a.BlockVerifier = block_verifier_base(version=v0_1a.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=v0_1a.version)

        block_verifier_v0_1a.invoke_func = mocker.MagicMock(side_effect=side_effect)

        if raise_exc:
            with pytest.raises(expected_exc):
                block_verifier_v0_1a.verify_invoke(TestBlockVerifierV0_1a.block_builder, current_block, prev_block)
        else:
            block_verifier_v0_1a.verify_invoke(TestBlockVerifierV0_1a.block_builder, current_block, prev_block)
            with pytest.raises(expected_exc):
                raise block_verifier_v0_1a.exceptions[0]

    def test_verify_invoke_with_wrong_commit_state(self, mocker, raise_exc, block_verifier_base, two_blocks_factory):
        block_verifier_v0_1a: v0_1a.BlockVerifier = block_verifier_base(version=v0_1a.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=v0_1a.version)
        object.__setattr__(current_block.header, "commit_state", Hash32(os.urandom(Hash32.size)))

        mock_new_block = prev_block
        mock_invoke_result = ""  # TODO: Need to mimic a invoke result?
        block_verifier_v0_1a.invoke_func = mocker.MagicMock(return_value=(mock_new_block, mock_invoke_result))

        if raise_exc:
            with pytest.raises(ScoreInvokeResultError):
                block_verifier_v0_1a.verify_invoke(TestBlockVerifierV0_1a.block_builder, current_block, prev_block)
        else:
            block_verifier_v0_1a.verify_invoke(TestBlockVerifierV0_1a.block_builder, current_block, prev_block)
            with pytest.raises(ScoreInvokeResultError):
                raise block_verifier_v0_1a.exceptions[0]

    def test_verify_invoke_passes_if_empty_block(self, mocker, raise_exc, block_verifier_base, two_blocks_factory):
        block_verifier_v0_1a: v0_1a.BlockVerifier = block_verifier_base(version=v0_1a.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=v0_1a.version)
        object.__setattr__(current_block.header, "commit_state", "")
        object.__setattr__(current_block.body, "transactions", [])

        mock_invoke_result = ""  # TODO: Need to mimic a invoke result?
        mock_new_block = prev_block
        block_verifier_v0_1a.invoke_func = mocker.MagicMock(return_value=(mock_new_block, mock_invoke_result))

        block_verifier_v0_1a.verify_invoke(TestBlockVerifierV0_1a.block_builder, current_block, prev_block)

    def test_verify_prev_block_with_wrong_leader(self, mocker, raise_exc, block_verifier_base, two_blocks_factory):
        block_verifier_v0_1a: v0_1a.BlockVerifier = block_verifier_base(version=v0_1a.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=v0_1a.version)
        object.__setattr__(prev_block.header, "next_leader", ExternalAddress(os.urandom(ExternalAddress.size)))

        with mocker.patch.object(BlockVerifier, "verify_prev_block"):
            if raise_exc:
                with pytest.raises(RuntimeError):
                    block_verifier_v0_1a.verify_prev_block(current_block, prev_block)
            else:
                block_verifier_v0_1a.verify_prev_block(current_block, prev_block)
                with pytest.raises(RuntimeError):
                    raise block_verifier_v0_1a.exceptions[0]

    def test_verify_generator_with_wrong_generator(self, raise_exc, block_verifier_base, block_builder_factory_base):
        block_verifier_v0_1a: v0_1a.BlockVerifier = block_verifier_base(version=v0_1a.version, raise_exceptions=raise_exc)
        block_builder: BlockBuilder = block_builder_factory_base(block_version=v0_1a.version)
        block: Block = block_builder.build()

        if raise_exc:
            with pytest.raises(RuntimeError, match="Generator"):
                block_verifier_v0_1a.verify_generator(block, generator=ExternalAddress(os.urandom(ExternalAddress.size)))
        else:
            block_verifier_v0_1a.verify_generator(block, generator=ExternalAddress(os.urandom(ExternalAddress.size)))
            with pytest.raises(RuntimeError):
                raise block_verifier_v0_1a.exceptions[0]

    def test_verify_common_with_wrong_merkle_tree_root_hash(self, mocker, raise_exc, block_verifier_base, two_blocks_factory):
        block_verifier_v0_1a: v0_1a.BlockVerifier = block_verifier_base(version=v0_1a.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=v0_1a.version)

        with mocker.patch.object(v0_1a.BlockBuilder, "_build_merkle_tree_root_hash", return_value=Hash32(os.urandom(Hash32.size))):
            if raise_exc:
                with pytest.raises(RuntimeError, match="MerkleTreeRootHash"):
                    block_verifier_v0_1a._verify_common(current_block, prev_block)
            else:
                with pytest.raises(Exception):
                    block_verifier_v0_1a._verify_common(current_block, prev_block)
                with pytest.raises(RuntimeError, match="MerkleTreeRootHash"):
                    raise block_verifier_v0_1a.exceptions[0]

    def test_verify_common_with_wrong_build_hash(self, monkeypatch, mocker, raise_exc, block_verifier_base, two_blocks_factory):
        block_verifier_v0_1a: v0_1a.BlockVerifier = block_verifier_base(version=v0_1a.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=v0_1a.version)

        with mocker.patch.object(v0_1a.BlockBuilder, "_build_hash", return_value=Hash32(os.urandom(Hash32.size))):
            if raise_exc:
                with pytest.raises(RuntimeError, match="Hash"):
                    block_verifier_v0_1a._verify_common(current_block, prev_block)
            else:
                block_verifier_v0_1a._verify_common(current_block, prev_block)
                with pytest.raises(RuntimeError, match="Hash"):
                    raise block_verifier_v0_1a.exceptions[0]


@pytest.mark.skip(reason="Vote fixture needed")
@pytest.mark.parametrize("raise_exc", [True])
class TestBlockVerifierV0_3:
    def test_verify_common(self, raise_exc, block_verifier_base, two_blocks_factory):
        # TODO: hash not in hash? Check return type of reps_getter
        block_verifier_v0_3: v0_3.BlockVerifier = block_verifier_base(version=v0_3.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=v0_3.version)

        def mock_reps_getter(reps):
            fake_reps_hash = Hash32(os.urandom(Hash32.size))

            return fake_reps_hash

        if raise_exc:
            with pytest.raises(NotInReps):
                block_verifier_v0_3._verify_common(current_block, prev_block, reps_getter=mock_reps_getter)
        else:
            with pytest.raises(Exception):
                block_verifier_v0_3._verify_common(current_block, prev_block, reps_getter=mock_reps_getter)
            with pytest.raises(NotInReps):
                raise block_verifier_v0_3.exceptions[0]

    def test_verify_leader_votes(self, raise_exc, block_verifier_base, two_blocks_factory):
        block_verifier_v0_3: v0_3.BlockVerifier = block_verifier_base(version=v0_3.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=v0_3.version)

        block_verifier_v0_3.verify_leader_votes(current_block, prev_block, reps=[])

    def test_verify_invoke_with_wrong_state_hash(self, mocker, raise_exc, block_verifier_base, two_blocks_factory):
        block_verifier_v0_3: v0_3.BlockVerifier = block_verifier_base(version=v0_3.version, raise_exceptions=raise_exc)
        current_block, prev_block = two_blocks_factory(block_version=v0_3.version)

        def mock_invoke_func(block: Block, prev_block: Block):
            object.__setattr__(block.header, "state_hash", Hash32(os.urandom(Hash32.size)))
            object.__setattr__(prev_block.header, "state_hash", Hash32(os.urandom(Hash32.size)))

            invoke_result = ""

            return prev_block, invoke_result

        mocker.patch.object(block_verifier_v0_3, "invoke_func", mock_invoke_func)
        builder = BlockBuilder.new(version=v0_3.version, tx_versioner=TransactionVersioner())

        if raise_exc:
            with pytest.raises(RuntimeError, match="StateRootHash"):
                block_verifier_v0_3.verify_invoke(builder, current_block, prev_block)
        else:
            block_verifier_v0_3.verify_invoke(builder, current_block, prev_block)
            with pytest.raises(RuntimeError, match="StateRootHash"):
                raise block_verifier_v0_3.exceptions[0]
