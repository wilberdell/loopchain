import pytest

from loopchain.blockchain.blocks import Block, BlockBuilder
from loopchain.blockchain.blocks import v0_1a
from loopchain.blockchain.blocks import v0_3
from loopchain.blockchain.blocks.block_serializer import BlockSerializer, BlockVersionNotMatch
from loopchain.blockchain.transactions import TransactionVersioner


@pytest.fixture
def block_serializer_factory():
    def _block_serializer_factory(version):
        return BlockSerializer.new(version=version, tx_versioner=TransactionVersioner())

    return _block_serializer_factory


@pytest.mark.parametrize("module", [v0_1a, v0_3])
class TestBlockSerializer:
    def test_constructor_version_check(self, block_serializer_factory, module):
        bs = block_serializer_factory(version=module.version)

        assert isinstance(bs, module.BlockSerializer)

    def test_serialize_raises_exc_if_block_has_different_version(self, module,
                                                                 block_serializer_factory, block_builder_factory_base):
        bs = block_serializer_factory(version=module.version)
        block_builder: BlockBuilder = block_builder_factory_base(block_version=module.version)
        block: Block = block_builder.build()

        object.__setattr__(block.header, "version", "wrong_block_version")

        with pytest.raises(BlockVersionNotMatch):
            bs.serialize(block=block)

    def test_serialize_calls_implemented_method(self, module, mocker,
                                                block_serializer_factory, block_builder_factory_base):
        bs = block_serializer_factory(version=module.version)
        block_builder: BlockBuilder = block_builder_factory_base(block_version=module.version)
        block: Block = block_builder.build()

        # Implemented serialize method manipulates Block, So those shall be tested in Block section.
        bs._serialize = mocker.MagicMock()
        bs.serialize(block=block)

        assert bs._serialize.called

    def test_deserialize_raises_exc_if_block_has_different_version(self, block_serializer_factory, module):
        block_dumped = {
            "version": "wrong_version"
        }
        bs = block_serializer_factory(version=module.version)
        with pytest.raises(BlockVersionNotMatch):
            bs.deserialize(block_dumped)

    @pytest.mark.skip
    def test_deserialize_call(self, block_serializer_factory, module):
        block_dumped = {
            "version": module.version
        }
        bs = block_serializer_factory(version=module.version)
        bs.deserialize(block_dumped)

