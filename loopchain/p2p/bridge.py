import abc
from typing import Tuple, Dict


class PeerBridgeBase(abc.ABC):

    @abc.abstractmethod
    def channel_reset_timer(self, channel_name) -> None:
        pass

    @abc.abstractmethod
    def channel_get_status_data(self, channel_name):
        pass

    @abc.abstractmethod
    def channel_get_peer_status_data(self, channel_name):
        pass

    @abc.abstractmethod
    def channel_get_peer_list(self, channel_name) -> Tuple:
        pass

    @abc.abstractmethod
    def channel_get_tx_by_address(self, channel_name, address, index) -> Tuple:
        pass

    @abc.abstractmethod
    def channel_mq_status_data(self, channel_name) -> Dict:
        pass

    @abc.abstractmethod
    def channel_get_score_status(self, channel_name):
        pass

    @abc.abstractmethod
    def channel_complain_leader(self, channel_name: str, complain_vote: str):
        pass

    @abc.abstractmethod
    def channel_create_tx(self, channel_name, data):
        pass

    @abc.abstractmethod
    def channel_add_tx(self, channel_name, request):
        pass

    @abc.abstractmethod
    def channel_tx_receiver_add_tx_list(self, channel_name, request):
        pass

    @abc.abstractmethod
    def channel_get_tx(self, channel_name, tx_hash):
        pass

    @abc.abstractmethod
    def channel_get_block(self, channel_name, block_height, block_hash, block_data_filter, tx_data_filter):
        pass

    @abc.abstractmethod
    def channel_get_precommit_block(self, channel_name, last_block_height) -> Tuple:
        pass

    @abc.abstractmethod
    def channel_get_invoke_result(self, channel_name, tx_hash) -> Tuple:
        pass

    @abc.abstractmethod
    def channel_announce_unconfirmed_block(self, channel_name, block):
        pass

    @abc.abstractmethod
    def channel_block_sync(self, channel_name, block_hash, block_height) -> Tuple:
        pass

    @abc.abstractmethod
    def channel_add_audience(self, channel_name, peer_target):
        pass

    @abc.abstractmethod
    def channel_remove_audience(self, channel_name, peer_target):
        pass

    @abc.abstractmethod
    def channel_vote_unconfirmed_block(self, channel_name, vote_dumped):
        pass

    @abc.abstractmethod
    def peer_get_channel_infos(self):
        pass
