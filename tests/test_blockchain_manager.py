from typing import Optional

from bt_ddos_shield.address import DefaultAddressSerializer
from bt_ddos_shield.blockchain_manager import AbstractBlockchainManager
from bt_ddos_shield.utils import Hotkey


class MemoryBlockchainManager(AbstractBlockchainManager):
    known_data: dict[Hotkey, bytes]

    def __init__(self):
        super().__init__(DefaultAddressSerializer())
        self.known_data = {}

    def put(self, hotkey: Hotkey, data: bytes):
        self.known_data[hotkey] = data

    def get(self, hotkey: Hotkey) -> Optional[bytes]:
        return self.known_data.get(hotkey)


class TestBlockchainManager:
    """
    Test suite for the blockchain manager.
    """
    pass
