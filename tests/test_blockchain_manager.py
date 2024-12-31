import threading
from typing import Optional

from bt_ddos_shield.address import DefaultAddressSerializer
from bt_ddos_shield.blockchain_manager import AbstractBlockchainManager
from bt_ddos_shield.utils import Hotkey


class MemoryBlockchainManager(AbstractBlockchainManager):
    known_data: dict[Hotkey, bytes]
    put_counter: int

    def __init__(self, miner_hotkey: Hotkey):
        super().__init__(miner_hotkey, DefaultAddressSerializer())
        self.known_data = {}
        self.put_counter = 0
        self._lock = threading.Lock()

    def put(self, hotkey: Hotkey, data: bytes):
        with self._lock:
            self.known_data[hotkey] = data
            self.put_counter += 1

    def get(self, hotkey: Hotkey) -> Optional[bytes]:
        with self._lock:
            return self.known_data.get(hotkey)


class TestBlockchainManager:
    """
    Test suite for the blockchain manager.
    """
    pass
