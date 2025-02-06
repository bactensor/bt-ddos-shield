import threading
from typing import Optional

from bt_ddos_shield.blockchain_manager import (
    AbstractBlockchainManager,
)
from bt_ddos_shield.utils import Hotkey


class MemoryBlockchainManager(AbstractBlockchainManager):
    known_data: dict[Hotkey, bytes]
    put_counter: int

    def __init__(self, miner_hotkey: Hotkey):
        self.miner_hotkey = miner_hotkey
        self.known_data = {}
        self.put_counter = 0
        self._lock = threading.Lock()

    def get_hotkey(self) -> Hotkey:
        return self.miner_hotkey

    def put_metadata(self, data: bytes):
        with self._lock:
            self.known_data[self.miner_hotkey] = data
            self.put_counter += 1

    async def get_metadata(self, hotkey: Hotkey) -> Optional[bytes]:
        with self._lock:
            return self.known_data.get(self.miner_hotkey)
