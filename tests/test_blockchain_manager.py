from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from bt_ddos_shield.blockchain_manager import (
    AbstractBlockchainManager,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from bt_ddos_shield.utils import Hotkey, PublicKey


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

    async def get_metadata(self, hotkeys: Iterable[Hotkey]) -> dict[Hotkey, bytes | None]:
        with self._lock:
            return {hotkey: self.known_data.get(hotkey) for hotkey in hotkeys}

    def get_own_public_key(self) -> PublicKey:
        return 'public_key'

    def upload_public_key(self, public_key: PublicKey):
        pass
