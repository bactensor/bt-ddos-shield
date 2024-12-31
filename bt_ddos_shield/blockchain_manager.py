from abc import ABC, abstractmethod
from typing import Optional

from bt_ddos_shield.address import (
    AbstractAddressSerializer,
    Address,
    AddressDeserializationException,
)
from bt_ddos_shield.utils import Hotkey


class BlockchainManagerException(Exception):
    pass


class AbstractBlockchainManager(ABC):
    """
    Abstract base class for manager handling publishing address to blockchain.
    """

    miner_hotkey: Hotkey
    address_serializer: AbstractAddressSerializer

    def __init__(self, miner_hotkey: Hotkey, address_serializer: AbstractAddressSerializer):
        self.miner_hotkey = miner_hotkey
        self.address_serializer = address_serializer

    def put_miner_manifest_address(self, address: Address):
        """
        Put miner manifest address to blockchain.
        """
        self.put(self.miner_hotkey, self.address_serializer.serialize(address))

    def get_miner_manifest_address(self) -> Optional[Address]:
        """
        Get miner manifest address from blockchain or None if not found or not valid.
        """
        serialized_address: Optional[bytes] = self.get(self.miner_hotkey)
        if serialized_address is None:
            return None
        try:
            return self.address_serializer.deserialize(serialized_address)
        except AddressDeserializationException:
            return None

    @abstractmethod
    def put(self, hotkey: Hotkey, data: bytes):
        """
        Put data to blockchain for given user identified by hotkey.
        """
        pass

    @abstractmethod
    def get(self, hotkey: Hotkey) -> Optional[bytes]:
        """
        Get data from blockchain for given user identified by hotkey or None if not found.
        """
        pass
