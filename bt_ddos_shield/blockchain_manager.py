from abc import ABC, abstractmethod
from typing import Optional

from bt_ddos_shield.address import Address, AbstractAddressSerializer, AddressDeserializationException
from bt_ddos_shield.utils import Hotkey


class BlockchainManagerException(Exception):
    pass


class AbstractBlockchainManager(ABC):
    """
    Abstract base class for manager handling publishing address to blockchain.
    """

    address_serializer: AbstractAddressSerializer

    def __init__(self, address_serializer: AbstractAddressSerializer):
        self.address_serializer = address_serializer

    def put_address(self, hotkey: Hotkey, address: Address):
        """
        Put address to blockchain for given user identified by hotkey.
        """
        self.put(hotkey, self.address_serializer.serialize(address))

    def get_address(self, hotkey: Hotkey) -> Optional[Address]:
        """
        Get address from blockchain for given user identified by hotkey or None if not found or not valid.
        """
        serialized_address: Optional[bytes] = self.get(hotkey)
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
