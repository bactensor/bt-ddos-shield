from abc import ABC, abstractmethod

from bt_ddos_shield.address import Address, AddressSerializer
from bt_ddos_shield.utils import Hotkey


class BlockchainManagerException(Exception):
    pass


class AbstractBlockchainManager(ABC):
    """
    Abstract base class for manager handling publishing address to blockchain.
    """

    address_serializer: AddressSerializer

    def __init__(self, address_serializer: AddressSerializer):
        self.address_serializer = address_serializer

    def put_address(self, hotkey: Hotkey, address: Address):
        """
        Put address to blockchain for given user identified by hotkey.
        """
        self.put(hotkey, self.address_serializer.serialize(address))

    def get_address(self, hotkey: Hotkey) -> Address:
        """
        Get address from blockchain for given user identified by hotkey.
        """
        return self.address_serializer.deserialize(self.get(hotkey))

    @abstractmethod
    def put(self, hotkey: Hotkey, data: bytes):
        """
        Put data to blockchain for given user identified by hotkey.
        """
        pass

    @abstractmethod
    def get(self, hotkey: Hotkey) -> bytes:
        """
        Get data from blockchain for given user identified by hotkey.
        """
        pass
