from abc import ABC, abstractmethod

from bt_ddos_shield.utils import Hotkey


class AbstractBlockchainManager(ABC):
    """
    Abstract base class for manager handling publishing blocks to blockchain.
    """

    @abstractmethod
    def put(self, hotkey: Hotkey, data: bytes):
        """
        Puts data to blockchain for given user identified by hotkey.
        """
        pass

    @abstractmethod
    def get(self, hotkey: Hotkey) -> bytes:
        """
        Gets data from blockchain for given user identified by hotkey.

        Returns:
            data: Last block of data put by user.
        """
        pass
