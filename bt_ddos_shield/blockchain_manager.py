from abc import ABC, abstractmethod


class AbstractBlockchainManager(ABC):
    """
    Abstract base class for manager handling publishing blocks to blockchain.
    """

    @abstractmethod
    def publish(self, data: bytes):
        """
        Puts data to blockchain.

        Args:
            data: Data.
        """
        pass
