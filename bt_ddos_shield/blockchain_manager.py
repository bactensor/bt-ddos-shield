from abc import ABC, abstractmethod

class BlockchainManager(ABC):
    """
    Abstract base class for manager handling publishing blocks to blockchain.
    """

    def __init__(self):
        pass

    @abstractmethod
    def publish(self, data: bytes):
        """
            Puts data to blockchain.

            Args:
                data: Data.
            """
        pass
