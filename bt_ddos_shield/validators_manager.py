from abc import ABC, abstractmethod

from bt_ddos_shield.utils import Hotkey


class AbstractValidatorsManager(ABC):
    """
    Abstract base class for manager of validators and their public keys used for encryption.
    """

    @abstractmethod
    def get_validators(self) -> dict[Hotkey, str]:
        """
        Get cached dictionary of validators - maps HotKey of validator to public key.
        """
        pass

    @abstractmethod
    def refresh_validators(self) -> bool:
        """
        Refresh validators dictionary. Blocks code execution until new validators set is fetched.

        Returns:
            bool: True if validators set is different after refreshing.
        """
        pass
