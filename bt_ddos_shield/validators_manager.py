from abc import ABC, abstractmethod
from types import MappingProxyType

from bt_ddos_shield.utils import Hotkey, PublicKey


class AbstractValidatorsManager(ABC):
    """
    Abstract base class for manager of validators and their public keys used for encryption.
    """

    @abstractmethod
    def get_validators(self) -> MappingProxyType[Hotkey, PublicKey]:
        """
        Get cached dictionary of validators.

        Returns:
            dict[Hotkey, PublicKey]: Mapping HotKey of validator -> his public key.
        """
        pass

    @abstractmethod
    def reload_validators(self):
        """
        Reload validators dictionary. Blocks code execution until new validators set is fetched.
        """
        pass
