from abc import ABC, abstractmethod
from types import MappingProxyType

from bt_ddos_shield.address import Address
from bt_ddos_shield.utils import Hotkey


class AbstractAddressManager(ABC):
    """
    Abstract base class for manager handling public IP/domain addresses assigned to validators.
    """

    miner_address_id: str

    def __init__(self, miner_address_id: str):
        """
        Args:
            miner_address_id: Identifier of the address of original miner's server. All created addresses for validators
                              should redirect to this address.
        """
        self.miner_address_id = miner_address_id

    def hide_original_server(self):
        """
        If method is implemented, it should hide the original server IP address from public access.
        See auto_hide_original_server in MinerShield options.
        """
        pass

    @abstractmethod
    def create_address(self) -> Address:
        """
        Create and return a new address redirecting to Miner server to be used by validator.
        """
        pass

    @abstractmethod
    def remove_address(self, address: Address):
        pass

    @abstractmethod
    def validate_addresses(self, addresses: MappingProxyType[Hotkey, Address]) -> set[Hotkey]:
        """
        Validate if given addresses exist and are working properly.

        Args:
            addresses: Dictionary of addresses to validate (validator HotKey -> Address).

        Returns:
            set[Hotkey]: Set of HotKeys of validators with invalid addresses.
        """
        pass
