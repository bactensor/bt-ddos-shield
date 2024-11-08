from abc import ABC, abstractmethod
from typing import Type

from bt_ddos_shield.address import Address


class AbstractAddressManager(ABC):
    """
    Abstract base class for manager handling public IP/domain addresses assigned to validators.
    """

    def __init__(self, address_class: Type[Address], miner_address_id):
        """
        Args:
            address_class: Class of the address used by manager.
            miner_address_id: Identifier of the address of original miner's server. All created addresses for validators
                              should redirect to this address.
        """
        self.address_class = address_class
        self.miner_address_id = miner_address_id

    def deserialize_address(self, serialized_data: bytes) -> Address:
        """
        Deserialize address data and create instance of Address class.

        Args:
            serialized_data: Data serialized before by Address.serialize method.

        Returns:
            Address: Created address.
        """
        return self.address_class.deserialize(serialized_data)

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
    def remove_address(self, address_id):
        """
        Remove address with given ID redirecting to Miner server.
        """
        pass

    @abstractmethod
    def address_exists(self, address_id) -> bool:
        """
        Returns if address with given ID exists and is working.
        """
        pass
