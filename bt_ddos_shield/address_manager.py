from abc import ABC, abstractmethod

from bt_ddos_shield.address import Address


class AbstractAddressManager(ABC):
    """
    Abstract base class for manager handling public IP/domain addresses assigned to validators.
    """

    def __init__(self, address_id):
        """
        Args:
            address_id: Identifier of the address of original miner's server. All created addresses for validators
                        should redirect to this address.
        """
        self.address_id = address_id

    @abstractmethod
    def create_address(self) -> Address:
        """
        Create a new address.

        Returns:
            Address: New address to be used by validator.
        """
        pass

    @abstractmethod
    def remove_address(self, address_id):
        """
        Remove address.

        Args:
            address_id: Identifier of the address to remove.
        """
        pass

    @abstractmethod
    def address_exists(self, address_id) -> bool:
        """
        Check if address exists.

        Args:
            address_id: Identifier of the address to check.

            Returns:
                bool: If address exists.
        """
        pass

    def hide_original_server(self):
        """
        If method is implemented, it should hide the original server IP address from public access.
        See auto_hide_original_server in MinerShield options.
        """
        pass
