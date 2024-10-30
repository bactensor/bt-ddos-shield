from abc import ABC, abstractmethod

from bt_ddos_shield.address import Address
from bt_ddos_shield.utils import Hotkey


class AbstractManifestManager(ABC):
    """
    Abstract base class for manager handling publishing manifest file containing encrypted addresses for validators.
    """

    def add_mapping_file(self, address_mapping: dict[Hotkey, Address]) -> Address:
        """
        Adds a mapping as file with encrypted addresses to the storage.

        Args:
            address_mapping: A dictionary containing the address mapping (validator HotKey -> Address).

        Returns:
            Address: Address where file is put.
        """
        # TODO - add implementation (encrypt with EncryptionManager and call put_file)
        pass

    @abstractmethod
    def _put_file(self, data: bytes) -> Address:
        """
        Puts a file into the storage.

        Args:
            data: File contents.

        Returns:
            Address: Address where file is put.
        """
        pass
