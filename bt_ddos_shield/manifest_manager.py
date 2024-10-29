from abc import ABC, abstractmethod

from bt_ddos_shield.dns_manager import Domain


class ManifestManager(ABC):
    """
    Abstract base class for manager handling publishing manifest file containing encrypted domains for validators.
    """

    def __init__(self):
        pass

    def add_mapping_file(self, domain_mapping: dict[str, Domain]) -> Domain:
        """
        Adds a mapping as file with encrypted domains to the storage.

        Args:
            domain_mapping: A dictionary containing the domain mapping (validator HotKey -> Domain).

        Returns:
            Domain: Domain where file is put.
        """
        # TODO - add implementation (encrypt with EncryptionManager and call put_file)
        pass

    @abstractmethod
    def put_file(self, data: str) -> Domain:
        """
        Puts a file into the storage.

        Args:
            data: File contents.

        Returns:
            Domain: Domain where file is put.
        """
        pass
