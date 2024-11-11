from abc import ABC, abstractmethod
from types import MappingProxyType

from bt_ddos_shield.address import Address, AddressSerializer
from bt_ddos_shield.utils import Hotkey, PublicKey


class ManifestManagerException(Exception):
    pass


class ManifestDeserializationException(ManifestManagerException):
    """
    Exception thrown when deserialization of manifest data fails.
    """
    pass


class ManifestNotFoundException(ManifestManagerException):
    """
    Exception thrown when manifest file is not found under given address.
    """
    pass


class AbstractManifestManager(ABC):
    """
    Abstract base class for manager handling publishing manifest file containing encrypted addresses for validators.
    """

    address_serializer: AddressSerializer

    def __init__(self, address_serializer: AddressSerializer):
        self.address_serializer = address_serializer

    def create_and_put_manifest_file(self, address_mapping: MappingProxyType[Hotkey, Address],
                                     validators_public_keys: MappingProxyType[Hotkey, PublicKey]) -> Address:
        data: bytes = self.create_manifest_file(address_mapping, validators_public_keys)
        return self.put_manifest_file(data)

    def create_manifest_file(self, address_mapping: MappingProxyType[Hotkey, Address],
                             validators_public_keys: MappingProxyType[Hotkey, PublicKey]) -> bytes:
        """
        Create manifest with encrypted addresses for validators.

        Args:
            address_mapping: Dictionary containing address mapping (validator HotKey -> Address).
            validators_public_keys: Dictionary containing public keys of validators (validator HotKey -> PublicKey).

        Returns:
            bytes: Encrypted and serialized manifest data.
        """
        # TODO - add implementation (encrypt with EncryptionManager and serialize)
        pass

    def get_manifest_mapping(self, address: Address) -> dict[Hotkey, bytes]:
        """
        Get manifest file from given address and deserialize it. Throws ManifestDeserializationError if data format
        is not recognized.

        Returns:
            dict[Hotkey, bytes]: Mapping with addresses for validators (validator HotKey -> encrypted address).
        """
        raw_data: bytes = self.get_manifest_file(address)
        return self._deserialize_manifest(raw_data)

    @abstractmethod
    def put_manifest_file(self, data: bytes) -> Address:
        """
        Put manifest file into the storage.

        Returns:
            Address: Address for accessing file.
        """
        pass

    @abstractmethod
    def get_manifest_file(self, address: Address) -> bytes:
        """
        Get manifest file from given address. Should throw ManifestNotFoundException if file is not found.
        """
        pass

    @abstractmethod
    def _serialize_manifest(self, encrypted_address_mapping: dict[Hotkey, bytes]) -> bytes:
        """
        Serialize manifest. Output format depends on the implementation.
        """
        pass

    @abstractmethod
    def _deserialize_manifest(self, serialized_data: bytes) -> dict[Hotkey, bytes]:
        """
        Deserialize manifest. Throws ManifestDeserializationException if data format is not recognized.

        Args:
            serialized_data: Data serialized before by _serialize_manifest method.

        Returns:
            dict[Hotkey, bytes]: Mapping with addresses for validators (validator HotKey -> encrypted address).
        """
        pass
