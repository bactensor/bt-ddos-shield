import base64
import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from bt_ddos_shield.address import Address, AbstractAddressSerializer
from bt_ddos_shield.encryption_manager import AbstractEncryptionManager
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


@dataclass
class Manifest:
    """
    Class representing manifest file containing encrypted addresses for validators.
    """

    encrypted_address_mapping: dict[Hotkey, bytes]
    """ Mapping with addresses for validators (validator HotKey -> encrypted address) """
    md5_hash: str
    """ MD5 hash of the manifest data """


class AbstractManifestSerializer(ABC):
    """
    Class used to serialize and deserialize manifest file.
    """

    @abstractmethod
    def serialize(self, manifest: Manifest) -> bytes:
        """
        Serialize manifest. Output format depends on the implementation.
        """
        pass

    @abstractmethod
    def deserialize(self, serialized_data: bytes) -> Manifest:
        """
        Deserialize manifest. Throws ManifestDeserializationException if data format is not recognized.
        """
        pass


class JsonManifestSerializer(AbstractManifestSerializer):
    """
    Manifest serializer implementation which serialize manifest to Json.
    """

    encoding: str

    def __init__(self, encoding: str = "utf-8"):
        """
        Args:
            encoding: Encoding used for transforming Json string to bytes.
        """
        self.encoding = encoding

    def serialize(self, manifest: Manifest) -> bytes:
        data: dict = {
            "encrypted_address_mapping": manifest.encrypted_address_mapping,
            "md5_hash": manifest.md5_hash
        }
        json_str: str = json.dumps(data, default=self._custom_encoder)
        return json_str.encode(encoding=self.encoding)

    def deserialize(self, serialized_data: bytes) -> Manifest:
        try:
            json_str: str = serialized_data.decode(encoding=self.encoding)
            data = json.loads(json_str, object_hook=self._custom_decoder)
            return Manifest(data["encrypted_address_mapping"], data["md5_hash"])
        except Exception as e:
            raise ManifestDeserializationException(f"Failed to deserialize manifest data: {e}")

    @staticmethod
    def _custom_encoder(obj: Any) -> Any:
        if isinstance(obj, Hotkey):
            return str(obj)

        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()

    @staticmethod
    def _custom_decoder(json_mapping: dict[str, Any]) -> Any:
        if "encrypted_address_mapping" in json_mapping:
            decoded_mapping: dict[Hotkey, bytes] = {}
            for hotkey, encoded_address in json_mapping["encrypted_address_mapping"].items():
                decoded_mapping[Hotkey(hotkey)] = base64.b64decode(encoded_address.encode())
            json_mapping["encrypted_address_mapping"] = decoded_mapping
        return json_mapping


class AbstractManifestManager(ABC):
    """
    Abstract base class for manager handling publishing manifest file containing encrypted addresses for validators.
    """

    address_serializer: AbstractAddressSerializer
    manifest_serializer: AbstractManifestSerializer
    encryption_manager: AbstractEncryptionManager

    def __init__(self, address_serializer: AbstractAddressSerializer, manifest_serializer: AbstractManifestSerializer,
                 encryption_manager: AbstractEncryptionManager):
        self.address_serializer = address_serializer
        self.manifest_serializer = manifest_serializer
        self.encryption_manager = encryption_manager

    def upload_manifest(self, manifest: Manifest) -> Address:
        data: bytes = self.manifest_serializer.serialize(manifest)
        return self._put_manifest_file(data)

    def create_manifest(self, address_mapping: MappingProxyType[Hotkey, Address],
                        validators_public_keys: MappingProxyType[Hotkey, PublicKey]) -> Manifest:
        """
        Create manifest with encrypted addresses for validators.

        Args:
            address_mapping: Dictionary containing address mapping (validator HotKey -> Address).
            validators_public_keys: Dictionary containing public keys of validators (validator HotKey -> PublicKey).
        """
        encrypted_address_mapping: dict[Hotkey, bytes] = {}
        md5_hash = hashlib.md5()

        for hotkey, address in address_mapping.items():
            public_key: PublicKey = validators_public_keys[hotkey]
            serialized_address: bytes = self.address_serializer.serialize(address)
            encrypted_address_mapping[hotkey] = self.encryption_manager.encrypt(public_key, serialized_address)

            md5_hash.update(hotkey.encode())
            public_key_bytes: bytes = public_key.encode() if isinstance(public_key, str) else public_key
            md5_hash.update(public_key_bytes)
            md5_hash.update(serialized_address)

        return Manifest(encrypted_address_mapping, md5_hash.hexdigest())

    def get_manifest(self, address: Address) -> Manifest:
        """
        Get manifest file from given address and deserialize it. Throws ManifestDeserializationException if data format
        is not recognized.
        """
        raw_data: bytes = self._get_manifest_file(address)
        return self.manifest_serializer.deserialize(raw_data)

    @abstractmethod
    def _put_manifest_file(self, data: bytes) -> Address:
        """
        Put manifest file into the storage. Should remove old manifest file if it exists.

        Returns:
            Address: Address for accessing file.
        """
        pass

    @abstractmethod
    def _get_manifest_file(self, address: Address) -> bytes:
        """
        Get manifest file from given address. Should throw ManifestNotFoundException if file is not found.
        """
        pass
