import base64
import hashlib
import json
import requests

from abc import ABC, abstractmethod
from collections import namedtuple
from dataclasses import dataclass
from http import HTTPStatus
from types import MappingProxyType
from typing import Any, Optional

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from bt_ddos_shield.address import (
    AbstractAddressSerializer,
    Address,
    AddressDeserializationException,
    AddressType,
)
from bt_ddos_shield.encryption_manager import AbstractEncryptionManager
from bt_ddos_shield.utils import AWSClientFactory, Hotkey, PrivateKey, PublicKey


class ManifestManagerException(Exception):
    pass


class ManifestDeserializationException(ManifestManagerException):
    """
    Exception thrown when deserialization of manifest data fails.
    """
    pass


class ManifestDownloadException(ManifestManagerException):
    """
    Exception thrown when error occurs during downloading manifest file.
    """
    pass


class ManifestNotFoundException(ManifestDownloadException):
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
            raise ManifestDeserializationException(f"Failed to deserialize manifest data: {e}") from e

    @staticmethod
    def _custom_encoder(obj: Any) -> Any:
        if isinstance(obj, Hotkey):
            return str(obj)

        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()  # type: ignore

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

            md5_hash.update(hotkey.encode())  # type: ignore
            public_key_bytes: bytes = public_key.encode() if isinstance(public_key, str) else public_key
            md5_hash.update(public_key_bytes)  # type: ignore
            md5_hash.update(serialized_address)  # type: ignore

        return Manifest(encrypted_address_mapping, md5_hash.hexdigest())

    def get_manifest(self, address: Address) -> Manifest:
        """
        Get manifest file from given address and deserialize it. Throws ManifestDeserializationException if data format
        is not recognized.
        """
        raw_data: bytes = self._get_manifest_file(address)
        return self.manifest_serializer.deserialize(raw_data)

    def get_address_for_validator(self, manifest: Manifest, validator_hotkey: Hotkey,
                                  validator_private_key: PrivateKey) -> Address:
        """
        Get address for validator identified by hotkey from manifest. Decrypts address using validator's private key.
        """
        encrypted_address: bytes = manifest.encrypted_address_mapping[validator_hotkey]
        decrypted_address: bytes = self.encryption_manager.decrypt(validator_private_key, encrypted_address)
        return self.address_serializer.deserialize(decrypted_address)

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


ManifestS3Address = namedtuple('ManifestS3Address', ['region_name', 'bucket_name', 'file_key'])


class ReadOnlyS3ManifestManager(AbstractManifestManager):
    """
    Manifest manager only for getting file uploaded by S3ManifestManager.
    """

    MANIFEST_FILE_NAME: str = "miner_manifest.json"

    def __init__(self, address_serializer: AbstractAddressSerializer, manifest_serializer: AbstractManifestSerializer,
                 encryption_manager: AbstractEncryptionManager):
        super().__init__(address_serializer, manifest_serializer, encryption_manager)

    def _get_manifest_file(self, address: Address) -> bytes:
        s3_address: ManifestS3Address = self._deserialize_manifest_address(address)
        url: str = f"https://{s3_address.bucket_name}.s3.{s3_address.region_name}.amazonaws.com/{s3_address.file_key}"

        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.content
        except requests.HTTPError as e:
            # S3 returns 403 Forbidden if file does not exist in bucket
            if e.response.status_code in (HTTPStatus.FORBIDDEN, HTTPStatus.NOT_FOUND):
                raise ManifestNotFoundException(f"File {url} not found")
            raise ManifestDownloadException(f"HTTP error when downloading file from {url}: {e}") from e
        except requests.RequestException as e:
            raise ManifestDownloadException(f"Failed to download file from {url}: {e}") from e

    def _put_manifest_file(self, data: bytes) -> Address:
        raise NotImplementedError

    @classmethod
    def _serialize_manifest_address(cls, s3_address: ManifestS3Address) -> str:
        return f"{s3_address.region_name}/{s3_address.bucket_name}/{s3_address.file_key}"

    @classmethod
    def _deserialize_manifest_address(cls, address: Address) -> ManifestS3Address:
        if address.address_type != AddressType.S3:
            raise AddressDeserializationException(f"Invalid address type, address='{address}'")
        parts = address.address.split("/")
        if len(parts) != 3:
            raise AddressDeserializationException(f"Invalid number of parts, address='{address}'")

        region_name = parts[0]
        bucket_name = parts[1]
        file_key = parts[2]
        return ManifestS3Address(region_name, bucket_name, file_key)


class S3ManifestManager(ReadOnlyS3ManifestManager):
    """
    Manifest manager using AWS S3 service to manage file.
    """

    _bucket_name: str
    _aws_client_factory: AWSClientFactory
    _s3_client: Optional[BaseClient]

    def __init__(self, address_serializer: AbstractAddressSerializer, manifest_serializer: AbstractManifestSerializer,
                 encryption_manager: AbstractEncryptionManager, aws_client_factory: AWSClientFactory, bucket_name: str):
        super().__init__(address_serializer, manifest_serializer, encryption_manager)
        self._aws_client_factory = aws_client_factory
        self._bucket_name = bucket_name
        self._s3_client = None

    @property
    def s3_client(self):
        if self._s3_client is None:
            self._s3_client = self._aws_client_factory.boto3_client("s3")
        return self._s3_client

    def _get_manifest_file(self, address: Address) -> bytes:
        try:
            response = self.s3_client.get_object(Bucket=self._bucket_name, Key=address.address_id)
            return response['Body'].read()
        except ClientError as e:
            if e.response['Error']['Code'] == "NoSuchKey":
                raise ManifestNotFoundException(f"File {address.address_id} not found")
            raise ManifestDownloadException(f"Failed to download file {address.address_id} from S3: {e}") from e

    def _put_manifest_file(self, data: bytes) -> Address:
        file_key: str = self.MANIFEST_FILE_NAME
        self.s3_client.put_object(Bucket=self._bucket_name, Key=file_key, Body=data, ACL='public-read')
        s3_address: ManifestS3Address = ManifestS3Address(self._aws_client_factory.aws_region_name, self._bucket_name,
                                                          file_key)
        serialized_address: str = self._serialize_manifest_address(s3_address)
        return Address(address_id=file_key, address_type=AddressType.S3, address=serialized_address, port=0)
