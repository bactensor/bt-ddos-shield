import base64
import functools
import hashlib
import json
import requests

from abc import ABC, abstractmethod
from dataclasses import dataclass
from http import HTTPStatus
from types import MappingProxyType
from typing import Any

from botocore.client import BaseClient
from bt_ddos_shield.address import (
    Address,
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

    encrypted_url_mapping: dict[Hotkey, bytes]
    """ Mapping with addresses for validators (validator HotKey -> encrypted url) """
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
            "encrypted_url_mapping": manifest.encrypted_url_mapping,
            "md5_hash": manifest.md5_hash
        }
        json_str: str = json.dumps(data, default=self._custom_encoder)
        return json_str.encode(encoding=self.encoding)

    def deserialize(self, serialized_data: bytes) -> Manifest:
        try:
            json_str: str = serialized_data.decode(encoding=self.encoding)
            data = json.loads(json_str, object_hook=self._custom_decoder)
            return Manifest(data["encrypted_url_mapping"], data["md5_hash"])
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
        if "encrypted_url_mapping" in json_mapping:
            decoded_mapping: dict[Hotkey, bytes] = {}
            for hotkey, encoded_address in json_mapping["encrypted_url_mapping"].items():
                decoded_mapping[Hotkey(hotkey)] = base64.b64decode(encoded_address.encode())
            json_mapping["encrypted_url_mapping"] = decoded_mapping
        return json_mapping


class ReadOnlyManifestManager(ABC):
    """
    Manifest manager only for getting file uploaded by ManifestManager.
    """

    manifest_serializer: AbstractManifestSerializer
    encryption_manager: AbstractEncryptionManager
    _requests_session: requests.Session
    _download_timeout: int

    def __init__(self, manifest_serializer: AbstractManifestSerializer,
                 encryption_manager: AbstractEncryptionManager, download_timeout: int = 10):
        self.manifest_serializer = manifest_serializer
        self.encryption_manager = encryption_manager
        self._requests_session = requests.Session()
        self._download_timeout = download_timeout

    def get_manifest(self, url: str) -> Manifest:
        """
        Get manifest file from given url and deserialize it.
        Throws ManifestNotFoundException if file is not found.
        Throws ManifestDeserializationException if data format is not recognized.
        """
        raw_data: bytes = self._get_manifest_file(url)
        return self.manifest_serializer.deserialize(raw_data)

    def get_address_for_validator(self, manifest: Manifest, validator_hotkey: Hotkey,
                                  validator_private_key: PrivateKey) -> str:
        """
        Get URL for validator identified by hotkey from manifest. Decrypts address using validator's private key.
        """
        encrypted_url: bytes = manifest.encrypted_url_mapping[validator_hotkey]
        decrypted_url: bytes = self.encryption_manager.decrypt(validator_private_key, encrypted_url)
        return decrypted_url.decode()

    def _get_manifest_file(self, url: str) -> bytes:
        """
        Get manifest file from given url. Throws ManifestNotFoundException if file is not found.
        """
        try:
            response = self._requests_session.get(url, timeout=self._download_timeout)
            response.raise_for_status()
            return response.content
        except requests.HTTPError as e:
            if e.response.status_code in (HTTPStatus.FORBIDDEN, HTTPStatus.NOT_FOUND):
                # ManifestNotFoundException should be returned for non-retryable errors.
                # REMARK: S3 returns 403 Forbidden if file does not exist in bucket.
                raise ManifestNotFoundException(f"File {url} not found, status code={e.response.status_code}") from e
            raise ManifestDownloadException(f"HTTP error when downloading file from {url}: {e}") from e
        except requests.RequestException as e:
            raise ManifestDownloadException(f"Failed to download file from {url}: {e}") from e


class AbstractManifestManager(ReadOnlyManifestManager):
    """
    Abstract base class for manager handling manifest file containing encrypted addresses for validators.
    """

    def upload_manifest(self, manifest: Manifest):
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
            url: str = f"{address.address}:{address.port}"
            serialized_url: bytes = url.encode()
            encrypted_address_mapping[hotkey] = self.encryption_manager.encrypt(public_key, serialized_url)

            md5_hash.update(hotkey.encode())  # type: ignore
            public_key_bytes: bytes = public_key.encode() if isinstance(public_key, str) else public_key
            md5_hash.update(public_key_bytes)  # type: ignore
            md5_hash.update(serialized_url)  # type: ignore

        return Manifest(encrypted_address_mapping, md5_hash.hexdigest())

    @abstractmethod
    def get_manifest_url(self) -> str:
        """
        Return URL where manifest file is stored.
        """
        pass

    @abstractmethod
    def _put_manifest_file(self, data: bytes):
        """
        Put manifest file into the storage. Should overwrite manifest file if it exists.
        """
        pass


class S3ManifestManager(AbstractManifestManager):
    """
    Manifest manager using AWS S3 service to manage file.
    """

    MANIFEST_FILE_NAME: str = "shield_manifest.json"

    _aws_client_factory: AWSClientFactory
    _bucket_name: str

    def __init__(self, manifest_serializer: AbstractManifestSerializer,
                 encryption_manager: AbstractEncryptionManager, aws_client_factory: AWSClientFactory, bucket_name: str,
                 download_timeout: int = 10):
        super().__init__(manifest_serializer, encryption_manager, download_timeout)
        self._aws_client_factory = aws_client_factory
        self._bucket_name = bucket_name

    def get_manifest_url(self) -> str:
        region_name: str = self._aws_client_factory.aws_region_name
        return f"https://{self._bucket_name}.s3.{region_name}.amazonaws.com/{self.MANIFEST_FILE_NAME}"

    @functools.cached_property
    def _s3_client(self) -> BaseClient:
        return self._aws_client_factory.boto3_client("s3")

    def _put_manifest_file(self, data: bytes):
        self._s3_client.put_object(Bucket=self._bucket_name, Key=self.MANIFEST_FILE_NAME, Body=data, ACL='public-read')
