from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

import aiohttp

if TYPE_CHECKING:
    from types import MappingProxyType

    from mypy_boto3_s3 import S3Client

    from bt_ddos_shield.encryption_manager import AbstractEncryptionManager
    from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor
    from bt_ddos_shield.utils import AWSClientFactory, Hotkey, PrivateKey, PublicKey, ShieldAddress


class ManifestManagerException(Exception):
    pass


class ManifestDeserializationException(ManifestManagerException):
    """
    Exception thrown when deserialization of manifest data fails.
    """


class ManifestDownloadException(ManifestManagerException):
    """
    Exception thrown when error occurs during downloading manifest file.
    """


class ManifestNotFoundException(ManifestDownloadException):
    """
    Exception thrown when manifest file is not found under given address.
    """


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

    MANIFEST_ROOT_JSON_KEY: str = 'ddos_shield_manifest'

    encoding: str

    def __init__(self, encoding: str = 'utf-8'):
        """
        Args:
            encoding: Encoding used for transforming Json string to bytes.
        """
        self.encoding = encoding

    def serialize(self, manifest: Manifest) -> bytes:
        data: dict = {
            self.MANIFEST_ROOT_JSON_KEY: asdict(manifest)  # type: ignore
        }
        json_str: str = json.dumps(data, default=self._custom_encoder)
        return json_str.encode(encoding=self.encoding)

    def deserialize(self, serialized_data: bytes) -> Manifest:
        try:
            json_str: str = serialized_data.decode(encoding=self.encoding)
            data = json.loads(json_str, object_hook=self._custom_decoder)
            return Manifest(**data[self.MANIFEST_ROOT_JSON_KEY])
        except Exception as e:
            raise ManifestDeserializationException(f'Failed to deserialize manifest data: {e}') from e

    @staticmethod
    def _custom_encoder(obj: Any) -> Any:
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()

    @staticmethod
    def _custom_decoder(json_mapping: dict[str, Any]) -> Any:
        if 'encrypted_url_mapping' in json_mapping:
            decoded_mapping: dict[Hotkey, bytes] = {}
            for hotkey, encoded_address in json_mapping['encrypted_url_mapping'].items():
                decoded_mapping[hotkey] = base64.b64decode(encoded_address.encode())
            json_mapping['encrypted_url_mapping'] = decoded_mapping
        return json_mapping


class ReadOnlyManifestManager(ABC):
    """
    Manifest manager only for getting file uploaded by ManifestManager.
    """

    manifest_serializer: AbstractManifestSerializer
    encryption_manager: AbstractEncryptionManager
    event_processor: AbstractMinerShieldEventProcessor
    _download_timeout: int

    def __init__(
        self,
        manifest_serializer: AbstractManifestSerializer,
        encryption_manager: AbstractEncryptionManager,
        event_processor: AbstractMinerShieldEventProcessor,
        download_timeout: int = 10,
    ):
        self.manifest_serializer = manifest_serializer
        self.encryption_manager = encryption_manager
        self.event_processor = event_processor
        self._download_timeout = download_timeout

    async def get_manifest(self, url: str) -> Manifest:
        """
        Get manifest file from given url and deserialize it.
        Throws ManifestNotFoundException if file is not found.
        Throws ManifestDeserializationException if data format is not recognized.
        """
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self._download_timeout)) as session:
            raw_data: bytes | None = await self._get_manifest_file(session, None, url)
        if raw_data is None:
            raise ManifestDownloadException(f'Manifest file not found at {url}')
        return self.manifest_serializer.deserialize(raw_data)

    async def get_manifests(self, urls: dict[Hotkey, str | None]) -> dict[Hotkey, Manifest | None]:
        """
        Get manifest files from given urls and deserialize them. If url is None, None is returned in the result.
        None is also returned if manifest file is not found or has invalid format.

        Args:
            urls: Dictionary with urls for neurons (neuron HotKey -> url).
        """
        raw_manifests_data: dict[Hotkey, bytes | None] = await self._get_manifest_files(urls)
        manifests: dict[Hotkey, Manifest | None] = {}
        for hotkey, raw_data in raw_manifests_data.items():
            manifest: Manifest | None = None
            if raw_data is not None:
                try:
                    manifest = self.manifest_serializer.deserialize(raw_data)
                except ManifestDeserializationException:
                    self.event_processor.event(
                        'Manifest file corrupted for hotkey={hotkey}, url={url}', hotkey=hotkey, url=urls[hotkey]
                    )
            manifests[hotkey] = manifest
        return manifests

    def get_address_for_validator(
        self, manifest: Manifest, validator_hotkey: Hotkey, validator_private_key: PrivateKey
    ) -> tuple[str, int] | None:
        """
        Get URL and port for validator identified by hotkey from manifest or None if not found.
        Decrypts address using validator's private key.
        Throws ManifestDeserializationException if address format is invalid.
        """
        encrypted_url: bytes | None = manifest.encrypted_url_mapping.get(validator_hotkey)
        if encrypted_url is None:
            return None
        try:
            decrypted_url: bytes = self.encryption_manager.decrypt(validator_private_key, encrypted_url)
            url: str = decrypted_url.decode()
            parts: list[str] = url.split(':')
            return parts[0], int(parts[1])
        except Exception as e:
            raise ManifestDeserializationException(
                f'Invalid address format for validator {validator_hotkey}: {e}'
            ) from e

    async def _get_manifest_file(
        self,
        http_session: aiohttp.ClientSession,
        manifest_owner_hotkey: Hotkey | None,
        url: str | None,
    ) -> bytes | None:
        """
        Get manifest file.
        Args:
            http_session: aiohttp session
            manifest_owner_hotkey: Hotkey of the owner of the manifest file. Used for logging purposes.
            url: URL of the manifest file. If it is None, there is no manifest for given neuron, but it makes code
                cleaner if we just run this method with None param than filter out Nones as we are building dictionary
                of results.
        """
        if url is None:
            return None

        try:
            async with http_session.get(url) as response:
                response.raise_for_status()
                return await response.read()
        except aiohttp.InvalidUrlClientError:
            # Treat it as manifest URL was not uploaded (there was commitment with other data)
            return None
        except aiohttp.ClientResponseError as e:
            if e.status in (HTTPStatus.FORBIDDEN, HTTPStatus.NOT_FOUND):
                # REMARK: S3 returns 403 Forbidden if file does not exist in bucket.
                self.event_processor.event(
                    'Manifest file not found for hotkey={hotkey}, url={url}, status code={status_code}',
                    hotkey=manifest_owner_hotkey,
                    url=url,
                    status_code=e.status,
                )
                return None
            raise ManifestDownloadException(f'HTTP error when downloading file from {url}: {e}') from e
        except (TimeoutError, aiohttp.ClientConnectionError) as e:
            raise ManifestDownloadException(f'Failed to download file from {url}: {e}') from e

    async def _get_manifest_file_with_retry(
        self,
        http_session: aiohttp.ClientSession,
        manifest_owner_hotkey: Hotkey,
        url: str | None,
    ) -> bytes | None:
        try:
            return await self._get_manifest_file(http_session, manifest_owner_hotkey, url)
        except ManifestDownloadException:
            # Retry once
            time.sleep(1)
            return await self._get_manifest_file(http_session, manifest_owner_hotkey, url)

    async def _get_manifest_files(self, urls: dict[Hotkey, str | None]) -> dict[Hotkey, bytes | None]:
        """
        Get manifest files from given urls. If url is None, None is returned in the result. None is also returned if
        manifest file is not found.

        Args:
            urls: Dictionary with urls for neurons (neuron HotKey -> url).
        """
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self._download_timeout)) as session:
            tasks = [self._get_manifest_file_with_retry(session, hotkey, url) for hotkey, url in urls.items()]
            results: list[bytes | None] = await asyncio.gather(*tasks)
        return dict(zip(urls.keys(), results, strict=True))


class AbstractManifestManager(ReadOnlyManifestManager):
    """
    Abstract base class for manager handling manifest file containing encrypted addresses for validators.
    """

    def upload_manifest(self, manifest: Manifest):
        data: bytes = self.manifest_serializer.serialize(manifest)
        return self._put_manifest_file(data)

    def create_manifest(
        self,
        address_mapping: MappingProxyType[Hotkey, ShieldAddress],
        validators_public_keys: MappingProxyType[Hotkey, PublicKey],
    ) -> Manifest:
        """
        Create manifest with encrypted addresses for validators.

        Args:
            address_mapping: Dictionary containing address mapping (validator HotKey -> Address).
            validators_public_keys: Dictionary containing public keys of validators (validator HotKey -> PublicKey).
        """
        encrypted_address_mapping: dict[Hotkey, bytes] = {}
        md5_hash = hashlib.md5(usedforsecurity=False)

        for hotkey, address in address_mapping.items():
            public_key: PublicKey = validators_public_keys[hotkey]
            url: str = f'{address.address}:{address.port}'
            serialized_url: bytes = url.encode()
            encrypted_address_mapping[hotkey] = self.encryption_manager.encrypt(public_key, serialized_url)

            md5_hash.update(hotkey.encode())
            public_key_bytes: bytes = public_key.encode() if isinstance(public_key, str) else public_key
            md5_hash.update(public_key_bytes)
            md5_hash.update(serialized_url)

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

    MANIFEST_FILE_NAME: str = 'shield_manifest.json'

    _aws_client_factory: AWSClientFactory
    _bucket_name: str

    def __init__(
        self,
        manifest_serializer: AbstractManifestSerializer,
        encryption_manager: AbstractEncryptionManager,
        event_processor: AbstractMinerShieldEventProcessor,
        aws_client_factory: AWSClientFactory,
        bucket_name: str,
        download_timeout: int = 10,
    ):
        super().__init__(manifest_serializer, encryption_manager, event_processor, download_timeout)
        self._aws_client_factory = aws_client_factory
        self._bucket_name = bucket_name

    def get_manifest_url(self) -> str:
        assert self._aws_client_factory.aws_region_name is not None, 'aws_region_name needs to be initialized first'
        region_name: str = self._aws_client_factory.aws_region_name
        return f'https://{self._bucket_name}.s3.{region_name}.amazonaws.com/{self.MANIFEST_FILE_NAME}'

    @functools.cached_property
    def _s3_client(self) -> S3Client:
        return self._aws_client_factory.boto3_client('s3')  # type: ignore

    def _put_manifest_file(self, data: bytes):
        self._s3_client.put_object(Bucket=self._bucket_name, Key=self.MANIFEST_FILE_NAME, Body=data, ACL='public-read')
