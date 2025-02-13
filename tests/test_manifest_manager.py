from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import aiohttp

from bt_ddos_shield.encryption_manager import ECIESEncryptionManager
from bt_ddos_shield.event_processor import PrintingMinerShieldEventProcessor
from bt_ddos_shield.manifest_manager import (
    AbstractManifestManager,
    JsonManifestSerializer,
    Manifest,
    ReadOnlyManifestManager,
    S3ManifestManager,
)
from bt_ddos_shield.utils import AWSClientFactory, Hotkey

if TYPE_CHECKING:
    from tests.conftest import ShieldTestSettings


class MemoryManifestManager(AbstractManifestManager):
    _manifest_url: str
    stored_file: bytes | None
    put_counter: int

    def __init__(self):
        super().__init__(JsonManifestSerializer(), ECIESEncryptionManager(), PrintingMinerShieldEventProcessor())
        self._manifest_url = 'https://manifest.com'
        self.stored_file = None
        self.put_counter = 0

    def get_manifest_url(self) -> str:
        return self._manifest_url

    def _put_manifest_file(self, data: bytes):
        self.stored_file = data
        self.put_counter += 1

    async def _get_manifest_file(self, http_session: aiohttp.ClientSession, url: str | None) -> bytes | None:
        if self.stored_file is None or url != self._manifest_url:
            return None
        return self.stored_file


class TestManifestManager:
    """
    Test suite for the manifest manager.
    """

    def test_json_serializer(self) -> None:
        manifest_serializer = JsonManifestSerializer()
        mapping: dict[Hotkey, bytes] = {'validator1': b'address1', 'validator2': b'address2'}
        md5_hash: str = 'some_hash'
        manifest: Manifest = Manifest(mapping, md5_hash)
        json_data: bytes = manifest_serializer.serialize(manifest)
        deserialized_manifest: Manifest = manifest_serializer.deserialize(json_data)
        assert manifest == deserialized_manifest

    def test_s3_put_get(self, shield_settings: ShieldTestSettings):
        """Test S3ManifestManager class. Put manifest file, get it and check if it was stored correctly."""
        aws_client_factory: AWSClientFactory = AWSClientFactory(
            shield_settings.aws_access_key_id, shield_settings.aws_secret_access_key, shield_settings.aws_region_name
        )
        manifest_manager = S3ManifestManager(
            aws_client_factory=aws_client_factory,
            bucket_name=shield_settings.aws_s3_bucket_name,
            manifest_serializer=JsonManifestSerializer(),
            encryption_manager=ECIESEncryptionManager(),
            event_processor=PrintingMinerShieldEventProcessor(),
        )
        http_session: aiohttp.ClientSession = aiohttp.ClientSession(loop=asyncio.get_event_loop())

        try:
            data: bytes = b'some_data'
            manifest_manager._put_manifest_file(data)
            manifest_url: str = manifest_manager.get_manifest_url()
            retrieved_data: bytes | None = asyncio.run(manifest_manager._get_manifest_file(http_session, manifest_url))
            assert retrieved_data == data
            assert asyncio.run(manifest_manager._get_manifest_file(http_session, manifest_url + 'xxx')) is None

            other_data: bytes = b'other_data'
            manifest_manager._put_manifest_file(other_data)
            retrieved_data = asyncio.run(manifest_manager._get_manifest_file(http_session, manifest_url))
            assert retrieved_data == other_data

            validator_manifest_manager = ReadOnlyManifestManager(
                manifest_serializer=JsonManifestSerializer(),
                encryption_manager=ECIESEncryptionManager(),
                event_processor=PrintingMinerShieldEventProcessor(),
            )
            retrieved_data = asyncio.run(validator_manifest_manager._get_manifest_file(http_session, manifest_url))
            assert retrieved_data == other_data
        finally:
            asyncio.run(http_session.close())
