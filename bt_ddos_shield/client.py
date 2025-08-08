from __future__ import annotations

import asyncio
import os
import typing

from bt_ddos_shield.blockchain_manager import BlockchainManagerException
from bt_ddos_shield.certificate_manager import EDDSACertificateManager, Certificate
from bt_ddos_shield.encryption_manager import ECIESEncryptionManager
from bt_ddos_shield.manifest_manager import (
    JsonManifestSerializer,
    Manifest,
    ManifestDeserializationException,
    ReadOnlyManifestManager,
)
from bt_ddos_shield.shield_metagraph import ShieldMetagraphOptions

if typing.TYPE_CHECKING:
    import bittensor_wallet

    from bt_ddos_shield.blockchain_manager import AbstractBlockchainManager
    from bt_ddos_shield.encryption_manager import AbstractEncryptionManager
    from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor
    from bt_ddos_shield.utils import Hotkey


class ShieldClient:
    blockchain_manager: AbstractBlockchainManager
    certificate: Certificate
    encryption_manager: AbstractEncryptionManager
    certificate_manager: EDDSACertificateManager
    event_processor: AbstractMinerShieldEventProcessor
    manifest_manager: ReadOnlyManifestManager
    options: ShieldMetagraphOptions
    wallet: bittensor_wallet.Wallet

    def __init__(
        self,
        netuid: int,
        wallet: bittensor_wallet.Wallet,
        event_processor: AbstractMinerShieldEventProcessor,
        blockchain_manager: AbstractBlockchainManager,
        encryption_manager: AbstractEncryptionManager | None = None,
        certificate_manager: EDDSACertificateManager | None = None,
        manifest_manager: ReadOnlyManifestManager | None = None,
        options: ShieldMetagraphOptions | None = None,
    ):
        self.netuid = netuid
        self.wallet = wallet
        self.options = options or ShieldMetagraphOptions()
        self.event_processor = event_processor
        self.blockchain_manager = blockchain_manager
        self.certificate_manager = certificate_manager or self.create_default_certificate_manager()
        self.encryption_manager = encryption_manager or self.create_default_encryption_manager()
        self.manifest_manager = manifest_manager or self.create_default_manifest_manager(
            self.event_processor,
            self.encryption_manager,
        )

    async def __aenter__(self):
        await self._init_certificate()

    async def __aexit__(self, *args, **kwargs):
        pass

    @classmethod
    def create_default_certificate_manager(cls):
        return EDDSACertificateManager()

    @classmethod
    def create_default_encryption_manager(cls):
        return ECIESEncryptionManager()

    @classmethod
    def create_default_manifest_manager(
        cls,
        event_processor: AbstractMinerShieldEventProcessor,
        encryption_manager: AbstractEncryptionManager,
    ) -> ReadOnlyManifestManager:
        return ReadOnlyManifestManager(JsonManifestSerializer(), encryption_manager, event_processor)

    async def _init_certificate(self) -> None:
        certificate_path: str = self.options.certificate_path or os.getenv(
            'VALIDATOR_SHIELD_CERTIFICATE_PATH', './validator_cert.pem'
        )

        try:
            self.certificate = self.certificate_manager.load_certificate(certificate_path)
            public_key = await self.blockchain_manager.get_own_public_key_async()

            if self.certificate.public_key == public_key:
                return
        except FileNotFoundError:
            self.certificate = self.certificate_manager.generate_certificate()
            self.certificate_manager.save_certificate(self.certificate, certificate_path)

        if self.options.disable_uploading_certificate:
            return

        try:
            await self.blockchain_manager.upload_public_key_async(
                self.certificate.public_key, self.certificate.algorithm
            )
        except BlockchainManagerException:
            # Retry once
            await asyncio.sleep(3)
            await self.blockchain_manager.upload_public_key_async(
                self.certificate.public_key, self.certificate.algorithm
            )

    async def get_manifests(
        self,
        hotkeys: typing.Iterable[Hotkey],
    ) -> dict[Hotkey, Manifest | None]:
        manifests_urls = await self.blockchain_manager.get_manifest_urls(hotkeys)
        manifests = await self.manifest_manager.get_manifests(manifests_urls)

        return manifests

    def get_address(
        self,
        hotkey: Hotkey,
        manifest: Manifest,
    ) -> tuple[str, int] | None:
        try:
            return self.manifest_manager.get_address_for_validator(
                manifest,
                hotkey,
                self.certificate.private_key,
            )
        except ManifestDeserializationException as e:
            self.event_processor.event(
                'Error while getting shield address for miner {hotkey}',
                exception=e,
                hotkey=hotkey,
            )
            return None
