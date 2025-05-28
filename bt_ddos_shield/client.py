from __future__ import annotations

import asyncio
import os
import typing

from bt_ddos_shield.blockchain_manager import BlockchainManagerException
from bt_ddos_shield.encryption_manager import ECIESEncryptionManager, EncryptionCertificate
from bt_ddos_shield.manifest_manager import (
    JsonManifestSerializer,
    ReadOnlyManifestManager,
)
from bt_ddos_shield.shield_metagraph import ShieldMetagraphOptions

if typing.TYPE_CHECKING:
    import bittensor_wallet

    from bt_ddos_shield.blockchain_manager import AbstractBlockchainManager
    from bt_ddos_shield.encryption_manager import AbstractEncryptionManager
    from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor


class ShieldClient:
    blockchain_manager: AbstractBlockchainManager
    certificate: EncryptionCertificate
    encryption_manager: AbstractEncryptionManager
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
        manifest_manager: ReadOnlyManifestManager | None = None,
        options: ShieldMetagraphOptions | None = None,
    ):
        self.netuid = netuid
        self.wallet = wallet
        self.options = options or ShieldMetagraphOptions()
        self.event_processor = event_processor
        self.blockchain_manager = blockchain_manager
        self.encryption_manager = encryption_manager or self.create_default_encryption_manager()
        self.manifest_manager = manifest_manager or self.create_default_manifest_manager(
            self.event_processor,
            self.encryption_manager,
        )

    async def __aenter__(self):
        await self.init_certificate()

    async def __aexit__(self, *args, **kwargs):
        pass

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

    async def init_certificate(self) -> None:
        certificate_path: str = self.options.certificate_path or os.getenv(
            'VALIDATOR_SHIELD_CERTIFICATE_PATH', './validator_cert.pem'
        )

        try:
            certificate = self.encryption_manager.load_certificate(certificate_path)
            self.certificate = self.encryption_manager.serialize_certificate(certificate)
            public_key = await self.blockchain_manager.get_own_public_key_async()

            if self.certificate.public_key == public_key:
                return
        except FileNotFoundError:
            certificate = self.encryption_manager.generate_certificate()
            self.encryption_manager.save_certificate(certificate, certificate_path)
            self.certificate = self.encryption_manager.serialize_certificate(certificate)

        if self.options.disable_uploading_certificate:
            return

        try:
            await self.blockchain_manager.upload_public_key_async(self.certificate.public_key)
        except BlockchainManagerException:
            # Retry once
            await asyncio.sleep(3)
            await self.blockchain_manager.upload_public_key_async(self.certificate.public_key)
