import asyncio
import os
from collections import namedtuple
from dataclasses import dataclass
from typing import Optional

from tests.test_blockchain_manager import MemoryBlockchainManager

from bt_ddos_shield.address import AbstractAddressSerializer, Address, AddressType, DefaultAddressSerializer
from bt_ddos_shield.blockchain_manager import AbstractBlockchainManager
from bt_ddos_shield.encryption_manager import AbstractEncryptionManager, ECIESEncryptionManager
from bt_ddos_shield.manifest_manager import (
    AbstractManifestManager,
    AbstractManifestSerializer,
    JsonManifestSerializer,
    Manifest,
    S3ManifestManager,
)
from bt_ddos_shield.utils import AWSClientFactory, Hotkey, PrivateKey


@dataclass
class ValidatorOptions:
    retry_delay_sec: int = 10
    """ Time in seconds to wait before retrying fetching miner address. """


MinerAddress = namedtuple('MinerAddress', ['domain', 'port'])


class Validator:
    """
    Validator class used to retrieve address of miner shielded by MinerShield.
    """

    _validator_hotkey: Hotkey
    _validator_private_key: PrivateKey
    _blockchain_manager: AbstractBlockchainManager
    _manifest_manager: AbstractManifestManager
    _options: ValidatorOptions

    def __init__(self, validator_hotkey: Hotkey, validator_private_key: PrivateKey,
                 blockchain_manager: AbstractBlockchainManager, manifest_manager: AbstractManifestManager,
                 options: ValidatorOptions):
        self._validator_hotkey = validator_hotkey
        self._validator_private_key = validator_private_key
        self._blockchain_manager = blockchain_manager
        self._manifest_manager = manifest_manager
        self._options = options

    async def fetch_miner_address(self) -> MinerAddress:
        while True:
            miner_manifest_address: Optional[Address] = self._blockchain_manager.get_miner_manifest_address()
            if miner_manifest_address is not None:
                break

            await asyncio.sleep(self._options.retry_delay_sec)

        manifest: Manifest = self._manifest_manager.get_manifest(miner_manifest_address)
        address: Address = self._manifest_manager.get_address_for_validator(manifest, self._validator_hotkey,
                                                                            self._validator_private_key)
        assert address.address_type == AddressType.DOMAIN
        return MinerAddress(domain=address.address, port=address.port)


class ValidatorFactoryException(Exception):
    pass


class ValidatorFactory:
    """
    Factory class to create proper Validator instance basing on set environmental variables.
    """

    @classmethod
    def create_validator(cls) -> Validator:
        """
        Create Validator instance basing on set environmental variables.

        List of required env variables:
        - MINER_HOTKEY: Hotkey of shielded miner.
        - VALIDATOR_HOTKEY: Hotkey of validator.
        - VALIDATOR_PRIVATE_KEY: Hex representation of secp256k1 private key of validator.
        - AWS_ACCESS_KEY_ID: AWS access key ID.
        - AWS_SECRET_ACCESS_KEY: AWS secret access key.
        """
        miner_hotkey: Hotkey = os.getenv('MINER_HOTKEY')
        if not miner_hotkey:
            raise ValidatorFactoryException("MINER_HOTKEY env is not set")

        validator_hotkey: Hotkey = os.getenv('VALIDATOR_HOTKEY')
        if not validator_hotkey:
            raise ValidatorFactoryException("VALIDATOR_HOTKEY env is not set")

        validator_private_key: PrivateKey = os.getenv('VALIDATOR_PRIVATE_KEY')
        if not validator_private_key:
            raise ValidatorFactoryException("VALIDATOR_PRIVATE_KEY env is not set")

        aws_client_factory: AWSClientFactory = cls.create_aws_client_factory()
        encryption_manager: AbstractEncryptionManager = cls.create_encryption_manager()
        manifest_manager: AbstractManifestManager = cls.create_manifest_manager(encryption_manager, aws_client_factory)
        blockchain_manager: AbstractBlockchainManager = cls.create_blockchain_manager(miner_hotkey)
        options: ValidatorOptions = ValidatorOptions()
        return Validator(validator_hotkey, validator_private_key, blockchain_manager, manifest_manager, options)

    @classmethod
    def create_aws_client_factory(cls) -> AWSClientFactory:
        aws_access_key_id: str = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_access_key: str = os.getenv('AWS_SECRET_ACCESS_KEY')
        if not aws_access_key_id or not aws_secret_access_key:
            raise ValidatorFactoryException("AWS credentials are not set")
        return AWSClientFactory(aws_access_key_id, aws_secret_access_key)

    @classmethod
    def create_encryption_manager(cls) -> AbstractEncryptionManager:
        return ECIESEncryptionManager()

    @classmethod
    def create_manifest_manager(cls, encryption_manager: AbstractEncryptionManager,
                                aws_client_factory: AWSClientFactory) -> AbstractManifestManager:
        address_serializer: AbstractAddressSerializer = DefaultAddressSerializer()
        manifest_serializer: AbstractManifestSerializer = JsonManifestSerializer()
        return S3ManifestManager(address_serializer, manifest_serializer, encryption_manager, aws_client_factory)

    @classmethod
    def create_blockchain_manager(cls, miner_hotkey: Hotkey) -> AbstractBlockchainManager:
        # TODO: waiting for implementation of blockchain manager
        return MemoryBlockchainManager(miner_hotkey)
