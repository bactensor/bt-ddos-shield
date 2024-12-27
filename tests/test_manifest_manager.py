from typing import Optional

import pytest
from bt_ddos_shield.address import Address, AddressType, DefaultAddressSerializer
from bt_ddos_shield.encryption_manager import ECIESEncryptionManager
from bt_ddos_shield.manifest_manager import (
    AbstractManifestManager,
    JsonManifestSerializer,
    Manifest,
    ManifestNotFoundException,
    S3ManifestManager,
)
from bt_ddos_shield.utils import AWSClientFactory, Hotkey
from tests.test_credentials import (
    aws_access_key_id,
    aws_region_name,
    aws_s3_bucket_name,
    aws_secret_access_key,
)


class MemoryManifestManager(AbstractManifestManager):
    default_address: Address
    stored_file: Optional[bytes]
    put_counter: int

    def __init__(self):
        super().__init__(DefaultAddressSerializer(), JsonManifestSerializer(), ECIESEncryptionManager())
        self.default_address = Address(address_id='default_id', address_type=AddressType.DOMAIN,
                                       address='manifest.com', port=80)
        self.stored_file = None
        self.put_counter = 0

    def _put_manifest_file(self, data: bytes) -> Address:
        self.stored_file = data
        self.put_counter += 1
        return self.default_address

    def _get_manifest_file(self, address: Address) -> bytes:
        if self.stored_file is None or address != self.default_address:
            raise ManifestNotFoundException(f"Manifest file not found under address: {address}")
        return self.stored_file


class TestManifestManager:
    """
    Test suite for the manifest manager.
    """

    def test_json_serializer(self):
        manifest_serializer = JsonManifestSerializer()
        mapping: dict[Hotkey, bytes] = {Hotkey('validator1'): b'address1', Hotkey('validator2'): b'address2'}
        md5_hash: str = "some_hash"
        manifest: Manifest = Manifest(mapping, md5_hash)
        json_data: bytes = manifest_serializer.serialize(manifest)
        deserialized_manifest: Manifest = manifest_serializer.deserialize(json_data)

        assert manifest == deserialized_manifest

    def test_s3_put_get(self):
        """ Test S3ManifestManager class. Put manifest file, get it and check if it was stored correctly. """
        aws_client_factory: AWSClientFactory = AWSClientFactory(aws_access_key_id, aws_secret_access_key,
                                                                aws_region_name)
        manifest_manager = S3ManifestManager(aws_client_factory=aws_client_factory, bucket_name=aws_s3_bucket_name,
                                             address_serializer=DefaultAddressSerializer(),
                                             manifest_serializer=JsonManifestSerializer(),
                                             encryption_manager=ECIESEncryptionManager())

        data: bytes = b'some_data'
        address: Address = manifest_manager._put_manifest_file(data)
        retrieved_data: bytes = manifest_manager._get_manifest_file(address)
        assert retrieved_data == data

        other_data: bytes = b'other_data'
        address: Address = manifest_manager._put_manifest_file(other_data)
        retrieved_data: bytes = manifest_manager._get_manifest_file(address)
        assert retrieved_data == other_data

        validator_aws_client_factory: AWSClientFactory = AWSClientFactory(aws_access_key_id, aws_secret_access_key)
        validator_manifest_manager = S3ManifestManager(address_serializer=DefaultAddressSerializer(),
                                                       manifest_serializer=JsonManifestSerializer(),
                                                       encryption_manager=ECIESEncryptionManager(),
                                                       aws_client_factory=validator_aws_client_factory)
        validator_manifest_manager.init_client_from_address(address)
        retrieved_data: bytes = validator_manifest_manager._get_manifest_file(address)
        assert retrieved_data == other_data

        address.address_id = 'xxx'
        with pytest.raises(ManifestNotFoundException):
            manifest_manager._get_manifest_file(address)
