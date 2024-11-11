from typing import Optional

from bt_ddos_shield.address import DefaultAddressSerializer, Address, AddressType
from bt_ddos_shield.encryption_manager import ECIESEncryptionManager
from bt_ddos_shield.manifest_manager import JsonManifestSerializer, AbstractManifestManager, ManifestNotFoundException
from bt_ddos_shield.utils import Hotkey


class MemoryManifestManager(AbstractManifestManager):
    address: Address
    stored_file: Optional[bytes]

    def __init__(self):
        super().__init__(DefaultAddressSerializer(), JsonManifestSerializer(), ECIESEncryptionManager())
        self.address = Address(address_id='default_id', address_type=AddressType.DOMAIN,
                               address=f'manifest.com', port=80)
        self.stored_file = None

    def put_manifest_file(self, data: bytes) -> Address:
        self.stored_file = data
        return self.address

    def get_manifest_file(self, address: Address) -> bytes:
        if self.stored_file is None or address != self.address:
            raise ManifestNotFoundException(f"Manifest file not found under address: {address}")
        return self.stored_file


class TestManifestManager:
    """
    Test suite for the manifest manager.
    """

    def test_json_serializer(self):
        manifest_serializer = JsonManifestSerializer()
        data: dict[Hotkey, bytes] = {Hotkey('validator1'): b'address1', Hotkey('validator2'): b'address2'}
        json_data = manifest_serializer.serialize(data)
        deserialized_data: dict[Hotkey, bytes] = manifest_serializer.deserialize(json_data)

        assert data == deserialized_data, "Decrypted data should match the original data"