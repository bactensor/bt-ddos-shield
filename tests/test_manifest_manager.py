from typing import Optional

from bt_ddos_shield.address import DefaultAddressSerializer, Address, AddressType
from bt_ddos_shield.encryption_manager import ECIESEncryptionManager
from bt_ddos_shield.manifest_manager import JsonManifestSerializer, AbstractManifestManager, \
    ManifestNotFoundException, Manifest
from bt_ddos_shield.utils import Hotkey


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
