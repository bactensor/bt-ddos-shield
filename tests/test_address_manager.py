from types import MappingProxyType

from bt_ddos_shield.address import Address, AddressType
from bt_ddos_shield.address_manager import AbstractAddressManager, Route53AddressManager
from bt_ddos_shield.utils import Hotkey


class MemoryAddressManager(AbstractAddressManager):
    id_counter: int
    known_addresses: dict[str, Address]
    invalid_addresses: set[Hotkey]

    def __init__(self):
        super().__init__(Address(address_id="miner", address_type=AddressType.IP, address="1.2.3.4", port=80))
        self.id_counter = 0
        self.known_addresses = {}
        self.invalid_addresses = set()

    def create_address(self, hotkey: Hotkey) -> Address:
        address = Address(address_id=str(self.id_counter), address_type=AddressType.DOMAIN,
                          address=f"addr{self.id_counter}.com", port=80)
        self.known_addresses[address.address_id] = address
        self.id_counter += 1
        return address

    def remove_address(self, address: Address):
        self.known_addresses.pop(address.address_id, None)

    def validate_addresses(self, addresses: MappingProxyType[Hotkey, Address]) -> set[Hotkey]:
        for hotkey in self.invalid_addresses:
            if hotkey in addresses:
                self.known_addresses.pop(addresses[hotkey].address_id, None)
        return self.invalid_addresses


class TestAddressManager:
    """
    Test suite for the address manager.
    """

    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    hosted_zone_id: str = "Z07475802PJEQKQZI12TT"
    miner_new_address: Address = Address(address_id="miner", address_type=AddressType.IPV6,
                                         address="2001:0db8:85a3:0000:0000:8a2e:0370:7334", port=80)

    def test_route53_address_manager(self):
        """ Test Route53AddressManager class. Create address, validate it and remove created address. """
        address_manager = Route53AddressManager(self.aws_access_key_id, self.aws_secret_access_key,
                                                hosted_zone_id=self.hosted_zone_id,
                                                miner_new_address=self.miner_new_address)
        address: Address = address_manager.create_address("validator1")
        invalid_address: Address = Address(address_id="invalid", address_type=AddressType.DOMAIN, address="invalid.com",
                                           port=80)
        mapping: dict[Hotkey, Address] = {Hotkey("hotkey"): address, Hotkey("invalid"): invalid_address}
        invalid_addresses: set[Hotkey] = address_manager.validate_addresses(MappingProxyType(mapping))
        address_manager.remove_address(address)

        assert invalid_addresses == {Hotkey("invalid")}
