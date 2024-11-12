from types import MappingProxyType

from bt_ddos_shield.address import Address, AddressType
from bt_ddos_shield.address_manager import AbstractAddressManager
from bt_ddos_shield.utils import Hotkey


class MemoryAddressManager(AbstractAddressManager):
    id_counter: int
    known_addresses: dict[str, Address]
    invalid_addresses: set[Hotkey]

    def __init__(self):
        super().__init__(miner_address_id="miner_id")
        self.id_counter = 0
        self.known_addresses = {}
        self.invalid_addresses = set()

    def create_address(self) -> Address:
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
    pass
