from types import MappingProxyType

from bt_ddos_shield.address import Address, AddressType
from bt_ddos_shield.address_manager import AbstractAddressManager, AwsAddressManager, AwsObjectTypes
from bt_ddos_shield.event_processor import PrintingMinerShieldEventProcessor
from bt_ddos_shield.state_manager import MinerShieldState
from bt_ddos_shield.utils import Hotkey
from tests.test_credentials import aws_access_key_id, aws_secret_access_key, aws_route53_hosted_zone_id, \
    miner_instance_id, miner_instance_port, miner_region_name, miner_instance_ip
from tests.test_state_manager import MemoryMinerShieldStateManager


def get_miner_address_from_credentials(address_type: AddressType) -> Address:
    if address_type == AddressType.EC2:
        return Address(address_id="miner", address_type=AddressType.EC2, address=miner_instance_id,
                       port=miner_instance_port)
    elif address_type == AddressType.IP:
        return Address(address_id="miner", address_type=AddressType.IP, address=miner_instance_ip,
                       port=miner_instance_port)
    else:
        raise ValueError("Invalid address type")


class MemoryAddressManager(AbstractAddressManager):
    id_counter: int
    known_addresses: dict[str, Address]
    invalid_addresses: set[Hotkey]

    def __init__(self):
        self.id_counter = 0
        self.known_addresses = {}
        self.invalid_addresses = set()

    def clean_all(self):
        self.id_counter = 0
        self.known_addresses.clear()
        self.invalid_addresses.clear()

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

    def create_aws_address_manager(self):
        miner_address: Address = get_miner_address_from_credentials(AddressType.IP)
        self.state_manager: MemoryMinerShieldStateManager = MemoryMinerShieldStateManager()
        self.address_manager: AwsAddressManager = \
            AwsAddressManager(aws_access_key_id, aws_secret_access_key, hosted_zone_id=aws_route53_hosted_zone_id,
                              miner_region_name=miner_region_name, miner_address=miner_address,
                              event_processor=PrintingMinerShieldEventProcessor(), state_manager=self.state_manager)

    def test_create_elb(self):
        """ Test creating ELB by AwsAddressManager class. """
        self.create_aws_address_manager()

        try:
            # This triggers creation of ELB
            self.address_manager.validate_addresses(MappingProxyType({}))

            state: MinerShieldState = self.state_manager.get_state()
            address_manager_state: MappingProxyType[str, str] = state.address_manager_state
            assert address_manager_state[self.address_manager.HOSTED_ZONE_ID_KEY] == aws_route53_hosted_zone_id
            assert address_manager_state[self.address_manager.INSTANCE_ID_KEY] == miner_instance_id
            created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
            assert AwsObjectTypes.ELB.value not in created_objects
            assert len(created_objects[AwsObjectTypes.SUBNET.value]) == 1
            assert AwsObjectTypes.DNS_ENTRY.value not in created_objects

            reloaded_state: MinerShieldState = self.state_manager.get_state(reload=True)
            assert reloaded_state == state

            # Call clean_all and check if everything was removed
            self.address_manager.clean_all()
            state = self.state_manager.get_state()
            created_objects = state.address_manager_created_objects
            assert AwsObjectTypes.ELB.value not in created_objects
            assert AwsObjectTypes.SUBNET.value not in created_objects
            assert AwsObjectTypes.DNS_ENTRY.value not in created_objects
        finally:
            self.address_manager.clean_all()

    def test_handle_address(self):
        """ Create address, validate it and remove created address. """
        self.create_aws_address_manager()

        try:
            address: Address = self.address_manager.create_address("validator1")
            invalid_address: Address = Address(address_id="invalid", address_type=AddressType.DOMAIN,
                                               address="invalid.com", port=80)
            mapping: dict[Hotkey, Address] = {Hotkey("hotkey"): address, Hotkey("invalid"): invalid_address}
            invalid_addresses: set[Hotkey] = self.address_manager.validate_addresses(MappingProxyType(mapping))
            assert invalid_addresses == {Hotkey("invalid")}

            state: MinerShieldState = self.state_manager.get_state()
            created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
            # assert len(created_objects[AwsObjectTypes.ELB.value]) == 1, "ELB should be created before adding address"
            assert AwsObjectTypes.ELB.value not in created_objects
            assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1

            self.address_manager.remove_address(address)
            state = self.state_manager.get_state()
            created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
            # assert len(created_objects[AwsObjectTypes.ELB.value]) == 1
            assert AwsObjectTypes.ELB.value not in created_objects
            assert AwsObjectTypes.DNS_ENTRY.value not in created_objects
        finally:
            self.address_manager.clean_all()

    def test_hosted_zone_id_change(self):
        """ Test changing hosted zone id. """
        # TODO create some address in AwsAddressManager and then create new instance of AwsAddressManager with
        # different hosted_zone_id
        pass

    def test_miner_instance_id_change(self):
        """ Test changing Miner instance id. """
        # TODO create some address in AwsAddressManager and then create new instance of AwsAddressManager with
        # different miner_instance_id
        pass
