from types import MappingProxyType

from bt_ddos_shield.address import Address, AddressType
from bt_ddos_shield.address_manager import AbstractAddressManager, AwsAddressManager, AwsObjectTypes
from bt_ddos_shield.event_processor import PrintingMinerShieldEventProcessor
from bt_ddos_shield.state_manager import MinerShieldState
from bt_ddos_shield.utils import Hotkey, AWSClientFactory
from tests.test_credentials import aws_access_key_id, aws_secret_access_key, miner_instance_id, \
    miner_instance_ip, miner_instance_port, miner_region_name, aws_route53_hosted_zone_id, \
    aws_route53_other_hosted_zone_id
from tests.test_state_manager import MemoryMinerShieldStateManager


def get_miner_address_from_credentials(address_type: AddressType, port: int = miner_instance_port) -> Address:
    if address_type == AddressType.EC2:
        return Address(address_id="miner", address_type=AddressType.EC2, address=miner_instance_id,
                       port=port)
    elif address_type == AddressType.IP:
        return Address(address_id="miner", address_type=AddressType.IP, address=miner_instance_ip,
                       port=port)
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

    def create_aws_address_manager(self, port: int = miner_instance_port,
                                   hosted_zone_id: str = aws_route53_hosted_zone_id,
                                   create_state_manager: bool = True) -> AwsAddressManager:
        miner_address: Address = get_miner_address_from_credentials(AddressType.IP, port)
        if create_state_manager:
            self.state_manager: MemoryMinerShieldStateManager = MemoryMinerShieldStateManager()
        aws_client_factory: AWSClientFactory = AWSClientFactory(aws_access_key_id, aws_secret_access_key,
                                                                miner_region_name)
        return AwsAddressManager(aws_client_factory=aws_client_factory, miner_address=miner_address,
                                 hosted_zone_id=hosted_zone_id, event_processor=PrintingMinerShieldEventProcessor(),
                                 state_manager=self.state_manager)

    def test_create_elb(self):
        """ Test creating ELB by AwsAddressManager class. """
        address_manager: AwsAddressManager = self.create_aws_address_manager()

        try:
            # This triggers creation of ELB
            address_manager.validate_addresses(MappingProxyType({}))

            state: MinerShieldState = self.state_manager.get_state()
            address_manager_state: MappingProxyType[str, str] = state.address_manager_state
            assert address_manager_state[address_manager.HOSTED_ZONE_ID_KEY] == aws_route53_hosted_zone_id
            assert address_manager_state[address_manager.INSTANCE_ID_KEY] == miner_instance_id
            assert int(address_manager_state[address_manager.INSTANCE_PORT_KEY]) == miner_instance_port
            created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
            assert len(created_objects[AwsObjectTypes.WAF.value]) == 1
            assert len(created_objects[AwsObjectTypes.ELB.value]) == 1
            assert len(created_objects[AwsObjectTypes.SUBNET.value]) == 1
            assert len(created_objects[AwsObjectTypes.TARGET_GROUP.value]) == 1
            assert len(created_objects[AwsObjectTypes.SECURITY_GROUP.value]) == 1
            assert AwsObjectTypes.DNS_ENTRY.value not in created_objects

            reloaded_state: MinerShieldState = self.state_manager.get_state(reload=True)
            assert reloaded_state == state

            # Call clean_all and check if everything was removed
            address_manager.clean_all()
            state = self.state_manager.get_state()
            created_objects = state.address_manager_created_objects
            assert AwsObjectTypes.WAF.value not in created_objects
            assert AwsObjectTypes.ELB.value not in created_objects
            assert AwsObjectTypes.SUBNET.value not in created_objects
            assert AwsObjectTypes.TARGET_GROUP.value not in created_objects
            assert AwsObjectTypes.SECURITY_GROUP.value not in created_objects
            assert AwsObjectTypes.DNS_ENTRY.value not in created_objects
        finally:
            address_manager.clean_all()

    def test_handle_address(self):
        """ Create address, validate it and remove created address. """
        address_manager: AwsAddressManager = self.create_aws_address_manager()

        try:
            address1: Address = address_manager.create_address("validator1")
            address2: Address = address_manager.create_address("validator2")
            invalid_address: Address = Address(address_id="invalid", address_type=AddressType.DOMAIN,
                                               address="invalid.com", port=80)
            mapping: dict[Hotkey, Address] = {Hotkey("hotkey1"): address1,
                                              Hotkey("hotkey2"): address2,
                                              Hotkey("invalid"): invalid_address}
            invalid_addresses: set[Hotkey] = address_manager.validate_addresses(MappingProxyType(mapping))
            assert invalid_addresses == {Hotkey("invalid")}

            state: MinerShieldState = self.state_manager.get_state()
            created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
            assert len(created_objects[AwsObjectTypes.ELB.value]) == 1, "ELB should be created before adding address"
            assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 2

            address_manager.remove_address(address1)
            state = self.state_manager.get_state()
            created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
            assert len(created_objects[AwsObjectTypes.ELB.value]) == 1
            assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1
            invalid_addresses = address_manager.validate_addresses(MappingProxyType(mapping))
            assert invalid_addresses == {Hotkey("hotkey1"), Hotkey("invalid")}
        finally:
            address_manager.clean_all()

    def test_miner_instance_change(self):
        """ Test changing Miner instance when initializing shield. """
        address_manager: AwsAddressManager = self.create_aws_address_manager()
        try:
            address: Address = address_manager.create_address("validator1")
            hotkey: Hotkey = "hotkey"
            mapping: dict[Hotkey, Address] = {hotkey: address}
            invalid_addresses: set[Hotkey] = address_manager.validate_addresses(MappingProxyType(mapping))
            assert invalid_addresses == set()

            state: MinerShieldState = self.state_manager.get_state()
            created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
            assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1
            assert len(created_objects[AwsObjectTypes.ELB.value]) == 1, "ELB should be created before adding address"
            elb_id: str = next(iter(created_objects[AwsObjectTypes.ELB.value]))

            # Create new manager with different port - ELB should be recreated
            address_manager = self.create_aws_address_manager(port=miner_instance_port + 1, create_state_manager=False)
            invalid_addresses = address_manager.validate_addresses(MappingProxyType(mapping))
            assert invalid_addresses == {hotkey}

            state = self.state_manager.get_state()
            created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
            assert AwsObjectTypes.DNS_ENTRY.value not in created_objects, "DNS entry should be removed"
            assert len(created_objects[AwsObjectTypes.ELB.value]) == 1
            new_elb_id: str = next(iter(created_objects[AwsObjectTypes.ELB.value]))
            assert new_elb_id != elb_id
        finally:
            address_manager.clean_all()

    def test_hosted_zone_id_change(self):
        """ Test changing hosted zone id when initializing shield. """
        address_manager: AwsAddressManager = self.create_aws_address_manager()
        try:
            address: Address = address_manager.create_address("validator1")
            hotkey: Hotkey = "hotkey"
            mapping: dict[Hotkey, Address] = {hotkey: address}
            invalid_addresses: set[Hotkey] = address_manager.validate_addresses(MappingProxyType(mapping))
            assert invalid_addresses == set()

            state: MinerShieldState = self.state_manager.get_state()
            created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
            assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1
            assert len(created_objects[AwsObjectTypes.ELB.value]) == 1, "ELB should be created before adding address"
            elb_id: str = next(iter(created_objects[AwsObjectTypes.ELB.value]))

            # Create new manager with different hosted zone - only addresses should be removed
            address_manager = self.create_aws_address_manager(hosted_zone_id=aws_route53_other_hosted_zone_id,
                                                              create_state_manager=False)
            invalid_addresses = address_manager.validate_addresses(MappingProxyType(mapping))
            assert invalid_addresses == {hotkey}

            state = self.state_manager.get_state()
            created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
            assert AwsObjectTypes.DNS_ENTRY.value not in created_objects, "DNS entry should be removed"
            assert len(created_objects[AwsObjectTypes.ELB.value]) == 1
            new_elb_id: str = next(iter(created_objects[AwsObjectTypes.ELB.value]))
            assert new_elb_id == elb_id
        finally:
            address_manager.clean_all()
