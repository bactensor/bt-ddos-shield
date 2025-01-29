import copy
from types import MappingProxyType

import pytest
from bt_ddos_shield.address import Address, AddressType
from bt_ddos_shield.address_manager import AbstractAddressManager, AwsAddressManager, AwsObjectTypes, \
    AwsShieldedServerData
from bt_ddos_shield.event_processor import PrintingMinerShieldEventProcessor
from bt_ddos_shield.state_manager import MinerShieldState
from bt_ddos_shield.utils import AWSClientFactory, Hotkey
from tests.test_state_manager import MemoryMinerShieldStateManager
from tests.conftest import ShieldTestSettings


def get_miner_address_from_credentials(address_type: AddressType, port: int, miner_instance_id: str = '',
                                       miner_instance_ip: str = '') -> Address:
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

    def create_aws_address_manager(self, test_settings: ShieldTestSettings, server_type: AddressType,
                                   create_state_manager: bool = True) -> AwsAddressManager:
        miner_address: Address = get_miner_address_from_credentials(
            server_type, test_settings.miner_instance_port, miner_instance_id=test_settings.aws_miner_instance_id,
            miner_instance_ip=test_settings.aws_miner_instance_ip
        )
        if create_state_manager:
            self.state_manager: MemoryMinerShieldStateManager = MemoryMinerShieldStateManager()
        aws_client_factory: AWSClientFactory = AWSClientFactory(test_settings.aws_access_key_id,
                                                                test_settings.aws_secret_access_key,
                                                                test_settings.aws_region_name)
        return AwsAddressManager(aws_client_factory=aws_client_factory, server_address=miner_address,
                                 hosted_zone_id=test_settings.aws_route53_hosted_zone_id,
                                 event_processor=PrintingMinerShieldEventProcessor(),
                                 state_manager=self.state_manager)

    @pytest.fixture
    def address_manager(self, shield_settings: ShieldTestSettings):
        manager = self.create_aws_address_manager(shield_settings, AddressType.EC2)
        yield manager
        manager.clean_all()

    def test_create_elb_for_ec2(self, shield_settings: ShieldTestSettings, address_manager: AwsAddressManager):
        """
        Test creating ELB by AwsAddressManager class when shielding EC2 instance.

        IMPORTANT: Test can run for many minutes due to AWS delays.
        """

        # This triggers creation of ELB
        address_manager.validate_addresses(MappingProxyType({}))

        state: MinerShieldState = self.state_manager.get_state()
        address_manager_state: MappingProxyType[str, str] = state.address_manager_state
        current_hosted_zone_id: str = address_manager_state[address_manager.HOSTED_ZONE_ID_STATE_KEY]
        assert current_hosted_zone_id == shield_settings.aws_route53_hosted_zone_id
        json_data: str = state.address_manager_state[address_manager.SHIELDED_SERVER_STATE_KEY]
        server_data = AwsShieldedServerData.from_json(json_data)
        assert server_data.aws_location.server_id == shield_settings.aws_miner_instance_id
        assert server_data.server_address.port == shield_settings.miner_instance_port
        created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
        assert len(created_objects[AwsObjectTypes.WAF.value]) == 1
        assert len(created_objects[AwsObjectTypes.ELB.value]) == 1
        assert AwsObjectTypes.VPC.value not in created_objects
        assert len(created_objects[AwsObjectTypes.SUBNET.value]) == 1
        assert len(created_objects[AwsObjectTypes.TARGET_GROUP.value]) == 1
        assert len(created_objects[AwsObjectTypes.SECURITY_GROUP.value]) == 1
        assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1

        reloaded_state: MinerShieldState = self.state_manager.get_state(reload=True)
        assert reloaded_state == state

        # Call clean_all and check if everything was removed
        address_manager.clean_all()
        state = self.state_manager.get_state()
        created_objects = state.address_manager_created_objects
        assert AwsObjectTypes.WAF.value not in created_objects
        assert AwsObjectTypes.ELB.value not in created_objects
        assert AwsObjectTypes.VPC.value not in created_objects
        assert AwsObjectTypes.SUBNET.value not in created_objects
        assert AwsObjectTypes.TARGET_GROUP.value not in created_objects
        assert AwsObjectTypes.SECURITY_GROUP.value not in created_objects
        assert AwsObjectTypes.DNS_ENTRY.value not in created_objects

    def test_create_elb_for_ip(self, shield_settings: ShieldTestSettings, address_manager: AwsAddressManager):
        """
        Test creating ELB by AwsAddressManager class when shielding some public IP address.

        IMPORTANT: Test can run for many minutes due to AWS delays.
        """

        # TODO: Hiding IP address doesn't work as for now. When implementing copy test_create_elb_for_ec2 and
        # change needed things.
        return

    def test_handle_address(self, address_manager: AwsAddressManager):
        """
        Create address, validate it and remove created address.

        IMPORTANT: Test can run for many minutes due to AWS delays.
        """
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
        assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1, "only wildcard DNS entry should be created"

        address_manager.remove_address(address1)
        state = self.state_manager.get_state()
        created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
        assert len(created_objects[AwsObjectTypes.ELB.value]) == 1
        assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1
        invalid_addresses = address_manager.validate_addresses(MappingProxyType(mapping))
        assert invalid_addresses == {Hotkey("hotkey1"), Hotkey("invalid")}

    def test_miner_instance_change(self, shield_settings: ShieldTestSettings, address_manager: AwsAddressManager):
        """
        Test changing Miner instance when initializing shield.

        IMPORTANT: Test can run for many minutes due to AWS delays.
        """
        address: Address = address_manager.create_address("validator1")
        hotkey: Hotkey = "hotkey"
        mapping: dict[Hotkey, Address] = {hotkey: address}
        invalid_addresses: set[Hotkey] = address_manager.validate_addresses(MappingProxyType(mapping))
        assert invalid_addresses == set()

        state: MinerShieldState = self.state_manager.get_state()
        created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
        assert len(created_objects[AwsObjectTypes.ELB.value]) == 1, "ELB should be created before adding address"
        elb_id: str = next(iter(created_objects[AwsObjectTypes.ELB.value]))
        hosted_zone_id: str = state.address_manager_state[address_manager.HOSTED_ZONE_ID_STATE_KEY]
        dns_entry_id: str = next(iter(created_objects[AwsObjectTypes.DNS_ENTRY.value]))

        # Create new manager with different port - ELB should be recreated
        new_test_settings: ShieldTestSettings = copy.deepcopy(shield_settings)
        new_test_settings.miner_instance_port += 1
        address_manager = self.create_aws_address_manager(new_test_settings, AddressType.EC2,
                                                          create_state_manager=False)
        invalid_addresses = address_manager.validate_addresses(MappingProxyType(mapping))
        assert invalid_addresses == {hotkey}

        state = self.state_manager.get_state()
        created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
        assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1
        assert len(created_objects[AwsObjectTypes.ELB.value]) == 1
        new_elb_id: str = next(iter(created_objects[AwsObjectTypes.ELB.value]))
        assert new_elb_id != elb_id
        new_hosted_zone_id: str = state.address_manager_state[address_manager.HOSTED_ZONE_ID_STATE_KEY]
        assert hosted_zone_id == new_hosted_zone_id
        new_dns_entry_id: str = next(iter(created_objects[AwsObjectTypes.DNS_ENTRY.value]))
        assert dns_entry_id == new_dns_entry_id

    def test_hosted_zone_id_change(self, shield_settings: ShieldTestSettings, address_manager: AwsAddressManager):
        """
        Test changing hosted zone id when initializing shield.

        IMPORTANT: Test can run for many minutes due to AWS delays.
        """
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
        hosted_zone_id: str = state.address_manager_state[address_manager.HOSTED_ZONE_ID_STATE_KEY]
        dns_entry_id: str = next(iter(created_objects[AwsObjectTypes.DNS_ENTRY.value]))

        try:
            # Create new manager with different hosted zone - only addresses should be removed
            new_test_settings: ShieldTestSettings = copy.deepcopy(shield_settings)
            new_test_settings.aws_route53_hosted_zone_id = shield_settings.aws_route53_other_hosted_zone_id
            address_manager = self.create_aws_address_manager(new_test_settings, AddressType.EC2,
                                                              create_state_manager=False)
            invalid_addresses = address_manager.validate_addresses(MappingProxyType(mapping))
            assert invalid_addresses == {hotkey}

            state = self.state_manager.get_state()
            created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
            assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1
            assert len(created_objects[AwsObjectTypes.ELB.value]) == 1
            new_elb_id: str = next(iter(created_objects[AwsObjectTypes.ELB.value]))
            assert new_elb_id == elb_id
            new_hosted_zone_id: str = state.address_manager_state[address_manager.HOSTED_ZONE_ID_STATE_KEY]
            assert hosted_zone_id != new_hosted_zone_id
            new_dns_entry_id: str = next(iter(created_objects[AwsObjectTypes.DNS_ENTRY.value]))
            assert dns_entry_id != new_dns_entry_id
        finally:
            address_manager.clean_all()  # Needed to remove created DNS entry in new hosted zone
