from __future__ import annotations

import copy
from types import MappingProxyType
from typing import TYPE_CHECKING

import pytest

from bt_ddos_shield.address_manager import (
    AbstractAddressManager,
    AwsAddressManager,
    AwsObjectTypes,
    AwsShieldedServerData,
    ShieldedServerLocation,
    ShieldedServerLocationType,
)
from bt_ddos_shield.event_processor import PrintingMinerShieldEventProcessor
from bt_ddos_shield.utils import AWSClientFactory, Hotkey, ShieldAddress
from tests.test_state_manager import MemoryMinerShieldStateManager

if TYPE_CHECKING:
    from bt_ddos_shield.state_manager import MinerShieldState
    from tests.conftest import ShieldTestSettings


def get_miner_location_from_credentials(
    location_type: ShieldedServerLocationType, test_settings: ShieldTestSettings
) -> ShieldedServerLocation:
    location_value: str
    if location_type == ShieldedServerLocationType.EC2_ID:
        location_value = test_settings.aws_miner_instance_id
    else:
        assert location_type == ShieldedServerLocationType.EC2_IP
        location_value = test_settings.aws_miner_instance_ip
    return ShieldedServerLocation(
        location_type=location_type, location_value=location_value, port=test_settings.miner_instance_port
    )


class MemoryAddressManager(AbstractAddressManager):
    id_counter: int
    known_addresses: dict[str, ShieldAddress]
    invalid_addresses: set[Hotkey]

    def __init__(self):
        self.id_counter = 0
        self.known_addresses = {}
        self.invalid_addresses = set()

    def clean_all(self):
        self.id_counter = 0
        self.known_addresses.clear()
        self.invalid_addresses.clear()

    def create_address(self, hotkey: Hotkey) -> ShieldAddress:
        address = ShieldAddress(
            address_id=str(self.id_counter),
            address=f'addr{self.id_counter}.com',
            port=80,
        )
        self.known_addresses[address.address_id] = address
        self.id_counter += 1
        return address

    def remove_address(self, address: ShieldAddress):
        self.known_addresses.pop(address.address_id, None)

    def validate_addresses(self, addresses: MappingProxyType[Hotkey, ShieldAddress]) -> set[Hotkey]:
        for hotkey in self.invalid_addresses:
            if hotkey in addresses:
                self.known_addresses.pop(addresses[hotkey].address_id, None)
        return self.invalid_addresses


class TestAddressManager:
    """
    Test suite for the address manager.
    """

    def create_aws_address_manager(
        self,
        test_settings: ShieldTestSettings,
        location_type: ShieldedServerLocationType,
        create_state_manager: bool = True,
    ) -> AwsAddressManager:
        miner_location: ShieldedServerLocation = get_miner_location_from_credentials(location_type, test_settings)
        if create_state_manager:
            self.state_manager: MemoryMinerShieldStateManager = MemoryMinerShieldStateManager()
        aws_client_factory: AWSClientFactory = AWSClientFactory(
            test_settings.aws_access_key_id, test_settings.aws_secret_access_key, test_settings.aws_region_name
        )
        return AwsAddressManager(
            aws_client_factory=aws_client_factory,
            server_location=miner_location,
            hosted_zone_id=test_settings.aws_route53_hosted_zone_id,
            event_processor=PrintingMinerShieldEventProcessor(),
            state_manager=self.state_manager,
        )

    @pytest.fixture
    def address_manager(self, shield_settings: ShieldTestSettings):
        manager = self.create_aws_address_manager(shield_settings, ShieldedServerLocationType.EC2_ID)
        yield manager
        manager.clean_all()

    def test_address_manager_creation(self, shield_settings: ShieldTestSettings):
        address_manager_for_ec2_id = self.create_aws_address_manager(shield_settings, ShieldedServerLocationType.EC2_ID)
        address_manager_for_ec2_ip = self.create_aws_address_manager(shield_settings, ShieldedServerLocationType.EC2_IP)
        assert address_manager_for_ec2_id.shielded_server_data == address_manager_for_ec2_ip.shielded_server_data, (
            'IP address should be resolved to instance ID'
        )

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
        assert server_data.aws_location and server_data.aws_location.server_id == shield_settings.aws_miner_instance_id
        assert server_data.server_location.port == shield_settings.miner_instance_port
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

    def test_handle_address(self, address_manager: AwsAddressManager):
        """
        Create address, validate it and remove created address.

        IMPORTANT: Test can run for many minutes due to AWS delays.
        """
        address1: ShieldAddress = address_manager.create_address('validator1')
        address2: ShieldAddress = address_manager.create_address('validator2')
        invalid_address: ShieldAddress = ShieldAddress(address_id='invalid', address='invalid.com', port=80)
        mapping: dict[Hotkey, ShieldAddress] = {'hotkey1': address1, 'hotkey2': address2, 'invalid': invalid_address}
        invalid_addresses: set[Hotkey] = address_manager.validate_addresses(MappingProxyType(mapping))
        assert invalid_addresses == {'invalid'}

        state: MinerShieldState = self.state_manager.get_state()
        created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
        assert len(created_objects[AwsObjectTypes.ELB.value]) == 1, 'ELB should be created before adding address'
        assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1, 'only wildcard DNS entry should be created'

        address_manager.remove_address(address1)
        state = self.state_manager.get_state()
        created_objects = state.address_manager_created_objects
        assert len(created_objects[AwsObjectTypes.ELB.value]) == 1
        assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1
        invalid_addresses = address_manager.validate_addresses(MappingProxyType(mapping))
        assert invalid_addresses == {'hotkey1', 'invalid'}

    def test_miner_instance_change(self, shield_settings: ShieldTestSettings, address_manager: AwsAddressManager):
        """
        Test changing Miner instance when initializing shield.

        IMPORTANT: Test can run for many minutes due to AWS delays.
        """
        address: ShieldAddress = address_manager.create_address('validator1')
        hotkey: Hotkey = 'hotkey'
        mapping: dict[Hotkey, ShieldAddress] = {hotkey: address}
        invalid_addresses: set[Hotkey] = address_manager.validate_addresses(MappingProxyType(mapping))
        assert invalid_addresses == set()

        state: MinerShieldState = self.state_manager.get_state()
        created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
        assert len(created_objects[AwsObjectTypes.ELB.value]) == 1, 'ELB should be created before adding address'
        elb_id: str = next(iter(created_objects[AwsObjectTypes.ELB.value]))
        hosted_zone_id: str = state.address_manager_state[address_manager.HOSTED_ZONE_ID_STATE_KEY]
        dns_entry_id: str = next(iter(created_objects[AwsObjectTypes.DNS_ENTRY.value]))

        # Create new manager with different port - ELB should be recreated
        new_test_settings: ShieldTestSettings = copy.deepcopy(shield_settings)
        new_test_settings.miner_instance_port += 1
        address_manager = self.create_aws_address_manager(
            new_test_settings, ShieldedServerLocationType.EC2_ID, create_state_manager=False
        )
        invalid_addresses = address_manager.validate_addresses(MappingProxyType(mapping))
        assert invalid_addresses == {hotkey}

        state = self.state_manager.get_state()
        created_objects = state.address_manager_created_objects
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
        address: ShieldAddress = address_manager.create_address('validator1')
        hotkey: Hotkey = 'hotkey'
        mapping: dict[Hotkey, ShieldAddress] = {hotkey: address}
        invalid_addresses: set[Hotkey] = address_manager.validate_addresses(MappingProxyType(mapping))
        assert invalid_addresses == set()

        state: MinerShieldState = self.state_manager.get_state()
        created_objects: MappingProxyType[str, frozenset[str]] = state.address_manager_created_objects
        assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1
        assert len(created_objects[AwsObjectTypes.ELB.value]) == 1, 'ELB should be created before adding address'
        elb_id: str = next(iter(created_objects[AwsObjectTypes.ELB.value]))
        hosted_zone_id: str = state.address_manager_state[address_manager.HOSTED_ZONE_ID_STATE_KEY]
        dns_entry_id: str = next(iter(created_objects[AwsObjectTypes.DNS_ENTRY.value]))

        try:
            # Create new manager with different hosted zone - only addresses should be removed
            new_test_settings: ShieldTestSettings = copy.deepcopy(shield_settings)
            new_test_settings.aws_route53_hosted_zone_id = shield_settings.aws_route53_other_hosted_zone_id
            address_manager = self.create_aws_address_manager(
                new_test_settings, ShieldedServerLocationType.EC2_ID, create_state_manager=False
            )
            invalid_addresses = address_manager.validate_addresses(MappingProxyType(mapping))
            assert invalid_addresses == {hotkey}

            state = self.state_manager.get_state()
            created_objects = state.address_manager_created_objects
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
