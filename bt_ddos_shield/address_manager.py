import ipaddress
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Network, IPv6Network
from types import MappingProxyType
from typing import Any, Union

import boto3
import route53
from route53.connection import Route53Connection
from route53.hosted_zone import HostedZone
from route53.resource_record_set import NSResourceRecordSet

from bt_ddos_shield.address import Address, AddressType
from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor
from bt_ddos_shield.state_manager import AbstractMinerShieldStateManager, MinerShieldState
from bt_ddos_shield.utils import Hotkey


class AddressManagerException(Exception):
    pass


class AbstractAddressManager(ABC):
    """
    Abstract base class for manager handling public IP/domain addresses assigned to validators.
    """

    def hide_original_server(self):
        """
        If method is implemented, it should hide the original server IP address from public access.
        See auto_hide_original_server in MinerShield options.
        """
        pass

    @abstractmethod
    def clean_all(self):
        """
        Clean everything created before by the address manager.
        """
        pass

    @abstractmethod
    def create_address(self, hotkey: Hotkey) -> Address:
        """
        Create and return a new address redirecting to Miner server to be used by validator identified by hotkey.
        """
        pass

    @abstractmethod
    def remove_address(self, address: Address):
        pass

    @abstractmethod
    def validate_addresses(self, addresses: MappingProxyType[Hotkey, Address]) -> set[Hotkey]:
        """
        Validate if given addresses exist and are working properly.

        Args:
            addresses: Dictionary of addresses to validate (validator HotKey -> Address).

        Returns:
            set[Hotkey]: Set of HotKeys of validators with invalid addresses.
        """
        pass


@dataclass
class AwsEC2InstanceData:
    instance_id: str
    vpc_id: str
    subnet_id: str
    private_ip: str
    security_groups: list[str]


@dataclass
class AwsSubnetData:
    subnet_id: str
    availability_zone: str
    cidr_block: str


@dataclass
class AwsVpcData:
    vpc_id: str
    cidr_block: str
    subnets: list[AwsSubnetData]


class AwsObjectTypes(Enum):
    ELB = 'ELB'
    SUBNET = 'SUBNET'
    DNS_ENTRY = 'DNS_ENTRY'


class AwsAddressManager(AbstractAddressManager):
    """
    Address manager using AWS Route53 service to manage DNS records and ELB for handling access to Miner server.
    """

    miner_region_name: str
    """ AWS region name where miner server is located. """
    miner_instance_id: str
    """ ID of miner EC2 instance in AWS. All traffic will be redirected to this instance. """
    miner_instance: AwsEC2InstanceData
    miner_instance_port: int
    """ Port where miner server is working. """
    ec2_client: Any
    route53_client: Route53Connection
    hosted_zone_id: str
    """ ID of hosted zone in Route53 where addresses are located. """
    hosted_zone: HostedZone
    """ Hosted zone object. """
    hosted_zone_domain: str
    """ Domain for given hosted zone. """
    event_processor: AbstractMinerShieldEventProcessor
    state_manager: AbstractMinerShieldStateManager

    HOSTED_ZONE_ID_KEY: str = 'aws_hosted_zone_id'
    INSTANCE_ID_KEY: str = 'ec2_instance_id'

    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, hosted_zone_id: str,
                 miner_region_name: str, miner_instance_id: str, miner_instance_port: int,
                 event_processor: AbstractMinerShieldEventProcessor, state_manager: AbstractMinerShieldStateManager):
        self.miner_region_name = miner_region_name
        self.miner_instance_id = miner_instance_id
        self.miner_instance_port = miner_instance_port
        self.event_processor = event_processor
        self.state_manager = state_manager

        self.route53_client = route53.connect(aws_access_key_id, aws_secret_access_key)
        self.hosted_zone_id = hosted_zone_id
        self.hosted_zone = self.route53_client.get_hosted_zone_by_id(hosted_zone_id)
        self.hosted_zone_domain = self._get_hosted_zone_domain(self.hosted_zone)

        self.ec2_client = boto3.client('ec2', aws_access_key_id=aws_access_key_id,
                                       aws_secret_access_key=aws_secret_access_key, region_name=miner_region_name)
        self.miner_instance = self._get_ec2_instance_data(miner_instance_id)

    @classmethod
    def _get_hosted_zone_domain(cls, hosted_zone: HostedZone):
        for record_set in hosted_zone.record_sets:
            if isinstance(record_set, NSResourceRecordSet):
                return record_set.name
        else:
            # it shouldn't happen
            raise AddressManagerException('Hosted zone does not contain NS record set')

    def clean_all(self):
        self.clean_route53_addresses()

        created_objects: MappingProxyType[str, frozenset[str]] = \
            self.state_manager.get_state().address_manager_created_objects

        for object_type, created_objects_ids in created_objects.items():
            if object_type == AwsObjectTypes.SUBNET.value:
                for subnet_id in created_objects_ids:
                    self._remove_subnet(subnet_id)
            else:
                # DNS_ENTRY should be cleaned by clean_route53_addresses
                assert False, "Deletion of some object is not handled"

    def clean_route53_addresses(self):
        state: MinerShieldState = self.state_manager.get_state()
        hosted_zone_id: str = state.address_manager_state[self.HOSTED_ZONE_ID_KEY]
        if not hosted_zone_id or AwsObjectTypes.DNS_ENTRY.value not in state.address_manager_created_objects:
            return

        created_entries: frozenset[str] = state.address_manager_created_objects[AwsObjectTypes.DNS_ENTRY.value]
        hosted_zone = self.route53_client.get_hosted_zone_by_id(hosted_zone_id)
        for record_set in hosted_zone.record_sets:
            if record_set.name in created_entries:
                self._delete_route53_record(record_set, hosted_zone)

        # Clean from state entries without working address
        for created_entry in state.address_manager_created_objects[AwsObjectTypes.DNS_ENTRY.value]:
            self.state_manager.del_address_manager_created_object(AwsObjectTypes.DNS_ENTRY.value, created_entry)

    def create_address(self, hotkey: Hotkey) -> Address:
        self._validate_manager_state()

        # TODO below is old implementation pointing to IP - new one should create address pointing to ELB
        new_address_domain: str = f'{self._generate_subdomain(hotkey)}.{self.hosted_zone_domain}'
        self._add_route53_record(new_address_domain, self.hosted_zone)
        # There is no ID in Route53, so we use the domain name as an ID. Cut '.' from the end for working address.
        return Address(address_id=new_address_domain, address_type=AddressType.DOMAIN,
                       address=new_address_domain[:-1], port=self.miner_instance_port)

    @classmethod
    def _generate_subdomain(cls, hotkey: Hotkey) -> str:
        return f'{hotkey[:8]}_{secrets.token_urlsafe(16)}'.lower()

    def remove_address(self, address: Address):
        self._validate_manager_state()

        # TODO handle removing in ELB
        self._delete_route53_record_by_id(address.address_id, self.hosted_zone)

    def validate_addresses(self, addresses: MappingProxyType[Hotkey, Address]) -> set[Hotkey]:
        # TODO handle change of miner_instance_port
        if self._validate_manager_state():
            return {hotkey for hotkey, _ in addresses.items()}

        if not addresses:
            return set()

        # TODO validate addresses also in ELB
        zone_addresses_ids: set[str] = {record_set.name for record_set in self.hosted_zone.record_sets}
        invalid_hotkeys: set[Hotkey] = {hotkey for hotkey, address in addresses.items()
                                        if address.address_id not in zone_addresses_ids}
        return invalid_hotkeys

    def _validate_manager_state(self) -> bool:
        """ Returns if we should invalidate all addresses created before. """
        ret: bool = self._handle_instance_id_change()
        ret = self._handle_hosted_zone_change() or ret
        ret = self._create_elb_if_needed(self.miner_instance, self.miner_instance_port) or ret
        return ret

    def _handle_instance_id_change(self) -> bool:
        state: MinerShieldState = self.state_manager.get_state()
        if self.INSTANCE_ID_KEY in state.address_manager_state:
            if state.address_manager_state[self.INSTANCE_ID_KEY] == self.miner_instance_id:
                return False
            else:
                # If instance ID changed, we need to recreate ELB
                self.event_processor.event('Shielded EC2 instance ID changed from {old_id} to {new_id}',
                                           old_id=state.address_manager_state[self.INSTANCE_ID_KEY],
                                           new_id=self.miner_instance_id)
                self.clean_all()
                self.state_manager.update_address_manager_state(self.INSTANCE_ID_KEY, self.miner_instance_id)
                return True
        else:
            self.state_manager.update_address_manager_state(self.INSTANCE_ID_KEY, self.miner_instance_id)
            return False

    def _handle_hosted_zone_change(self) -> bool:
        state: MinerShieldState = self.state_manager.get_state()
        if self.HOSTED_ZONE_ID_KEY in state.address_manager_state:
            if state.address_manager_state[self.HOSTED_ZONE_ID_KEY] == self.hosted_zone_id:
                return False
            else:
                # If hosted zone changed, we need to clean all previous route53 addresses
                self.event_processor.event('Route53 hosted zone changed from {old_id} to {new_id}',
                                           old_id=state.address_manager_state[self.HOSTED_ZONE_ID_KEY],
                                           new_id=self.hosted_zone_id)
                self.clean_route53_addresses()
                self.state_manager.update_address_manager_state(self.HOSTED_ZONE_ID_KEY, self.hosted_zone_id)
                return True
        else:
            self.state_manager.update_address_manager_state(self.HOSTED_ZONE_ID_KEY, self.hosted_zone_id)
            return False

    def _get_ec2_instance_data(self, instance_id: str) -> AwsEC2InstanceData:
        response: dict[str, Any] = self.ec2_client.describe_instances(InstanceIds=[instance_id])
        instance_data: dict[str, Any] = response['Reservations'][0]['Instances'][0]
        return AwsEC2InstanceData(instance_id=instance_id, vpc_id=instance_data['VpcId'],
                                  subnet_id=instance_data['SubnetId'], private_ip=instance_data['PrivateIpAddress'],
                                  security_groups=instance_data['SecurityGroups'])

    def _get_vpc_data(self, vpc_id: str) -> AwsVpcData:
        response: dict[str, Any] = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])
        vpc_data: dict[str, Any] = response['Vpcs'][0]
        cidr_block: str = vpc_data['CidrBlock']

        response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        subnets: list[AwsSubnetData] = [AwsSubnetData(subnet_id=subnet['SubnetId'],
                                                      availability_zone=subnet['AvailabilityZone'],
                                                      cidr_block=subnet['CidrBlock'])
                                        for subnet in response['Subnets']]
        return AwsVpcData(vpc_id=vpc_id, cidr_block=cidr_block, subnets=subnets)

    def _get_subnet_data(self, subnet_id: str) -> AwsSubnetData:
        response: dict[str, Any] = self.ec2_client.describe_subnets(SubnetIds=[subnet_id])
        subnet_data: dict[str, Any] = response['Subnets'][0]
        return AwsSubnetData(subnet_id=subnet_id, availability_zone=subnet_data['AvailabilityZone'],
                             cidr_block=subnet_data['CidrBlock'])

    def _add_route53_record(self, record_id: str, hosted_zone):
        self.hosted_zone.create_a_record(name=record_id, values=[self.miner_instance.private_ip])
        self.event_processor.event('Added Route53 record {name} to hosted zone {zone_id}',
                                   name=record_id, zone_id=hosted_zone.id)
        try:
            self.state_manager.add_address_manager_created_object(AwsObjectTypes.DNS_ENTRY.value, record_id)
        except Exception as e:
            self._delete_route53_record_by_id(record_id, hosted_zone)
            raise e

    def _delete_route53_record_by_id(self, record_id: str, hosted_zone):
        for record_set in self.hosted_zone.record_sets:
            if record_set.name == record_id:
                self._delete_route53_record(record_set, hosted_zone)
                return

    def _delete_route53_record(self, record_set, hosted_zone):
        record_set.delete()
        self.event_processor.event('Deleted Route53 record {name} from hosted zone {zone_id}',
                                   name=record_set.name, zone_id=hosted_zone.id)
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.DNS_ENTRY.value, record_set.name)

    def _create_subnet(self, vpc_id: str, cidr_block: str, availability_zone: str) -> AwsSubnetData:
        response: dict[str, Any] = self.ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=cidr_block,
                                                                 AvailabilityZone=availability_zone)
        subnet = AwsSubnetData(subnet_id=response['Subnet']['SubnetId'], availability_zone=availability_zone,
                               cidr_block=cidr_block)
        self.event_processor.event('Created AWS subnet {id} with cidr={cidr} in {az} availability zone',
                                   id=subnet.subnet_id, cidr=subnet.cidr_block, az=subnet.availability_zone)
        try:
            self.state_manager.add_address_manager_created_object(AwsObjectTypes.SUBNET.value, subnet.subnet_id)
        except Exception as e:
            self._remove_subnet(subnet.subnet_id)
            raise e
        return subnet

    def _remove_subnet(self, subnet_id: str):
        self.ec2_client.delete_subnet(SubnetId=subnet_id)
        self.event_processor.event('Deleted AWS subnet {id}', id=subnet_id)
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.SUBNET.value, subnet_id)

    @classmethod
    def _get_available_cidr(cls, vpc: AwsVpcData, subnet_mask: int) -> str:
        vpc_network: Union[IPv4Network, IPv6Network] = ipaddress.ip_network(vpc.cidr_block)
        subnets_cidrs: list[str] = [subnet.cidr_block for subnet in vpc.subnets]

        # Find the first available subnet that does not overlap with existing subnets
        for subnet in vpc_network.subnets(new_prefix=subnet_mask):
            if not any(ipaddress.ip_network(used_cidr).overlaps(subnet) for used_cidr in subnets_cidrs):
                return str(subnet)

        raise AddressManagerException('No available CIDR block found for the new subnet')

    def _create_bonus_subnet_if_needed(self, miner_vpc: AwsVpcData, miner_subnet: AwsSubnetData,
                                       created_objects: MappingProxyType[str, frozenset[str]]) -> AwsSubnetData:
        if AwsObjectTypes.SUBNET.value in created_objects:
            assert len(created_objects[AwsObjectTypes.SUBNET.value]) == 1, "only one subnet should be created"
            bonus_subnet_id = next(iter(created_objects[AwsObjectTypes.SUBNET.value]))
            return self._get_subnet_data(bonus_subnet_id)

        bonus_subnet_availability_zone: str
        for subnet in miner_vpc.subnets:
            if subnet.availability_zone != miner_subnet.availability_zone:
                bonus_subnet_availability_zone = subnet.availability_zone
                break
        else:
            raise AddressManagerException("Miner instance VPC doesn't have subnet in different availability zone")

        # Create new subnet in the same VPC as miner instance, because ELB needs at least two subnets in different AZs
        min_elb_subnet_mask: int = 27  # 27 as specified in documentation
        bonus_subnet_cidr: str = self._get_available_cidr(miner_vpc, min_elb_subnet_mask)
        bonus_subnet: AwsSubnetData = self._create_subnet(miner_vpc.vpc_id, bonus_subnet_cidr,
                                                          bonus_subnet_availability_zone)
        return bonus_subnet

    def _create_elb_if_needed(self, miner_instance: AwsEC2InstanceData, miner_port: int):
        miner_vpc: AwsVpcData = self._get_vpc_data(miner_instance.vpc_id)
        miner_subnet: AwsSubnetData = self._get_subnet_data(miner_instance.subnet_id)
        created_objects: MappingProxyType[str, frozenset[str]] = \
            self.state_manager.get_state().address_manager_created_objects

        bonus_subnet: AwsSubnetData = self._create_bonus_subnet_if_needed(miner_vpc, miner_subnet, created_objects)

        # TODO create ELB
        pass
