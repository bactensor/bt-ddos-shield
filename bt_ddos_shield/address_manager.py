import ipaddress
import secrets
import string
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Network, IPv6Network
from types import MappingProxyType
from typing import Any, Union, Optional, Callable

import boto3
import route53
from botocore.exceptions import ClientError
from route53.connection import Route53Connection
from route53.hosted_zone import HostedZone
from route53.resource_record_set import ResourceRecordSet

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
    security_groups: list[dict[str, str]]


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


@dataclass
class AwsELBData:
    id: str
    dns_name: str
    hosted_zone_id: str


class AwsObjectTypes(Enum):
    WAF = 'WAF'
    ELB = 'ELB'
    SUBNET = 'SUBNET'
    DNS_ENTRY = 'DNS_ENTRY'
    TARGET_GROUP = 'TARGET_GROUP'
    SECURITY_GROUP = 'SECURITY_GROUP'


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
    waf_client: Any
    waf_arn: Optional[str]
    elb_client: Any
    elb_data: Optional[AwsELBData]
    ec2_client: Any
    hosted_zone_id: str
    """ ID of hosted zone in Route53 where addresses are located. """
    hosted_zone: HostedZone
    route53_client: Route53Connection
    route53_boto_client: Any
    event_processor: AbstractMinerShieldEventProcessor
    state_manager: AbstractMinerShieldStateManager

    HOSTED_ZONE_ID_KEY: str = 'aws_hosted_zone_id'
    INSTANCE_PORT_KEY: str = 'ec2_instance_port'
    INSTANCE_ID_KEY: str = 'ec2_instance_id'

    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, miner_region_name: str,
                 miner_address: Address, hosted_zone_id: str, event_processor: AbstractMinerShieldEventProcessor,
                 state_manager: AbstractMinerShieldStateManager):
        """
        Initialize AWS address manager. miner_address can be passed as EC2 type (then AWS instance_id should be set in
        address field) or as IP/IPV6 (then we try to find EC2 instance with this IP, which should be private IP
        address of EC2 instance) - where port means destination port and address_id is ignored.
        """
        self.miner_region_name = miner_region_name
        self.event_processor = event_processor
        self.state_manager = state_manager

        self.waf_client = boto3.client('wafv2', aws_access_key_id=aws_access_key_id,
                                       aws_secret_access_key=aws_secret_access_key, region_name=miner_region_name)
        self.waf_arn = None
        self.elb_client = boto3.client('elbv2', aws_access_key_id=aws_access_key_id,
                                       aws_secret_access_key=aws_secret_access_key, region_name=miner_region_name)
        self.elb_data = None
        self.route53_client = route53.connect(aws_access_key_id, aws_secret_access_key)
        self.hosted_zone_id = hosted_zone_id
        self.hosted_zone = self.route53_client.get_hosted_zone_by_id(hosted_zone_id)
        self.route53_boto_client = boto3.client('route53', aws_access_key_id=aws_access_key_id,
                                                aws_secret_access_key=aws_secret_access_key)
        self.ec2_client = boto3.client('ec2', aws_access_key_id=aws_access_key_id,
                                       aws_secret_access_key=aws_secret_access_key, region_name=miner_region_name)
        self._initialize_miner_instance(miner_address)

    def _initialize_miner_instance(self, miner_address: Address):
        if miner_address.address_type == AddressType.EC2:
            self.miner_instance_id = miner_address.address
        elif miner_address.address_type in (AddressType.IP, AddressType.IPV6):
            if miner_address.address_type == AddressType.IPV6:
                # TODO implement IPv6 support
                raise AddressManagerException('IPv6 is not yet supported')
            self.miner_instance_id = self._find_ec2_instance_id_by_ip(miner_address.address)
        else:
            raise AddressManagerException('Miner address should be of type EC2 or IP')
        self.miner_instance = self._get_ec2_instance_data(self.miner_instance_id)
        self.miner_instance_port = miner_address.port

    def _find_ec2_instance_id_by_ip(self, ip_address: str) -> str:
        response: dict[str, Any] = self.ec2_client.describe_instances(Filters=[{'Name': 'private-ip-address',
                                                                                'Values': [ip_address]}])
        if not response['Reservations']:
            raise AddressManagerException(f'No EC2 instance found with private IP address {ip_address}')
        return response['Reservations'][0]['Instances'][0]['InstanceId']

    def clean_all(self):
        created_objects: MappingProxyType[str, frozenset[str]] = \
            self.state_manager.get_state().address_manager_created_objects

        self._delete_route53_records(self.hosted_zone_id)

        # Order of removal is important
        cleaned: bool = True
        cleaned = self._clean_aws_objects(created_objects, AwsObjectTypes.WAF,
                                          self._remove_firewall) and cleaned
        cleaned = self._clean_aws_objects(created_objects, AwsObjectTypes.ELB,
                                          self._remove_elb) and cleaned
        cleaned = self._clean_aws_objects(created_objects, AwsObjectTypes.SECURITY_GROUP,
                                          self._remove_security_group) and cleaned
        cleaned = self._clean_aws_objects(created_objects, AwsObjectTypes.TARGET_GROUP,
                                          self._remove_target_group) and cleaned
        cleaned = self._clean_aws_objects(created_objects, AwsObjectTypes.SUBNET,
                                          self._remove_subnet) and cleaned
        if not cleaned:
            raise AddressManagerException('Failed to clean all AWS objects')

    @classmethod
    def _clean_aws_objects(cls, created_objects: MappingProxyType[str, frozenset[str]], object_type: AwsObjectTypes,
                           remove_method: Callable[[str], bool]) -> bool:
        if object_type.value not in created_objects:
            return True
        cleaned: bool = True
        for object_id in created_objects[object_type.value]:
            cleaned = remove_method(object_id) and cleaned
        return cleaned

    def create_address(self, hotkey: Hotkey) -> Address:
        self._validate_manager_state()

        new_address_domain_id: str = f'{self._generate_subdomain(hotkey)}.{self.hosted_zone.name}'
        new_address_domain: str = new_address_domain_id[:-1]  # Cut '.' from the end for working address
        record_id: str = self._add_route53_record(new_address_domain_id, self.hosted_zone)

        try:
            self._add_domain_rule_to_firewall(self.waf_arn, new_address_domain)
        except Exception as e:
            self._delete_route53_record_by_id(record_id, self.hosted_zone)
            raise e

        return Address(address_id=record_id, address_type=AddressType.DOMAIN,
                       address=new_address_domain, port=self.miner_instance_port)

    @classmethod
    def _generate_subdomain(cls, hotkey: Hotkey) -> str:
        return f'{hotkey[:8]}_{secrets.token_urlsafe(16)}'.lower()

    def remove_address(self, address: Address):
        self._validate_manager_state()
        self._remove_domain_rule_from_firewall(self.waf_arn, address.address)
        self._delete_route53_record_by_id(address.address_id, self.hosted_zone)

    def validate_addresses(self, addresses: MappingProxyType[Hotkey, Address]) -> set[Hotkey]:
        if self._validate_manager_state():
            return {hotkey for hotkey, _ in addresses.items()}

        if not addresses:
            return set()

        zone_addresses_ids: set[str] = {record_set.name for record_set in self.hosted_zone.record_sets}
        waf_data: dict[str, Any] = self._get_firewall_info(self.waf_arn)
        rules: list[dict[str, Any]] = waf_data['WebACL']['Rules']

        invalid_hotkeys: set[Hotkey] = set()
        for hotkey, address in addresses.items():
            if address.address_id not in zone_addresses_ids:
                invalid_hotkeys.add(hotkey)
                continue

            rule: Optional[dict[str, Any]] = self._find_rule(rules, address.address)
            if rule is None:
                invalid_hotkeys.add(hotkey)
        return invalid_hotkeys

    def _validate_manager_state(self) -> bool:
        """ Returns if we should invalidate all addresses created before. """
        ret: bool = self._handle_shielded_instance_change()
        ret = self._handle_hosted_zone_change() or ret
        self.elb_data = self._create_elb_if_needed(self.miner_instance, self.miner_instance_port)
        self.waf_arn = self._create_firewall_if_needed()
        return ret

    def _handle_shielded_instance_change(self) -> bool:
        state: MinerShieldState = self.state_manager.get_state()

        id_changed: bool = False
        old_id: Optional[str] = None
        if self.INSTANCE_ID_KEY in state.address_manager_state:
            old_id = state.address_manager_state[self.INSTANCE_ID_KEY]
            if old_id != self.miner_instance_id:
                id_changed = True
        else:
            id_changed = True

        port_changed: bool = False
        old_port: Optional[int] = None
        if self.INSTANCE_PORT_KEY in state.address_manager_state:
            old_port = int(state.address_manager_state[self.INSTANCE_PORT_KEY])
            if old_port != self.miner_instance_port:
                port_changed = True
        else:
            port_changed = True

        recreate_needed: bool = id_changed or port_changed
        if recreate_needed:
            # If shielded instance ID or port changed, we need to recreate ELB. Maybe we can try to change only
            # needed objects, but changing ELB is the easiest way and this operation should happen rarely.
            self.event_processor.event('Shielded EC2 instance ID changed from {old_id}:{old_port} to '
                                       '{new_id}:{new_port}', old_id=old_id, old_port=old_port,
                                       new_id=self.miner_instance_id, new_port=self.miner_instance_port)
            self.clean_all()

        if id_changed:
            self.state_manager.update_address_manager_state(self.INSTANCE_ID_KEY, self.miner_instance_id)
        if port_changed:
            self.state_manager.update_address_manager_state(self.INSTANCE_PORT_KEY, str(self.miner_instance_port))

        return recreate_needed

    def _handle_hosted_zone_change(self) -> bool:
        state: MinerShieldState = self.state_manager.get_state()
        zone_changed: bool = False
        if self.HOSTED_ZONE_ID_KEY in state.address_manager_state:
            old_zone_id: str = state.address_manager_state[self.HOSTED_ZONE_ID_KEY]
            if old_zone_id != self.hosted_zone_id:
                # If hosted zone changed, we need to clean all previous route53 addresses
                self.event_processor.event('Route53 hosted zone changed from {old_id} to {new_id}',
                                           old_id=old_zone_id,
                                           new_id=self.hosted_zone_id)
                self._delete_route53_records(old_zone_id)
                zone_changed = True
        else:
            zone_changed = True

        if zone_changed:
            self.state_manager.update_address_manager_state(self.HOSTED_ZONE_ID_KEY, self.hosted_zone_id)
        return zone_changed

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

    def _add_route53_record(self, record_id: str, hosted_zone: HostedZone) -> str:
        # Route53Connection doesn't handle alias records properly, so we use boto3 client directly
        self.route53_boto_client.change_resource_record_sets(
            HostedZoneId=hosted_zone.id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'CREATE',
                        'ResourceRecordSet': {
                            'Name': record_id,
                            'Type': 'A',
                            'AliasTarget': {
                                'HostedZoneId': self.elb_data.hosted_zone_id,
                                'DNSName': self.elb_data.dns_name,
                                'EvaluateTargetHealth': False
                            }
                        }
                    }
                ]
            }
        )
        self.event_processor.event('Added Route53 record {name} to hosted zone {zone_id}',
                                   name=record_id, zone_id=hosted_zone.id)
        try:
            self.state_manager.add_address_manager_created_object(AwsObjectTypes.DNS_ENTRY.value, record_id)
        except Exception as e:
            self._delete_route53_record_by_id(record_id, hosted_zone)
            raise e

        # There is no ID for Route53 addresses, so we use domain name as an ID.
        return record_id

    def _delete_route53_record_by_id(self, record_id: str, hosted_zone: HostedZone):
        for record_set in hosted_zone.record_sets:
            if record_set.name == record_id:
                self._delete_route53_record(record_set, hosted_zone)
                return

    def _delete_route53_record(self, record_set: ResourceRecordSet, hosted_zone: HostedZone):
        # Route53Connection doesn't handle alias records properly, so we use boto3 client directly
        response: dict[str, Any] = self.route53_boto_client.list_resource_record_sets(
            HostedZoneId=hosted_zone.id,
            StartRecordName=record_set.name,
            StartRecordType=record_set.rrset_type,
            MaxItems='1'
        )
        record_set_data: dict[str, Any] = response['ResourceRecordSets'][0]

        self.route53_boto_client.change_resource_record_sets(
            HostedZoneId=hosted_zone.id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': record_set_data
                    }
                ]
            }
        )
        self.event_processor.event('Deleted Route53 record {name} from hosted zone {zone_id}',
                                   name=record_set.name, zone_id=hosted_zone.id)
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.DNS_ENTRY.value, record_set.name)

    @classmethod
    def _generate_random_alnum_string(cls, length: int) -> str:
        characters = string.ascii_letters + string.digits
        return ''.join(secrets.choice(characters) for _ in range(length))

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

    def _remove_subnet(self, subnet_id: str) -> bool:
        self.ec2_client.delete_subnet(SubnetId=subnet_id)
        self.event_processor.event('Deleted AWS subnet {id}', id=subnet_id)
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.SUBNET.value, subnet_id)
        return True

    def _create_target_group(self, miner_vpc: AwsVpcData, miner_instance_id: str, miner_instance_port: int) -> str:
        group_name: str = f'miner-target-group-{self._generate_random_alnum_string(8)}'
        # Health check can't be disabled, when targeting instance - as for now we use traffic-port
        response: dict[str, Any] = self.elb_client.create_target_group(Name=group_name, Protocol='HTTP',
                                                                       Port=miner_instance_port, VpcId=miner_vpc.vpc_id,
                                                                       HealthCheckPort='traffic-port',
                                                                       TargetType='instance')
        target_group_id: str = response['TargetGroups'][0]['TargetGroupArn']
        self.event_processor.event('Created AWS TargetGroup, name={name}, id={id}',
                                   name=group_name, id=target_group_id)

        try:
            self.elb_client.register_targets(TargetGroupArn=target_group_id, Targets=[{'Id': miner_instance_id,
                                                                                       'Port': miner_instance_port}])
            self.state_manager.add_address_manager_created_object(AwsObjectTypes.TARGET_GROUP.value, target_group_id)
        except Exception as e:
            self._remove_target_group(target_group_id)
            raise e

        return target_group_id

    def _remove_target_group(self, target_group_id: str) -> bool:
        old_instance_id: str = self.state_manager.get_state().address_manager_state[self.INSTANCE_ID_KEY]
        self.elb_client.deregister_targets(TargetGroupArn=target_group_id, Targets=[{'Id': old_instance_id}])

        retries_count: int = 20
        error_code: str = ''
        for _ in range(retries_count):
            try:
                self.elb_client.delete_target_group(TargetGroupArn=target_group_id)
                break
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceInUse':
                    time.sleep(6)  # wait for target group to be deregistered
                else:
                    raise e
        else:
            # It happens quite often and sometimes AWS waits for many minutes before allowing to remove target group.
            # But we don't want to wait for so long - 2 minutes is long enough.
            # If it happens during tests, user should remove target group later manually using AWS panel to not leave
            # unneeded objects in AWS.
            self.event_processor.event('Failed to remove AWS TargetGroup {id}, error={error_code}',
                                       id=target_group_id, error_code=error_code)
            return False

        self.event_processor.event('Deleted AWS TargetGroup {id}', id=target_group_id)
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.TARGET_GROUP.value, target_group_id)
        return True

    def _create_elb(self, miner_instance: AwsEC2InstanceData, bonus_subnet: AwsSubnetData, target_group_id: str,
                    security_group_id: str) -> str:
        elb_name: str = f'miner-elb-{self._generate_random_alnum_string(8)}'
        subnets: list[str] = [miner_instance.subnet_id, bonus_subnet.subnet_id]
        response: dict[str, Any] = self.elb_client.create_load_balancer(Name=elb_name, Subnets=subnets,
                                                                        SecurityGroups=[security_group_id],
                                                                        Scheme='internet-facing', Type='application')
        elb_info: dict[str, Any] = response['LoadBalancers'][0]
        elb_id: str = elb_info['LoadBalancerArn']
        self.event_processor.event('Created AWS ELB, name={name}, id={id}', name=elb_name, id=elb_id)

        try:
            self.elb_client.create_listener(LoadBalancerArn=elb_id, Protocol='HTTP', Port=80,
                                            DefaultActions=[{'Type': 'forward', 'TargetGroupArn': target_group_id}])
            self.state_manager.add_address_manager_created_object(AwsObjectTypes.ELB.value, elb_id)
        except Exception as e:
            self._remove_elb(elb_id)
            raise e

        return elb_id

    def _remove_elb(self, elb_id: str) -> bool:
        self.elb_client.delete_load_balancer(LoadBalancerArn=elb_id)
        self.event_processor.event('Deleted AWS ELB {id}', id=elb_id)
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.ELB.value, elb_id)
        return True

    def _get_elb_info(self, elb_id: str) -> AwsELBData:
        response: dict[str, Any] = self.elb_client.describe_load_balancers(LoadBalancerArns=[elb_id])
        elb_info: dict[str, Any] = response['LoadBalancers'][0]
        return AwsELBData(id=elb_info['LoadBalancerArn'], dns_name=elb_info['DNSName'],
                          hosted_zone_id=elb_info['CanonicalHostedZoneId'])

    def _create_security_group(self, miner_vpc: AwsVpcData, miner_instance_port: int) -> str:
        group_name: str = f'miner-security-group-{self._generate_random_alnum_string(8)}'
        response: dict[str, Any] = \
            self.ec2_client.create_security_group(GroupName=group_name,
                                                  Description='Security group for miner instance',
                                                  VpcId=miner_vpc.vpc_id)
        security_group_id: str = response['GroupId']
        self.event_processor.event('Created AWS SecurityGroup, name={name}, id={id}',
                                   name=group_name, id=security_group_id)

        try:
            self.ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[{
                    'FromPort': 80, 'ToPort': miner_instance_port, 'IpProtocol': 'tcp',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )
            self.state_manager.add_address_manager_created_object(AwsObjectTypes.SECURITY_GROUP.value,
                                                                  security_group_id)
        except Exception as e:
            self._remove_security_group(security_group_id)
            raise e

        return security_group_id

    def _remove_security_group(self, security_group_id: str) -> bool:
        retries_count: int = 10
        error_code: str = ''
        for _ in range(retries_count):
            try:
                self.ec2_client.delete_security_group(GroupId=security_group_id)
                break
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'DependencyViolation':
                    time.sleep(6)  # wait for ELB to be removed
                else:
                    raise e
        else:
            self.event_processor.event('Failed to remove AWS SecurityGroup {id}, error={error_code}',
                                       id=security_group_id, error_code=error_code)
            return False

        self.event_processor.event('Deleted AWS SecurityGroup {id}', id=security_group_id)
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.SECURITY_GROUP.value, security_group_id)
        return True

    def _delete_route53_records(self, hosted_zone_id: str):
        address_manager_created_objects: MappingProxyType[str, frozenset[str]] = \
            self.state_manager.get_state().address_manager_created_objects
        if AwsObjectTypes.DNS_ENTRY.value not in address_manager_created_objects:
            return

        created_entries: frozenset[str] = \
            self.state_manager.get_state().address_manager_created_objects[AwsObjectTypes.DNS_ENTRY.value]
        hosted_zone = self.route53_client.get_hosted_zone_by_id(hosted_zone_id)
        for record_set in hosted_zone.record_sets:
            if record_set.name in created_entries:
                self._delete_route53_record(record_set, hosted_zone)

        # Clean from state entries without working address
        address_manager_created_objects = self.state_manager.get_state().address_manager_created_objects
        if AwsObjectTypes.DNS_ENTRY.value not in address_manager_created_objects:
            return
        for created_entry in address_manager_created_objects[AwsObjectTypes.DNS_ENTRY.value]:
            self.state_manager.del_address_manager_created_object(AwsObjectTypes.DNS_ENTRY.value, created_entry)

    def _create_firewall(self) -> str:
        waf_name: str = f'miner-waf-{self._generate_random_alnum_string(8)}'
        response: dict[str, Any] = self.waf_client.create_web_acl(
            Name=waf_name,
            Scope='REGIONAL',
            DefaultAction={'Block': {}},
            Rules=[],
            VisibilityConfig={
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': waf_name
            })
        waf_arn: str = response['Summary']['ARN']
        self.event_processor.event('Created AWS WAF, name={name}, id={id}', name=waf_name, id=waf_arn)

        retries_count: int = 10
        error_code: str = ''
        for _ in range(retries_count):
            try:
                self.waf_client.associate_web_acl(WebACLArn=waf_arn, ResourceArn=self.elb_data.id)
                self.event_processor.event('Associated AWS WAF {waf_id} to ELB {elb_id}',
                                           waf_id=waf_arn, elb_id=self.elb_data.id)
                break
            except ClientError as e:
                error_code = e.response['Error']['Code']
                time.sleep(6)  # wait for WAF to be created
        else:
            self._remove_firewall(waf_arn)
            raise AddressManagerException(f'Failed to associate AWS WAF {waf_arn} with ELB, error={error_code}')

        try:
            self.state_manager.add_address_manager_created_object(AwsObjectTypes.WAF.value, waf_arn)
        except Exception as e:
            self._remove_firewall(waf_arn)
            raise e

        return waf_arn

    def _remove_firewall(self, waf_arn: str) -> bool:
        created_objects: MappingProxyType[str, frozenset[str]] = \
            self.state_manager.get_state().address_manager_created_objects

        if AwsObjectTypes.ELB.value in created_objects:
            assert len(created_objects[AwsObjectTypes.ELB.value]) == 1, "only one ELB should be created"
            elb_id: str = next(iter(created_objects[AwsObjectTypes.ELB.value]))
            self.waf_client.disassociate_web_acl(ResourceArn=elb_id)

        waf_data: dict[str, Any] = self._get_firewall_info(waf_arn)
        acl_data: dict[str, Any] = waf_data['WebACL']
        lock_token = waf_data['LockToken']
        self.waf_client.delete_web_acl(Name=acl_data['Name'], Id=acl_data['Id'], Scope='REGIONAL', LockToken=lock_token)
        self.event_processor.event('Deleted AWS WAF {id}', id=waf_arn)
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.WAF.value, waf_arn)
        return True

    def _get_firewall_info(self, waf_arn: str) -> dict[str, Any]:
        waf_name: str = self._get_name_from_waf_arn(waf_arn)
        waf_id: str = self._get_id_from_waf_arn(waf_arn)
        return self.waf_client.get_web_acl(Name=waf_name, Id=waf_id, Scope='REGIONAL')

    def _update_web_acl(self, waf_data: dict[str, Any], rules: list[dict[str, Any]]):
        acl_data: dict[str, Any] = waf_data['WebACL']
        lock_token = waf_data['LockToken']
        self.waf_client.update_web_acl(Name=acl_data['Name'], Id=acl_data['Id'], Scope='REGIONAL',
                                       DefaultAction=acl_data['DefaultAction'], Rules=rules,
                                       VisibilityConfig=acl_data['VisibilityConfig'], LockToken=lock_token)

    def _add_domain_rule_to_firewall(self, waf_arn: str, domain: str):
        waf_data: dict[str, Any] = self._get_firewall_info(waf_arn)
        rules: list[dict[str, Any]] = waf_data['WebACL']['Rules']
        rule_name: str = f'miner-waf-rule-{self._generate_random_alnum_string(8)}'
        priority: int = rules[-1]['Priority'] + 1 if rules else 1
        rule = {
            'Name': rule_name,
            'Priority': priority,
            'Statement': {
                'ByteMatchStatement': {
                    'SearchString': domain,
                    'FieldToMatch': {
                        'SingleHeader': {
                            'Name': 'host'
                        }
                    },
                    'TextTransformations': [
                        {
                            'Priority': 0,
                            'Type': 'NONE'
                        }
                    ],
                    'PositionalConstraint': 'EXACTLY'
                }
            },
            'Action': {
                'Allow': {}
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': rule_name
            }
        }
        rules.append(rule)
        self._update_web_acl(waf_data, rules)
        self.event_processor.event('Added rule {rule_name} to AWS WAF {waf_id}, domain={domain}',
                                   rule_name=rule_name, waf_id=waf_arn, domain=domain)

    def _remove_domain_rule_from_firewall(self, waf_arn: str, domain: str):
        waf_data: dict[str, Any] = self._get_firewall_info(waf_arn)
        rules: list[dict[str, Any]] = waf_data['WebACL']['Rules']
        rule: Optional[dict[str, Any]] = self._find_rule(rules, domain)
        if rule is None:
            return
        rules.remove(rule)
        self._update_web_acl(waf_data, rules)
        self.event_processor.event('Removed rule {rule_name} from AWS WAF {waf_id}, domain={domain}',
                                   rule_name=rule['Name'], waf_id=waf_arn, domain=domain)

    @classmethod
    def _find_rule(cls, rules: list[dict[str, Any]], domain: str) -> Optional[dict[str, Any]]:
        for rule in rules:
            try:
                rule_domain: str = rule['Statement']['ByteMatchStatement']['SearchString'].decode()
            except KeyError:
                continue
            if rule_domain == domain:
                return rule
        return None

    @classmethod
    def _get_id_from_waf_arn(cls, waf_arn: str) -> str:
        return waf_arn.split('/')[-1]

    @classmethod
    def _get_name_from_waf_arn(cls, waf_arn: str) -> str:
        return waf_arn.split('/')[-2]

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
            bonus_subnet_id: str = next(iter(created_objects[AwsObjectTypes.SUBNET.value]))
            return self._get_subnet_data(bonus_subnet_id)

        for subnet in miner_vpc.subnets:
            if subnet.availability_zone != miner_subnet.availability_zone:
                bonus_subnet_availability_zone: str = subnet.availability_zone
                break
        else:
            raise AddressManagerException("Miner instance VPC doesn't have subnet in different availability zone")

        # Create new subnet in the same VPC as miner instance, because ELB needs at least two subnets in different AZs
        min_elb_subnet_mask: int = 27  # 27 as specified in documentation
        bonus_subnet_cidr: str = self._get_available_cidr(miner_vpc, min_elb_subnet_mask)
        bonus_subnet: AwsSubnetData = self._create_subnet(miner_vpc.vpc_id, bonus_subnet_cidr,
                                                          bonus_subnet_availability_zone)
        return bonus_subnet

    def _create_target_group_if_needed(self, miner_vpc: AwsVpcData, miner_instance_id: str, miner_instance_port: int,
                                       created_objects: MappingProxyType[str, frozenset[str]]) -> str:
        if AwsObjectTypes.TARGET_GROUP.value in created_objects:
            assert len(created_objects[AwsObjectTypes.TARGET_GROUP.value]) == 1, "only one group should be created"
            target_group_id: str = next(iter(created_objects[AwsObjectTypes.TARGET_GROUP.value]))
            return target_group_id

        return self._create_target_group(miner_vpc, miner_instance_id, miner_instance_port)

    def _create_security_group_if_needed(self, miner_vpc, miner_instance_port: int,
                                         created_objects: MappingProxyType[str, frozenset[str]]) -> str:
        if AwsObjectTypes.SECURITY_GROUP.value in created_objects:
            assert len(created_objects[AwsObjectTypes.SECURITY_GROUP.value]) == 1, "only one group should be created"
            security_group_id: str = next(iter(created_objects[AwsObjectTypes.SECURITY_GROUP.value]))
            return security_group_id

        return self._create_security_group(miner_vpc, miner_instance_port)

    def _create_elb_if_needed(self, miner_instance: AwsEC2InstanceData, miner_port: int) -> AwsELBData:
        created_objects: MappingProxyType[str, frozenset[str]] = \
            self.state_manager.get_state().address_manager_created_objects

        if AwsObjectTypes.ELB.value in created_objects:
            assert len(created_objects[AwsObjectTypes.ELB.value]) == 1, "only one ELB should be created"
            return self._get_elb_info(next(iter(created_objects[AwsObjectTypes.ELB.value])))

        miner_vpc: AwsVpcData = self._get_vpc_data(miner_instance.vpc_id)
        miner_subnet: AwsSubnetData = self._get_subnet_data(miner_instance.subnet_id)
        bonus_subnet: AwsSubnetData = self._create_bonus_subnet_if_needed(miner_vpc, miner_subnet, created_objects)
        target_group_id: str = self._create_target_group_if_needed(miner_vpc, miner_instance.instance_id,
                                                                   miner_port, created_objects)
        security_group_id: str = self._create_security_group_if_needed(miner_vpc, miner_port,
                                                                       created_objects)
        elb_id: str = self._create_elb(miner_instance, bonus_subnet, target_group_id, security_group_id)
        return self._get_elb_info(elb_id)

    def _create_firewall_if_needed(self) -> str:
        created_objects: MappingProxyType[str, frozenset[str]] = \
            self.state_manager.get_state().address_manager_created_objects
        if AwsObjectTypes.WAF.value in created_objects:
            assert len(created_objects[AwsObjectTypes.WAF.value]) == 1, "only one firewall should be created"
            return next(iter(created_objects[AwsObjectTypes.WAF.value]))

        return self._create_firewall()
