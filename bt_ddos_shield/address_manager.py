from __future__ import annotations

import codecs
import ipaddress
import secrets
import string
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Network, IPv6Network
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError
from pydantic import BaseModel

from bt_ddos_shield.utils import ShieldAddress

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import MappingProxyType

    from mypy_boto3_ec2 import EC2Client
    from mypy_boto3_ec2.type_defs import (
        CreateSecurityGroupResultTypeDef,
        CreateSubnetResultTypeDef,
        CreateVpcResultTypeDef,
        DescribeAvailabilityZonesResultTypeDef,
        DescribeInstancesResultTypeDef,
        DescribeSubnetsResultTypeDef,
        DescribeVpcsResultTypeDef,
        GroupIdentifierTypeDef,
        InstanceTypeDef,
        SubnetTypeDef,
        VpcTypeDef,
    )
    from mypy_boto3_elbv2 import ElasticLoadBalancingv2Client
    from mypy_boto3_elbv2.type_defs import (
        CreateLoadBalancerOutputTypeDef,
        CreateTargetGroupOutputTypeDef,
        DescribeLoadBalancersOutputTypeDef,
        LoadBalancerTypeDef,
    )
    from mypy_boto3_route53 import Route53Client
    from mypy_boto3_route53.type_defs import (
        ListResourceRecordSetsResponseTypeDef,
        ResourceRecordSetOutputTypeDef,
        ResourceRecordSetTypeDef,
    )
    from mypy_boto3_wafv2 import WAFV2Client
    from mypy_boto3_wafv2.type_defs import (
        CreateWebACLResponseTypeDef,
        GetWebACLResponseTypeDef,
        RuleOutputTypeDef,
        RuleTypeDef,
        WebACLTypeDef,
    )
    from route53.connection import Route53Connection
    from route53.hosted_zone import HostedZone
    from route53.resource_record_set import ResourceRecordSet

    from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor
    from bt_ddos_shield.state_manager import AbstractMinerShieldStateManager, MinerShieldState
    from bt_ddos_shield.utils import AWSClientFactory, Hotkey


class ShieldedServerLocationType(Enum):
    """
    Possible types of shielded server location.
    """

    EC2_ID = 'ec2_id'
    """ ID of EC2 instance """
    EC2_IP = 'ec2_ip'
    """ IPv4 address of EC2 instance """


@dataclass
class ShieldedServerLocation:
    """
    Location of server, which shield should protect.
    """

    location_type: ShieldedServerLocationType
    location_value: str
    """ Value depends on location type """
    port: int
    """ Port used by shielded server """


class AddressManagerException(Exception):
    pass


class AbstractAddressManager(ABC):
    """
    Abstract base class for manager handling public IP/domain addresses assigned to validators.
    """

    def hide_original_server(self):  # noqa: B027
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
    def create_address(self, hotkey: Hotkey) -> ShieldAddress:
        """
        Create and return a new address redirecting to Miner server to be used by validator identified by hotkey.
        """
        pass

    @abstractmethod
    def remove_address(self, address: ShieldAddress):
        pass

    @abstractmethod
    def validate_addresses(self, addresses: MappingProxyType[Hotkey, ShieldAddress]) -> set[Hotkey]:
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
    security_groups: list[GroupIdentifierTypeDef]


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


class AwsEC2ServerLocation(BaseModel):
    vpc_id: str
    subnet_id: str
    server_id: str


class AwsShieldedServerData(BaseModel):
    server_location: ShieldedServerLocation
    """ Location of shielded server. """
    aws_location: AwsEC2ServerLocation | None
    """ Detailed location of server in AWS (only if it is EC2 instance). """

    def to_json(self) -> str:
        return self.model_dump_json()

    @staticmethod
    def from_json(json_str: str) -> AwsShieldedServerData:
        return AwsShieldedServerData.model_validate_json(json_str)


class AwsObjectTypes(Enum):
    WAF = 'WAF'
    ELB = 'ELB'
    SUBNET = 'SUBNET'
    VPC = 'VPC'
    DNS_ENTRY = 'DNS_ENTRY'
    TARGET_GROUP = 'TARGET_GROUP'
    SECURITY_GROUP = 'SECURITY_GROUP'


class AwsAddressManager(AbstractAddressManager):
    """
    Address manager using AWS Route53 service to manage DNS records and ELB for handling access to Miner server.
    """

    shielded_server_data: AwsShieldedServerData
    waf_client: WAFV2Client
    waf_arn: str | None
    elb_client: ElasticLoadBalancingv2Client
    elb_data: AwsELBData | None
    ec2_client: EC2Client
    hosted_zone_id: str
    """ ID of hosted zone in Route53 where addresses are located. """
    hosted_zone: HostedZone
    route53_client: Route53Connection
    route53_boto_client: Route53Client
    event_processor: AbstractMinerShieldEventProcessor
    state_manager: AbstractMinerShieldStateManager

    HOSTED_ZONE_ID_STATE_KEY: str = 'aws_hosted_zone_id'
    SHIELDED_SERVER_STATE_KEY: str = 'aws_shielded_server'

    ELB_LISTENING_PORT: int = 80

    AWS_OPERATION_MAX_RETRIES: int = 20
    """ How many retries should be done for AWS operations, which need long time until can be processed. """
    AWS_OPERATION_RETRY_DELAY_SEC: int = 9
    """
    Delay in seconds between retries for AWS operations. Total time for waiting for operation is
    AWS_OPERATION_MAX_RETRIES * AWS_OPERATION_RETRY_DELAY_SEC seconds.
    """

    def __init__(
        self,
        aws_client_factory: AWSClientFactory,
        server_location: ShieldedServerLocation,
        hosted_zone_id: str,
        event_processor: AbstractMinerShieldEventProcessor,
        state_manager: AbstractMinerShieldStateManager,
    ):
        """
        Initialize AWS address manager.
        """
        self.event_processor = event_processor
        self.state_manager = state_manager

        self.waf_client = aws_client_factory.boto3_client('wafv2')  # type: ignore
        self.waf_arn = None
        self.elb_client = aws_client_factory.boto3_client('elbv2')  # type: ignore
        self.elb_data = None
        self.route53_client = aws_client_factory.route53_client()
        self.hosted_zone_id = hosted_zone_id
        self.hosted_zone = self.route53_client.get_hosted_zone_by_id(hosted_zone_id)
        self.route53_boto_client = aws_client_factory.boto3_client('route53')  # type: ignore
        self.ec2_client = aws_client_factory.boto3_client('ec2')  # type: ignore
        self._initialize_server_data(server_location)

    def _initialize_server_data(self, server_location: ShieldedServerLocation):
        server_instance: AwsEC2InstanceData
        if server_location.location_type == ShieldedServerLocationType.EC2_IP:
            server_instance = self._get_ec2_instance_data(private_ip=server_location.location_value)
        else:
            assert server_location.location_type == ShieldedServerLocationType.EC2_ID
            server_instance = self._get_ec2_instance_data(instance_id=server_location.location_value)

        server_location = ShieldedServerLocation(
            location_type=ShieldedServerLocationType.EC2_ID,
            location_value=server_instance.instance_id,
            port=server_location.port,
        )
        server_aws_location = AwsEC2ServerLocation(
            vpc_id=server_instance.vpc_id, subnet_id=server_instance.subnet_id, server_id=server_instance.instance_id
        )
        self.shielded_server_data = AwsShieldedServerData(
            server_location=server_location, aws_location=server_aws_location
        )

    def clean_all(self) -> None:
        created_objects: MappingProxyType[str, frozenset[str]] = (
            self.state_manager.get_state().address_manager_created_objects
        )

        self._delete_route53_records(self.hosted_zone_id)

        # Order of removal is important
        cleaned: bool = True
        cleaned = self._clean_aws_objects(created_objects, AwsObjectTypes.WAF, self._remove_firewall) and cleaned
        cleaned = self._clean_aws_objects(created_objects, AwsObjectTypes.ELB, self._remove_elb) and cleaned
        cleaned = (
            self._clean_aws_objects(created_objects, AwsObjectTypes.SECURITY_GROUP, self._remove_security_group)
            and cleaned
        )
        cleaned = (
            self._clean_aws_objects(created_objects, AwsObjectTypes.TARGET_GROUP, self._remove_target_group) and cleaned
        )
        cleaned = self._clean_aws_objects(created_objects, AwsObjectTypes.SUBNET, self._remove_subnet) and cleaned
        cleaned = self._clean_aws_objects(created_objects, AwsObjectTypes.VPC, self._remove_vpc) and cleaned
        if not cleaned:
            raise AddressManagerException(
                'Failed to clean all AWS objects that are no longer needed. Check logs to see what is left.'
                ' Also try to run cleaning later. Sometimes AWS needs 15-20 minutes to be able to clean some of'
                ' them - especially TargetGroups.'
            )

    @classmethod
    def _clean_aws_objects(
        cls,
        created_objects: MappingProxyType[str, frozenset[str]],
        object_type: AwsObjectTypes,
        remove_method: Callable[[str], bool],
    ) -> bool:
        if object_type.value not in created_objects:
            return True
        cleaned: bool = True
        for object_id in created_objects[object_type.value]:
            try:
                cleaned = remove_method(object_id) and cleaned
            except Exception as e:
                cls.event_processor.event(
                    'Failed to remove {object_type} AWS object with id={id}',
                    exception=e,
                    object_type=object_type.value,
                    id=object_id,
                )
                cleaned = False
        return cleaned

    def create_address(self, hotkey: Hotkey) -> ShieldAddress:
        self._validate_manager_state()

        subdomain: str = self._generate_subdomain(hotkey)
        new_address_domain: str = f'{subdomain}.{self._get_hosted_zone_domain(self.hosted_zone)}'
        assert self.waf_arn is not None, '_validate_manager_state creates WAF and should be called before'
        self._add_domain_rule_to_firewall(self.waf_arn, new_address_domain)
        return ShieldAddress(
            address_id=subdomain,
            address=new_address_domain,
            port=self.ELB_LISTENING_PORT,
        )

    @classmethod
    def _generate_subdomain(cls, hotkey: Hotkey) -> str:
        return f'{hotkey[:8]}_{secrets.token_urlsafe(16)}'.lower()

    @classmethod
    def _get_hosted_zone_domain(cls, hosted_zone: HostedZone) -> str:
        return hosted_zone.name[:-1]  # Cut '.' from the end of hosted zone name

    def remove_address(self, address: ShieldAddress):
        self._validate_manager_state()
        assert self.waf_arn is not None, '_validate_manager_state creates WAF and should be called before'
        self._remove_domain_rule_from_firewall(self.waf_arn, address.address)

    def validate_addresses(self, addresses: MappingProxyType[Hotkey, ShieldAddress]) -> set[Hotkey]:
        if self._validate_manager_state():
            return {hotkey for hotkey, _ in addresses.items()}

        if not addresses:
            return set()

        assert self.waf_arn is not None, '_validate_manager_state creates WAF and should be called before'
        waf_data: GetWebACLResponseTypeDef = self._get_firewall_info(self.waf_arn)
        rules: list[RuleOutputTypeDef] = waf_data['WebACL']['Rules']

        invalid_hotkeys: set[Hotkey] = set()
        for hotkey, address in addresses.items():
            rule: RuleOutputTypeDef | None = self._find_rule(rules, address.address)
            if rule is None:
                invalid_hotkeys.add(hotkey)
        return invalid_hotkeys

    def _validate_manager_state(self) -> bool:
        """Returns if we should invalidate all addresses created before."""
        ret: bool = self._handle_shielded_server_change()
        self.elb_data = self._create_elb_if_needed(self.shielded_server_data)
        self.waf_arn = self._create_firewall_if_needed()

        ret = self._handle_hosted_zone_change() or ret
        self._init_hosted_zone_if_needed()

        return ret

    def _store_server_data(self, server_data: AwsShieldedServerData):
        self.state_manager.update_address_manager_state(self.SHIELDED_SERVER_STATE_KEY, server_data.to_json())

    def _load_server_data(self) -> AwsShieldedServerData | None:
        state: MinerShieldState = self.state_manager.get_state()
        if self.SHIELDED_SERVER_STATE_KEY not in state.address_manager_state:
            return None
        json_data: str = state.address_manager_state[self.SHIELDED_SERVER_STATE_KEY]
        return AwsShieldedServerData.from_json(json_data)

    def _handle_shielded_server_change(self) -> bool:
        old_server_data: AwsShieldedServerData | None = self._load_server_data()
        if old_server_data != self.shielded_server_data:
            # If shielded server changed, we need to recreate ELB. Maybe we can try to change only
            # needed objects, but changing ELB is the easiest way and this operation should happen rarely.
            self.event_processor.event(
                'Shielded server changed from {old_server_desc} to {new_server_desc}',
                old_server_desc=str(old_server_data) if old_server_data else 'None',
                new_server_desc=str(self.shielded_server_data),
            )
            self.clean_all()
            self._store_server_data(self.shielded_server_data)
            return True

        return False

    def _handle_hosted_zone_change(self) -> bool:
        state: MinerShieldState = self.state_manager.get_state()
        zone_changed: bool = False
        if self.HOSTED_ZONE_ID_STATE_KEY in state.address_manager_state:
            old_zone_id: str = state.address_manager_state[self.HOSTED_ZONE_ID_STATE_KEY]
            if old_zone_id != self.hosted_zone_id:
                # If hosted zone changed, we need to clean all previous route53 addresses and WAF rules
                self.event_processor.event(
                    'Route53 hosted zone changed from {old_id} to {new_id}',
                    old_id=old_zone_id,
                    new_id=self.hosted_zone_id,
                )
                self._delete_route53_records(old_zone_id)
                assert self.waf_arn is not None, '_validate_manager_state creates WAF and should be called before'
                self._clear_firewall_rules(self.waf_arn)
                zone_changed = True
        else:
            zone_changed = True

        if zone_changed:
            self.state_manager.update_address_manager_state(self.HOSTED_ZONE_ID_STATE_KEY, self.hosted_zone_id)
        return zone_changed

    def _get_ec2_instance_data(
        self, instance_id: str | None = None, private_ip: str | None = None
    ) -> AwsEC2InstanceData:
        assert instance_id or private_ip
        ec2_client_args: dict[str, Any] = (
            {'InstanceIds': [instance_id]}
            if instance_id
            else {'Filters': [{'Name': 'private-ip-address', 'Values': [private_ip]}]}
        )
        response: DescribeInstancesResultTypeDef = self.ec2_client.describe_instances(**ec2_client_args)
        if not response['Reservations']:
            raise AddressManagerException(
                f'No EC2 instance found with instance_id={instance_id} or IP address {private_ip}'
            )
        instance_data: InstanceTypeDef = response['Reservations'][0]['Instances'][0]
        return AwsEC2InstanceData(
            instance_id=instance_data['InstanceId'],
            vpc_id=instance_data['VpcId'],
            subnet_id=instance_data['SubnetId'],
            private_ip=instance_data['PrivateIpAddress'],
            security_groups=instance_data['SecurityGroups'],
        )

    def _get_vpc_data(self, vpc_id: str) -> AwsVpcData:
        vpc_response: DescribeVpcsResultTypeDef = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])
        vpc_data: VpcTypeDef = vpc_response['Vpcs'][0]
        cidr_block: str = vpc_data['CidrBlock']

        subnet_response: DescribeSubnetsResultTypeDef = self.ec2_client.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        subnets: list[AwsSubnetData] = [
            AwsSubnetData(
                subnet_id=subnet['SubnetId'],
                availability_zone=subnet['AvailabilityZone'],
                cidr_block=subnet['CidrBlock'],
            )
            for subnet in subnet_response['Subnets']
        ]
        return AwsVpcData(vpc_id=vpc_id, cidr_block=cidr_block, subnets=subnets)

    def _get_subnet_data(self, subnet_id: str) -> AwsSubnetData:
        response: DescribeSubnetsResultTypeDef = self.ec2_client.describe_subnets(SubnetIds=[subnet_id])
        subnet_data: SubnetTypeDef = response['Subnets'][0]
        return AwsSubnetData(
            subnet_id=subnet_id, availability_zone=subnet_data['AvailabilityZone'], cidr_block=subnet_data['CidrBlock']
        )

    def _add_route53_record(self, subdomain: str, hosted_zone: HostedZone):
        domain_name: str = f'{subdomain}.{hosted_zone.name}'
        assert self.elb_data is not None, '_validate_manager_state creates ELB and should be called before'
        record_set: ResourceRecordSetTypeDef = {
            'Name': domain_name,
            'Type': 'A',
            'AliasTarget': {
                'HostedZoneId': self.elb_data.hosted_zone_id,
                'DNSName': self.elb_data.dns_name,
                'EvaluateTargetHealth': False,
            },
        }

        # Route53Connection doesn't handle alias records properly, so we use boto3 client directly
        self.route53_boto_client.change_resource_record_sets(
            HostedZoneId=hosted_zone.id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'CREATE',
                        'ResourceRecordSet': record_set,
                    }
                ]
            },
        )
        self.event_processor.event(
            'Added Route53 record {domain_name} to hosted zone {zone_id}',
            domain_name=domain_name,
            zone_id=hosted_zone.id,
        )
        try:
            # There is no ID for Route53 addresses, so we use domain name as an ID
            self.state_manager.add_address_manager_created_object(AwsObjectTypes.DNS_ENTRY.value, domain_name)
        except Exception as e:
            self._delete_route53_record_by_domain_name(domain_name, hosted_zone)
            raise e

    def _delete_route53_record_by_domain_name(self, domain_name: str, hosted_zone: HostedZone):
        for record_set in hosted_zone.record_sets:
            if codecs.decode(record_set.name, 'unicode_escape') == domain_name:
                self._delete_route53_record(record_set, hosted_zone)
                return

    def _delete_route53_record(self, record_set: ResourceRecordSet, hosted_zone: HostedZone):
        # Route53Connection doesn't handle alias records properly, so we use boto3 client directly
        response: ListResourceRecordSetsResponseTypeDef = self.route53_boto_client.list_resource_record_sets(
            HostedZoneId=hosted_zone.id,
            StartRecordName=record_set.name,
            StartRecordType=record_set.rrset_type,
            MaxItems='1',
        )
        record_set_data: ResourceRecordSetOutputTypeDef = response['ResourceRecordSets'][0]

        self.route53_boto_client.change_resource_record_sets(
            HostedZoneId=hosted_zone.id,
            ChangeBatch={'Changes': [{'Action': 'DELETE', 'ResourceRecordSet': record_set_data}]},
        )
        self.event_processor.event(
            'Deleted Route53 record {name} from hosted zone {zone_id}', name=record_set.name, zone_id=hosted_zone.id
        )
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.DNS_ENTRY.value, record_set.name)

    @classmethod
    def _generate_random_alnum_string(cls, length: int) -> str:
        characters = string.ascii_letters + string.digits
        return ''.join(secrets.choice(characters) for _ in range(length))

    def _get_vpc_networks(self) -> list[IPv4Network | IPv6Network]:
        response: DescribeVpcsResultTypeDef = self.ec2_client.describe_vpcs()
        return [ipaddress.ip_network(vpc['CidrBlock']) for vpc in response['Vpcs']]

    @classmethod
    def _get_subnet_networks(cls, vpc: AwsVpcData) -> list[IPv4Network | IPv6Network]:
        return [ipaddress.ip_network(subnet.cidr_block) for subnet in vpc.subnets]

    @classmethod
    def _find_available_subnet(
        cls, network: IPv4Network | IPv6Network, used_subnets: list[IPv4Network | IPv6Network], subnet_size: int
    ) -> str:
        """
        Find available CIDR block (subnet) of specified size inside network. This block must not collide with any
        subnets from used_subnets param.
        """
        for subnet in network.subnets(new_prefix=subnet_size):
            if not any(subnet.overlaps(used) for used in used_subnets):
                return str(subnet)

        raise AddressManagerException('No available CIDR block found in AWS')

    def _create_vpc(self) -> str:
        # Preferable IP range for VPC is 10.0.0.0/8 according to
        # https://docs.aws.amazon.com/vpc/latest/userguide/vpc-cidr-blocks.html.
        # Do not try 172.* and 192.* as 10.* should be enough.
        network: IPv4Network | IPv6Network = ipaddress.ip_network('10.0.0.0/8')
        vpc_network_size: int = 24  # Network size 24 (255 addresses) is enough for shield
        cidr: str = self._find_available_subnet(network, self._get_vpc_networks(), vpc_network_size)
        response: CreateVpcResultTypeDef = self.ec2_client.create_vpc(
            CidrBlock=cidr,
            TagSpecifications=[{'ResourceType': 'vpc', 'Tags': [{'Key': 'Name', 'Value': 'DDosShield'}]}],
        )
        vpc_id: str = response['Vpc']['VpcId']
        self.event_processor.event('Created AWS VPC {id} with cidr={cidr}', id=vpc_id, cidr=cidr)
        try:
            self.state_manager.add_address_manager_created_object(AwsObjectTypes.VPC.value, vpc_id)
        except Exception as e:
            self._remove_vpc(vpc_id)
            raise e
        return vpc_id

    def _remove_vpc(self, vpc_id: str) -> bool:
        self.ec2_client.delete_vpc(VpcId=vpc_id)
        self.event_processor.event('Deleted AWS VPC {id}', id=vpc_id)
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.VPC.value, vpc_id)
        return True

    def _create_subnet(self, vpc_id: str, cidr_block: str, availability_zone: str) -> AwsSubnetData:
        response: CreateSubnetResultTypeDef = self.ec2_client.create_subnet(
            VpcId=vpc_id, CidrBlock=cidr_block, AvailabilityZone=availability_zone
        )
        subnet = AwsSubnetData(
            subnet_id=response['Subnet']['SubnetId'], availability_zone=availability_zone, cidr_block=cidr_block
        )
        self.event_processor.event(
            'Created AWS subnet {id} with cidr={cidr} in {az} availability zone',
            id=subnet.subnet_id,
            cidr=subnet.cidr_block,
            az=subnet.availability_zone,
        )
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

    def _create_target_group(self, vpc_data: AwsVpcData, server_data: AwsShieldedServerData) -> str:
        group_name: str = f'miner-target-group-{self._generate_random_alnum_string(8)}'
        # Health check can't be disabled - as for now we use traffic-port
        response: CreateTargetGroupOutputTypeDef = self.elb_client.create_target_group(
            Name=group_name,
            Protocol='HTTP',
            Port=server_data.server_location.port,
            VpcId=vpc_data.vpc_id,
            TargetType='instance',
            HealthCheckEnabled=True,
            HealthCheckProtocol='HTTP',
            HealthCheckPort='traffic-port',
        )
        target_group_id: str = response['TargetGroups'][0]['TargetGroupArn']
        self.event_processor.event('Created AWS TargetGroup, name={name}, id={id}', name=group_name, id=target_group_id)

        try:
            # TODO: AWS load balancers prohibit redirection to IP address from outside of AWS. This have to be done
            # other way - probably by creating EC2 instance and configuring there haproxy, which will redirect traffic
            # to the shielded server.
            self.elb_client.register_targets(
                TargetGroupArn=target_group_id,
                Targets=[{'Id': server_data.server_location.location_value, 'Port': server_data.server_location.port}],
            )
            self.state_manager.add_address_manager_created_object(AwsObjectTypes.TARGET_GROUP.value, target_group_id)
        except Exception as e:
            self._remove_target_group(target_group_id)
            raise e

        return target_group_id

    def _remove_target_group(self, target_group_id: str) -> bool:
        current_server_data: AwsShieldedServerData | None = self._load_server_data()
        if current_server_data:
            self.elb_client.deregister_targets(
                TargetGroupArn=target_group_id, Targets=[{'Id': current_server_data.server_location.location_value}]
            )

        error_code: str = ''
        for _ in range(self.AWS_OPERATION_MAX_RETRIES):
            try:
                self.elb_client.delete_target_group(TargetGroupArn=target_group_id)
                break
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceInUse':
                    time.sleep(self.AWS_OPERATION_RETRY_DELAY_SEC)  # Wait for target group to be deregistered
                else:
                    raise e
        else:
            # It happens quite often and sometimes AWS waits for many minutes before allowing to remove target group.
            # But we don't want to wait for too long.
            # If it happens during tests, user should remove target group later manually using AWS panel to not leave
            # unneeded objects in AWS.
            self.event_processor.event(
                'Failed to remove AWS TargetGroup {id}, error={error_code}', id=target_group_id, error_code=error_code
            )
            return False

        self.event_processor.event('Deleted AWS TargetGroup {id}', id=target_group_id)
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.TARGET_GROUP.value, target_group_id)
        return True

    def _create_elb(self, shield_subnets: list[AwsSubnetData], target_group_id: str, security_group_id: str) -> str:
        elb_name: str = f'miner-elb-{self._generate_random_alnum_string(8)}'
        subnets_ids: list[str] = [subnet.subnet_id for subnet in shield_subnets]
        response: CreateLoadBalancerOutputTypeDef = self.elb_client.create_load_balancer(
            Name=elb_name,
            Subnets=subnets_ids,
            SecurityGroups=[security_group_id],
            Scheme='internet-facing',
            Type='application',
        )
        elb_info: LoadBalancerTypeDef = response['LoadBalancers'][0]
        elb_id: str = elb_info['LoadBalancerArn']
        self.event_processor.event('Created AWS ELB, name={name}, id={id}', name=elb_name, id=elb_id)

        try:
            self.elb_client.create_listener(
                LoadBalancerArn=elb_id,
                Protocol='HTTP',
                Port=self.ELB_LISTENING_PORT,
                DefaultActions=[{'Type': 'forward', 'TargetGroupArn': target_group_id}],
            )
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
        response: DescribeLoadBalancersOutputTypeDef = self.elb_client.describe_load_balancers(
            LoadBalancerArns=[elb_id]
        )
        elb_info: LoadBalancerTypeDef = response['LoadBalancers'][0]
        return AwsELBData(
            id=elb_info['LoadBalancerArn'],
            dns_name=elb_info['DNSName'],
            hosted_zone_id=elb_info['CanonicalHostedZoneId'],
        )

    def _create_security_group(self, vpc_data: AwsVpcData, server_port: int) -> str:
        group_name: str = f'miner-security-group-{self._generate_random_alnum_string(8)}'
        response: CreateSecurityGroupResultTypeDef = self.ec2_client.create_security_group(
            GroupName=group_name, Description='Security group for miner instance', VpcId=vpc_data.vpc_id
        )
        security_group_id: str = response['GroupId']
        self.event_processor.event(
            'Created AWS SecurityGroup, name={name}, id={id}', name=group_name, id=security_group_id
        )

        try:
            self.ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {'FromPort': 80, 'ToPort': server_port, 'IpProtocol': 'tcp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                ],
            )
            self.state_manager.add_address_manager_created_object(
                AwsObjectTypes.SECURITY_GROUP.value, security_group_id
            )
        except Exception as e:
            self._remove_security_group(security_group_id)
            raise e

        return security_group_id

    def _remove_security_group(self, security_group_id: str) -> bool:
        error_code: str = ''
        for _ in range(self.AWS_OPERATION_MAX_RETRIES):
            try:
                self.ec2_client.delete_security_group(GroupId=security_group_id)
                break
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'DependencyViolation':
                    time.sleep(self.AWS_OPERATION_RETRY_DELAY_SEC)  # Wait for ELB to be removed
                else:
                    raise e
        else:
            # It happens quite often and sometimes AWS waits for many minutes before allowing to remove security group.
            # But we don't want to wait for too long.
            # If it happens during tests, user should remove security group later manually using AWS panel to not leave
            # unneeded objects in AWS.
            self.event_processor.event(
                'Failed to remove AWS SecurityGroup {id}, error={error_code}',
                id=security_group_id,
                error_code=error_code,
            )
            return False

        self.event_processor.event('Deleted AWS SecurityGroup {id}', id=security_group_id)
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.SECURITY_GROUP.value, security_group_id)
        return True

    def _delete_route53_records(self, hosted_zone_id: str):
        address_manager_created_objects: MappingProxyType[str, frozenset[str]] = (
            self.state_manager.get_state().address_manager_created_objects
        )
        if AwsObjectTypes.DNS_ENTRY.value not in address_manager_created_objects:
            return

        created_entries: frozenset[str] = self.state_manager.get_state().address_manager_created_objects[
            AwsObjectTypes.DNS_ENTRY.value
        ]
        hosted_zone = self.route53_client.get_hosted_zone_by_id(hosted_zone_id)
        for record_set in hosted_zone.record_sets:
            if codecs.decode(record_set.name, 'unicode_escape') in created_entries:
                self._delete_route53_record(record_set, hosted_zone)

        # Clean from state entries without working address (without corresponding record_set in hosted_zone)
        address_manager_created_objects = self.state_manager.get_state().address_manager_created_objects
        if AwsObjectTypes.DNS_ENTRY.value not in address_manager_created_objects:
            return
        for created_entry in address_manager_created_objects[AwsObjectTypes.DNS_ENTRY.value]:
            self.state_manager.del_address_manager_created_object(AwsObjectTypes.DNS_ENTRY.value, created_entry)

    def _create_firewall(self) -> str:
        waf_name: str = f'miner-waf-{self._generate_random_alnum_string(8)}'
        response: CreateWebACLResponseTypeDef = self.waf_client.create_web_acl(
            Name=waf_name,
            Scope='REGIONAL',
            DefaultAction={'Block': {}},
            Rules=[],
            VisibilityConfig={'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True, 'MetricName': waf_name},
        )
        waf_arn: str = response['Summary']['ARN']
        self.event_processor.event('Created AWS WAF, name={name}, id={id}', name=waf_name, id=waf_arn)

        assert self.elb_data is not None, '_validate_manager_state creates ELB and should be called before'

        error_code: str = ''
        for _ in range(self.AWS_OPERATION_MAX_RETRIES):
            try:
                self.waf_client.associate_web_acl(WebACLArn=waf_arn, ResourceArn=self.elb_data.id)
                self.event_processor.event(
                    'Associated AWS WAF {waf_id} to ELB {elb_id}', waf_id=waf_arn, elb_id=self.elb_data.id
                )
                break
            except ClientError as e:
                error_code = e.response['Error']['Code']
                time.sleep(self.AWS_OPERATION_RETRY_DELAY_SEC)  # Wait for WAF to be created
        else:
            self._remove_firewall(waf_arn)
            # It happens quite often and sometimes creation of ELB propagates for many minutes before association is
            # allowed. But we don't want to wait for too long.
            raise AddressManagerException(
                f'Failed to associate AWS WAF {waf_arn} with ELB {self.elb_data.id}, error={error_code}'
            )

        try:
            self.state_manager.add_address_manager_created_object(AwsObjectTypes.WAF.value, waf_arn)
        except Exception as e:
            self._remove_firewall(waf_arn)
            raise e

        return waf_arn

    def _remove_firewall(self, waf_arn: str) -> bool:
        created_objects: MappingProxyType[str, frozenset[str]] = (
            self.state_manager.get_state().address_manager_created_objects
        )

        if AwsObjectTypes.ELB.value in created_objects:
            assert len(created_objects[AwsObjectTypes.ELB.value]) == 1, 'only one ELB should be created'
            elb_id: str = next(iter(created_objects[AwsObjectTypes.ELB.value]))
            self.waf_client.disassociate_web_acl(ResourceArn=elb_id)

        waf_data: GetWebACLResponseTypeDef = self._get_firewall_info(waf_arn)
        acl_data: WebACLTypeDef = waf_data['WebACL']
        waf_id: str = acl_data['Id']
        lock_token = waf_data['LockToken']

        error_code: str = ''
        for _ in range(self.AWS_OPERATION_MAX_RETRIES):
            try:
                self.waf_client.delete_web_acl(Name=acl_data['Name'], Id=waf_id, Scope='REGIONAL', LockToken=lock_token)
                break
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'WAFAssociatedItemException':
                    time.sleep(self.AWS_OPERATION_RETRY_DELAY_SEC)  # Wait for ELB disassociating
                else:
                    raise e
        else:
            # It happens quite often and sometimes AWS waits for many minutes before allowing to remove WAF.
            # But we don't want to wait for too long.
            # If it happens during tests, user should remove WAF later manually using AWS panel to not leave
            # unneeded objects in AWS.
            self.event_processor.event(
                'Failed to remove AWS WAF {id}, error={error_code}', id=waf_id, error_code=error_code
            )
            return False

        self.event_processor.event('Deleted AWS WAF {id}', id=waf_arn)
        self.state_manager.del_address_manager_created_object(AwsObjectTypes.WAF.value, waf_arn)
        return True

    def _get_firewall_info(self, waf_arn: str) -> GetWebACLResponseTypeDef:
        waf_name: str = self._get_name_from_waf_arn(waf_arn)
        waf_id: str = self._get_id_from_waf_arn(waf_arn)
        return self.waf_client.get_web_acl(Name=waf_name, Id=waf_id, Scope='REGIONAL')

    def _update_web_acl(self, waf_data: GetWebACLResponseTypeDef, rules: Sequence[RuleTypeDef]):
        acl_data: WebACLTypeDef = waf_data['WebACL']
        lock_token = waf_data['LockToken']
        self.waf_client.update_web_acl(
            Name=acl_data['Name'],
            Id=acl_data['Id'],
            Scope='REGIONAL',
            DefaultAction=acl_data['DefaultAction'],  # type: ignore
            Rules=rules,
            VisibilityConfig=acl_data['VisibilityConfig'],
            LockToken=lock_token,
        )

    def _add_domain_rule_to_firewall(self, waf_arn: str, domain: str):
        waf_data: GetWebACLResponseTypeDef = self._get_firewall_info(waf_arn)
        rules: list[RuleTypeDef] = waf_data['WebACL']['Rules']  # type: ignore
        rule_name: str = f'miner-waf-rule-{self._generate_random_alnum_string(8)}'
        priority: int = rules[-1]['Priority'] + 1 if rules else 1
        rule: RuleTypeDef = {
            'Name': rule_name,
            'Priority': priority,
            'Statement': {
                'ByteMatchStatement': {
                    'SearchString': domain,
                    'FieldToMatch': {'SingleHeader': {'Name': 'host'}},
                    'TextTransformations': [{'Priority': 0, 'Type': 'NONE'}],
                    'PositionalConstraint': 'EXACTLY',
                }
            },
            'Action': {'Allow': {}},
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': rule_name,
            },
        }
        rules.append(rule)
        self._update_web_acl(waf_data, rules)
        self.event_processor.event(
            'Added rule {rule_name} to AWS WAF {waf_id}, domain={domain}',
            rule_name=rule_name,
            waf_id=waf_arn,
            domain=domain,
        )

    def _remove_domain_rule_from_firewall(self, waf_arn: str, domain: str):
        waf_data: GetWebACLResponseTypeDef = self._get_firewall_info(waf_arn)
        rules: list[RuleOutputTypeDef] = waf_data['WebACL']['Rules']
        rule: RuleOutputTypeDef | None = self._find_rule(rules, domain)
        if rule is None:
            return
        rules.remove(rule)
        self._update_web_acl(waf_data, rules)  # type: ignore
        self.event_processor.event(
            'Removed rule {rule_name} from AWS WAF {waf_id}, domain={domain}',
            rule_name=rule['Name'],
            waf_id=waf_arn,
            domain=domain,
        )

    def _clear_firewall_rules(self, waf_arn: str):
        waf_data: GetWebACLResponseTypeDef = self._get_firewall_info(waf_arn)
        self._update_web_acl(waf_data, [])

    def _init_hosted_zone(self):
        # Add wildcard subdomain to hosted zone - Host header validation is done by WAF
        self._add_route53_record('*', self.hosted_zone)

    @classmethod
    def _find_rule(cls, rules: list[RuleOutputTypeDef], domain: str) -> RuleOutputTypeDef | None:
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

    def _create_subnets_if_needed(
        self,
        vpc_data: AwsVpcData,
        server_data: AwsShieldedServerData,
        created_objects: MappingProxyType[str, frozenset[str]],
    ) -> list[AwsSubnetData]:
        shield_subnets: list[AwsSubnetData] = []
        if AwsObjectTypes.SUBNET.value in created_objects:
            for subnet_id in created_objects[AwsObjectTypes.SUBNET.value]:
                shield_subnets.append(self._get_subnet_data(subnet_id))
        if server_data.aws_location:
            shield_subnets.append(self._get_subnet_data(server_data.aws_location.subnet_id))

        # ELB needs at least two subnets in different AZs
        min_subnets_for_elb: int = 2
        if len(shield_subnets) >= min_subnets_for_elb:
            return shield_subnets

        response: DescribeAvailabilityZonesResultTypeDef = self.ec2_client.describe_availability_zones()
        vpc_availability_zones: set[str] = {az['ZoneName'] for az in response['AvailabilityZones']}
        subnets_availability_zones: set[str] = {subnet.availability_zone for subnet in shield_subnets}
        # Region should have at least 2 different availability zones, and we need to create at most 2 subnets, so
        # we can use set difference to find remaining availability zones.
        remaining_availability_zones: set[str] = vpc_availability_zones - subnets_availability_zones

        vpc_network: IPv4Network | IPv6Network = ipaddress.ip_network(vpc_data.cidr_block)
        used_networks: list[IPv4Network | IPv6Network] = self._get_subnet_networks(vpc_data)
        # 27 as specified in https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#availability-zones  # noqa: E501
        min_elb_subnet_size: int = 27

        while len(shield_subnets) < min_subnets_for_elb:
            new_subnet_cidr: str = self._find_available_subnet(vpc_network, used_networks, min_elb_subnet_size)
            new_subnet_az: str = remaining_availability_zones.pop()
            new_subnet: AwsSubnetData = self._create_subnet(vpc_data.vpc_id, new_subnet_cidr, new_subnet_az)
            used_networks.append(ipaddress.ip_network(new_subnet_cidr))
            shield_subnets.append(new_subnet)
        return shield_subnets

    def _create_target_group_if_needed(
        self,
        vpc_data: AwsVpcData,
        server_data: AwsShieldedServerData,
        created_objects: MappingProxyType[str, frozenset[str]],
    ) -> str:
        if AwsObjectTypes.TARGET_GROUP.value in created_objects:
            assert len(created_objects[AwsObjectTypes.TARGET_GROUP.value]) == 1, 'only one group should be created'
            target_group_id: str = next(iter(created_objects[AwsObjectTypes.TARGET_GROUP.value]))
            return target_group_id

        return self._create_target_group(vpc_data, server_data)

    def _create_security_group_if_needed(
        self, vpc_data: AwsVpcData, server_port: int, created_objects: MappingProxyType[str, frozenset[str]]
    ) -> str:
        if AwsObjectTypes.SECURITY_GROUP.value in created_objects:
            assert len(created_objects[AwsObjectTypes.SECURITY_GROUP.value]) == 1, 'only one group should be created'
            security_group_id: str = next(iter(created_objects[AwsObjectTypes.SECURITY_GROUP.value]))
            return security_group_id

        return self._create_security_group(vpc_data, server_port)

    def _create_vpc_if_needed(
        self, server_data: AwsShieldedServerData, created_objects: MappingProxyType[str, frozenset[str]]
    ) -> AwsVpcData:
        vpc_id: str
        if server_data.aws_location:
            assert AwsObjectTypes.VPC.value not in created_objects, 'VPC of EC2 instance should be used'
            vpc_id = server_data.aws_location.vpc_id
        else:
            if AwsObjectTypes.VPC.value in created_objects:
                assert len(created_objects[AwsObjectTypes.VPC.value]) == 1, 'only one VPC should be created'
                vpc_id = next(iter(created_objects[AwsObjectTypes.VPC.value]))
            else:
                vpc_id = self._create_vpc()

        return self._get_vpc_data(vpc_id)

    def _create_elb_if_needed(self, server_data: AwsShieldedServerData) -> AwsELBData:
        created_objects: MappingProxyType[str, frozenset[str]] = (
            self.state_manager.get_state().address_manager_created_objects
        )

        if AwsObjectTypes.ELB.value in created_objects:
            assert len(created_objects[AwsObjectTypes.ELB.value]) == 1, 'only one ELB should be created'
            return self._get_elb_info(next(iter(created_objects[AwsObjectTypes.ELB.value])))

        server_port: int = server_data.server_location.port
        vpc_data: AwsVpcData = self._create_vpc_if_needed(server_data, created_objects)
        shield_subnets: list[AwsSubnetData] = self._create_subnets_if_needed(vpc_data, server_data, created_objects)
        target_group_id: str = self._create_target_group_if_needed(vpc_data, server_data, created_objects)
        security_group_id: str = self._create_security_group_if_needed(vpc_data, server_port, created_objects)
        elb_id: str = self._create_elb(shield_subnets, target_group_id, security_group_id)
        return self._get_elb_info(elb_id)

    def _create_firewall_if_needed(self) -> str:
        created_objects: MappingProxyType[str, frozenset[str]] = (
            self.state_manager.get_state().address_manager_created_objects
        )
        if AwsObjectTypes.WAF.value in created_objects:
            assert len(created_objects[AwsObjectTypes.WAF.value]) == 1, 'only one firewall should be created'
            return next(iter(created_objects[AwsObjectTypes.WAF.value]))

        return self._create_firewall()

    def _init_hosted_zone_if_needed(self) -> None:
        created_objects: MappingProxyType[str, frozenset[str]] = (
            self.state_manager.get_state().address_manager_created_objects
        )
        if AwsObjectTypes.DNS_ENTRY.value in created_objects:
            assert len(created_objects[AwsObjectTypes.DNS_ENTRY.value]) == 1, 'only one entry should be created'
            return

        self._init_hosted_zone()
