import secrets
from abc import ABC, abstractmethod
from types import MappingProxyType

import route53
from route53.connection import Route53Connection
from route53.hosted_zone import HostedZone
from route53.resource_record_set import NSResourceRecordSet

from bt_ddos_shield.address import Address, AddressType
from bt_ddos_shield.utils import Hotkey


class AddressManagerException(Exception):
    pass


class AbstractAddressManager(ABC):
    """
    Abstract base class for manager handling public IP/domain addresses assigned to validators.
    """

    miner_new_address: Address

    def __init__(self, miner_new_address: Address):
        """
        Args:
            miner_new_address: New address of original miner's server. All created addresses for validators
                               should redirect to this address.
        """
        self.miner_new_address = miner_new_address

    def hide_original_server(self):
        """
        If method is implemented, it should hide the original server IP address from public access.
        See auto_hide_original_server in MinerShield options.
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


class Route53AddressManager(AbstractAddressManager):
    """
    Address manager using AWS Route53 service to manage DNS records. Miner new address can be either IP or IPv6.
    """

    route53_client: Route53Connection
    hosted_zone_id: str
    """ ID of hosted zone in Route53 where addresses are located. """
    hosted_zone: HostedZone
    """ Hosted zone object. """
    domain: str
    """ Domain for given hosted zone. """

    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, hosted_zone_id: str,
                 miner_new_address: Address):
        """
        Args:
            aws_access_key_id: AWS access key ID.
            aws_secret_access_key: AWS secret access key.
            hosted_zone_id: ID of hosted zone in Route53 where addresses are located.
            miner_new_address: New address of original miner's server - address_id is ignored and type has to
                               be either IP or IPv6. All created addresses for validators will redirect to this address.
        """
        super().__init__(miner_new_address)

        if miner_new_address.address_type not in {AddressType.IP, AddressType.IPV6}:
            raise ValueError("Only IP and IPv6 addresses are supported")

        self.route53_client = route53.connect(aws_access_key_id, aws_secret_access_key)
        self.hosted_zone_id = hosted_zone_id
        self.hosted_zone = self.route53_client.get_hosted_zone_by_id(hosted_zone_id)

        for record_set in self.hosted_zone.record_sets:
            if isinstance(record_set, NSResourceRecordSet):
                self.domain = record_set.name
                break
        else:
            # it shouldn't happen
            raise AddressManagerException("Hosted zone does not contain NS record set")

    def create_address(self, hotkey: Hotkey) -> Address:
        new_address_domain: str = f"{self._generate_subdomain(hotkey)}.{self.domain}"

        if self.miner_new_address.address_type == AddressType.IP:
            self.hosted_zone.create_a_record(name=new_address_domain, values=[self.miner_new_address.address])
        else:
            assert self.miner_new_address.address_type == AddressType.IPV6, "checked in constructor"
            self.hosted_zone.create_aaaa_record(name=new_address_domain, values=[self.miner_new_address.address])

        # There is no ID in Route53, so we use the domain name as an ID. Cut '.' from the end for working address.
        return Address(address_id=new_address_domain, address_type=AddressType.DOMAIN,
                       address=new_address_domain[:-1], port=self.miner_new_address.port)

    @classmethod
    def _generate_subdomain(cls, hotkey: Hotkey) -> str:
        # subdomain is first 8 characters from hotkey + 16 random characters
        return f"{hotkey[:8]}_{secrets.token_urlsafe(16)}".lower()

    def remove_address(self, address: Address):
        for record_set in self.hosted_zone.record_sets:
            if record_set.name == address.address_id:
                break
        else:
            return

        record_set.delete()

    def validate_addresses(self, addresses: MappingProxyType[Hotkey, Address]) -> set[Hotkey]:
        zone_addresses_ids: set[str] = {record_set.name for record_set in self.hosted_zone.record_sets}
        invalid_hotkeys: set[Hotkey] = {hotkey for hotkey, address in addresses.items()
                                        if address.address_id not in zone_addresses_ids}
        return invalid_hotkeys
