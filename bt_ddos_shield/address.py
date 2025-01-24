from dataclasses import dataclass
from enum import Enum


class AddressType(Enum):
    """
    Possible types of address.
    """
    IP = "ip"          # IPv4 address
    IPV6 = "ipv6"      # IPv6 address
    DOMAIN = "domain"  # domain name
    S3 = "s3"          # address identifies S3 object (id is object name)
    EC2 = "ec2"        # address identifies EC2 instance (id is instance id)


@dataclass
class Address:
    """
    Class describing some address - domain or IP.
    """

    address_id: str
    """ identifier (used by AbstractAddressManager implementation) of the address """
    address_type: AddressType
    address: str
    port: int

    def __repr__(self):
        return f"Address(id={self.address_id}, type={self.address_type}, address={self.address}:{self.port})"
