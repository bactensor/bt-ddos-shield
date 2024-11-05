from abc import ABC, abstractmethod
from enum import Enum


class AddressType(Enum):
    """
    Possible types of address.
    """
    IP = "ip"         # IPv4 address
    IPV6 = "ipv6"     # IPv6 address
    DOMAIN = "domain" # domain name


class Address(ABC):
    """
    Class describing address, which redirects to original miner's server.
    """

    def __init__(self, address_id, address_type: AddressType, address: str, port: int):
        """
        Args:
            address_id: Identifier (used by AddressManager) of the address. Type depends on the implementation.
            address_type: Type of the address.
            address: Address.
            port: Port of the address.
        """
        self.address_id = address_id
        self.address_type = address_type
        self.address = address
        self.port = port

    @abstractmethod
    def encrypt(self) -> bytes:
        """
        Encrypts address data.

        Returns:
            bytes: Encrypted address data.
        """
        pass

    @classmethod
    @abstractmethod
    def decrypt(cls, encrypted_data: bytes) -> 'Address':
        """
        Create address from encrypted address data.

        Args:
            encrypted_data: Encrypted address data.

        Returns:
            Address: Created address.
        """
        pass
