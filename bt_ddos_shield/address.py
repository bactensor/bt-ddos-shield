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

    def __repr__(self):
        return f"Address(id={self.address_id}, address={self.address}:{self.port})"

    @abstractmethod
    def serialize(self) -> bytes:
        """
        Serialize address data.

        Returns:
            bytes: Serialized address data.
        """
        pass

    @classmethod
    @abstractmethod
    def deserialize(cls, serialized_data: bytes) -> 'Address':
        """
        Deserialize address data.

        Args:
            serialized_data: Data serialized before by serialize method.

        Returns:
            Address: Created address.
        """
        pass
