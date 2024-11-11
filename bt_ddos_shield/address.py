from abc import ABC, abstractmethod
from enum import Enum
from typing import Any


class AddressType(Enum):
    """
    Possible types of address.
    """
    IP = "ip"          # IPv4 address
    IPV6 = "ipv6"      # IPv6 address
    DOMAIN = "domain"  # domain name


class Address:
    """
    Class describing some address - domain or IP.
    """

    address_id: Any
    address_type: AddressType
    address: str
    port: int

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


class AddressSerializerException(Exception):
    pass


class AddressDeserializationException(AddressSerializerException):
    """
    Exception thrown when deserialization of address data fails.
    """
    pass


class AddressSerializer(ABC):
    """
    Class used to serialize and deserialize addresses.
    """

    @abstractmethod
    def serialize(self, address: Address) -> bytes:
        """
        Serialize address data. Output format depends on the implementation.
        """
        pass

    @abstractmethod
    def deserialize(self, serialized_data: bytes) -> Address:
        """
        Deserialize address data. Throws AddressDeserializationException if data format is not recognized.

        Args:
            serialized_data: Data serialized before by serialize method.
        """
        pass
