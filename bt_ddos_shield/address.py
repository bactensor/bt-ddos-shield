from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class AddressType(Enum):
    """
    Possible types of address.
    """
    IP = "ip"          # IPv4 address
    IPV6 = "ipv6"      # IPv6 address
    DOMAIN = "domain"  # domain name


@dataclass
class Address:
    """
    Class describing some address - domain or IP.
    """

    address_id: str  # address_id: Identifier (used by AbstractAddressManager implementation) of the address.
    address_type: AddressType
    address: str
    port: int

    def __repr__(self):
        return f"Address(id={self.address_id}, address={self.address}:{self.port})"


class AddressSerializerException(Exception):
    pass


class AddressDeserializationException(AddressSerializerException):
    """
    Exception thrown when deserialization of address data fails.
    """
    pass


class AbstractAddressSerializer(ABC):
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


class DefaultAddressSerializer(AbstractAddressSerializer):
    """
    Address serializer implementation which serialize address to string.
    """

    encoding: str

    def __init__(self, encoding: str = "utf-8"):
        """
        Args:
            encoding: Encoding used for transforming generated address string to bytes.
        """
        self.encoding = encoding

    def serialize(self, address: Address) -> bytes:
        address_str: str = f"{address.address_id}:{address.address_type.value}:{address.address}:{address.port}"
        return address_str.encode(self.encoding)

    def deserialize(self, serialized_data: bytes) -> Address:
        try:
            address_str: str = serialized_data.decode(self.encoding)
            parts = address_str.split(":")
            if len(parts) != 4:
                raise AddressDeserializationException(f"Invalid number of parts, address_str='{address_str}'")
            address_id: str = parts[0]
            address_type: AddressType = AddressType(parts[1])
            address: str = parts[2]
            port: int = int(parts[3])
            return Address(address_id=address_id, address_type=address_type, address=address, port=port)
        except Exception as e:
            raise AddressDeserializationException(f"Failed to deserialize address, error='{e}'")
