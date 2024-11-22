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
        assert address.address.find(":") == -1, "Address should not contain colon character"
        address_str: str = f"{address.address_type.value}:{address.address}:{address.port}:{address.address_id}"
        return address_str.encode(self.encoding)

    def deserialize(self, serialized_data: bytes) -> Address:
        try:
            address_str: str = serialized_data.decode(self.encoding)
            parts = address_str.split(":")
            if len(parts) < 4:
                raise AddressDeserializationException(f"Invalid number of parts, address_str='{address_str}'")
            address_type: AddressType = AddressType(parts[0])
            address: str = parts[1]
            port: int = int(parts[2])
            address_id: str = ":".join(parts[3:])  # there can possibly be some colons in address_id
            return Address(address_id=address_id, address_type=address_type, address=address, port=port)
        except Exception as e:
            raise AddressDeserializationException(f"Failed to deserialize address, error='{e}'")
