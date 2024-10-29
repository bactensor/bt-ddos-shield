from abc import ABC, abstractmethod
from enum import Enum


class Domain(ABC):
    """
    Class describing domain.
    """

    class DomainType(Enum):
        """
        Possible types of domain.
        """
        IP = "ip"         # domain is an IPv4 address
        IPV6 = "ipv6"     # domain is an IPv6 address
        DOMAIN = "domain" # domain is a domain name

    def __init__(self, domain_id, domain_type: DomainType, address: str, port: int):
        """
        Args:
            domain_id: Identifier (used by DNSManager) of the domain. Type depends on the implementation.
            domain_type: Type of the domain.
            address: Address of the domain.
            port: Port of the domain.
        """
        self.domain_id = domain_id
        self.domain_type = domain_type
        self.address = address
        self.port = port

    @abstractmethod
    def encrypt(self) -> str:
        """
        Encrypts domain data.

        Returns:
            str: Encrypted domain data.
        """
        pass

    @classmethod
    @abstractmethod
    def decrypt(cls, encrypted_data: str) -> Domain:
        """
        Create domain from encrypted domain data.

        Returns:
            Domain: Created domain.
        """
        pass
