from abc import ABC, abstractmethod

from bt_ddos_shield.domain import Domain


class DNSManager(ABC):
    """
    Abstract base class for manager handling public IP/domain addresses assigned to validators.
    """

    def __init__(self):
        pass

    @abstractmethod
    def create_domain(self) -> Domain:
        """
        Create a new domain.

        Returns:
            Domain: New domain.
        """
        pass

    @abstractmethod
    def remove_domain(self, domain_id):
        """
        Remove domain.

        Args:
            domain_id: Identifier of the domain to remove.
        """
        pass

    @abstractmethod
    def domain_exists(self, domain_id):
        """
        Check if domain exists.

        Args:
            domain_id: Identifier of the domain to check.

            Returns:
                bool: If domain exists.
        """
        pass

    def hide_original_server(self):
        """
        If method is implemented, it should hide the original server IP address from public access.
        See auto_hide_original_server in MinerShield options.
        """
        pass
