from abc import ABC, abstractmethod
from datetime import datetime
from types import MappingProxyType
from typing import Optional

from bt_ddos_shield.address import Address
from bt_ddos_shield.utils import Hotkey, PublicKey


class MinerShieldState:
    _known_validators: dict[Hotkey, PublicKey]
    _banned_validators: dict[Hotkey, datetime]
    _active_validators_addresses: dict[Hotkey, Address]
    _manifest_address: Optional[Address]

    def __init__(self, known_validators: dict[Hotkey, PublicKey], banned_validators: dict[Hotkey, datetime],
                 active_validators_addresses: dict[Hotkey, Address], manifest_address: Optional[Address]):
        super().__setattr__('_known_validators', known_validators)
        super().__setattr__('_banned_validators', banned_validators)
        super().__setattr__('_active_validators_addresses', active_validators_addresses)
        super().__setattr__('_manifest_address', manifest_address)

    @property
    def known_validators(self) -> MappingProxyType[Hotkey, PublicKey]:
        """
        Get dictionary of known validators - maps validator HotKey -> validator public key.
        """
        return MappingProxyType(self._known_validators)

    @property
    def banned_validators(self) -> MappingProxyType[Hotkey, datetime]:
        """
        Get dictionary of banned validators - maps validator HotKey -> time of ban.
        """
        return MappingProxyType(self._banned_validators)

    @property
    def active_validators_addresses(self) -> MappingProxyType[Hotkey, Address]:
        """
        Get dictionary of active addresses (validator HotKey -> Address created for him)
        """
        return MappingProxyType(self._active_validators_addresses)

    @property
    def manifest_address(self) -> Optional[Address]:
        """
        Get manifest file address. If manifest file is not yet uploaded, return None.
        """
        return self._manifest_address

    def __setattr__(self, key, value):
        raise AttributeError("State is immutable")

    def __delattr__(self, item):
        raise AttributeError("State is immutable")


class AbstractMinerShieldStateManager(ABC):
    """
    Abstract base class for manager handling state of MinerShield. Each change in state should be instantly
    saved to storage.
    """
    current_miner_shield_state: MinerShieldState

    def get_state(self, reload: bool = False) -> MinerShieldState:
        """
        Get current state of MinerShield. If state is not loaded, it is loaded first.
        """
        if reload or self.current_miner_shield_state is None:
            self.current_miner_shield_state = self._load_state_from_storage()

        return self.current_miner_shield_state

    @abstractmethod
    def add_validator(self, validator_hotkey: Hotkey, validator_public_key: PublicKey, redirect_address: Address):
        """
        Add validator together with his public key and address (created for him) redirecting to Miner server.
        """
        pass

    @abstractmethod
    def update_validator_public_key(self, validator_hotkey: Hotkey, validator_public_key: PublicKey):
        pass

    @abstractmethod
    def add_banned_validator(self, validator_hotkey: Hotkey):
        pass

    @abstractmethod
    def remove_validator(self, validator_hotkey: Hotkey):
        """
        Remove validator from the sets of known validators and active addresses.
        """
        pass

    @abstractmethod
    def set_manifest_address(self, manifest_address: Address):
        pass

    @abstractmethod
    def _load_state_from_storage(self):
        pass
