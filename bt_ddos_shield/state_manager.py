from abc import ABC, abstractmethod
from datetime import datetime

from bt_ddos_shield.address import Address
from bt_ddos_shield.utils import Hotkey, PublicKey


class MinerShieldState:
    known_validators: dict[Hotkey, PublicKey]  # known validators (HotKey -> validator public key)
    banned_validators: dict[Hotkey, datetime]  # banned validators with ban time (HotKey -> time of ban)
    active_addresses: dict[Hotkey, Address]    # active addresses (validator HotKey -> Address created for him)

    def __init__(self):
        self.known_validators = {}
        self.banned_validators = {}
        self.active_addresses = {}


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
        Add to state validator together with his public key and address (created for him) redirecting to Miner server.
        """
        pass

    @abstractmethod
    def update_validator_public_key(self, validator_hotkey: Hotkey, validator_public_key: PublicKey):
        pass

    @abstractmethod
    def add_banned_validator(self, validator_hotkey: Hotkey):
        """
        Add validator to the set of banned validators.
        """
        pass

    @abstractmethod
    def remove_validator(self, validator_hotkey: Hotkey):
        """
        Remove validator from the sets of known validators and active addresses.
        """
        pass

    @abstractmethod
    def _load_state_from_storage(self):
        pass
