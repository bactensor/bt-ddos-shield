from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum

from bt_ddos_shield.address import Address
from bt_ddos_shield.miner_shield import Hotkey


class MinerShieldPhase(Enum):
    """
    Possible phases of shield.
    """
    DISABLED = "disabled"                         # disabled - initial state
    MANIFEST_PUBLISHED = "manifest_published"     # manifest is saved to storage
    MANIFEST_BROADCASTED = "manifest_broadcasted" # info about manifest is published to blockchain
    ENABLED = "enabled"                           # shield is enabled


class MinerShieldState:
    """
    Class representing state of MinerShield.
    """

    phase: MinerShieldPhase                   # current phase of the shield
    banned_validators: dict[Hotkey, datetime] # banned validators with ban time (HotKey -> time of ban)
    active_addresses: dict[Hotkey, Address]   # active addresses (validator HotKey -> Address created for him)

    def __init__(self):
        self.phase = MinerShieldPhase.DISABLED
        self.banned_validators = {}
        self.active_addresses = {}


class AbstractMinerShieldStateManager(ABC):
    """
    Abstract base class for manager handling state of MinerShield.
    """

    current_miner_shield_state: MinerShieldState

    @abstractmethod
    def load_state(self):
        pass

    @abstractmethod
    def save_state(self):
        pass

    @abstractmethod
    def ban_validator(self, validator_hotkey: Hotkey):
        """
        Add validator to the list of banned validators.

        Args:
            validator_hotkey: The hotkey of the validator.
        """
        pass

    @abstractmethod
    def remove_validator(self, validator_hotkey: Hotkey):
        """
        Remove validator from the lists of banned validators or active addresses.

        Args:
            validator_hotkey: The hotkey of the validator.
        """
        pass

    @abstractmethod
    def add_address(self, validator_hotkey: Hotkey, address: Address):
        """
        Add new address to state.

        Args:
            validator_hotkey: The hotkey of the validator.
            address: Address to add.
        """
        pass
