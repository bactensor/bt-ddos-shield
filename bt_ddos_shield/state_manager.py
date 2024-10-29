from abc import ABC, abstractmethod
from enum import Enum

from bt_ddos_shield.domain import Domain


class State:
    """
    Class representing state of MinerShield.
    """

    class ShieldPhase(Enum):
        """
        Possible phases of shield.
        """
        DISABLED = "disabled"                         # disabled - initial state
        MANIFEST_PUBLISHED = "manifest_published"     # manifest is saved to storage
        MANIFEST_BROADCASTED = "manifest_broadcasted" # info about manifest is published to blockchain
        ENABLED = "enabled"                           # shield is enabled

    phase: ShieldPhase                # current phase of the shield
    banned_validators: dict[str, int] # banned validators with ban time (HotKey -> ban timestamp)
    active_domains: dict[str, Domain] # active domains (validator HotKey -> Domain created for him)

    def __init__(self):
        self.phase = self.ShieldPhase.DISABLED
        self.banned_validators = {}
        self.active_domains = {}

class StateManager(ABC):
    """
    Abstract base class for manager handling state of MinerShield.
    """

    state: State # current state of MinerShield

    def __init__(self):
        pass

    @abstractmethod
    def load_state(self):
        """
        Load current state.
        """
        pass

    @abstractmethod
    def save_state(self):
        """
        Save current state.
        """
        pass

    @abstractmethod
    def ban_validator(self, validator_hotkey: str):
        """
        Add validator to the list of banned validators.

        Args:
            validator_hotkey: The hotkey of the validator.
        """
        pass

    @abstractmethod
    def remove_validator(self, validator_hotkey: str):
        """
        Remove validator from the lists of banned validators or active domains.

        Args:
            validator_hotkey: The hotkey of the validator.
        """
        pass

    @abstractmethod
    def add_domain(self, validator_hotkey: str, domain: Domain):
        """
        Add new domain to state.

        Args:
            validator_hotkey: The hotkey of the validator.
            domain: Domain to add.
        """
        pass
