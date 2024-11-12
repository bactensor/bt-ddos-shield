from datetime import datetime
from typing import Optional

from bt_ddos_shield.address import Address
from bt_ddos_shield.state_manager import AbstractMinerShieldStateManager, MinerShieldState
from bt_ddos_shield.utils import Hotkey, PublicKey


class MemoryMinerShieldStateManager(AbstractMinerShieldStateManager):
    def __init__(self):
        super().__init__()
        self.current_miner_shield_state = MinerShieldState(known_validators={}, banned_validators={},
                                                           validators_addresses={}, manifest_address=None)

    def add_validator(self, validator_hotkey: Hotkey, validator_public_key: PublicKey, redirect_address: Address):
        known_validators: dict[Hotkey, PublicKey] = dict(self.current_miner_shield_state.known_validators)
        known_validators[validator_hotkey] = validator_public_key
        validators_addresses: dict[Hotkey, Address] = dict(self.current_miner_shield_state.validators_addresses)
        validators_addresses[validator_hotkey] = redirect_address
        self._update_state(known_validators, None, validators_addresses, None)

    def update_validator_public_key(self, validator_hotkey: Hotkey, validator_public_key: PublicKey):
        known_validators: dict[Hotkey, PublicKey] = dict(self.current_miner_shield_state.known_validators)
        known_validators[validator_hotkey] = validator_public_key
        self._update_state(known_validators, None, None, None)

    def add_banned_validator(self, validator_hotkey: Hotkey):
        banned_validators: dict[Hotkey, datetime] = dict(self.current_miner_shield_state.banned_validators)
        if validator_hotkey in banned_validators:
            return
        banned_validators[validator_hotkey] = datetime.now()
        self._update_state(None, banned_validators, None, None)

    def remove_validator(self, validator_hotkey: Hotkey):
        known_validators: dict[Hotkey, PublicKey] = dict(self.current_miner_shield_state.known_validators)
        known_validators.pop(validator_hotkey, None)
        validators_addresses: dict[Hotkey, Address] = dict(self.current_miner_shield_state.validators_addresses)
        validators_addresses.pop(validator_hotkey, None)
        self._update_state(known_validators, None, validators_addresses, None)

    def set_manifest_address(self, manifest_address: Address):
        self._update_state(None, None, None, manifest_address)

    def _load_state_from_storage(self) -> MinerShieldState:
        return self.current_miner_shield_state

    def _update_state(self,
                      known_validators: Optional[dict[Hotkey, PublicKey]],
                      banned_validators: Optional[dict[Hotkey, datetime]],
                      validators_addresses: Optional[dict[Hotkey, Address]],
                      manifest_address: Optional[Address]):
        self.current_miner_shield_state = \
            MinerShieldState(dict(self.current_miner_shield_state.known_validators)
                             if known_validators is None else known_validators,
                             dict(self.current_miner_shield_state.banned_validators)
                             if banned_validators is None else banned_validators,
                             dict(self.current_miner_shield_state.validators_addresses)
                             if validators_addresses is None else validators_addresses,
                             self.current_miner_shield_state.manifest_address
                             if manifest_address is None else manifest_address)


class TestMinerShieldStateManager:
    """
    Test suite for the state manager.
    """
    pass
