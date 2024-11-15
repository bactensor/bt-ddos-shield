from datetime import datetime
from time import sleep

import pytest
from sqlalchemy.exc import IntegrityError, NoResultFound

from bt_ddos_shield.address import Address, AddressType
from bt_ddos_shield.state_manager import AbstractMinerShieldStateManager, MinerShieldState, \
    SQLAlchemyMinerShieldStateManager
from bt_ddos_shield.utils import Hotkey, PublicKey
from tests.test_credentials import sql_alchemy_db_url


class MemoryMinerShieldStateManager(AbstractMinerShieldStateManager):
    def __init__(self):
        super().__init__()
        self.current_miner_shield_state = MinerShieldState(known_validators={}, banned_validators={},
                                                           validators_addresses={}, manifest_address=None)

    def add_validator(self, validator_hotkey: Hotkey, validator_public_key: PublicKey, redirect_address: Address):
        self._state_add_validator(validator_hotkey, validator_public_key, redirect_address)

    def update_validator_public_key(self, validator_hotkey: Hotkey, validator_public_key: PublicKey):
        self._state_update_validator_public_key(validator_hotkey, validator_public_key)

    def add_banned_validator(self, validator_hotkey: Hotkey):
        if validator_hotkey in self.current_miner_shield_state.banned_validators:
            return
        self._state_add_banned_validator(validator_hotkey, datetime.now())

    def remove_validator(self, validator_hotkey: Hotkey):
        self._state_remove_validator(validator_hotkey)

    def set_manifest_address(self, manifest_address: Address):
        self._state_set_manifest_address(manifest_address)

    def _load_state_from_storage(self) -> MinerShieldState:
        return self.current_miner_shield_state


class TestMinerShieldStateManager:
    """
    Test suite for the state manager.
    """

    @classmethod
    def create_db_state_manager(cls) -> SQLAlchemyMinerShieldStateManager:
        state_manager = SQLAlchemyMinerShieldStateManager(sql_alchemy_db_url)
        state_manager.clear_tables()
        state_manager.get_state()
        return state_manager

    def test_active_validators(self):
        validator1_hotkey = "validator1"
        validator1_publickey = "publickey1"
        validator1_address = Address(address_id="validator1_id", address_type=AddressType.IP,
                                     address="1.2.3.4", port=80)

        validator2_hotkey = "validator2"
        validator2_publickey = "publickey2"
        validator2_new_publickey = "new_publickey2"
        validator2_address = Address(address_id="validator2_id", address_type=AddressType.IP,
                                     address="2.3.4.5", port=81)

        state_manager = self.create_db_state_manager()

        state_manager.add_validator(validator1_hotkey, validator1_publickey, validator1_address)
        # can't add again same address
        with pytest.raises(IntegrityError):
            state_manager.add_validator(validator2_hotkey, validator2_publickey, validator1_address)
        state_manager.add_validator(validator2_hotkey, validator2_publickey, validator2_address)
        # can't add again same validator
        with pytest.raises(IntegrityError):
            state_manager.add_validator(validator1_hotkey, validator1_publickey, validator1_address)

        state_manager.update_validator_public_key(validator2_hotkey, validator2_new_publickey)

        state_manager.remove_validator(validator1_hotkey)
        with pytest.raises(NoResultFound):
            state_manager.remove_validator(validator1_hotkey)

        with pytest.raises(NoResultFound):
            state_manager.update_validator_public_key(validator1_hotkey, validator2_new_publickey)

        state: MinerShieldState = state_manager.get_state()
        assert state.known_validators == {validator2_hotkey: validator2_new_publickey}
        assert state.validators_addresses == {validator2_hotkey: validator2_address}

        reloaded_state: MinerShieldState = state_manager.get_state(reload=True)
        assert state == reloaded_state

    def test_banned_validators(self):
        banned_validator_hotkey = "banned_validator"

        state_manager = self.create_db_state_manager()

        state_manager.add_banned_validator(banned_validator_hotkey)
        ban_time: datetime = state_manager.get_state().banned_validators[banned_validator_hotkey]
        sleep(2)
        state_manager.add_banned_validator(banned_validator_hotkey)
        assert ban_time == state_manager.get_state().banned_validators[banned_validator_hotkey], \
            "first ban time should not change"

        state: MinerShieldState = state_manager.get_state()
        assert state.banned_validators == {banned_validator_hotkey: ban_time}

        reloaded_state: MinerShieldState = state_manager.get_state(reload=True)
        assert state == reloaded_state

    def test_manifest_address(self):
        manifest_address1 = Address(address_id="manifest", address_type=AddressType.IP,
                                    address="1.2.3.4", port=80)
        manifest_address2 = Address(address_id="manifest", address_type=AddressType.IP,
                                    address="2.3.4.5", port=81)

        state_manager = self.create_db_state_manager()
        state_manager.set_manifest_address(manifest_address1)
        state_manager.set_manifest_address(manifest_address2)
        state: MinerShieldState = state_manager.get_state()
        assert state.manifest_address == manifest_address2

        reloaded_state: MinerShieldState = state_manager.get_state(reload=True)
        assert state == reloaded_state
