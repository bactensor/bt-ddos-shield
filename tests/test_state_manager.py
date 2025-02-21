from __future__ import annotations

from datetime import datetime
from time import sleep
from typing import TYPE_CHECKING

import pytest
from sqlalchemy.exc import IntegrityError, NoResultFound

from bt_ddos_shield.state_manager import (
    AbstractMinerShieldStateManager,
    MinerShieldState,
    SQLAlchemyMinerShieldStateManager,
)
from bt_ddos_shield.utils import ShieldAddress

if TYPE_CHECKING:
    from bt_ddos_shield.utils import Hotkey, PublicKey
    from tests.conftest import ShieldTestSettings


class MemoryMinerShieldStateManager(AbstractMinerShieldStateManager):
    def __init__(self):
        super().__init__()
        self.current_miner_shield_state = MinerShieldState(
            known_validators={},
            banned_validators={},
            validators_addresses={},
            address_manager_state={},
            address_manager_created_objects={},
        )

    def add_validator(self, validator_hotkey: Hotkey, validator_public_key: PublicKey, redirect_address: ShieldAddress):
        self._state_add_validator(validator_hotkey, validator_public_key, redirect_address)

    def update_validator_public_key(self, validator_hotkey: Hotkey, validator_public_key: PublicKey):
        self._state_update_validator_public_key(validator_hotkey, validator_public_key)

    def add_banned_validator(self, validator_hotkey: Hotkey):
        if validator_hotkey in self.current_miner_shield_state.banned_validators:
            return
        self._state_add_banned_validator(validator_hotkey, datetime.now())

    def remove_banned_validator(self, validator_hotkey: Hotkey):
        if validator_hotkey not in self.current_miner_shield_state.banned_validators:
            return
        self._state_remove_banned_validator(validator_hotkey)

    def remove_validator(self, validator_hotkey: Hotkey):
        self._state_remove_validator(validator_hotkey)

    def update_address_manager_state(self, key: str, value: str | None):
        self._state_update_address_manager_state(key, value)

    def add_address_manager_created_object(self, obj_type: str, obj_id: str):
        self._state_add_address_manager_created_object(obj_type, obj_id)

    def del_address_manager_created_object(self, obj_type: str, obj_id: str):
        self._state_del_address_manager_created_object(obj_type, obj_id)

    def _load_state_from_storage(self) -> MinerShieldState:
        assert self.current_miner_shield_state is not None
        return self.current_miner_shield_state


class TestMinerShieldStateManager:
    """
    Test suite for the state manager.
    """

    @classmethod
    def create_db_state_manager(cls, test_settings: ShieldTestSettings) -> SQLAlchemyMinerShieldStateManager:
        state_manager = SQLAlchemyMinerShieldStateManager(test_settings.sql_alchemy_db_url)
        state_manager.clear_tables()
        state_manager.get_state()
        return state_manager

    def test_active_validators(self, shield_settings: ShieldTestSettings):
        validator1_hotkey = 'validator1'
        validator1_publickey = 'publickey1'
        validator1_address = ShieldAddress(address_id='validator1_id', address='1.2.3.4', port=80)

        validator2_hotkey = 'validator2'
        validator2_publickey = 'publickey2'
        validator2_new_publickey = 'new_publickey2'
        validator2_address = ShieldAddress(address_id='validator2_id', address='2.3.4.5', port=81)

        state_manager = self.create_db_state_manager(shield_settings)

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

    def test_banned_validators(self, shield_settings: ShieldTestSettings):
        banned_validator_hotkey = 'banned_validator'

        state_manager = self.create_db_state_manager(shield_settings)

        state_manager.add_banned_validator(banned_validator_hotkey)
        ban_time: datetime = state_manager.get_state().banned_validators[banned_validator_hotkey]
        sleep(2)
        state_manager.add_banned_validator(banned_validator_hotkey)
        assert ban_time == state_manager.get_state().banned_validators[banned_validator_hotkey], (
            'first ban time should not change'
        )

        state: MinerShieldState = state_manager.get_state()
        assert state.banned_validators == {banned_validator_hotkey: ban_time}

        reloaded_state: MinerShieldState = state_manager.get_state(reload=True)
        assert state == reloaded_state

        state_manager.remove_banned_validator(banned_validator_hotkey)
        reloaded_state = state_manager.get_state(reload=True)
        assert reloaded_state.banned_validators == {}

    def test_address_manager_state(self, shield_settings: ShieldTestSettings):
        key1 = 'key1'
        value1 = 'value1'
        key2 = 'key2'
        value2 = 'value2'
        key3 = 'key3'

        state_manager = self.create_db_state_manager(shield_settings)

        # Add key-value pairs to the address manager state
        state_manager.update_address_manager_state(key1, value1)
        state_manager.update_address_manager_state(key2, value2)

        state: MinerShieldState = state_manager.get_state()
        assert state.address_manager_state == {key1: value1, key2: value2}

        # Update an existing key
        new_value1 = 'new_value1'
        state_manager.update_address_manager_state(key1, new_value1)
        state = state_manager.get_state()
        assert state.address_manager_state == {key1: new_value1, key2: value2}

        # Remove a key
        state_manager.update_address_manager_state(key2, None)
        state = state_manager.get_state()
        assert state.address_manager_state == {key1: new_value1}

        # Ensure a non-existent key is not present
        state_manager.update_address_manager_state(key3, None)
        state = state_manager.get_state()
        assert key3 not in state.address_manager_state

        reloaded_state: MinerShieldState = state_manager.get_state(reload=True)
        assert state == reloaded_state

    def test_address_manager_created_objects(self, shield_settings: ShieldTestSettings):
        object_type1 = 'type1'
        object_id1 = 'id1'
        object_type2 = 'type2'
        object_id2 = 'id2'
        object_id3 = 'id3'

        state_manager = self.create_db_state_manager(shield_settings)

        # Add objects to the address manager created objects
        state_manager.add_address_manager_created_object(object_type1, object_id1)
        state_manager.add_address_manager_created_object(object_type2, object_id2)

        state: MinerShieldState = state_manager.get_state()
        assert state.address_manager_created_objects == {object_type1: {object_id1}, object_type2: {object_id2}}

        # Add another object to an existing type
        state_manager.add_address_manager_created_object(object_type2, object_id3)
        state = state_manager.get_state()
        assert state.address_manager_created_objects == {
            object_type1: {object_id1},
            object_type2: {object_id2, object_id3},
        }

        reloaded_state: MinerShieldState = state_manager.get_state(reload=True)
        assert state == reloaded_state

        # Remove an object
        state_manager.del_address_manager_created_object(object_type2, object_id2)
        state = state_manager.get_state()
        assert state.address_manager_created_objects == {object_type1: {object_id1}, object_type2: {object_id3}}

        # Ensure a non-existent object is not present
        state_manager.del_address_manager_created_object(object_type2, 'non_existent_id')
        state = state_manager.get_state()
        assert state.address_manager_created_objects == {object_type1: {object_id1}, object_type2: {object_id3}}

        # Remove last object of given type
        state_manager.del_address_manager_created_object(object_type2, object_id3)
        state = state_manager.get_state()
        assert state.address_manager_created_objects == {object_type1: {object_id1}}

        reloaded_state = state_manager.get_state(reload=True)
        assert state == reloaded_state
