from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime
from types import MappingProxyType
from typing import TYPE_CHECKING

from sqlalchemy import (
    Column,
    DateTime,
    Engine,
    ForeignKey,
    Integer,
    PrimaryKeyConstraint,
    String,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from bt_ddos_shield.utils import ShieldAddress

if TYPE_CHECKING:
    from sqlalchemy.engine import url

    from bt_ddos_shield.utils import Hotkey, PublicKey


class MinerShieldState:
    _known_validators: dict[Hotkey, PublicKey]
    _banned_validators: dict[Hotkey, datetime]
    _validators_addresses: dict[Hotkey, ShieldAddress]
    _address_manager_state: dict[str, str]
    _address_manager_created_objects: dict[str, frozenset[str]]

    def __init__(
        self,
        known_validators: dict[Hotkey, PublicKey] | None = None,
        banned_validators: dict[Hotkey, datetime] | None = None,
        validators_addresses: dict[Hotkey, ShieldAddress] | None = None,
        address_manager_state: dict[str, str] | None = None,
        address_manager_created_objects: dict[str, frozenset[str]] | None = None,
    ):
        super().__setattr__('_known_validators', known_validators or {})
        super().__setattr__('_banned_validators', banned_validators or {})
        super().__setattr__('_validators_addresses', validators_addresses or {})
        super().__setattr__('_address_manager_state', address_manager_state or {})
        super().__setattr__('_address_manager_created_objects', address_manager_created_objects or {})

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
    def validators_addresses(self) -> MappingProxyType[Hotkey, ShieldAddress]:
        """
        Get dictionary of active addresses (validator HotKey -> Address created for him).
        """
        return MappingProxyType(self._validators_addresses)

    @property
    def address_manager_state(self) -> MappingProxyType[str, str]:
        """
        Get address manager state (key -> value).
        """
        return MappingProxyType(self._address_manager_state)

    @property
    def address_manager_created_objects(self) -> MappingProxyType[str, frozenset[str]]:
        """
        Get objects already created by address manager (object_type -> set of object_ids).
        """
        return MappingProxyType(self._address_manager_created_objects)

    def __setattr__(self, key, value):
        raise AttributeError('State is immutable')

    def __delattr__(self, item):
        raise AttributeError('State is immutable')

    def __eq__(self, other):
        if not isinstance(other, MinerShieldState):
            return False

        return (
            self._known_validators == other._known_validators
            and self._banned_validators == other._banned_validators
            and self._validators_addresses == other._validators_addresses
            and self._address_manager_state == other._address_manager_state
            and self._address_manager_created_objects == other._address_manager_created_objects
        )


class AbstractMinerShieldStateManager(ABC):
    """
    Abstract base class for manager handling state of MinerShield. Each change in state should be instantly
    saved to storage.
    """

    current_miner_shield_state: MinerShieldState = MinerShieldState()
    _initialized: bool = False

    def get_state(self, reload: bool = False) -> MinerShieldState:
        """
        Get current state of MinerShield. If state is not loaded, it is loaded first.
        """
        if reload or not self._initialized:
            self.current_miner_shield_state = self._load_state_from_storage()

        return self.current_miner_shield_state

    @abstractmethod
    def add_validator(self, validator_hotkey: Hotkey, validator_public_key: PublicKey, redirect_address: ShieldAddress):
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
    def remove_banned_validator(self, validator_hotkey: Hotkey):
        pass

    @abstractmethod
    def remove_validator(self, validator_hotkey: Hotkey):
        """
        Remove validator from the sets of known validators and active addresses.
        """
        pass

    @abstractmethod
    def update_address_manager_state(self, key: str, value: str | None):
        """
        Update address manager state (key -> value). If value is None, remove key from state.
        """
        pass

    @abstractmethod
    def add_address_manager_created_object(self, obj_type: str, obj_id: str):
        pass

    @abstractmethod
    def del_address_manager_created_object(self, obj_type: str, obj_id: str):
        pass

    @abstractmethod
    def _load_state_from_storage(self) -> MinerShieldState:
        pass

    def _update_state(
        self,
        known_validators: dict[Hotkey, PublicKey] | None = None,
        banned_validators: dict[Hotkey, datetime] | None = None,
        validators_addresses: dict[Hotkey, ShieldAddress] | None = None,
        address_manager_state: dict[str, str] | None = None,
        address_manager_created_objects: dict[str, frozenset[str]] | None = None,
    ):
        """
        Create new updated state with given new values and set it as current state. If value for field is None,
        it is copied from current state.
        """
        self.current_miner_shield_state = MinerShieldState(
            dict(self.current_miner_shield_state.known_validators) if known_validators is None else known_validators,
            dict(self.current_miner_shield_state.banned_validators) if banned_validators is None else banned_validators,
            dict(self.current_miner_shield_state.validators_addresses)
            if validators_addresses is None
            else validators_addresses,
            dict(self.current_miner_shield_state.address_manager_state)
            if address_manager_state is None
            else address_manager_state,
            dict(self.current_miner_shield_state.address_manager_created_objects)
            if address_manager_created_objects is None
            else address_manager_created_objects,
        )

    def _state_add_validator(
        self, validator_hotkey: Hotkey, validator_public_key: PublicKey, redirect_address: ShieldAddress
    ):
        """
        Add new validator to current state. Should be called only after updating state in storage.
        """
        known_validators: dict[Hotkey, PublicKey] = dict(self.current_miner_shield_state.known_validators)
        assert validator_hotkey not in known_validators, 'storage should not allow adding same validator'
        known_validators[validator_hotkey] = validator_public_key

        validators_addresses: dict[Hotkey, ShieldAddress] = dict(self.current_miner_shield_state.validators_addresses)
        assert validator_hotkey not in validators_addresses, 'storage should not allow adding same validator'
        validators_addresses[validator_hotkey] = redirect_address

        self._update_state(known_validators=known_validators, validators_addresses=validators_addresses)

    def _state_update_validator_public_key(self, validator_hotkey: Hotkey, validator_public_key: PublicKey):
        """
        Update validator in current state. Should be called only after updating state in storage.
        """
        known_validators: dict[Hotkey, PublicKey] = dict(self.current_miner_shield_state.known_validators)
        assert validator_hotkey in known_validators, 'updating storage should fail when validator does not exists'
        known_validators[validator_hotkey] = validator_public_key
        self._update_state(known_validators=known_validators)

    def _state_add_banned_validator(self, validator_hotkey: Hotkey, ban_time: datetime):
        """
        Add new banned validator to current state. Should be called only after updating state in storage.
        """
        banned_validators: dict[Hotkey, datetime] = dict(self.current_miner_shield_state.banned_validators)
        assert validator_hotkey not in banned_validators, 'time should be updated only when adding new ban'
        banned_validators[validator_hotkey] = ban_time
        self._update_state(banned_validators=banned_validators)

    def _state_remove_banned_validator(self, validator_hotkey: Hotkey):
        """
        Remove banned validator from current state. Should be called only after updating state in storage.
        """
        banned_validators: dict[Hotkey, datetime] = dict(self.current_miner_shield_state.banned_validators)
        banned_validators.pop(validator_hotkey)
        self._update_state(banned_validators=banned_validators)

    def _state_remove_validator(self, validator_hotkey: Hotkey):
        """
        Remove validator from current state. Should be called only after updating state in storage.
        """
        known_validators: dict[Hotkey, PublicKey] = dict(self.current_miner_shield_state.known_validators)
        assert validator_hotkey in known_validators, 'storage should not allow removing non-existent validator'
        known_validators.pop(validator_hotkey)
        validators_addresses: dict[Hotkey, ShieldAddress] = dict(self.current_miner_shield_state.validators_addresses)
        assert validator_hotkey in validators_addresses, 'storage should not allow removing non-existent validator'
        validators_addresses.pop(validator_hotkey)
        self._update_state(known_validators=known_validators, validators_addresses=validators_addresses)

    def _state_update_address_manager_state(self, key: str, value: str | None):
        """
        Updates AddressManager state in current shield state. Should be called only after updating state in storage.
        """
        address_manager_state: dict[str, str] = dict(self.current_miner_shield_state.address_manager_state)
        if value is None:
            address_manager_state.pop(key, None)
        else:
            address_manager_state[key] = value
        self._update_state(address_manager_state=address_manager_state)

    def _state_add_address_manager_created_object(self, obj_type: str, obj_id: str):
        """
        Add object to objects created by AddressManager. Should be called only after updating state in storage.
        """
        address_manager_created_objects: dict[str, frozenset[str]] = dict(
            self.current_miner_shield_state.address_manager_created_objects
        )
        if obj_type not in address_manager_created_objects:
            address_manager_created_objects[obj_type] = frozenset([obj_id])
        else:
            address_manager_created_objects[obj_type] = address_manager_created_objects[obj_type] | frozenset([obj_id])
        self._update_state(address_manager_created_objects=address_manager_created_objects)

    def _state_del_address_manager_created_object(self, obj_type: str, obj_id: str):
        """
        Remove object from objects created by AddressManager. Should be called only after updating state in storage.
        """
        address_manager_created_objects: dict[str, frozenset[str]] = dict(
            self.current_miner_shield_state.address_manager_created_objects
        )
        if obj_type not in address_manager_created_objects:
            return
        address_manager_created_objects[obj_type] = frozenset(
            o for o in address_manager_created_objects[obj_type] if o != obj_id
        )
        if not address_manager_created_objects[obj_type]:
            address_manager_created_objects.pop(obj_type)
        self._update_state(address_manager_created_objects=address_manager_created_objects)


class MinerShieldStateDeclarativeBase(DeclarativeBase):
    pass


class SqlValidator(MinerShieldStateDeclarativeBase):
    __tablename__ = 'validators'
    hotkey = Column(String, primary_key=True)
    public_key = Column(String, nullable=False)
    address_id = Column(String, ForeignKey('addresses.address_id', ondelete='CASCADE'), nullable=False)


class SqlAddress(MinerShieldStateDeclarativeBase):
    __tablename__ = 'addresses'
    address_id = Column(String, primary_key=True)
    address = Column(String, nullable=False)
    port = Column(Integer, nullable=False)


class SqlBannedValidator(MinerShieldStateDeclarativeBase):
    __tablename__ = 'banned_validators'
    hotkey = Column(String, primary_key=True)
    ban_time = Column(DateTime, nullable=False)


class SqlAddressManagerState(MinerShieldStateDeclarativeBase):
    __tablename__ = 'address_manager_state'
    key = Column(String, primary_key=True)
    value = Column(String, nullable=False)


class SqlAddressManagerCreatedObjects(MinerShieldStateDeclarativeBase):
    __tablename__ = 'address_manager_created_objects'
    object_type = Column(String, nullable=False)
    object_id = Column(String, nullable=False)
    __table_args__ = (PrimaryKeyConstraint('object_type', 'object_id', name='pk_object_type_object_id'),)


class SQLAlchemyMinerShieldStateManager(AbstractMinerShieldStateManager):
    """
    StateManager implementation using SQLAlchemy.
    """

    engine: Engine
    session_maker: sessionmaker

    def __init__(self, db_url: str | url.URL):
        """
        Args:
            db_url: URL of database to connect to. Should be in format accepted by SQLAlchemy - see create_engine doc.
        """
        super().__init__()
        self.engine = create_engine(db_url)
        MinerShieldStateDeclarativeBase.metadata.create_all(self.engine)
        self.session_maker = sessionmaker(bind=self.engine)

    def clear_tables(self):
        MinerShieldStateDeclarativeBase.metadata.drop_all(self.engine)
        MinerShieldStateDeclarativeBase.metadata.create_all(self.engine)

    def add_validator(self, validator_hotkey: Hotkey, validator_public_key: PublicKey, redirect_address: ShieldAddress):
        with self.session_maker() as session:
            session.add(
                SqlValidator(
                    hotkey=validator_hotkey, public_key=validator_public_key, address_id=redirect_address.address_id
                )
            )
            session.add(
                SqlAddress(
                    address_id=redirect_address.address_id,
                    address=redirect_address.address,
                    port=redirect_address.port,
                )
            )
            session.commit()

        self._state_add_validator(validator_hotkey, validator_public_key, redirect_address)

    def update_validator_public_key(self, validator_hotkey: Hotkey, validator_public_key: PublicKey):
        with self.session_maker() as session:
            validator = session.query(SqlValidator).filter_by(hotkey=validator_hotkey).one()
            validator.public_key = validator_public_key
            session.commit()

        self._state_update_validator_public_key(validator_hotkey, validator_public_key)

    def add_banned_validator(self, validator_hotkey: Hotkey):
        if validator_hotkey in self.current_miner_shield_state.banned_validators:
            # Do not update ban time
            return

        ban_time: datetime = datetime.now()

        with self.session_maker() as session:
            session.add(SqlBannedValidator(hotkey=validator_hotkey, ban_time=ban_time))
            session.commit()

        self._state_add_banned_validator(validator_hotkey, ban_time)

    def remove_banned_validator(self, validator_hotkey: Hotkey):
        if validator_hotkey not in self.current_miner_shield_state.banned_validators:
            return

        with self.session_maker() as session:
            validator = session.query(SqlBannedValidator).filter_by(hotkey=validator_hotkey).one()
            session.delete(validator)
            session.commit()

        self._state_remove_banned_validator(validator_hotkey)

    def remove_validator(self, validator_hotkey: Hotkey):
        with self.session_maker() as session:
            validator = session.query(SqlValidator).filter_by(hotkey=validator_hotkey).one()
            session.delete(validator)
            session.commit()

        self._state_remove_validator(validator_hotkey)

    def update_address_manager_state(self, key: str, value: str | None):
        with self.session_maker() as session:
            if value is None:
                # Remove the key from the database if the value is None
                session.query(SqlAddressManagerState).filter_by(key=key).delete()
            else:
                # Insert or update the key-value pair in the database
                state = session.query(SqlAddressManagerState).filter_by(key=key).one_or_none()
                if state is None:
                    session.add(SqlAddressManagerState(key=key, value=value))
                else:
                    state.value = value
            session.commit()

        self._state_update_address_manager_state(key, value)

    def add_address_manager_created_object(self, obj_type: str, obj_id: str):
        with self.session_maker() as session:
            session.add(SqlAddressManagerCreatedObjects(object_type=obj_type, object_id=obj_id))
            session.commit()

        self._state_add_address_manager_created_object(obj_type, obj_id)

    def del_address_manager_created_object(self, obj_type: str, obj_id: str):
        with self.session_maker() as session:
            session.query(SqlAddressManagerCreatedObjects).filter_by(object_type=obj_type, object_id=obj_id).delete()
            session.commit()

        self._state_del_address_manager_created_object(obj_type, obj_id)

    def _load_state_from_storage(self) -> MinerShieldState:
        with self.session_maker() as session:
            # noinspection PyTypeChecker
            known_validators: dict[Hotkey, PublicKey] = {
                v.hotkey: v.public_key for v in session.query(SqlValidator).all()
            }
            # noinspection PyTypeChecker
            banned_validators: dict[Hotkey, datetime] = {
                b.hotkey: b.ban_time for b in session.query(SqlBannedValidator).all()
            }
            # noinspection PyTypeChecker
            validators_addresses: dict[Hotkey, ShieldAddress] = {
                v.hotkey: self._load_address(session, v.address_id) for v in session.query(SqlValidator).all()
            }

            # noinspection PyTypeChecker
            address_manager_state: dict[str, str] = {
                s.key: s.value for s in session.query(SqlAddressManagerState).all()
            }

            tmp_address_manager_created_objects: defaultdict[str, set[str]] = defaultdict(set)
            for obj in session.query(SqlAddressManagerCreatedObjects).all():
                # noinspection PyTypeChecker
                tmp_address_manager_created_objects[obj.object_type].add(obj.object_id)

        address_manager_created_objects: dict[str, frozenset[str]] = {}
        for obj_type in tmp_address_manager_created_objects:
            address_manager_created_objects[obj_type] = frozenset(tmp_address_manager_created_objects[obj_type])

        return MinerShieldState(
            known_validators,
            banned_validators,
            validators_addresses,
            address_manager_state,
            address_manager_created_objects,
        )

    @classmethod
    def _load_address(cls, session, address_id: str) -> ShieldAddress:
        db_address = session.query(SqlAddress).filter_by(address_id=address_id).one()
        return ShieldAddress(
            address_id=db_address.address_id,
            address=db_address.address,
            port=db_address.port,
        )
