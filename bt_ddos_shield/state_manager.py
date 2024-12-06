from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime
from types import MappingProxyType
from typing import Optional, Union
from sqlalchemy import create_engine, Column, String, DateTime, ForeignKey, Integer, CheckConstraint, Engine, \
    PrimaryKeyConstraint
from sqlalchemy.engine import url
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from bt_ddos_shield.address import Address, AddressType
from bt_ddos_shield.utils import Hotkey, PublicKey


class MinerShieldState:
    _known_validators: dict[Hotkey, PublicKey]
    _banned_validators: dict[Hotkey, datetime]
    _validators_addresses: dict[Hotkey, Address]
    _manifest_address: Optional[Address]
    _address_manager_state: dict[str, str]
    _address_manager_created_objects: dict[str, frozenset[str]]

    def __init__(self, known_validators: dict[Hotkey, PublicKey], banned_validators: dict[Hotkey, datetime],
                 validators_addresses: dict[Hotkey, Address], manifest_address: Optional[Address],
                 address_manager_state: dict[str, str],
                 address_manager_created_objects: dict[str, frozenset[str]]):
        super().__setattr__('_known_validators', known_validators)
        super().__setattr__('_banned_validators', banned_validators)
        super().__setattr__('_validators_addresses', validators_addresses)
        super().__setattr__('_manifest_address', manifest_address)
        super().__setattr__('_address_manager_state', address_manager_state)
        super().__setattr__('_address_manager_created_objects', address_manager_created_objects)

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
    def validators_addresses(self) -> MappingProxyType[Hotkey, Address]:
        """
        Get dictionary of active addresses (validator HotKey -> Address created for him).
        """
        return MappingProxyType(self._validators_addresses)

    @property
    def manifest_address(self) -> Optional[Address]:
        """
        Get manifest file address. If manifest file is not yet uploaded, return None.
        """
        return self._manifest_address

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
        raise AttributeError("State is immutable")

    def __delattr__(self, item):
        raise AttributeError("State is immutable")

    def __eq__(self, other):
        if not isinstance(other, MinerShieldState):
            return False

        return self._known_validators == other._known_validators and \
            self._banned_validators == other._banned_validators and \
            self._validators_addresses == other._validators_addresses and \
            self._manifest_address == other._manifest_address and \
            self._address_manager_state == other._address_manager_state and \
            self._address_manager_created_objects == other._address_manager_created_objects


class AbstractMinerShieldStateManager(ABC):
    """
    Abstract base class for manager handling state of MinerShield. Each change in state should be instantly
    saved to storage.
    """
    current_miner_shield_state: Optional[MinerShieldState]

    def __init__(self):
        self.current_miner_shield_state = None

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
    def update_address_manager_state(self, key: str, value: Optional[str]):
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

    def _update_state(self,
                      known_validators: Optional[dict[Hotkey, PublicKey]] = None,
                      banned_validators: Optional[dict[Hotkey, datetime]] = None,
                      validators_addresses: Optional[dict[Hotkey, Address]] = None,
                      manifest_address: Optional[Address] = None,
                      address_manager_state: Optional[dict[str, str]] = None,
                      address_manager_created_objects: Optional[dict[str, frozenset[str]]] = None):
        """
        Create new updated state with given new values and set it as current state. If value for field is None,
        it is copied from current state.
        """
        self.current_miner_shield_state = \
            MinerShieldState(dict(self.current_miner_shield_state.known_validators)
                             if known_validators is None else known_validators,
                             dict(self.current_miner_shield_state.banned_validators)
                             if banned_validators is None else banned_validators,
                             dict(self.current_miner_shield_state.validators_addresses)
                             if validators_addresses is None else validators_addresses,
                             self.current_miner_shield_state.manifest_address
                             if manifest_address is None else manifest_address,
                             dict(self.current_miner_shield_state.address_manager_state)
                             if address_manager_state is None else address_manager_state,
                             dict(self.current_miner_shield_state.address_manager_created_objects)
                             if address_manager_created_objects is None else address_manager_created_objects)

    def _state_add_validator(self, validator_hotkey: Hotkey, validator_public_key: PublicKey,
                             redirect_address: Address):
        """
        Add new validator to current state. Should be called only after updating state in storage.
        """
        known_validators: dict[Hotkey, PublicKey] = dict(self.current_miner_shield_state.known_validators)
        assert validator_hotkey not in known_validators, "storage should not allow adding same validator"
        known_validators[validator_hotkey] = validator_public_key

        validators_addresses: dict[Hotkey, Address] = dict(self.current_miner_shield_state.validators_addresses)
        assert validator_hotkey not in validators_addresses, "storage should not allow adding same validator"
        validators_addresses[validator_hotkey] = redirect_address

        self._update_state(known_validators=known_validators, validators_addresses=validators_addresses)

    def _state_update_validator_public_key(self, validator_hotkey: Hotkey, validator_public_key: PublicKey):
        """
        Update validator in current state. Should be called only after updating state in storage.
        """
        known_validators: dict[Hotkey, PublicKey] = dict(self.current_miner_shield_state.known_validators)
        assert validator_hotkey in known_validators, "updating storage should fail when validator does not exists"
        known_validators[validator_hotkey] = validator_public_key
        self._update_state(known_validators=known_validators)

    def _state_add_banned_validator(self, validator_hotkey: Hotkey, ban_time: datetime):
        """
        Add new banned validator to current state. Should be called only after updating state in storage.
        """
        banned_validators: dict[Hotkey, datetime] = dict(self.current_miner_shield_state.banned_validators)
        assert validator_hotkey not in banned_validators, "time should be updated only when adding new ban"
        banned_validators[validator_hotkey] = ban_time
        self._update_state(banned_validators=banned_validators)

    def _state_remove_validator(self, validator_hotkey: Hotkey):
        """
        Remove validator from current state. Should be called only after updating state in storage.
        """
        known_validators: dict[Hotkey, PublicKey] = dict(self.current_miner_shield_state.known_validators)
        assert validator_hotkey in known_validators, "storage should not allow removing non-existent validator"
        known_validators.pop(validator_hotkey)
        validators_addresses: dict[Hotkey, Address] = dict(self.current_miner_shield_state.validators_addresses)
        assert validator_hotkey in validators_addresses, "storage should not allow removing non-existent validator"
        validators_addresses.pop(validator_hotkey)
        self._update_state(known_validators=known_validators, validators_addresses=validators_addresses)

    def _state_set_manifest_address(self, manifest_address: Address):
        """
        Update manifest address in current state. Should be called only after updating state in storage.
        """
        self._update_state(manifest_address=manifest_address)

    def _state_update_address_manager_state(self, key: str, value: Optional[str]):
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
        address_manager_created_objects: dict[str, frozenset[str]] = \
            dict(self.current_miner_shield_state.address_manager_created_objects)
        if obj_type not in address_manager_created_objects:
            address_manager_created_objects[obj_type] = frozenset([obj_id])
        else:
            address_manager_created_objects[obj_type] = address_manager_created_objects[obj_type] | frozenset([obj_id])
        self._update_state(address_manager_created_objects=address_manager_created_objects)

    def _state_del_address_manager_created_object(self, obj_type: str, obj_id: str):
        """
        Remove object from objects created by AddressManager. Should be called only after updating state in storage.
        """
        address_manager_created_objects: dict[str, frozenset[str]] = \
            dict(self.current_miner_shield_state.address_manager_created_objects)
        if obj_type not in address_manager_created_objects:
            return
        address_manager_created_objects[obj_type] = \
            frozenset(o for o in address_manager_created_objects[obj_type] if o != obj_id)
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
    address_type = Column(String, nullable=False)
    address = Column(String, nullable=False)
    port = Column(Integer, nullable=False)


class SqlBannedValidator(MinerShieldStateDeclarativeBase):
    __tablename__ = 'banned_validators'
    hotkey = Column(String, primary_key=True)
    ban_time = Column(DateTime, nullable=False)


class SqlManifest(MinerShieldStateDeclarativeBase):
    __tablename__ = 'manifest'
    id = Column(Integer, primary_key=True, default=1)
    address_id = Column(String, ForeignKey('addresses.address_id', ondelete='CASCADE'), nullable=False)
    __table_args__ = (
        CheckConstraint('id = 1', name='single_row_check'),
    )


class SqlAddressManagerState(MinerShieldStateDeclarativeBase):
    __tablename__ = 'address_manager_state'
    key = Column(String, primary_key=True)
    value = Column(String, nullable=False)


class SqlAddressManagerCreatedObjects(MinerShieldStateDeclarativeBase):
    __tablename__ = 'address_manager_created_objects'
    object_type = Column(String, nullable=False)
    object_id = Column(String, nullable=False)
    __table_args__ = (
        PrimaryKeyConstraint('object_type', 'object_id', name='pk_object_type_object_id'),
    )


class SQLAlchemyMinerShieldStateManager(AbstractMinerShieldStateManager):
    """
    StateManager implementation using SQLAlchemy.
    """

    engine: Engine
    session_maker: sessionmaker

    def __init__(self, db_url: Union[str, url.URL]):
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

    def add_validator(self, validator_hotkey: Hotkey, validator_public_key: PublicKey, redirect_address: Address):
        with self.session_maker() as session:
            session.add(SqlValidator(hotkey=validator_hotkey, public_key=validator_public_key,
                                     address_id=redirect_address.address_id))
            session.add(SqlAddress(address_id=redirect_address.address_id,
                                   address_type=redirect_address.address_type.value,
                                   address=redirect_address.address, port=redirect_address.port))
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
            # do not update ban time
            return

        ban_time: datetime = datetime.now()

        with self.session_maker() as session:
            session.add(SqlBannedValidator(hotkey=validator_hotkey, ban_time=ban_time))
            session.commit()

        self._state_add_banned_validator(validator_hotkey, ban_time)

    def remove_validator(self, validator_hotkey: Hotkey):
        with self.session_maker() as session:
            validator = session.query(SqlValidator).filter_by(hotkey=validator_hotkey).one()
            session.delete(validator)
            session.commit()

        self._state_remove_validator(validator_hotkey)

    def set_manifest_address(self, manifest_address: Address):
        with self.session_maker() as session:
            manifest = session.query(SqlManifest).first()
            if manifest is not None:
                db_address = session.query(SqlAddress).filter_by(address_id=manifest.address_id).one()
                session.delete(db_address)

            session.add(SqlAddress(address_id=manifest_address.address_id,
                                   address_type=manifest_address.address_type.value,
                                   address=manifest_address.address, port=manifest_address.port))

            if manifest is None:
                session.add(SqlManifest(address_id=manifest_address.address_id))
            else:
                manifest.address_id = manifest_address.address_id

            session.commit()

        self._state_set_manifest_address(manifest_address)

    def update_address_manager_state(self, key: str, value: Optional[str]):
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
            known_validators: dict[Hotkey, PublicKey] = \
                {v.hotkey: v.public_key for v in session.query(SqlValidator).all()}
            # noinspection PyTypeChecker
            banned_validators: dict[Hotkey, datetime] = \
                {b.hotkey: b.ban_time for b in session.query(SqlBannedValidator).all()}
            # noinspection PyTypeChecker
            validators_addresses: dict[Hotkey, Address] = \
                {v.hotkey: self._load_address(session, v.address_id) for v in session.query(SqlValidator).all()}

            manifest_address: Optional[Address] = None
            manifest_record = session.query(SqlManifest).first()
            if manifest_record is not None:
                # noinspection PyTypeChecker
                manifest_address = self._load_address(session, manifest_record.address_id)

            # noinspection PyTypeChecker
            address_manager_state: dict[str, str] = \
                {s.key: s.value for s in session.query(SqlAddressManagerState).all()}

            tmp_address_manager_created_objects: defaultdict[str, set[str]] = defaultdict(set)
            for obj in session.query(SqlAddressManagerCreatedObjects).all():
                # noinspection PyTypeChecker
                tmp_address_manager_created_objects[obj.object_type].add(obj.object_id)

        address_manager_created_objects: dict[str, frozenset[str]] = {}
        for obj_type in tmp_address_manager_created_objects:
            address_manager_created_objects[obj_type] = frozenset(tmp_address_manager_created_objects[obj_type])

        return MinerShieldState(known_validators, banned_validators, validators_addresses, manifest_address,
                                address_manager_state, address_manager_created_objects)

    @classmethod
    def _load_address(cls, session, address_id: str) -> Address:
        db_address = session.query(SqlAddress).filter_by(address_id=address_id).one()
        return Address(address_id=db_address.address_id,
                       address_type=AddressType(db_address.address_type),
                       address=db_address.address,
                       port=db_address.port)
