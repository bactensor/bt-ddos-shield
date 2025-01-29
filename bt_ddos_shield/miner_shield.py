import argparse
import functools
import logging
import re
import sys
import threading
from abc import ABC, abstractmethod
from queue import Queue
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from time import sleep
from types import MappingProxyType
from typing import Optional

import bittensor
import bittensor_wallet

from bt_ddos_shield.address import Address, AddressType
from bt_ddos_shield.address_manager import AbstractAddressManager, AwsAddressManager
from bt_ddos_shield.blockchain_manager import (
    AbstractBlockchainManager,
    BittensorBlockchainManager,
)
from bt_ddos_shield.encryption_manager import AbstractEncryptionManager, ECIESEncryptionManager
from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor, PrintingMinerShieldEventProcessor
from bt_ddos_shield.manifest_manager import (
    AbstractManifestManager,
    AbstractManifestSerializer,
    JsonManifestSerializer,
    Manifest,
    ManifestDeserializationException,
    ManifestNotFoundException,
    S3ManifestManager,
)
from bt_ddos_shield.state_manager import (
    AbstractMinerShieldStateManager,
    MinerShieldState,
    SQLAlchemyMinerShieldStateManager,
)
from bt_ddos_shield.utils import AWSClientFactory, Hotkey, PublicKey
from bt_ddos_shield.validators_manager import AbstractValidatorsManager, BittensorValidatorsManager


class MinerShieldOptions(BaseModel):
    """
    A class to represent the configuration options for the MinerShield.
    """

    auto_hide_original_server: bool = False
    """
    If True, the original server will be hidden after some time after shield gets enabled. Method hide_original_server
    in AddressManager will be called.
    """

    auto_hide_delay_sec: int = 1200
    """ Time in seconds after which the original server will be hidden if auto_hide_original_server is set to True. """

    retry_delay_sec: int = 5
    """ Time in seconds to wait before retrying failed task. """

    validate_interval_sec: int = 120
    """
    Time in seconds between cyclic calls of validate task. It checks if every part of shield is working
    correctly.
    """


class MinerShieldException(Exception):
    pass


class MinerShieldDisabledException(MinerShieldException):
    """
    Exception raised when shield is disabled and user want to schedule some action to it.
    """
    pass


class MinerShield:
    """
    Main class to be used by Miner to shield himself from DDoS. Call enable() to start the shield. No methods in
    managers should be called directly. All operations are done by worker thread. After starting shield user can
    schedule tasks to be executed asynchronously.
    """

    worker_thread: Optional[threading.Thread]  # main thread executing tasks
    task_queue: Queue['AbstractMinerShieldTask']  # queue of tasks to be executed
    run: bool  # flag meaning if shield is running
    finishing: bool  # flag meaning if shield should finish its work
    ticker: threading.Event  # ticker to be used in ticker_thread
    ticker_thread: Optional[threading.Thread]  # thread used to schedule validate operation cyclically
    validators_manager: AbstractValidatorsManager  # used to manage validators and their keys
    address_manager: AbstractAddressManager  # used to manage public IP/domain addresses assigned to validators
    manifest_manager: AbstractManifestManager  # used to manage publishing manifest file
    blockchain_manager: AbstractBlockchainManager  # used to manage blockchain operations
    state_manager: AbstractMinerShieldStateManager  # used to manage state of the shield
    event_processor: AbstractMinerShieldEventProcessor  # used to handle events generated by the shield
    options: MinerShieldOptions  # configuration options for shield

    def __init__(self, validators_manager: AbstractValidatorsManager,
                 address_manager: AbstractAddressManager, manifest_manager: AbstractManifestManager,
                 blockchain_manager: AbstractBlockchainManager, state_manager: AbstractMinerShieldStateManager,
                 event_processor: AbstractMinerShieldEventProcessor, options: MinerShieldOptions):
        self.validators_manager = validators_manager
        self.address_manager = address_manager
        self.manifest_manager = manifest_manager
        self.blockchain_manager = blockchain_manager
        self.state_manager = state_manager
        self.event_processor = event_processor
        self.options = options

        self.worker_thread = None
        self.task_queue = Queue()
        self.run = False
        self.finishing = False
        self.ticker = threading.Event()
        self.ticker_thread = None

    def enable(self):
        """
        Enable shield. It starts worker thread, which will do such steps if run for the first time:
        1. Fetch validators keys.
        2. Creates addresses for all validators.
        3. Save manifest file.
        4. Publish link to manifest file to blockchain.
        5. Eventually close public access to original IP after some time.

        It puts events to event_manager after each finished operation. Current state is managed by state_manager.
        If any error occurs it is retried forever until shield is disabled.

        When shield is running, user can schedule tasks to be processed by worker.
        """
        if self.worker_thread is not None:
            # already started
            return

        self.finishing = False
        self.ticker.clear()
        self.run = True
        self._add_task(MinerShieldInitializeTask())
        self.worker_thread = threading.Thread(target=self._worker_function)
        self.worker_thread.start()

    def disable(self):
        """
        Disable shield. It stops worker thread after finishing current task. Function blocks until worker is stopped.
        """
        self._add_task(MinerShieldDisableTask())

        self.finishing = True
        self.ticker.set()

        if self.worker_thread is not None:
            self.worker_thread.join()
            self.worker_thread = None

        self.task_queue = Queue()  # Clear task queue

        if self.ticker_thread is not None:
            self.ticker_thread.join()
            self.ticker_thread = None

    def ban_validator(self, validator_hotkey: Hotkey):
        """
        Ban a validator by its hotkey. Task will be executed by worker. It will update manifest file and publish info
        about new file version to blockchain.
        """
        self._add_task(MinerShieldBanValidatorTask(validator_hotkey))

    def _add_task(self, task: 'AbstractMinerShieldTask'):
        """
        Add task to task queue. It will be handled by _worker_function.
        """
        if not self.run:
            raise MinerShieldDisabledException()

        self.task_queue.put(task)

    def _worker_function(self):
        """
        Function called in separate thread by enable() to start the shield. It is handling events put to task_queue.
        """
        self._event("Starting shield")

        while self.run:
            task: AbstractMinerShieldTask = self.task_queue.get()
            try_count: int = 1

            while self.run:
                self._event("Handling task {task}, try {try_count}", task=task, try_count=try_count)

                try:
                    task.run(self)
                    self._event("Task {task} finished successfully", task=task)
                    break
                except Exception as e:
                    self._event("Error during handling task {task}", e, task=task)

                    if self.finishing:
                        break

                    try_count += 1
                    sleep(self.options.retry_delay_sec)

            self.task_queue.task_done()

        self._event("Stopping shield")

    def _ticker_function(self):
        while not self.ticker.wait(self.options.validate_interval_sec):
            self._add_task(MinerShieldValidateStateTask())

    def _handle_initialize(self):
        self._handle_validate_state(first_run=True)
        self.ticker_thread = threading.Thread(target=self._ticker_function)
        self.ticker_thread.start()

    def _reload_state(self, first_run: bool):
        try:
            self.state_manager.get_state(reload=True)
            self._event("State reloaded")
        except Exception as e:
            self._event("Error during reloading state", e)
            if first_run:
                # We cannot continue without initial shield state
                raise e

    def _reload_validators(self, first_run: bool) -> bool:
        """
        Reload validators from validators manager.

        Returns:
             bool: If validators set is different from one currently stored in shield state.
        """
        try:
            self.validators_manager.reload_validators()
            fetched_validators: MappingProxyType[Hotkey, PublicKey] = self.validators_manager.get_validators()

            deprecated_validators, new_validators, changed_validators = \
                self._calculate_validators_diff(self.state_manager.get_state(), fetched_validators)
            validators_changed: bool = bool(deprecated_validators) or bool(new_validators) or bool(changed_validators)

            self._event("Validators reloaded, got {validators_count} validators, "
                        "validators_changed={validators_changed}",
                        validators_count=len(fetched_validators), validators_changed=validators_changed)

            return validators_changed
        except Exception as e:
            self._event("Error during reloading validators", e)
            if first_run:
                # We cannot continue without initial validators state
                raise e

        return False

    def _validate_addresses(self, first_run: bool) -> bool:
        """
        Validate addresses used by validators. Remove validators with invalid addresses from shield state - they will
        be added again with new addresses in a moment.

        Returns:
             bool: If any validators were removed.
        """
        validators_changed: bool = False
        try:
            current_state: MinerShieldState = self.state_manager.get_state()
            invalid_addresses: set[Hotkey] = self.address_manager.validate_addresses(current_state.validators_addresses)
            if invalid_addresses:
                self._event("Removing invalid addresses for given validators: {invalid_addresses}",
                            invalid_addresses=invalid_addresses)
                for validator in invalid_addresses:
                    self.state_manager.remove_validator(validator)
                    validators_changed = True
        except Exception as e:
            self._event("Error during validating addresses", e)
            if first_run:
                # We cannot continue without initializing address_manager
                raise e
            # If error happens later, just proceed. It is only validation, and it will be called again
            # by _ticker_function.

        return validators_changed

    def _validate_manifest_file(self) -> bool:
        """
        Validate manifest file by comparing uploaded content with expected one. Returns if it is valid.
        """
        try:
            current_state: MinerShieldState = self.state_manager.get_state()
            current_manifest: Manifest = self.manifest_manager.get_manifest(self.manifest_manager.get_manifest_url())
            new_manifest: Manifest = self.manifest_manager.create_manifest(current_state.validators_addresses,
                                                                           current_state.known_validators)
            same_content: bool = new_manifest.md5_hash == current_manifest.md5_hash
            self._event("Manifest file validation finished, same content={same_content}",
                        same_content=same_content)
            return same_content
        except (ManifestNotFoundException, ManifestDeserializationException):
            return False
        except Exception as e:
            self._event("Error during validating manifest file", e)
            # If error happened, assume that manifest file is valid - it is only validation, and it will be called
            # again by _ticker_function
            return True

    def _handle_validate_state(self, first_run: bool = False):
        """
        Refresh all data and validate current state of shield. If shield is not yet fully working, it will finish
        startup process. If something is wrong, it will be fixed.
        """
        self._reload_state(first_run)
        validators_changed: bool = self._reload_validators(first_run)
        if self._validate_addresses(first_run):
            validators_changed = True

        if validators_changed:
            self._add_task(MinerShieldValidatorsChangedTask())
            # do not validate manifest, because it will be updated in the moment
            return

        if not self._validate_manifest_file():
            self._add_task(MinerShieldUpdateManifestTask())
            # do not validate manifest info, because it will be updated in the moment
            return

        # this will validate manifest info and will publish new one only if needed
        self._add_task(MinerShieldPublishManifestTask())

    def _handle_disable(self):
        self.run = False

    @classmethod
    def _calculate_validators_diff(cls, current_state: MinerShieldState,
                                   fetched_validators: MappingProxyType[Hotkey, PublicKey]):
        """
        Calculates difference between newly fetched validators set and one saved in state and returns validators
        which should be removed, added or updated.
        """
        # remove banned validators from fetched validators
        fetched_not_banned_validators: dict[Hotkey, PublicKey] = dict(fetched_validators)
        for banned_validator in current_state.banned_validators.keys():
            fetched_not_banned_validators.pop(banned_validator, None)

        # calculate difference between current state and fetched validators
        deprecated_validators = current_state.known_validators.keys() - fetched_not_banned_validators.keys()
        new_validators = fetched_not_banned_validators.keys() - current_state.known_validators.keys()
        common_validators = fetched_not_banned_validators.keys() & current_state.known_validators.keys()
        changed_validators = {
            k: fetched_not_banned_validators[k] for k in common_validators
            if fetched_not_banned_validators[k] != current_state.known_validators[k]
        }

        return deprecated_validators, new_validators, changed_validators

    def _handle_deprecated_validators(self, current_state: MinerShieldState, deprecated_validators: set[Hotkey]):
        for validator in deprecated_validators:
            self._event("Removing validator {validator}", validator=validator)

            active_validator_addresses = current_state.validators_addresses
            if validator in active_validator_addresses:
                self.address_manager.remove_address(active_validator_addresses[validator])

            self.state_manager.remove_validator(validator)

    def _handle_new_validators(self, fetched_validators: MappingProxyType[Hotkey, PublicKey],
                               new_validators: set[Hotkey]):
        for validator in new_validators:
            self._event("Adding validator {validator}", validator=validator)

            new_address: Address = self.address_manager.create_address(validator)

            try:
                self.state_manager.add_validator(validator, fetched_validators[validator], new_address)
            except Exception as e:
                self.address_manager.remove_address(new_address)
                raise e

    def _handle_changed_validators(self, changed_validators: dict[Hotkey, PublicKey]):
        for validator, new_key in changed_validators.items():
            self._event("Updating validator {validator}", validator=validator)
            self.state_manager.update_validator_public_key(validator, new_key)

    def _handle_validators_change(self):
        current_state: MinerShieldState = self.state_manager.get_state()
        fetched_validators: MappingProxyType[Hotkey, PublicKey] = self.validators_manager.get_validators()

        deprecated_validators, new_validators, changed_validators = \
            self._calculate_validators_diff(current_state, fetched_validators)

        self._event(
            "Handling validators change, deprecated_validators count={deprecated_validators_count}"
            ", new_validators count={new_validators_count}, changed_validators count={changed_validators_count}",
            deprecated_validators_count=len(deprecated_validators), new_validators_count=len(new_validators),
            changed_validators_count=len(changed_validators)
        )

        self._handle_deprecated_validators(current_state, deprecated_validators)
        self._handle_new_validators(fetched_validators, new_validators)
        self._handle_changed_validators(changed_validators)

        if deprecated_validators or new_validators or changed_validators:
            # if anything changed update manifest file and publish new version to blockchain
            self._add_task(MinerShieldUpdateManifestTask())

    def _handle_ban_validator(self, validator_hotkey: Hotkey):
        """
        Ban validator by its hotkey. If something changed, MinerShieldValidatorsChangedTask will apply asynchronously
        this change where needed.
        """
        self.state_manager.add_banned_validator(validator_hotkey)
        self._event("Validator {validator_hotkey} added to banned set", validator_hotkey=validator_hotkey)
        self._add_task(MinerShieldValidatorsChangedTask())

    def _handle_update_manifest(self):
        """
        Update manifest file and schedule publishing it to blockchain.
        """
        current_state: MinerShieldState = self.state_manager.get_state()
        manifest: Manifest = self.manifest_manager.create_manifest(current_state.validators_addresses,
                                                                   current_state.known_validators)
        self.manifest_manager.upload_manifest(manifest)
        self._event("Manifest updated, new address: {address}",
                    address=self.manifest_manager.get_manifest_url())
        self._add_task(MinerShieldPublishManifestTask())

    def _handle_publish_manifest(self):
        """
        Publish info about current manifest file to blockchain if it is not already there.
        """
        expected_url: str = self.manifest_manager.get_manifest_url()
        current_url: str = self.blockchain_manager.get_miner_manifest_address()
        if current_url == expected_url:
            self._event("Manifest address already published")
        else:
            self.blockchain_manager.put_miner_manifest_address(expected_url)
            self._event("Manifest published")

    def _event(self, template: str, exception: Exception = None, **kwargs):
        return self.event_processor.event(template, exception, **kwargs)


class AbstractMinerShieldTask(ABC):
    """
    Task to be executed by shield worker.
    """

    NAME_DELETER = re.compile(r'^MinerShield(.*)Task$')

    @abstractmethod
    def run(self, miner_shield: MinerShield):
        """
        Run task in miner_shield context.
        """
        pass

    def __repr__(self):
        return self.NAME_DELETER.sub(r'\1', self.__class__.__name__)


class MinerShieldInitializeTask(AbstractMinerShieldTask):
    def run(self, miner_shield: MinerShield):
        # noinspection PyProtectedMember
        miner_shield._handle_initialize()


class MinerShieldDisableTask(AbstractMinerShieldTask):
    def run(self, miner_shield: MinerShield):
        # noinspection PyProtectedMember
        miner_shield._handle_disable()


class MinerShieldValidateStateTask(AbstractMinerShieldTask):
    def run(self, miner_shield: MinerShield):
        # noinspection PyProtectedMember
        miner_shield._handle_validate_state()


class MinerShieldValidatorsChangedTask(AbstractMinerShieldTask):
    def run(self, miner_shield: MinerShield):
        # noinspection PyProtectedMember
        miner_shield._handle_validators_change()


class MinerShieldBanValidatorTask(AbstractMinerShieldTask):
    def __init__(self, validator_hotkey: Hotkey):
        self.validator_hotkey = validator_hotkey

    def run(self, miner_shield: MinerShield):
        # noinspection PyProtectedMember
        miner_shield._handle_ban_validator(self.validator_hotkey)


class MinerShieldUpdateManifestTask(AbstractMinerShieldTask):
    def run(self, miner_shield: MinerShield):
        # noinspection PyProtectedMember
        miner_shield._handle_update_manifest()


class MinerShieldPublishManifestTask(AbstractMinerShieldTask):
    def run(self, miner_shield: MinerShield):
        # noinspection PyProtectedMember
        miner_shield._handle_publish_manifest()


class SubtensorSettings(BaseModel):
    network: Optional[str] = None

    @functools.cached_property
    def client(self) -> bittensor.Subtensor:
        return bittensor.Subtensor(
            **self.model_dump()
        )


class WalletSettings(BaseModel):
    name: Optional[str] = None
    hotkey: Optional[str] = None
    path: Optional[str] = None

    @functools.cached_property
    def instance(self) -> bittensor_wallet.Wallet:
        return bittensor.Wallet(
            **self.model_dump()
        )


class ShieldSettings(BaseSettings):
    aws_access_key_id: str = Field(min_length=1)
    aws_secret_access_key: str = Field(min_length=1)
    aws_region_name: str = Field(min_length=1)
    """AWS region name where shield will be created"""
    aws_s3_bucket_name: str = Field(min_length=1)
    """AWS S3 bucket name where manifest file will be stored"""
    aws_route53_hosted_zone_id: str = Field(min_length=1)
    """AWS Route53 hosted zone ID for creating DNS entries for server clients"""
    aws_miner_instance_id: str = ''
    """AWS instance ID of miner server"""
    aws_miner_instance_ip: str = ''
    """AWS instance IP of miner server"""
    miner_instance_port: int
    """Port on which miner server is listening"""
    sql_alchemy_db_url: str = Field('sqlite:///ddos_shield.db', min_length=1)
    """SQL Alchemy URL to database where shield state is stored"""
    options: MinerShieldOptions = MinerShieldOptions()

    netuid: int
    subtensor: SubtensorSettings = SubtensorSettings()
    wallet: WalletSettings = WalletSettings()

    model_config = {
        'env_file': '.env',
        'env_nested_delimiter': '__',
    }


class MinerShieldFactory:
    """
    Factory class to create proper MinerShield instance basing on set environmental variables.
    """

    @classmethod
    def create_miner_shield(cls, settings: ShieldSettings,
                            validators: Optional[dict[Hotkey, PublicKey]] = None) -> MinerShield:
        """
        Args:
            settings: ShieldSettings instance.
            validators: Dictionary containing validators hotkeys and their public keys.
        """
        validators_manager: AbstractValidatorsManager = cls.create_validators_manager(settings, validators)
        event_processor: AbstractMinerShieldEventProcessor = cls.create_event_processor()
        state_manager: AbstractMinerShieldStateManager = cls.create_state_manager(settings)
        aws_client_factory: AWSClientFactory = cls.create_aws_client_factory(settings)
        address_manager: AbstractAddressManager = cls.create_address_manager(settings, aws_client_factory,
                                                                             event_processor, state_manager)
        encryption_manager: AbstractEncryptionManager = cls.create_encryption_manager()
        manifest_manager: AbstractManifestManager = cls.create_manifest_manager(settings, encryption_manager,
                                                                                aws_client_factory)
        blockchain_manager: AbstractBlockchainManager = cls.create_blockchain_manager(settings)

        if settings.options.auto_hide_original_server:
            raise MinerShieldException('Autohiding is not implemented yet')

        return MinerShield(validators_manager, address_manager, manifest_manager, blockchain_manager, state_manager,
                           event_processor, settings.options)

    @classmethod
    def create_validators_manager(
        cls,
        settings: ShieldSettings,
        validators: Optional[dict[Hotkey, PublicKey]] = None,
    ) -> AbstractValidatorsManager:
        return BittensorValidatorsManager(
            subtensor=settings.subtensor.client,
            netuid=settings.netuid,
            validators=validators,
        )

    @classmethod
    def create_event_processor(cls) -> AbstractMinerShieldEventProcessor:
        return PrintingMinerShieldEventProcessor()

    @classmethod
    def create_state_manager(cls, settings: ShieldSettings) -> AbstractMinerShieldStateManager:
        return SQLAlchemyMinerShieldStateManager(settings.sql_alchemy_db_url)

    @classmethod
    def create_aws_client_factory(cls, settings: ShieldSettings) -> AWSClientFactory:
        return AWSClientFactory(settings.aws_access_key_id, settings.aws_secret_access_key, settings.aws_region_name)

    @classmethod
    def load_miner_aws_address(cls, settings: ShieldSettings):
        if settings.aws_miner_instance_id:
            address = settings.aws_miner_instance_id
        elif settings.aws_miner_instance_ip:
            address = settings.aws_miner_instance_ip
        else:
            raise MinerShieldException("AWS_MINER_INSTANCE_ID or AWS_MINER_INSTANCE_IP env is not set")

        return Address(address_id="miner", address_type=AddressType.EC2, address=address,
                       port=settings.miner_instance_port)

    @classmethod
    def create_address_manager(cls, settings: ShieldSettings, aws_client_factory: Optional[AWSClientFactory],
                               event_processor: AbstractMinerShieldEventProcessor,
                               state_manager: AbstractMinerShieldStateManager) -> AbstractAddressManager:
        if aws_client_factory:
            return cls.create_aws_address_manager(settings, aws_client_factory, event_processor, state_manager)
        else:
            raise MinerShieldException("Cannot create address manager")

    @classmethod
    def create_aws_address_manager(cls, settings: ShieldSettings, aws_client_factory: AWSClientFactory,
                                   event_processor: AbstractMinerShieldEventProcessor,
                                   state_manager: AbstractMinerShieldStateManager) -> AbstractAddressManager:
        miner_address: Address = cls.load_miner_aws_address(settings)
        return AwsAddressManager(aws_client_factory, miner_address, settings.aws_route53_hosted_zone_id,
                                 event_processor, state_manager)

    @classmethod
    def create_encryption_manager(cls) -> AbstractEncryptionManager:
        return ECIESEncryptionManager()

    @classmethod
    def create_manifest_manager(cls, settings: ShieldSettings, encryption_manager: AbstractEncryptionManager,
                                aws_client_factory: AWSClientFactory) -> AbstractManifestManager:
        manifest_serializer: AbstractManifestSerializer = JsonManifestSerializer()
        return S3ManifestManager(manifest_serializer, encryption_manager, aws_client_factory,
                                 settings.aws_s3_bucket_name)

    @classmethod
    def create_blockchain_manager(
        cls,
        settings: ShieldSettings,
    ) -> AbstractBlockchainManager:
        return BittensorBlockchainManager(
            netuid=settings.netuid,
            subtensor=settings.subtensor.client,
            wallet=settings.wallet.instance,
        )


def run_shield() -> int:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    parser = argparse.ArgumentParser(description='MinerShield')
    subparsers = parser.add_subparsers(dest='command', help='Subcommands')
    subparsers.add_parser('start', help='Start the MinerShield')
    subparsers.add_parser('clean', help='Clean all stuff created by shield, especially AWS objects')
    args = parser.parse_args()

    settings: ShieldSettings = ShieldSettings()  # type: ignore
    miner_shield: MinerShield = MinerShieldFactory.create_miner_shield(settings, {})

    if args.command == 'clean':
        logging.info("Cleaning shield objects")
        miner_shield.address_manager.clean_all()
        logging.info("All objects cleaned")
        return 0

    if args.command == 'start' or args.command is None:
        try:
            logging.info("Starting shield")
            miner_shield.enable()
            logging.info("Shield started, press Ctrl+C to stop")
            threading.Event().wait()
            return -1
        except KeyboardInterrupt:
            logging.info("Keyboard interrupt, stopping shield")
            miner_shield.disable()
            return 0
        except MinerShieldException:
            logging.exception("Error during enabling shield")
            return 1


if __name__ == '__main__':
    sys.exit(run_shield())
