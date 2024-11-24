from time import sleep
from typing import Optional

from bt_ddos_shield.address import Address, DefaultAddressSerializer, AddressType
from bt_ddos_shield.address_manager import AwsAddressManager
from bt_ddos_shield.encryption_manager import ECIESEncryptionManager
from bt_ddos_shield.event_processor import PrintingMinerShieldEventProcessor
from bt_ddos_shield.manifest_manager import Manifest, S3ManifestManager, JsonManifestSerializer
from bt_ddos_shield.miner_shield import MinerShield, MinerShieldOptions
from bt_ddos_shield.state_manager import MinerShieldState, SQLAlchemyMinerShieldStateManager
from bt_ddos_shield.utils import Hotkey, PublicKey
from bt_ddos_shield.validators_manager import MemoryValidatorsManager
from tests.test_address_manager import MemoryAddressManager, get_miner_address_from_credentials
from tests.test_blockchain_manager import MemoryBlockchainManager
from tests.test_credentials import aws_access_key_id, aws_secret_access_key, \
    aws_s3_region_name, aws_s3_bucket_name, sql_alchemy_db_url, miner_region_name
from tests.test_encryption_manager import generate_key_pair
from tests.test_manifest_manager import MemoryManifestManager
from tests.test_state_manager import MemoryMinerShieldStateManager


class TestMinerShield:
    """
    Test suite for the MinerShield class.
    """

    MINER_HOTKEY: Hotkey = "miner"
    VALIDATOR_1_HOTKEY: Hotkey = "validator1"
    VALIDATOR_1_PUBLICKEY: PublicKey = generate_key_pair()[1]
    VALIDATOR_2_HOTKEY: Hotkey = "validator2"
    VALIDATOR_2_PUBLICKEY: PublicKey = generate_key_pair()[1]
    VALIDATOR_3_HOTKEY: Hotkey = "validator3"
    VALIDATOR_3_PUBLICKEY: PublicKey = generate_key_pair()[1]
    VALIDATOR_3_OTHER_PUBLICKEY: PublicKey = generate_key_pair()[1]
    VALIDATOR_4_HOTKEY: Hotkey = "validator4"
    VALIDATOR_4_PUBLICKEY: PublicKey = generate_key_pair()[1]
    OTHER_VALIDATOR_HOTKEY: Hotkey = "other_validator"
    DEFAULT_VALIDATORS = {VALIDATOR_1_HOTKEY: VALIDATOR_1_PUBLICKEY, VALIDATOR_2_HOTKEY: VALIDATOR_2_PUBLICKEY,
                          VALIDATOR_3_HOTKEY: VALIDATOR_3_PUBLICKEY}

    @classmethod
    def create_memory_validators_manager(cls, validators: Optional[dict[Hotkey, PublicKey]] = None)\
            -> MemoryValidatorsManager:
        if validators is None:
            validators = cls.DEFAULT_VALIDATORS
        return MemoryValidatorsManager(dict(validators))

    def create_default_shield(self, validate_interval_sec: int = 2):
        self.validators_manager: MemoryValidatorsManager = self.create_memory_validators_manager()
        self.address_manager: MemoryAddressManager = MemoryAddressManager()
        self.manifest_manager: MemoryManifestManager = MemoryManifestManager()
        self.blockchain_manager: MemoryBlockchainManager = MemoryBlockchainManager()
        self.state_manager: MemoryMinerShieldStateManager = MemoryMinerShieldStateManager()
        self.shield = MinerShield(self.MINER_HOTKEY, self.validators_manager, self.address_manager,
                                  self.manifest_manager, self.blockchain_manager, self.state_manager,
                                  PrintingMinerShieldEventProcessor(),
                                  MinerShieldOptions(retry_delay_sec=1, validate_interval_sec=validate_interval_sec))
        self.shield.enable()
        assert self.shield.run

    def test_start_stop_with_exception(self):
        """
        Test if shield is properly starting and stopping when exception is thrown during initialization.
        """
        state_manager = None  # set state_manager to None to force exception during initialization

        # noinspection PyTypeChecker
        shield = MinerShield(self.MINER_HOTKEY, self.create_memory_validators_manager(), MemoryAddressManager(),
                             MemoryManifestManager(), MemoryBlockchainManager(),
                             state_manager, PrintingMinerShieldEventProcessor(), MinerShieldOptions(retry_delay_sec=1))
        shield.enable()
        assert shield.run
        sleep(1)
        shield.disable()
        assert not shield.run

    def test_full_flow(self):
        """
        Test if shield is properly starting from scratch and fully enabling protection using mock memory managers.
        """
        self.create_default_shield()
        sleep(2 + 2*self.shield.options.validate_interval_sec)  # give some time to make sure validate is called

        try:
            state: MinerShieldState = self.state_manager.get_state()
            assert self.validators_manager.get_validators() == self.DEFAULT_VALIDATORS
            assert state.known_validators == self.validators_manager.get_validators()
            assert state.banned_validators == {}
            assert state.validators_addresses.keys() == self.validators_manager.get_validators().keys()
            assert state.manifest_address == self.manifest_manager.default_address
            assert list(state.validators_addresses.values()) == list(self.address_manager.known_addresses.values())
            assert self.address_manager.id_counter == len(state.validators_addresses)
            assert self.manifest_manager.stored_file is not None
            assert self.manifest_manager.put_counter == 1
            manifest_address: Address = self.manifest_manager.default_address
            manifest: Manifest = self.manifest_manager.get_manifest(manifest_address)
            assert manifest.encrypted_address_mapping.keys() == state.validators_addresses.keys()
            assert self.blockchain_manager.get_address(self.MINER_HOTKEY) == manifest_address
            assert self.blockchain_manager.put_counter == 1
        finally:
            self.shield.disable()
            assert not self.shield.run

    def test_integration(self):
        """
        Test if shield is properly starting from scratch and fully enabling protection using real managers.
        """
        validators_manager: MemoryValidatorsManager = self.create_memory_validators_manager()
        state_manager: SQLAlchemyMinerShieldStateManager = SQLAlchemyMinerShieldStateManager(sql_alchemy_db_url)
        state_manager.clear_tables()
        miner_address: Address = get_miner_address_from_credentials(AddressType.IP)
        address_manager: AwsAddressManager = \
            AwsAddressManager(aws_access_key_id, aws_secret_access_key,
                              miner_region_name=miner_region_name, miner_address=miner_address,
                              event_processor=PrintingMinerShieldEventProcessor(), state_manager=state_manager)
        manifest_manager: S3ManifestManager = \
            S3ManifestManager(aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key,
                              region_name=aws_s3_region_name, bucket_name=aws_s3_bucket_name,
                              address_serializer=DefaultAddressSerializer(),
                              manifest_serializer=JsonManifestSerializer(),
                              encryption_manager=ECIESEncryptionManager())
        blockchain_manager: MemoryBlockchainManager = MemoryBlockchainManager()

        validate_interval_sec = 10
        shield = MinerShield(self.MINER_HOTKEY, validators_manager, address_manager, manifest_manager,
                             blockchain_manager, state_manager, PrintingMinerShieldEventProcessor(),
                             MinerShieldOptions(retry_delay_sec=1, validate_interval_sec=validate_interval_sec))
        shield.enable()
        assert shield.run

        # give some time to make sure everything is initialized and validate is called
        sleep(10 + 2 * validate_interval_sec)

        try:
            state: MinerShieldState = state_manager.get_state()
            assert validators_manager.get_validators() == self.DEFAULT_VALIDATORS
            assert state.known_validators == validators_manager.get_validators()
            assert state.banned_validators == {}
            assert state.validators_addresses.keys() == validators_manager.get_validators().keys()
            assert state.manifest_address is not None
            manifest: Manifest = manifest_manager.get_manifest(state.manifest_address)
            assert manifest.encrypted_address_mapping.keys() == state.validators_addresses.keys()
            assert blockchain_manager.get_address(self.MINER_HOTKEY) == state.manifest_address

            reloaded_state: MinerShieldState = state_manager.get_state(reload=True)
            assert reloaded_state == state

            # Remove all validators to clean up everything (except S3 file) and check if validate loop is running.
            validators_manager.validators.clear()
            sleep(10 + validate_interval_sec)

            state = state_manager.get_state()
            assert state.known_validators == {}
            assert state.validators_addresses == {}
            manifest: Manifest = manifest_manager.get_manifest(state.manifest_address)
            assert manifest.encrypted_address_mapping == {}
            assert blockchain_manager.get_address(self.MINER_HOTKEY) == state.manifest_address

            reloaded_state: MinerShieldState = state_manager.get_state(reload=True)
            assert reloaded_state == state
        finally:
            shield.disable()
            assert not shield.run
            address_manager.clean_all()

    def test_ban_validator(self):
        """
        Test if shield is properly banning validators.
        """
        # Use long validate_interval_sec to avoid race conditions between manipulating data due to validation
        # and accessing state in tests.
        self.create_default_shield(validate_interval_sec=600)
        sleep(2)

        try:
            state: MinerShieldState = self.state_manager.get_state()
            assert state.known_validators == self.validators_manager.get_validators()
            assert state.banned_validators == {}

            # shield is working, ban single validator

            self.shield.ban_validator(self.VALIDATOR_1_HOTKEY)
            expected_validators: dict[Hotkey, PublicKey] = dict(self.validators_manager.get_validators())
            expected_validators.pop(self.VALIDATOR_1_HOTKEY)
            banned_validators: set[Hotkey] = {self.VALIDATOR_1_HOTKEY}
            sleep(2)

            state = self.state_manager.get_state()
            assert state.known_validators == expected_validators
            assert state.banned_validators.keys() == banned_validators
            assert self.manifest_manager.put_counter == 2
            assert self.blockchain_manager.put_counter == 1  # file is put under same address

            # check banning non-existing validator

            self.shield.ban_validator(self.OTHER_VALIDATOR_HOTKEY)
            banned_validators.add(self.OTHER_VALIDATOR_HOTKEY)
            sleep(2)

            state = self.state_manager.get_state()
            assert state.known_validators == expected_validators
            assert state.banned_validators.keys() == banned_validators
            assert self.manifest_manager.put_counter == 2  # known validators haven't changed
        finally:
            self.shield.disable()

    def test_reloading_validators(self):
        """
        Test if shield is properly handling changing validators set during runtime.
        """
        self.create_default_shield(validate_interval_sec=5)
        sleep(2)

        try:
            # add VALIDATOR_4 and remove VALIDATOR_2 - changes should be reflected in the state after validation runs
            self.validators_manager.validators.pop(self.VALIDATOR_2_HOTKEY)
            self.validators_manager.validators[self.VALIDATOR_4_HOTKEY] = self.VALIDATOR_4_PUBLICKEY
            expected_validators: dict[Hotkey, PublicKey] = dict(self.DEFAULT_VALIDATORS)
            expected_validators.pop(self.VALIDATOR_2_HOTKEY)
            expected_validators[self.VALIDATOR_4_HOTKEY] = self.VALIDATOR_4_PUBLICKEY
            state: MinerShieldState = self.state_manager.get_state()
            expected_address_id_counter: int = len(state.validators_addresses)
            assert self.address_manager.id_counter == expected_address_id_counter
            assert state.known_validators != expected_validators  # need to wait
            assert self.manifest_manager.put_counter == 1

            # wait for validation and check results
            sleep(self.shield.options.validate_interval_sec)
            state = self.state_manager.get_state()
            assert state.known_validators == expected_validators
            assert state.validators_addresses.keys() == state.known_validators.keys()
            assert list(state.validators_addresses.values()) == list(self.address_manager.known_addresses.values())
            expected_address_id_counter += 1  # +1 for new validator
            assert self.address_manager.id_counter == expected_address_id_counter
            assert self.manifest_manager.put_counter == 2

            # change public key of single validator - changes should be reflected in the state after validation runs
            self.validators_manager.validators[self.VALIDATOR_3_HOTKEY] = self.VALIDATOR_3_OTHER_PUBLICKEY
            expected_validators[self.VALIDATOR_3_HOTKEY] = self.VALIDATOR_3_OTHER_PUBLICKEY
            state = self.state_manager.get_state()
            assert state.known_validators != expected_validators  # need to wait

            # wait for validation and check results
            sleep(self.shield.options.validate_interval_sec)
            state = self.state_manager.get_state()
            assert state.known_validators == expected_validators
            assert self.address_manager.id_counter == expected_address_id_counter
            assert self.manifest_manager.put_counter == 3
        finally:
            self.shield.disable()

    def test_validate_addresses(self):
        """
        Test if shield is properly handling validating addresses during runtime.
        """
        self.create_default_shield(validate_interval_sec=5)
        sleep(2)

        try:
            expected_address_id_counter: int = len(self.DEFAULT_VALIDATORS)

            # set invalid address manually - new address should be created after validation runs
            self.address_manager.invalid_addresses = {self.VALIDATOR_1_HOTKEY}
            state: MinerShieldState = self.state_manager.get_state()
            assert self.address_manager.id_counter == expected_address_id_counter
            old_address = state.validators_addresses.get(self.VALIDATOR_1_HOTKEY)
            assert self.address_manager.known_addresses.get(old_address.address_id) == old_address

            # wait for validation and check results
            expected_address_id_counter += 1  # +1 for regenerating address
            sleep(self.shield.options.validate_interval_sec)
            state = self.state_manager.get_state()
            assert self.address_manager.id_counter == expected_address_id_counter
            assert self.manifest_manager.put_counter == 2
            new_address = state.validators_addresses.get(self.VALIDATOR_1_HOTKEY)
            assert old_address != new_address
            assert self.address_manager.known_addresses.get(new_address.address_id) == new_address
            assert self.address_manager.known_addresses.get(old_address.address_id, None) is None
        finally:
            self.shield.disable()

    def test_validate_manifest_file(self):
        """
        Test if shield is properly handling validating manifest file during runtime.
        """
        self.create_default_shield(validate_interval_sec=5)
        sleep(2)

        try:
            # change file contents manually - file should be overwritten after validation runs
            assert self.manifest_manager.put_counter == 1
            self.manifest_manager.stored_file = b'xxx'
            sleep(self.shield.options.validate_interval_sec)
            assert self.manifest_manager.put_counter == 2
        finally:
            self.shield.disable()
