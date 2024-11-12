from time import sleep
from typing import Optional

from ecies.utils import generate_eth_key

from bt_ddos_shield.event_processor import PrintingMinerShieldEventProcessor
from bt_ddos_shield.miner_shield import MinerShield, MinerShieldOptions
from bt_ddos_shield.state_manager import MinerShieldState
from bt_ddos_shield.utils import Hotkey, PublicKey
from bt_ddos_shield.validators_manager import MemoryValidatorsManager
from tests.test_address_manager import MemoryAddressManager
from tests.test_blockchain_manager import MemoryBlockchainManager
from tests.test_manifest_manager import MemoryManifestManager
from tests.test_state_manager import MemoryMinerShieldStateManager


class TestMinerShield:
    """
    Test suite for the MinerShield class.
    """

    MINER_HOTKEY = Hotkey('miner')
    VALIDATOR_1_HOTKEY = Hotkey('validator1')
    VALIDATOR_1_PUBLICKEY = PublicKey(generate_eth_key().public_key.to_hex())
    VALIDATOR_2_HOTKEY = Hotkey('validator2')
    VALIDATOR_2_PUBLICKEY = PublicKey(generate_eth_key().public_key.to_hex())
    VALIDATOR_3_HOTKEY = Hotkey('validator3')
    VALIDATOR_3_PUBLICKEY = PublicKey(generate_eth_key().public_key.to_hex())
    DEFAULT_VALIDATORS = {VALIDATOR_1_HOTKEY: VALIDATOR_1_PUBLICKEY, VALIDATOR_2_HOTKEY: VALIDATOR_2_PUBLICKEY,
                          VALIDATOR_3_HOTKEY: VALIDATOR_3_PUBLICKEY}

    @classmethod
    def create_memory_validators_manager(cls, validators: Optional[dict[Hotkey, PublicKey]] = None)\
            -> MemoryValidatorsManager:
        if validators is None:
            validators = cls.DEFAULT_VALIDATORS
        return MemoryValidatorsManager(validators)

    def create_default_shield(self):
        self.validators_manager: MemoryValidatorsManager = self.create_memory_validators_manager()
        self.address_manager: MemoryAddressManager = MemoryAddressManager()
        self.manifest_manager: MemoryManifestManager = MemoryManifestManager()
        self.blockchain_manager: MemoryBlockchainManager = MemoryBlockchainManager()
        self.state_manager: MemoryMinerShieldStateManager = MemoryMinerShieldStateManager()
        self.shield = MinerShield(self.MINER_HOTKEY, self.validators_manager, self.address_manager,
                                  self.manifest_manager, self.blockchain_manager, self.state_manager,
                                  PrintingMinerShieldEventProcessor(), MinerShieldOptions(retry_delay_sec=1))
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
        Test if shield is properly starting from scratch and fully enabling protection.
        """
        self.create_default_shield()

        sleep(2)

        state: MinerShieldState = self.state_manager.get_state()
        assert state.known_validators == self.validators_manager.get_validators()
        assert state.banned_validators == {}
        assert state.validators_addresses.keys() == self.validators_manager.get_validators().keys()
        assert state.manifest_address == self.manifest_manager.default_address
        assert list(state.validators_addresses.values()) == list(self.address_manager.known_addresses.values())
        assert self.manifest_manager.stored_file is not None
        assert self.blockchain_manager.get(self.MINER_HOTKEY) is not None

        self.shield.disable()
        assert not self.shield.run
