from time import sleep
from types import MappingProxyType
from typing import Optional

from bt_ddos_shield.address import Address, AddressType
from bt_ddos_shield.address_manager import AbstractAddressManager
from bt_ddos_shield.event_processor import PrintingMinerShieldEventProcessor
from bt_ddos_shield.miner_shield import MinerShield, MinerShieldOptions
from bt_ddos_shield.utils import Hotkey, PublicKey
from bt_ddos_shield.validators_manager import MemoryValidatorsManager
from tests.test_manifest_manager import MemoryManifestManager


class MemoryAddressManager(AbstractAddressManager):
    id_counter: int
    known_addresses: dict[str, Address]

    def __init__(self):
        super().__init__(miner_address_id=0)
        self.id_counter = 1
        self.known_addresses = {}

    def create_address(self) -> Address:
        address = Address(address_id=str(self.id_counter), address_type=AddressType.DOMAIN,
                          address=f'addr{self.id_counter}.com', port=80)
        self.known_addresses[address.address_id] = address
        self.id_counter += 1
        return address

    def remove_address(self, address: Address):
        self.known_addresses.pop(address.address_id, None)

    def validate_addresses(self, addresses: MappingProxyType[Hotkey, Address]) -> set[Hotkey]:
        return set()


class TestMinerShield:
    """
    Test suite for the MinerShield class.
    """

    MINER_HOTKEY = Hotkey('miner')
    VALIDATOR_1_HOTKEY = Hotkey('validator1')
    VALIDATOR_1_PUBLICKEY = PublicKey('key1')
    VALIDATOR_2_HOTKEY = Hotkey('validator2')
    VALIDATOR_2_PUBLICKEY = PublicKey('key2')
    VALIDATOR_3_HOTKEY = Hotkey('validator3')
    VALIDATOR_3_PUBLICKEY = PublicKey('key3')
    DEFAULT_VALIDATORS = {VALIDATOR_1_HOTKEY: VALIDATOR_1_PUBLICKEY, VALIDATOR_2_HOTKEY: VALIDATOR_2_PUBLICKEY,
                          VALIDATOR_3_HOTKEY: VALIDATOR_3_PUBLICKEY}

    @classmethod
    def create_memory_validators_manager(cls, validators: Optional[dict[Hotkey, PublicKey]] = None)\
            -> MemoryValidatorsManager:
        if validators is None:
            validators = cls.DEFAULT_VALIDATORS
        return MemoryValidatorsManager(validators)

    def test_start_stop_with_exception(self):
        """
        Test if shield is properly starting and stopping when exception is thrown during initialization.
        """
        state_manager = None # set state_manager to None to force exception during initialization

        # noinspection PyTypeChecker
        shield = MinerShield(self.MINER_HOTKEY, self.create_memory_validators_manager(), MemoryAddressManager(),
                             MemoryManifestManager(), None,
                             state_manager, PrintingMinerShieldEventProcessor(), MinerShieldOptions(retry_delay_sec=1))
        shield.enable()
        assert shield.run
        sleep(1)
        shield.disable()
        assert not shield.run
