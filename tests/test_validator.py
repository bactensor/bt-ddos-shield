import asyncio
import os
from urllib.parse import urlparse

from bt_ddos_shield.address_manager import AbstractAddressManager
from bt_ddos_shield.miner_shield import MinerShield, MinerShieldFactory
from bt_ddos_shield.state_manager import SQLAlchemyMinerShieldStateManager
from bt_ddos_shield.utils import Hotkey
from bt_ddos_shield.validator import MinerAddress, Validator, ValidatorFactory, ValidatorSettings
from tests.conftest import ShieldTestSettings, ValidatorTestSettings
from tests.test_encryption_manager import generate_key_pair


class TestValidator:
    """
    Test suite for the Validator class.
    """

    def test_full_flow(self, shield_settings: ShieldTestSettings):
        """
        Test if validator is working using real managers and real shield.

        IMPORTANT: Test can run for many minutes due to AWS delays.
        """
        validator_private_key, validator_public_key = generate_key_pair()

        os.environ["VALIDATOR_PRIVATE_KEY"] = validator_private_key
        validator_settings: ValidatorSettings = ValidatorTestSettings()
        validator: Validator = ValidatorFactory.create_validator(validator_settings)

        validators = {validator_settings.validator_hotkey: validator_public_key}
        shield: MinerShield = MinerShieldFactory.create_miner_shield(shield_settings, validators)

        assert isinstance(shield.state_manager, SQLAlchemyMinerShieldStateManager)
        state_manager: SQLAlchemyMinerShieldStateManager = shield.state_manager  # type: ignore
        state_manager.clear_tables()

        address_manager: AbstractAddressManager = shield.address_manager

        # TODO: Connect blockchain managers because there is only MemoryBlockchainManager as for now
        validator._blockchain_manager = shield.blockchain_manager

        shield.enable()
        assert shield.run

        try:
            miner_address: MinerAddress = asyncio.run(asyncio.wait_for(validator.fetch_miner_address(), timeout=180))
            urlparse(miner_address.domain)
            assert miner_address.port == shield_settings.miner_instance_port
        finally:
            shield.disable()
            assert not shield.run
            address_manager.clean_all()
