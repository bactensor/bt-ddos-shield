import asyncio
from urllib.parse import urlparse, ParseResult

from bt_ddos_shield.address_manager import AbstractAddressManager
from bt_ddos_shield.miner_shield import MinerShield, MinerShieldFactory
from bt_ddos_shield.state_manager import SQLAlchemyMinerShieldStateManager
from bt_ddos_shield.validator import Validator, ValidatorFactory, ValidatorSettings
from tests.conftest import ShieldTestSettings, ValidatorTestSettings


class TestValidator:
    """
    Test suite for the Validator class.
    """

    def test_full_flow(self, shield_settings: ShieldTestSettings):
        """
        Test if validator is working using real managers and real shield.

        IMPORTANT: Test can run for many minutes due to AWS delays.
        """

        validator_settings: ValidatorSettings = ValidatorTestSettings()  # type: ignore
        validator: Validator = ValidatorFactory.create_validator(validator_settings)

        validators = {validator_settings.validator_hotkey: ""}
        shield: MinerShield = MinerShieldFactory.create_miner_shield(shield_settings, validators)

        assert isinstance(shield.state_manager, SQLAlchemyMinerShieldStateManager)
        state_manager: SQLAlchemyMinerShieldStateManager = shield.state_manager  # type: ignore
        state_manager.clear_tables()

        address_manager: AbstractAddressManager = shield.address_manager

        shield.enable()
        assert shield.run

        shield.task_queue.join()

        try:
            miner_hotkey: str = shield_settings.wallet.instance.hotkey.ss58_address
            miner_url: str = asyncio.run(asyncio.wait_for(validator.fetch_miner_address(miner_hotkey),
                                                          timeout=20))
            parsed_url: ParseResult = urlparse('http://' + miner_url)
            assert parsed_url.port == shield_settings.miner_instance_port
        finally:
            shield.disable()
            assert not shield.run
            address_manager.clean_all()
