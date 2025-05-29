from __future__ import annotations

import asyncio
import copy
from typing import TYPE_CHECKING

import pytest

from bt_ddos_shield.address_manager import AwsAddressManager
from bt_ddos_shield.miner_shield import MinerShield, MinerShieldFactory
from bt_ddos_shield.shield_metagraph import ShieldMetagraph
from bt_ddos_shield.state_manager import SQLAlchemyMinerShieldStateManager
from bt_ddos_shield.validators_manager import BittensorValidatorsManager

if TYPE_CHECKING:
    from bittensor.core.chain_data import AxonInfo

    from tests.conftest import ShieldTestSettings


@pytest.fixture
def miner_shield(shield_settings: ShieldTestSettings):
    # We need to add any validator to set, otherwise manifest addresses will be created for all validators in
    # network including tested validator, what we don't want
    validators = {'unknown_hotkey'}

    shield = MinerShieldFactory.create_miner_shield(
        shield_settings,
        validators,
    )

    assert isinstance(shield.address_manager, AwsAddressManager)
    assert isinstance(shield.state_manager, SQLAlchemyMinerShieldStateManager)
    assert isinstance(shield.validators_manager, BittensorValidatorsManager)

    shield.state_manager.clear_tables()
    shield.enable()
    assert shield.run

    # Wait for full shield initialization - should create empty manifest
    shield.task_queue.join()

    yield shield

    shield.disable()
    assert not shield.run
    shield.address_manager.clean_all()


class TestValidator:
    """
    Test suite for the Validator class.
    """

    def test_full_flow(self, miner_shield: MinerShield, shield_settings: ShieldTestSettings):
        """
        Test if validator is working using real managers and real shield.

        IMPORTANT: Test can run for many minutes due to AWS delays.
        """
        miner_hotkey: str = shield_settings.wallet.instance.hotkey.ss58_address

        metagraph: ShieldMetagraph = ShieldMetagraph(
            wallet=shield_settings.validator_wallet.instance,
            subtensor=shield_settings.subtensor.create_client(),
            netuid=shield_settings.netuid,
        )
        miner_axon: AxonInfo = next(axon for axon in metagraph.axons if axon.hotkey == miner_hotkey)

        miner_shield.disable()
        miner_shield.validators_manager.validators = frozenset()
        miner_shield.enable()
        miner_shield.task_queue.join()  # Wait for full shield initialization - should add validator to manifest

        metagraph.sync()
        shielded_miner_axon: AxonInfo = next(axon for axon in metagraph.axons if axon.hotkey == miner_hotkey)
        assert shielded_miner_axon.ip != miner_axon.ip
        assert shielded_miner_axon.port == miner_shield.address_manager.ELB_LISTENING_PORT

    def test_full_flow_in_async_context(self, shield_settings: ShieldTestSettings):
        async def async_wrapper():
            self.test_full_flow(shield_settings)

        asyncio.run(async_wrapper())

    def test_copy(self, shield_settings: ShieldTestSettings):
        metagraph: ShieldMetagraph = ShieldMetagraph(
            wallet=shield_settings.validator_wallet.instance,
            subtensor=shield_settings.subtensor.create_client(),
            netuid=shield_settings.netuid,
        )

        metagraph_copy: ShieldMetagraph = copy.deepcopy(metagraph)
        assert metagraph_copy.axons == metagraph.axons
        assert metagraph.subtensor is not None
        assert metagraph_copy.subtensor is None, 'Metagraph class ignores subtensor field during deepcopy'

        metagraph_copy = copy.copy(metagraph)
        assert metagraph_copy.axons == metagraph.axons
        assert metagraph.subtensor is not None
        assert metagraph_copy.subtensor is None, 'Metagraph class ignores subtensor field during copy'


class TestTurboBittensor:
    """
    Test suite for turbobt's ShieldedBittensor.
    """

    @pytest.fixture(autouse=True, scope='class')
    def importorskip(self):
        pytest.importorskip('turbobt')

    @pytest.mark.asyncio
    async def test_full_flow(self, miner_shield, shield_settings: ShieldTestSettings):
        """
        Test if validator is working using real managers and real shield.

        IMPORTANT: Test can run for many minutes due to AWS delays.
        """
        from bt_ddos_shield.turbobt import ShieldedBittensor

        miner_hotkey: str = shield_settings.wallet.instance.hotkey.ss58_address

        async with ShieldedBittensor(
            shield_settings.subtensor.network,
            ddos_shield_netuid=shield_settings.netuid,
            wallet=shield_settings.validator_wallet.instance,
        ) as bittensor:
            subnet = bittensor.subnet(shield_settings.netuid)
            neurons = await subnet.list_neurons()

            miner = next(neuron for neuron in neurons if neuron.hotkey == miner_hotkey)

            miner_shield.disable()
            miner_shield.validators_manager.validators = frozenset()
            miner_shield.enable()

            # Wait for full shield initialization - should add validator to manifest
            miner_shield.task_queue.join()

            neurons = await subnet.list_neurons()

            shielded_miner = next(neuron for neuron in neurons if neuron.hotkey == miner_hotkey)

            assert shielded_miner.axon_info.ip != miner.axon_info.ip
            assert shielded_miner.axon_info.port == miner_shield.address_manager.ELB_LISTENING_PORT
