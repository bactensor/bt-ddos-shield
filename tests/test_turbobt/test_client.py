import asyncio

from bt_ddos_shield.turbobt import ShieldedBittensor


def test_e2e(shield_settings):
    loop = asyncio.get_event_loop()
    bittensor = ShieldedBittensor(
        # "ws://127.0.0.1:9944",
        # verify=None,
        "wss://entrypoint-finney.opentensor.ai",
        wallet=shield_settings.validator_wallet.instance,
    )

    # loop.run_until_complete(bittensor.__aenter__())

    neurons = loop.run_until_complete(bittensor.subnet(12).list_neurons())

    assert neurons == 1
