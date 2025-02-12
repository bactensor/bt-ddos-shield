import unittest.mock

import bittensor
from bt_ddos_shield.validators_manager import BittensorValidatorsManager


def test_bittensor_get():
    mock_subtensor = unittest.mock.Mock()
    mock_subtensor.neurons_lite.return_value = [
        unittest.mock.Mock(
            **{
                "hotkey": "MinerHotkey",
                "stake": bittensor.Balance(0),
            },
        ),
        unittest.mock.Mock(
            **{
                "hotkey": "ValidatorHotkey",
                "stake": bittensor.Balance(1000),
            },
        ),
    ]
    mock_subtensor.query_map.return_value = unittest.mock.MagicMock()
    mock_subtensor.query_map.return_value.__iter__.return_value = iter(
        [
            (
                unittest.mock.Mock(
                    **{
                        "serialize.return_value": "ValidatorHotkey",
                    },
                ),
                unittest.mock.Mock(
                    **{
                        "serialize.return_value": {
                            "public_key": "0xValidatorPubkey",
                            "algorithm": 4,
                        },
                    },
                ),
            )
        ]
    )

    manager = BittensorValidatorsManager(
        subtensor=mock_subtensor,
        netuid=1,
    )
    manager.reload_validators()

    mock_subtensor.query_map.assert_called_once_with(
        module="SubtensorModule",
        name="NeuronCertificates",
        params=[1],
    )

    assert manager.certificates == {
        "ValidatorHotkey": "ValidatorPubkey",
    }
