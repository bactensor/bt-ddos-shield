import threading
import unittest.mock
from typing import Optional

import pytest
import websockets.exceptions

from bt_ddos_shield.address import DefaultAddressSerializer
from bt_ddos_shield.blockchain_manager import (
    AbstractBlockchainManager,
    BittensorBlockchainManager,
)
from bt_ddos_shield.utils import Hotkey


class MemoryBlockchainManager(AbstractBlockchainManager):
    known_data: dict[Hotkey, bytes]
    put_counter: int

    def __init__(self, miner_hotkey: Hotkey):
        super().__init__(miner_hotkey, DefaultAddressSerializer())
        self.known_data = {}
        self.put_counter = 0
        self._lock = threading.Lock()

    def put(self, hotkey: Hotkey, data: bytes):
        with self._lock:
            self.known_data[hotkey] = data
            self.put_counter += 1

    def get(self, hotkey: Hotkey) -> Optional[bytes]:
        with self._lock:
            return self.known_data.get(hotkey)


@pytest.fixture
def hotkey():
    return "5EU2xVWC7qffsUNGtvakp5WCj7WGJMPkwG1dsm3qnU2Kqvee"


def test_bittensor_get(hotkey):
    mock_subtensor = unittest.mock.MagicMock()
    mock_substrate = mock_subtensor.substrate.__enter__.return_value
    mock_substrate.query.return_value = unittest.mock.Mock(
        value={
            "info": {
                "fields": None,
            },
        },
    )

    manager = BittensorBlockchainManager(
        miner_hotkey=hotkey,
        address_serializer=DefaultAddressSerializer(),
        subtensor=mock_subtensor,
        wallet=unittest.mock.Mock(),
        netuid=1,
    )

    assert manager.get(hotkey) is None

    mock_substrate.query.assert_called_once_with(
        module="Commitments",
        storage_function="CommitmentOf",
        params=[1, "5EU2xVWC7qffsUNGtvakp5WCj7WGJMPkwG1dsm3qnU2Kqvee"],
        block_hash=None,
    )

    mock_substrate.query.reset_mock()
    mock_substrate.query.return_value = unittest.mock.Mock(
        value={
            "info": {
                "fields": [
                    {
                        "Raw4": "0x64617461",
                    },
                ],
            },
        },
    )

    assert manager.get(hotkey) == b"data"


def test_bittensor_put(hotkey):
    mock_subtensor = unittest.mock.MagicMock()
    mock_substrate = mock_subtensor.substrate.__enter__.return_value

    mock_wallet = unittest.mock.Mock()
    mock_wallet.hotkey.ss58_address = hotkey

    manager = BittensorBlockchainManager(
        miner_hotkey=hotkey,
        address_serializer=DefaultAddressSerializer(),
        subtensor=mock_subtensor,
        wallet=mock_wallet,
        netuid=1,
    )

    manager.put(hotkey, b"data")

    mock_substrate.compose_call.assert_called_once_with(
        call_module="Commitments",
        call_function="set_commitment",
        call_params={
            "netuid": 1,
            "info": {
                "fields": [
                    [
                        {
                            "Raw4": b"data",
                        },
                    ],
                ],
            },
        },
    )
    mock_substrate.create_signed_extrinsic.assert_called_once_with(
        call=mock_substrate.compose_call.return_value,
        keypair=mock_wallet.hotkey,
    )
    mock_subtensor.substrate.submit_extrinsic.assert_called_once_with(
        mock_substrate.create_signed_extrinsic.return_value,
        wait_for_inclusion=False,
        wait_for_finalization=True,
    )


def test_bittensor_put_not_own_hotkey():
    mock_wallet = unittest.mock.Mock()
    mock_wallet.hotkey.ss58_address = "MyHotkey"

    manager = BittensorBlockchainManager(
        miner_hotkey="MyHotkey",
        address_serializer=DefaultAddressSerializer(),
        subtensor=unittest.mock.MagicMock(),
        wallet=mock_wallet,
        netuid=1,
    )

    with pytest.raises(ValueError):
        manager.put("SomeoneHotkey", b"data")


def test_bittensor_retries(hotkey):
    mock_wallet = unittest.mock.Mock()
    mock_wallet.hotkey.ss58_address = hotkey

    mock_subtensor = unittest.mock.MagicMock()
    mock_substrate = mock_subtensor.substrate.__enter__.return_value
    mock_substrate.query.side_effect = (
        websockets.exceptions.ConnectionClosed(None, None),
        unittest.mock.Mock(
            value={
                "info": {
                    "fields": [
                        {
                            "Raw4": "0x64617461",
                        },
                    ],
                },
            },
        ),
    )

    manager = BittensorBlockchainManager(
        miner_hotkey=hotkey,
        address_serializer=DefaultAddressSerializer(),
        subtensor=mock_subtensor,
        wallet=mock_wallet,
        netuid=1,
    )

    assert manager.get(hotkey) == b"data"
    assert mock_substrate.query.call_count == 2

    mock_subtensor.substrate.submit_extrinsic.side_effect = (
        websockets.exceptions.ConnectionClosed(None, None),
        unittest.mock.Mock(),
    )

    manager.put(hotkey, b"data")

    assert mock_subtensor.substrate.submit_extrinsic.call_count == 2
