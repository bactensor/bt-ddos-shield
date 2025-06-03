from __future__ import annotations

import typing

import turbobt

from bt_ddos_shield.blockchain_manager import AbstractBlockchainManager, BlockchainManagerException
from bt_ddos_shield.utils import decode_subtensor_certificate_info

if typing.TYPE_CHECKING:
    from collections.abc import Iterable

    import bittensor_wallet

    from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor
    from bt_ddos_shield.utils import Hotkey, PublicKey


class TurboBittensorBlockchainManager(AbstractBlockchainManager):
    def __init__(
        self,
        bittensor: turbobt.Bittensor,
        netuid: int,
        wallet: bittensor_wallet.Wallet,
        event_processor: AbstractMinerShieldEventProcessor,
    ):
        self.bittensor = bittensor
        self.wallet = wallet
        self.event_processor = event_processor

        self.subnet = turbobt.Bittensor.subnet(self.bittensor, netuid)

    def get_hotkey(self) -> Hotkey:
        return self.wallet.hotkey.ss58_address

    def get_own_public_key(self) -> PublicKey | None:
        raise NotImplementedError

    async def get_own_public_key_async(self) -> PublicKey | None:
        neuron = self.subnet.neuron(
            hotkey=self.get_hotkey(),
        )
        certificate = await neuron.get_certificate()

        if not certificate:
            return None

        certificate['public_key'] = [
            bytes.fromhex(certificate['public_key'][2:]),
        ]

        decoded_certificate = decode_subtensor_certificate_info(certificate)

        if not decoded_certificate:
            return None

        return decoded_certificate.hex_data

    async def get_metadata(self, hotkeys: Iterable[Hotkey]) -> dict[Hotkey, bytes | None]:
        commitments = await self.subnet.commitments.fetch()
        commitments = {
            key: value
            for key, value in commitments.items()
            if key in hotkeys
        }

        for key in hotkeys:
            if key not in commitments:
                commitments[key] = None

        return commitments

    def put_metadata(self, data: bytes):
        raise NotImplementedError

    def upload_public_key(self, public_key: PublicKey):
        raise NotImplementedError

    async def upload_public_key_async(self, public_key: PublicKey) -> None:
        try:
            neuron = await self.subnet.get_neuron(self.get_hotkey())

            ip = '1.1.1.1'
            port = 1
            protocol = 0

            if neuron and neuron.axon_info:
                ip = str(neuron.axon_info.ip or ip)
                port = neuron.axon_info.port or port
                protocol = neuron.axon_info.protocol or protocol

            await self.subnet.neurons.serve(
                ip,
                port,
                certificate=bytes.fromhex(public_key),
                wallet=self.wallet,
            )
        except Exception as e:
            self.event_processor.event(
                'Failed to upload public key for netuid={netuid}, wallet={wallet}',
                exception=e,
                netuid=self.subnet.netuid,
                wallet=self.wallet,
            )
            raise BlockchainManagerException(f'Failed to upload public key: {e}') from e
