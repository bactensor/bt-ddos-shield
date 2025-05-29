from __future__ import annotations

import dataclasses
import typing

import turbobt
import turbobt.neuron
import turbobt.subnet

from bt_ddos_shield.client import ShieldClient
from bt_ddos_shield.event_processor import PrintingMinerShieldEventProcessor
from bt_ddos_shield.manifest_manager import ManifestDeserializationException
from bt_ddos_shield.turbobt.blockchain_manager import TurboBittensorBlockchainManager

if typing.TYPE_CHECKING:
    import bittensor_wallet

    from bt_ddos_shield.shield_metagraph import ShieldMetagraphOptions


class ShieldedBittensor(turbobt.Bittensor):
    ddos_shield: ShieldClient

    def __init__(
        self,
        *args,
        wallet: bittensor_wallet.Wallet,
        ddos_shield_netuid: int,
        ddos_shield_options: ShieldMetagraphOptions | None = None,
        **kwargs,
    ):
        super().__init__(
            *args,
            wallet=wallet,
            **kwargs,
        )

        event_processor = PrintingMinerShieldEventProcessor()

        self.ddos_shield = ShieldClient(
            ddos_shield_netuid,
            wallet,
            blockchain_manager=TurboBittensorBlockchainManager(
                self,
                netuid=ddos_shield_netuid,
                wallet=wallet,
                event_processor=event_processor,
            ),
            event_processor=event_processor,
            options=ddos_shield_options,
        )

    async def __aenter__(self):
        await super().__aenter__()
        await self.ddos_shield.__aenter__()
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.ddos_shield.__aexit__(*args, **kwargs)
        await super().__aexit__(*args, **kwargs)

    def subnet(self, netuid: int) -> turbobt.subnet.SubnetReference:
        if netuid == self.ddos_shield.netuid:
            return ShieldedSubnetReference(
                netuid,
                client=self,
            )

        return super().subnet(netuid)


class ShieldedSubnetReference(turbobt.subnet.SubnetReference):
    client: ShieldedBittensor = dataclasses.field(compare=False, repr=False)

    async def list_neurons(self, *args, **kwargs) -> list[turbobt.neuron.Neuron]:
        neurons = await super().list_neurons(*args, **kwargs)

        manifests_urls = await self.client.ddos_shield.blockchain_manager.get_manifest_urls([
            neuron.hotkey for neuron in neurons
        ])
        manifests = await self.client.ddos_shield.manifest_manager.get_manifests(
            manifests_urls,
        )

        for neuron in neurons:
            manifest = manifests.get(neuron.hotkey)

            if not manifest:
                continue

            try:
                shield_address = self.client.ddos_shield.manifest_manager.get_address_for_validator(
                    manifest,
                    self.client.wallet.hotkey.ss58_address,
                    self.client.ddos_shield.certificate.private_key,
                )
            except ManifestDeserializationException as e:
                self.client.event_processor.event(
                    'Error while getting shield address for miner {hotkey}',
                    exception=e,
                    hotkey=neuron.hotkey,
                )
                continue

            if shield_address is None:
                continue

            if self.client.ddos_shield.options.replace_ip_address_for_axon:
                neuron.axon_info.ip = shield_address[0]
            else:
                neuron.axon_info.shield_address = shield_address[0]

            neuron.axon_info.port = shield_address[1]

        return neurons
