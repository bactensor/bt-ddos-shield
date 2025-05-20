from __future__ import annotations

import dataclasses
import ipaddress
import typing

import turbobt
import turbobt.neuron

# TODO export?
import turbobt.subnet

from bt_ddos_shield.client import ShieldClient
from bt_ddos_shield.event_processor import PrintingMinerShieldEventProcessor
from bt_ddos_shield.manifest_manager import (
    ManifestDeserializationException,
    ReadOnlyManifestManager,
)
from bt_ddos_shield.turbobt.blockchain_manager import TurboBittensorBlockchainManager

if typing.TYPE_CHECKING:
    import bittensor_wallet

    from bt_ddos_shield.blockchain_manager import AbstractBlockchainManager
    from bt_ddos_shield.encryption_manager import AbstractEncryptionManager
    from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor
    from bt_ddos_shield.shield_metagraph import ShieldMetagraphOptions


@dataclasses.dataclass
class ShieldConfig:
    event_processor: AbstractMinerShieldEventProcessor | None = None
    encryption_manager: AbstractEncryptionManager | None = None
    blockchain_manager: AbstractBlockchainManager | None = None
    manifest_manager: ReadOnlyManifestManager | None = None
    options: ShieldMetagraphOptions | None = None


class ShieldedBittensor(turbobt.Bittensor):
    ddos_shield: ShieldClient

    def __init__(
        self,
        *args,
        wallet: bittensor_wallet.Wallet,
        ddos_shield: ShieldConfig | None = None,
        **kwargs,
    ):
        super().__init__(
            *args,
            wallet=wallet,
            **kwargs,
        )

        if not ddos_shield:
            ddos_shield = ShieldConfig()

        event_processor = ddos_shield.event_processor or PrintingMinerShieldEventProcessor()

        self.ddos_shield = ShieldClient(
            wallet,
            netuid=12,  # TODO
            event_processor=event_processor,
            encryption_manager=ddos_shield.encryption_manager,
            blockchain_manager=ddos_shield.blockchain_manager
            or TurboBittensorBlockchainManager(
                self,
                netuid=12,  # TODO
                wallet=wallet,
                event_processor=event_processor,
            ),
            manifest_manager=ddos_shield.manifest_manager,
            options=ddos_shield.options,
        )

    async def __aenter__(self):
        result = await super().__aenter__()
        await self.ddos_shield.__aenter__()
        return result

    async def __aexit__(self, *args, **kwargs):
        await self.ddos_shield.__aexit__(*args, **kwargs)
        await super().__aexit__(*args, **kwargs)

    def subnet(self, netuid: int) -> ShieldedSubnetReference:
        return ShieldedSubnetReference(
            netuid,
            client=self,
        )


class ShieldedSubnetReference(turbobt.subnet.SubnetReference):
    client: ShieldedBittensor = dataclasses.field(compare=False, repr=False)

    async def list_neurons(self, *args, **kwargs) -> list[turbobt.neuron.Neuron]:  # TODO ShieldedNeuron?
        neurons = await super().list_neurons(*args, **kwargs)

        # XXX netuid
        hotkeys_manifests_urls = await self.client.ddos_shield.blockchain_manager.get_manifest_urls([
            neuron.hotkey for neuron in neurons
        ])
        hotkeys_manifests = await self.client.ddos_shield.manifest_manager.get_manifests(
            hotkeys_manifests_urls,
        )

        for neuron in neurons:
            manifest = hotkeys_manifests.get(neuron.hotkey)
            
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
                    'Error while getting shield address for miner {hotkey}', exception=e, hotkey=neuron.hotkey
                )
                continue

            if shield_address is None:
                continue

            if self.client.ddos_shield.options.replace_ip_address_for_axon:
                neuron.axon_info.ip = ipaddress.ip_address(shield_address[0])
            else:
                neuron.axon_info.shield_address = ipaddress.ip_address(shield_address[0])

            neuron.axon_info.port = shield_address[1]

        return neurons
