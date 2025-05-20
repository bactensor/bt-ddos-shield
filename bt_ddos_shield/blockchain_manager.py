from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

import bittensor
from bittensor.core.extrinsics.serving import (
    publish_metadata,
    serve_extrinsic,
)

from bt_ddos_shield.utils import SubtensorCertificate, decode_subtensor_certificate_info

if TYPE_CHECKING:
    from collections.abc import Iterable

    import bittensor_wallet
    from bittensor.core.chain_data.axon_info import AxonInfo
    from bittensor.core.chain_data.neuron_info import NeuronInfo

    from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor
    from bt_ddos_shield.utils import Hotkey, PublicKey


class BlockchainManagerException(Exception):
    pass


class AbstractBlockchainManager(ABC):
    """
    Abstract base class for manager handling publishing manifest address to blockchain.
    """

    def put_manifest_url(self, url: str):
        """
        Put manifest url to blockchain for wallet owner.
        """
        self.put_metadata(url.encode())

    async def get_manifest_urls(self, hotkeys: Iterable[Hotkey]) -> dict[Hotkey, str | None]:
        """
        Get manifest urls for given neurons identified by hotkeys.
        Returns dictionary with urls for given neurons, filled with None if url is not found.
        """
        try:
            serialized_urls: dict[Hotkey, bytes | None] = await self.get_metadata(hotkeys)
        except BlockchainManagerException:
            # Retry once
            time.sleep(3)
            serialized_urls = await self.get_metadata(hotkeys)
        deserialized_urls: dict[Hotkey, str | None] = {}
        for hotkey, serialized_url in serialized_urls.items():
            url: str | None = None
            if serialized_url is not None:
                try:
                    url = serialized_url.decode()
                except UnicodeDecodeError:
                    pass
            deserialized_urls[hotkey] = url
        return deserialized_urls

    async def get_own_manifest_url(self) -> str | None:
        """
        Get manifest url for wallet owner. Returns None if url is not found.
        """
        own_hotkey: Hotkey = self.get_hotkey()
        urls: dict[Hotkey, str | None] = await self.get_manifest_urls([own_hotkey])
        return urls.get(own_hotkey)

    @abstractmethod
    def put_metadata(self, data: bytes):
        """
        Put neuron metadata to blockchain for wallet owner.
        """
        pass

    @abstractmethod
    async def get_metadata(self, hotkeys: Iterable[Hotkey]) -> dict[Hotkey, bytes | None]:
        """
        Get metadata from blockchain for given neurons identified by hotkeys.
        Returns dictionary with metadata for given neurons, filled with None if metadata is not found.
        """
        pass

    @abstractmethod
    def get_hotkey(self) -> Hotkey:
        """Returns hotkey of the wallet owner."""
        pass

    @abstractmethod
    def get_own_public_key(self) -> PublicKey | None:
        """Returns public key for wallet owner."""
        pass

    async def get_own_public_key_async(self) -> PublicKey | None:
        """Async verson of get_own_public_key."""
        raise NotImplementedError

    @abstractmethod
    def upload_public_key(self, public_key: PublicKey):
        """Uploads public key to blockchain for wallet owner."""
        pass

    async def upload_public_key_async(self, public_key: PublicKey):
        """Async version of upload_public_key."""
        raise NotImplementedError


class BittensorBlockchainManager(AbstractBlockchainManager):
    """
    Bittensor BlockchainManager implementation using commitments of knowledge as storage.
    """

    subtensor: bittensor.Subtensor
    netuid: int
    wallet: bittensor_wallet.Wallet
    event_processor: AbstractMinerShieldEventProcessor

    def __init__(
        self,
        subtensor: bittensor.Subtensor,
        netuid: int,
        wallet: bittensor_wallet.Wallet,
        event_processor: AbstractMinerShieldEventProcessor,
    ):
        self.subtensor = subtensor
        self.netuid = netuid
        self.wallet = wallet
        self.event_processor = event_processor

    async def get_metadata(self, hotkeys: Iterable[Hotkey]) -> dict[Hotkey, bytes | None]:
        try:
            async with bittensor.AsyncSubtensor(self.subtensor.chain_endpoint) as async_subtensor:
                tasks = [self.get_single_metadata(async_subtensor, hotkey) for hotkey in hotkeys]
                results: list[bytes | None] = await asyncio.gather(*tasks)
            return dict(zip(hotkeys, results, strict=True))
        except Exception as e:
            self.event_processor.event('Failed to get metadata for netuid={netuid}', exception=e, netuid=self.netuid)
            raise BlockchainManagerException(f'Failed to get metadata: {e}') from e

    async def get_single_metadata(self, async_subtensor: bittensor.AsyncSubtensor, hotkey: Hotkey) -> bytes | None:
        metadata: dict = await async_subtensor.substrate.query(
            module='Commitments',
            storage_function='CommitmentOf',
            params=[self.netuid, hotkey],
        )

        try:
            # This structure is hardcoded in bittensor publish_metadata function, but corresponding get_metadata
            # function does not use it, so we need to extract the value manually.

            # Commented parts of the code shows how this extraction should look if async version will work properly,
            # the same as sync version does. Now async version doesn't decode raw SCALE objects properly. I left this
            # code as it will be easier one day to restore this proper parsing.
            # fields: list[dict[str, str]] = metadata["info"]["fields"]
            fields = metadata['info']['fields']

            # As for now there is only one field in metadata. Field contains map from type of data to data itself.
            # field: dict[str, str] = fields[0]
            field = fields[0][0]

            # Find data of 'Raw' type.
            for data_type in field.keys():
                if data_type.startswith('Raw'):
                    break
            else:
                return None

            # Raw data is hex-encoded and prefixed with '0x'.
            # return bytes.fromhex(field[data_type][2:])
            return bytes(field[data_type][0])
        except (TypeError, LookupError):
            return None

    def put_metadata(self, data: bytes):
        try:
            publish_metadata(
                self.subtensor,
                self.wallet,
                self.netuid,
                data_type=f'Raw{len(data)}',
                data=data,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
        except Exception as e:
            self.event_processor.event(
                'Failed to publish metadata for netuid={netuid}, wallet={wallet}',
                exception=e,
                netuid=self.netuid,
                wallet=str(self.wallet),
            )
            raise BlockchainManagerException(f'Failed to publish metadata: {e}') from e

    def get_hotkey(self) -> Hotkey:
        return self.wallet.hotkey.ss58_address

    def get_own_public_key(self) -> PublicKey | None:
        certificate: Any | None = self.subtensor.query_subtensor(
            name='NeuronCertificates',
            params=[self.netuid, self.get_hotkey()],
        )
        if certificate is None:
            return None
        decoded_certificate: SubtensorCertificate | None = decode_subtensor_certificate_info(certificate)
        if decoded_certificate is None:
            return None
        return decoded_certificate.hex_data

    def upload_public_key(self, public_key: PublicKey):
        try:
            # As for now there is no method for uploading only certificate to Subtensor, so we need to use
            # serve_extrinsic function. Because of that we need to get current neuron info to not overwrite existing
            # data - if there is not existing data, we will use default dummy values.
            neuron: NeuronInfo | None = self.subtensor.get_neuron_for_pubkey_and_subnet(
                self.wallet.hotkey.ss58_address, netuid=self.netuid
            )
            axon_info: AxonInfo | None = (
                None
                if neuron is None or neuron.axon_info is None or not neuron.axon_info.is_serving
                else neuron.axon_info
            )

            new_ip: str = '1.1.1.1' if axon_info is None else axon_info.ip
            new_port: int = 1 if axon_info is None else axon_info.port
            new_protocol: int = 0 if axon_info is None else axon_info.protocol
            # We need to change any field, otherwise extrinsic will not be sent, so use placeholder1 (increased by 1
            # and modulo 256 as it is u8 field) to not modify any real data.
            new_placeholder1: int = 0 if axon_info is None else (axon_info.placeholder1 + 1) % 256
            # certificate param is of str type in library, but actually we need to pass bytes there
            certificate_data: bytes = bytes.fromhex(public_key)

            serve_extrinsic(
                self.subtensor,
                self.wallet,
                new_ip,
                new_port,
                new_protocol,
                self.netuid,
                certificate=certificate_data,  # type: ignore
                placeholder1=new_placeholder1,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
        except Exception as e:
            self.event_processor.event(
                'Failed to upload public key for netuid={netuid}, wallet={wallet}',
                exception=e,
                netuid=self.netuid,
                wallet=str(self.wallet),
            )
            raise BlockchainManagerException(f'Failed to upload public key: {e}') from e
