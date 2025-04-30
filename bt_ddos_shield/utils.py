from __future__ import annotations

import asyncio
import functools
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import bittensor
import boto3
import route53
from pydantic import BaseModel

if TYPE_CHECKING:
    import bittensor_wallet
    from botocore.client import BaseClient
    from route53.connection import Route53Connection

Hotkey = str
PublicKey = str
PrivateKey = str


@dataclass
class ShieldAddress:
    """
    Class describing address created by DDosShield.
    """

    address_id: str
    """ Identifier of the address """
    address: str
    """ Domain address used to connecting to Miner's server """
    port: int
    """ Port used to connecting to Miner's server """

    def __repr__(self):
        return f'Address(id={self.address_id}, address={self.address}:{self.port})'


class AWSClientFactory:
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_region_name: str | None

    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, aws_region_name: str | None = None):
        """
        Args:
            aws_access_key_id: AWS access key ID.
            aws_secret_access_key: AWS secret access key.
            aws_region_name: AWS region name. If not known, it can be set later using set_aws_region_name method.
        """
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_region_name = aws_region_name or ''

    def set_aws_region_name(self, aws_region_name: str) -> bool:
        """Set AWS region name. Returns if region name was changed."""
        if self.aws_region_name == aws_region_name:
            return False
        self.aws_region_name = aws_region_name
        return True

    def boto3_client(self, service_name: str) -> BaseClient:
        return boto3.client(  # type: ignore
            service_name,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            region_name=self.aws_region_name,
        )

    def route53_client(self) -> Route53Connection:
        return route53.connect(self.aws_access_key_id, self.aws_secret_access_key)


class WalletSettings(BaseModel):
    name: str | None = None
    hotkey: str | None = None
    path: str | None = None

    @functools.cached_property
    def instance(self) -> bittensor_wallet.Wallet:
        return bittensor.Wallet(**self.model_dump())


class SubtensorSettings(BaseModel):
    network: str | None = None

    @functools.cached_property
    def client(self) -> bittensor.Subtensor:
        return self.create_client()

    def create_client(self) -> bittensor.Subtensor:
        return bittensor.Subtensor(**self.model_dump())


@dataclass
class SubtensorCertificate:
    algorithm: int
    hex_data: str


def decode_subtensor_certificate_info(subtensor_certificate_info: dict[str, Any]) -> SubtensorCertificate | None:
    """Decode certificate info from Subtensor query result."""
    try:
        algorithm: int = subtensor_certificate_info['algorithm']
        data: tuple[int] = subtensor_certificate_info['public_key'][0]
    except (KeyError, TypeError):
        # This should not happen as Subtensor should return data in expected format
        return None
    hex_algorithm: str = format(algorithm, '02x')
    hex_data: str = bytes(data).hex()
    hex_data = hex_algorithm + hex_data  # Prefix cert data with algorithm as it is desired format
    return SubtensorCertificate(algorithm, hex_data)


def run_async_in_thread(async_fn) -> Any:
    """
    Function to run an async function in a background thread with its own event loop.
    Allows calling it from sync code and blocks until result is ready.
    """
    try:
        asyncio.get_running_loop()
        # If exception was not raised, we already have running loop and needs to schedule execution to thread...
    except RuntimeError:
        # ... but if we don't have a running loop, we can run the async function directly
        return asyncio.run(async_fn)

    result = None
    exception = None

    def thread_runner():
        try:
            nonlocal result
            result = asyncio.run(async_fn)
        except Exception as e:
            nonlocal exception
            exception = e

    thread = threading.Thread(target=thread_runner)
    thread.start()
    thread.join()

    if exception:
        raise exception
    return result
