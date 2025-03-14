from __future__ import annotations

import os

import pytest
from pydantic import Field

from bt_ddos_shield.miner_shield import ShieldSettings
from bt_ddos_shield.utils import WalletSettings


class ShieldTestSettings(ShieldSettings):
    aws_route53_other_hosted_zone_id: str
    miner_instance_port: int = 8080

    validator_wallet: WalletSettings = WalletSettings()
    validator_cert_path: str = Field(min_length=1)
    """ Path to file with certificate """

    model_config = {
        'env_file': '.env.test',
        'extra': 'ignore',
    }


@pytest.fixture
def shield_settings():
    settings: ShieldTestSettings = ShieldTestSettings()  # type: ignore
    settings.options.retry_limit = 1  # Do not retry forever as tests can hang
    os.environ['VALIDATOR_SHIELD_CERTIFICATE_PATH'] = settings.validator_cert_path
    yield settings
    settings.subtensor.client.close()
