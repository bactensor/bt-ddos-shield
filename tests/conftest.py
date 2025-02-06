import pytest
from pydantic import Field

from bt_ddos_shield.miner_shield import ShieldSettings
from bt_ddos_shield.utils import WalletSettings


class ShieldTestSettings(ShieldSettings):
    aws_route53_other_hosted_zone_id: str
    miner_instance_port: int = 8080

    validator_wallet: WalletSettings = WalletSettings()
    validator_public_key: str = Field(min_length=1)
    """ Hex representation of secp256k1 public key of validator """
    validator_private_key: str = Field(min_length=1)
    """ Hex representation of secp256k1 private key of validator """

    model_config = {
        'env_file': '.env.test',
        'extra': 'ignore',
    }


@pytest.fixture
def shield_settings() -> ShieldTestSettings:
    settings: ShieldTestSettings = ShieldTestSettings()  # type: ignore
    settings.options.retry_limit = 1  # Do not retry forever as tests can hang
    return settings
