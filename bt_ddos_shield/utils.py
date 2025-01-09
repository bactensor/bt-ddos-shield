from typing import Optional, TypeAlias

import boto3
import route53
from botocore.client import BaseClient
from pydantic import BaseModel
from route53.connection import Route53Connection

Hotkey: TypeAlias = str
PublicKey: TypeAlias = str
PrivateKey: TypeAlias = str


class AWSClientFactory:
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_region_name: Optional[str]

    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, aws_region_name: Optional[str] = None):
        """
        Args:
            aws_access_key_id: AWS access key ID.
            aws_secret_access_key: AWS secret access key.
            aws_region_name: AWS region name. If not known, it can be set later using set_aws_region_name method.
        """
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_region_name = aws_region_name

    def set_aws_region_name(self, aws_region_name: str) -> bool:
        """ Set AWS region name. Returns if region name was changed. """
        if self.aws_region_name == aws_region_name:
            return False
        self.aws_region_name = aws_region_name
        return True

    def boto3_client(self, service_name: str) -> BaseClient:
        return boto3.client(service_name, aws_access_key_id=self.aws_access_key_id,
                            aws_secret_access_key=self.aws_secret_access_key, region_name=self.aws_region_name)

    def route53_client(self) -> Route53Connection:
        return route53.connect(self.aws_access_key_id, self.aws_secret_access_key)


class BooleanModel(BaseModel):
    bool_value: bool
