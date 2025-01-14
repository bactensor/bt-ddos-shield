import os

aws_access_key_id: str = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_access_key: str = os.getenv('AWS_SECRET_ACCESS_KEY')
aws_region_name: str = os.getenv('AWS_REGION_NAME')
aws_s3_bucket_name: str = os.getenv('AWS_S3_BUCKET_NAME')
sql_alchemy_db_url: str = 'sqlite:///ddos_shield.db'
aws_route53_hosted_zone_id: str = os.getenv('AWS_ROUTE53_HOSTED_ZONE_ID')
aws_route53_other_hosted_zone_id: str = os.getenv('AWS_ROUTE53_OTHER_HOSTED_ZONE_ID')

# either miner_instance_id or miner_instance_ip should be used
miner_instance_id: str = os.getenv('MINER_INSTANCE_ID')
miner_instance_ip: str = os.getenv('MINER_INSTANCE_IP')

miner_instance_port: int = int(os.getenv('MINER_INSTANCE_PORT'))
