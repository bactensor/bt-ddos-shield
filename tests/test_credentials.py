# When running integration tests, the following values will be used. Fill it with your own values.
aws_access_key_id: str = ""
aws_secret_access_key: str = ""
aws_region_name: str = ""
aws_s3_bucket_name: str = ""
sql_alchemy_db_url: str = "sqlite:///ddos_shield.db"
aws_route53_hosted_zone_id: str = ""
aws_route53_other_hosted_zone_id: str = ""

# either miner_instance_id or miner_instance_ip should be used
miner_instance_id: str = ""
miner_instance_ip: str = ""

miner_instance_port: int = 80
