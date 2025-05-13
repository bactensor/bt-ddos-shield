
# BT DDoS Shield

[![PyPI](https://img.shields.io/pypi/v/bt-ddos-shield-client)](https://pypi.org/project/bt-ddos-shield-client/)
[![License](https://img.shields.io/github/license/bactensor/bt-ddos-shield)](https://github.com/bactensor/bt-ddos-shield/blob/main/LICENSE)

BT DDoS Shield is a solution designed for **Bittensor subnet owners who want to protect miners from Distributed Denial-of-Service (DDoS)** attacks and foster honest competition.

The basic principle behind the shield is to assign multiple addresses to miners - one for each validator - **instead of exposing the miner's public IP in the metagraph**. 
These addresses are communicated to validators using Knowledge Commitments and encrypted with ECIES 
([Elliptic Curve Integrated Encryption Scheme](https://github.com/ecies/py)) keys published by the validators. 
This creates **a secure, permissionless method of distributing miner connection details**.

To use the shield in a subnet, the validator code must be modified by replacing the standard `metagraph` from the `bittensor` 
library with the drop-in replacement `bt_ddos_shield_client.ShieldMetagraph`. 
**Each miner is then responsible for running the shield server** to secure their infrastructure. 
Unshielded miners will still be reachable by their default public addresses published to the metagraph.

BT DDoS Shield offers a scalable and **cost-effective solution for subnets handling large volumes of data**.

## Product Highlights

BT DDoS Shield delivers a secure, decentralized, and scalable solution that:

- **Eliminates vulnerabilities:** Keeps sensitive IP addresses and ports off-chain, reducing the attack surface.
- **Encrypts the handshake:** Uses ECIES ([Elliptic Curve Integrated Encryption Scheme](https://github.com/ecies/py)) 
  to securely exchange connection information between miners and validators.
- **Delivers cost-effective defense:** Provides a decentralized alternative to traditional DDoS protection methods, maintaining performance while minimizing attack vectors.

## Getting Started

If you're a **subnet owner**, enable `bt-ddos-shield-client` in your validator code 
(see [Using Shield on Client (Validator) Side](#using-shield-on-client-validator-side)) so that everything runs automatically. 
**Validators** can review the detailed workings in that section.

If you're a **miner**, activate `bt-ddos-shield-server` on your end by running it as described in the [Running Shield on Server (Miner) Side](#running-shield-on-server-miner-side) section.

We welcome your contributions—see [Contribution Guidelines](#contribution-guidelines) for more information. 

For requests, feedback, or questions, **join us on the [ComputeHorde Discord channel](https://discordapp.com/channels/799672011265015819/1201941624243109888)**.

Also, be sure to check out our subnet and other products at [ComputeHorde](https://computehorde.io).


## Running Shield on server (Miner) side

### Disclaimers

* As for now BT DDoS Shield can only be used for hiding AWS EC2 server and uses AWS ELB and WAF to handle communication.
* As autohiding is not yet implemented, after starting the Shield it is required to manually block the traffic from all sources except the
Shield's load balancer (ELB created by the Shield during first run). This can be done using any firewall (like UFW) locally on
server or by configuring security groups in AWS via AWS panel (EC2 instance security groups should allow traffic only from ELB).

### Prerequisites

* AWS account with given privileges:
  * `ec2:DescribeInstances`
  * `ec2:DescribeVpcs`
  * `ec2:DescribeAvailabilityZones`
  * `ec2:CreateSubnet`
  * `ec2:DeleteSubnet`
  * `ec2:DescribeSubnets`
  * `ec2:CreateSecurityGroup`
  * `ec2:DeleteSecurityGroup`
  * `ec2:AuthorizeSecurityGroupIngress`
  * `wafv2:CreateWebACL`
  * `wafv2:DeleteWebACL`
  * `wafv2:GetWebACL`
  * `wafv2:UpdateWebACL`
  * `wafv2:AssociateWebACL`
  * `wafv2:DisassociateWebACL`
  * `elasticloadbalancing:CreateLoadBalancer`
  * `elasticloadbalancing:DeleteLoadBalancer`
  * `elasticloadbalancing:DescribeLoadBalancers`
  * `elasticloadbalancing:CreateListener`
  * `elasticloadbalancing:CreateTargetGroup`
  * `elasticloadbalancing:DeleteTargetGroup`
  * `elasticloadbalancing:RegisterTargets`
  * `elasticloadbalancing:DeregisterTargets`
  * `route53:ListHostedZones`
  * `route53:ChangeResourceRecordSets`
  * `route53:ListResourceRecordSets`
  * `route53:GetHostedZone`
  * `s3:PutObject`
* A domain, either 
  * registered via AWS; or
  * via another registrar, a Route 53 hosted zone created for it, and name servers configured to match those of the Route 53 hosted zone     
* Hosted zone id from the previous step, can be obtained from `aws route53 list-hosted-zones --query "HostedZones[].{Name:Name,Id:Id}" --output table `
* S3 bucket with public read and ACLs enabled
* Miner's server needs to respond to ELB health checks. This can be done by configuring server to respond with 200 status
to `GET /` request on server's traffic port. Also, server security group should allow traffic from ELB.
* Miner hotkey - the shield server process will need access to it.

### Running `bt-ddos-shield-server` Docker image

The shield server is distributed as docker image. Below are instructions on how to run it (and make it start after restarts) using `docker compose`

1. Create `.env` file and fill template with your values. Template is:
```
# Shielded server details (only EC2 instance now)

# Either AWS_MINER_INSTANCE_ID or AWS_MINER_INSTANCE_IP (private IP of EC2 server) must be provided
AWS_MINER_INSTANCE_ID=i-0123456789abcdef0
# AWS_MINER_INSTANCE_IP=

# Axon port of the miner
MINER_INSTANCE_PORT=80


# AWS credentials

AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF
AWS_SECRET_ACCESS_KEY=+55aBcDefghijklmnopqrstuvwxyz12345678ABC
AWS_REGION_NAME=eu-north-1
AWS_S3_BUCKET_NAME=shield_bucket
AWS_ROUTE53_HOSTED_ZONE_ID=Z0123456789ABCDEFGHIJ


# Bittensor configuration

SUBTENSOR__NETWORK=finney
NETUID=1


# Wallet location

WALLET__NAME=bt_ddos_shield
WALLET__HOTKEY=miner
```

2. Create `docker-compose.yml` configuration file with this content (Make sure to replace `/YOUR/PATH/TO...` with the right path below):
```yaml
services:
  bt-ddos-shield-server:
    image: backenddevelopersltd/bt-ddos-shield-server:latest
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - ddos_shield_db:/root/src/db
      - /YOUR/PATH/TO/BITTENSOR/WALLET/DIRECTORY/IT/USUALLY/IS/~/.bittensor/wallets:/root/.bittensor/wallets
    entrypoint: ["./entrypoint.sh"]

volumes:
  ddos_shield_db:
```

If everything is prepared, to start the Shield using docker compose, run this command:
```bash
docker compose up -d
```

After this step, the shield server will automatically detect validators, create addresses for them and publish them (encrypted).

To stop Shield, run this command:
```bash
docker compose down
```



### Banning validators

To ban malicious validator, run the Shield's (first stop the current container)
`ban` command with the hotkey param:
```bash
docker-compose run bt-ddos-shield-server ban <HOTKEY>
```
This will remove given validator and update the manifest file.
After banning operation is finished the Shield process will stop.
The banned validator will be saved to local database and will not be included in manifest file until it is unbanned.
To unban a validator use `unban` command:
```bash
docker-compose run bt-ddos-shield-server unban <HOTKEY>
```

## Basic Communication Flow

<!--
@startuml ./assets/diagrams/CommunicationFlow
participant Validator
participant Miner
participant AddressManager
database Storage
database Bittensor
Validator -> Validator: Generate Validator key-pair
Validator -> Bittensor: Publish public key (via certificate field)
Bittensor -> Miner: Discover new Validator and fetch public key
Miner -> AddressManager: Generate new address
Miner -> Miner: Encrypt generated address with Validator public key
Miner -> Storage: Update file with encrypted addresses for Validators
Miner -> Bittensor: Publish file location
Bittensor -> Validator: Fetch file location
Storage -> Validator: Fetch Miner file
Validator -> Validator: Decrypt Miner file entry encrypted for given Validator
Validator -> Miner: Send request using decrypted Miner address
@enduml
-->

![](./assets/diagrams/CommunicationFlow.svg)

### Shield workflow

1. When started for the first time, the Shield will create an ELB and WAF in AWS (along with other needed objects).
It might take few minutes for AWS to create these objects. There will be logs in the console informing about the progress.
When the Shield is run next time, it will use already created objects - info about them is stored in local database.
2. When initialization is done, validators list is retrieved from Bittensor and the Shield creates domain address for each
validator, which uploaded their public key to Bittensor (using `bt-ddos-shield-client` on their side).
3. These addresses are aggregated into manifest file, encrypted and uploaded to S3 bucket. 
Then the info about manifest file is published to Bittensor.
4. When the Shield is running, it cyclically checks if there are any new validators or if any validator's public key has
changed. If so, it updates manifest file and uploads it to S3 bucket. Stopping the Shield process (container) with `Ctrl-C` only
stops these cyclic checks - the Shield will be still working as AWS objects are left.
5. To disable the Shield completely and clean objects created by the Shield, run the Shield's image `clean` command:
```bash
docker-compose run bt-ddos-shield-server clean
```


## Using Shield on client (Validator) side

### Usage instructions:

```bash
pip install bt-ddos-shield-client
```

In your validator code replace 
```python3
metagraph = subtensor.metagraph(netuid)
```
with
```python3
from bt_ddos_shield import ShieldMetagraph

metagraph = ShieldMetagraph(wallet, netuid, subtensor=subtensor)
```

Or if you are creating metagraph is such way
```python3
metagraph = Metagraph(netuid, network)
```
then replace it with
```python3
from bt_ddos_shield import ShieldMetagraph

metagraph = ShieldMetagraph(wallet, netuid, network)
```

If you are running Validator in Docker, make sure to mount a volume for storing certificate generated for
encrypting addresses to not regenerate it on each run - see [Encryption key and cert](#encryption-key-and-cert) for more
information. If you are mounting a volume with wallet to the container, you can use the same volume for the certificate.

### Advanced usage:

#### Encryption key and cert

Upon first call of `ShieldMetagraph`, by default, a cert-key pair will be created, saved on disk and pushed to the Subtensor. If for
whatever reason one needs to provide their own pregenerated cert-key pair (for example when moving to a new validator node), make sure to put the
cert and key files on the server and provide `VALIDATOR_SHIELD_CERTIFICATE_PATH` env var (or use certificate_path option in options passed
via constructor) when starting the new validator instance. Default value for this env var is `./validator_cert.pem`.

### Implementation details:

During `sync` metagraph operation `ShieldMetagraph` class is trying to fetch manifest files for all miners in subnet. For those,
who have manifest file uploaded, `ShieldMetagraph` fetches the file and decrypts prepared address using validator's private key.
If manifest file or entry for given validator is not found, then nothing happens for given miner. If it is found and
successfully decrypted, then `ip` and `port` fields are updated in metagraph axon info. Please note, that after this update
`ip` field will contain domain address, not IP address. Connecting to miners should work without problems as before, but
if there were any problems with this, `replace_ip_address_for_axon` option in `ShieldMetagraph` can be disabled - there
is an `options` param in `ShieldMetagraph` constructor.


## Contribution Guidelines

To contribute to BT DDoS Shield, follow the steps below. Contact us via GitHub.

### 1. Clone the Repository:

```bash
git clone https://github.com/bactensor/bt-ddos-shield.git
cd bt-ddos-shield
```

### 2. Install Dependencies:

Run `setup-dev.sh` script to install the required dependencies and set up the development environment.

### 3. Run Tests:

First create a `.env.test` file filling template file `envs/.env.test.template`. Stub should be made by `setup-dev.sh` script.
Then activate venv with source .venv/bin/activate and run the following command to execute tests:
```bash
pytest
```

### 4. Make changes:

Make changes to the codebase and ensure that the tests pass. Then send a pull request with the changes.

### 5. TODO list:

Improvements we will appreciate (and help you with):
* Allowing the use of Shield with cloud providers other than AWS. One must implement `AbstractAddressManager` (like `AwsAddressManager` does).

### Running the Shield locally:

Run `setup-dev.sh` script to install the required dependencies and set up the development environment.
Then create a `.env` file filling template file `envs/.env.template`. Stub should be made by `setup-dev.sh` script.
Then activate venv with `source .venv/bin/activate` and run the following command to run the Shield:
```bash
bin/run_shield.sh
```
Commands can be passed as arguments to `run_shield.sh` script. Example:
```bash
bin/run_shield.sh clean
```

### Working with the Shield Docker image

- **Creating Docker image**
  To create the Shield Docker image, run the following command:
  ```bash
  cd docker && ./build_image.sh
  ```

- **Running Docker image locally**
  To run created Docker image, first create a `docker/.env` file filling template file `envs/.env.template`.
  Then run the following command:
  ```bash
  cd docker && ./run_image.sh
  ```
  Commands can be passed as arguments to `run_image.sh` script. Example:
  ```bash
  ./run_image.sh clean
  ```

## License

See the [LICENSE](./LICENSE) file for more details.
