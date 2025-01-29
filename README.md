# BT DDoS Shield

## Overview

`bt-ddos-shield` is a Python package designed to address the critical issue of Distributed Denial-of-Service (DDoS) attacks
in bittensor ecosystem. The project leverages encryption to protect communication between miners and validators, ensuring
the IPs and ports of these nodes remain secure and hidden from malicious actors. This decentralized solution aims to eliminate
the financial burden caused by traditional DDoS protection methods like WAF and Cloudflare, which are often costly and
impractical for subnets handling large volumes of data.

## Project Goals

The goal of this project is to implement a distributed and decentralized system that:
- Protects miner and validator IP addresses from exposure, preventing potential DDoS attacks.
- Removes the need for on-chain storage of unencrypted IP addresses and ports, eliminating an obvious attack surface.
- Uses encrypted messages between miners and validators to securely exchange connection information (connection address).
- Provides a scalable, decentralized alternative to traditional DDoS protection methods while maintaining performance and minimizing attack vectors.

## Features

1. **Encryption-Based Communication**:
   - Uses ECIES (Elliptic Curve Integrated Encryption Scheme) to encrypt communication between miners and validators.
   - The encrypted data includes connection details for validator (IP, IP version, and port).

2. **Decentralized DDoS Mitigation**:
   - Removes the need for centralized DDoS protection services by distributing connection information securely across nodes.
   - Prevents IP address exposure by sharing encrypted connection data through a decentralized network of subtensors.

3. **Secure Message Exchange**:
   - Validators can request the connection information of miners from the subtensor network. This information is validated and
     decrypted locally using the validator's private key.

## Basic Communication Flow

<!--
@startuml ./assets/diagrams/CommunicationFlow
participant Validator
participant Miner
participant AddressManager
database Storage
database Bittensor
Validator -> Validator: Generate Validator key-pair
Validator -> Bittensor: Publish public key along with HotKey
Bittensor -> Miner: Fetch new Validator info
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


## Contribution Guidelines

To contribute to the `bt-ddos-shield` package, the steps below:

### 1. Clone the Repository:

```bash
git clone https://github.com/bactensor/bt-ddos-shield.git
cd bt-ddos-shield
```

### 2. Install Dependencies:

Run `setup-dev.sh` script to install the required dependencies and set up the development environment.

### 3. Run Tests:

First create a `.env.test` file filling template file `envs/.env.test.template`. Stub should be made by `setup-dev.sh` script.
Then activate venv with source .venv/bin/activate and run the following command to execute the tests:
```bash
PYTHONPATH=./ pytest
```

## Running shield on server (Miner) side

### 1. Requirements:

* Shield can only be used for hiding AWS EC2 server as for now.
* To run shield, first Route53 hosted zone needs to be created and configured. Some external domain owned by user is needed
for it.
* User needs to manually block traffic from all sources except shield. This can be done using some firewall like UFW or 
by configuring security group in AWS. Autohiding is not yet implemented.

### 2. Run Shield locally:

First create a `.env` file filling template file `envs/.env.template`. Stub should be made by `setup-dev.sh` script.
Then activate venv with source .venv/bin/activate and run the following command to run the shield:
```bash
bin/run_shield.sh
```

### 3. Docker usage

#### Creating Docker Image

To create a docker image, run the following command:
```bash
cd docker && ./build_image.sh
```

#### Running Docker Image

To run created docker image, first create a `docker/.env` file filling template file `envs/.env.template`.
Then run the following command:
```bash
cd docker && ./run_image.sh
```

If one wants to clean objects created by shield run the following command:
```bash
cd docker && ./run_image.sh clean
```

## Running shield on client (Validator) side

TODO

## License

See the [LICENSE](./LICENSE) file for more details.
