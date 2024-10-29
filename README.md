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
- Uses encrypted messages between miners and validators to securely exchange connection information (IP, IP version, and port).
- Provides a scalable, decentralized alternative to traditional DDoS protection methods while maintaining performance and minimizing attack vectors.

## Features

1. **Encryption-Based Communication**:
   - Uses ECIES (Elliptic Curve Integrated Encryption Scheme) to encrypt communication between miners and validators.
   - The encrypted data includes the miner's hotkey, subnet ID, and validator connection details (IP, IP version, and port).

2. **Decentralized DDoS Mitigation**:
   - Removes the need for centralized DDoS protection services by distributing connection information securely across nodes.
   - Prevents IP address exposure by sharing encrypted connection data through a decentralized network of subtensors.

3. **Secure Message Exchange**:
   - Validators can request the connection information of miners from the subtensor network. This information is validated and
     decrypted locally using the validator's private key.

## Communication Flow

<!--
@startuml ./assets/diagrams/CommunicationFlow
participant Validator
participant Miner
participant GitHub
participant Storage
participant Bittensor
Validator -> Validator: Generate Validator key-pair
Validator -> GitHub: Publish public key along with HotKey
GitHub -> Miner: Fetch Validator info
Miner -> Miner: Encrypt Miner IP/Domain with Validator public key
Miner -> Storage: Add/update file with encrypted IPs/Domains for Validators
Miner -> Bittensor: Publish file location
Bittensor -> Validator: Fetch file location
Storage -> Validator: Fetch Miner file
Validator -> Validator: Decrypt Miner file entry encrypted for given Validator
Validator -> Miner: Send request using decrypted Miner IP/Domain
@enduml
-->

![](./assets/diagrams/CommunicationFlow.svg)

## Installation
```
pip install bt-ddos-shield
```

## Contribution Guidelines

To contribute to the `bt-ddos-shield` package, the steps below:

### 1. Clone the Repository:

```bash
git clone https://github.com/bactensor/bt-ddos-shield.git
cd bt-ddos-shield
```

### 2. Install Dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install poetry
poetry install
```

### 3. Build the Pacakge:
```bash
poetry build
```

### 4. Run Tests:
```bash
poetry run pytest
```

### 5. Local Pacakge Usage

To install the package locally for development purposes:
```bash
pip insatll -e <path/to/package>
```

### 6. Publish the Package
```bash
poetry publish
```

## License

See the [LICENSE](./LICENSE) file for more details.
