#!/bin/bash
set -eux -o pipefail

# TODO: To be removed - needed as for now because of still using MemoryBlockchainManager
export PYTHONPATH=.:${PYTHONPATH:-}

python bt_ddos_shield/miner_shield.py "$@"
