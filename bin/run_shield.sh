#!/bin/bash
set -eux -o pipefail

python -m bt_ddos_shield.miner_shield "$@"
