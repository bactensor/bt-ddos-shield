#!/bin/bash
set -eux -o pipefail

exec python -m bt_ddos_shield.miner_shield "$@"
