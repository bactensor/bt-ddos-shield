#!/bin/bash
set -eux -o pipefail

docker run --env-file .env -v ddos_shield_db:/root/src/db -it bt_ddos_shield ./entrypoint.sh "$@"

# To clean objects created by shield in AWS use following command:
# docker run --env-file .env -v ddos_shield_db:/root/src/db -it bt_ddos_shield ./entrypoint.sh clean
