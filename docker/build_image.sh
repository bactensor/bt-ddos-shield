#!/bin/bash
set -eux -o pipefail

cd .. && docker build --platform linux/amd64 -t bt_ddos_shield -f docker/Dockerfile .
