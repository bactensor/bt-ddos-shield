#!/usr/bin/env bash

set -e

ENV_DIR="./envs"

# Create a lock file, install Python dependencies
[ -f uv.lock ] || uv lock
uv sync --group test --group format --group lint --group type_check --group security_check

# Create .env from the template if doesn't exist
[[ -f "${ENV_DIR}/.envrc" ]] || cp "${ENV_DIR}/.env.template" ".envrc"

# Set symlinks
ln -sf "bin/run_shield.sh" run_shield.sh

# Ensure that the script returns zero for the CI
exit 0
