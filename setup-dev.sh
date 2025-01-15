#!/usr/bin/env bash

set -e

ENV_DIR="./envs"

# Create a lock file, install Python dependencies
[ -f uv.lock ] || uv lock
uv sync --group test --group format --group lint --group type_check --group security_check

# Create .env files from the template if not already created
[[ -f "${ENV_DIR}/.env" ]] || cp "${ENV_DIR}/.env.template" "${ENV_DIR}/.env"
[[ -f "${ENV_DIR}/.env.test" ]] || cp "${ENV_DIR}/.env.test.template" "${ENV_DIR}/.env.test"

# Set symlinks
ln -sf "${ENV_DIR}/.env" ".env"
ln -sf "${ENV_DIR}/.env.test" ".env.test"
ln -sf "../${ENV_DIR}/.env.test" "tests/.env.test"

# Ensure that the script returns zero for the CI
exit 0
