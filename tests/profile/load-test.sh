#!/usr/bin/env bash
#
# Run the load test inside the Linux profiling container.
#
# Usage (from the repo root):
#   composer test-load-docker
#   composer test-load-docker -- --seed-entries=5000 --clients=4
#
set -euo pipefail

compose_file="$(cd "$(dirname "$0")" && pwd)/docker-compose.yml"

docker compose -f "$compose_file" up -d --build --wait
docker exec freedsx-profile composer install --no-interaction --quiet
docker exec freedsx-profile composer test-load -- "$@"
