#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NPM_DIR="${SCRIPT_DIR}/../npm"

MAX_RETRIES=3
RETRY_DELAY=10

publish_with_retry() {
  local pkg_dir="$1"
  local attempt=1

  while [[ ${attempt} -le ${MAX_RETRIES} ]]; do
    echo "Publishing $(basename "${pkg_dir}") (attempt ${attempt}/${MAX_RETRIES})..."
    if npm publish "${pkg_dir}" --provenance --access public; then
      echo "Successfully published $(basename "${pkg_dir}")"
      return 0
    fi
    echo "Publish failed, retrying in ${RETRY_DELAY}s..."
    sleep "${RETRY_DELAY}"
    attempt=$((attempt + 1))
  done

  echo "ERROR: Failed to publish $(basename "${pkg_dir}") after ${MAX_RETRIES} attempts" >&2
  return 1
}

# Publish platform packages first (no inter-dependencies)
PLATFORM_PACKAGES=(
  agentd-linux-x64
  agentd-linux-arm64
  agentd-darwin-x64
  agentd-darwin-arm64
)

for pkg in "${PLATFORM_PACKAGES[@]}"; do
  publish_with_retry "${NPM_DIR}/${pkg}"
done

# Wait for registry to propagate platform packages
echo "Waiting 30s for registry propagation..."
sleep 30

# Publish the main wrapper package
publish_with_retry "${NPM_DIR}/agentd"

echo "All npm packages published successfully"
