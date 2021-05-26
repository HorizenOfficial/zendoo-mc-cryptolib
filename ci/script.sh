#!/bin/bash

set -euo pipefail

command -v docker &> /dev/null && have_docker="true" || have_docker="false"
# absolute path to project from relative location of this script
workdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
# defaults if not provided via env
DOCKER_ORG="${DOCKER_ORG:-zencash}"
IMAGE_NAME="${IMAGE_NAME:-sc-ci-base}"
IMAGE_TAG="${IMAGE_TAG:-bionic_rust-stable_latest}"
image="${DOCKER_ORG}/${IMAGE_NAME}:${IMAGE_TAG}"

# run tests in docker or natively
if [ -n "${TESTS:-}" ]; then
  if [ "$have_docker" = "true" ]; then
    docker run --rm -t -v "$workdir":/build --entrypoint /build/ci/docker/entrypoint.sh -e TESTS -e LOCAL_USER_ID="$(id -u)" \
      -e LOCAL_GRP_ID="$(id -g)" --env-file <(env | grep -E '^(RUSTFLAGS=|CARGOARGS=|RUST_CROSS_TARGETS=|RUSTUP_TOOLCHAIN=).+$') \
      "$image" /build/ci/run_tests.sh
  else
    "${workdir:-.}/ci/run_tests.sh"
  fi
fi
