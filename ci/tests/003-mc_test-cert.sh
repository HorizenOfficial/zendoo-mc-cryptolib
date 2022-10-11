#!/bin/bash

set -xeo pipefail

make test-cert -C mc_test/
