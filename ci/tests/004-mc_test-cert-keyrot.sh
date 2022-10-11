#!/bin/bash

set -xeo pipefail

make test-cert-keyrot -C mc_test/
