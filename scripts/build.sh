#!/bin/bash

# Copyright (c) The Strcoin Core Contributors
# SPDX-License-Identifier: Apache-2.0

set -e

SCRIPT_PATH="$( cd "$( dirname "$0" )" >/dev/null 2>&1 && pwd )"

cd "$SCRIPT_PATH/../poly-cross-chain" || exit
mpm package build --doc --abi --force

cd "$SCRIPT_PATH/../stc-assets" || exit
mpm package build --doc --abi --force

cd "$SCRIPT_PATH/../stc-smt" || exit
mpm package build --doc --abi --force

cd "$SCRIPT_PATH/../stc-utils" || exit
mpm package build --doc --abi --force

cd "$SCRIPT_PATH/../zion-cross-chain" || exit
mpm package build --doc --abi --force