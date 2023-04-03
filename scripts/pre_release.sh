#!/bin/bash

set -e

SCRIPT_PATH="$( cd "$( dirname "$0" )" >/dev/null 2>&1 && pwd )"

cd "$SCRIPT_PATH/../poly-cross-chain" || exit
mpm package test
mpm release
mpm integration-test -p ./

cd "$SCRIPT_PATH/../stc-assets" || exit
mpm package test
mpm integration-test -p ./
mpm release


cd "$SCRIPT_PATH/../stc-smt" || exit
mpm package test
mpm integration-test -p ./
mpm release

cd "$SCRIPT_PATH/../stc-utils" || exit
mpm package test
mpm integration-test -d ./
mpm release

cd "$SCRIPT_PATH/../zion-cross-chain" || exit
mpm package test
mpm integration-test -d ./
mpm release
