#!/bin/bash

set -e

SCRIPT_PATH="$( cd "$( dirname "$0" )" >/dev/null 2>&1 && pwd )"

cd "$SCRIPT_PATH/../poly-cross-chain" || exit
mpm release

cd "$SCRIPT_PATH/../stc-assets" || exit
mpm release

cd "$SCRIPT_PATH/../stc-smt" || exit
mpm release

cd "$SCRIPT_PATH/../stc-utils" || exit
mpm release

cd "$SCRIPT_PATH/../zion-cross-chain" || exit
mpm release