#!/usr/bin/env bash
set -euo pipefail

mkdir -p build/examples
cc -g -fno-omit-frame-pointer -O1 -o build/examples/memcpy_overflow examples/memcpy_overflow.c
cc -g -fno-omit-frame-pointer -O1 -o build/examples/double_free examples/double_free.c
cc -g -fno-omit-frame-pointer -O1 -o build/examples/invalid_free examples/invalid_free.c
echo "Built examples under build/examples/"


