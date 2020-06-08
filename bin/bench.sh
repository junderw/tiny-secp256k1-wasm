#!/usr/bin/env bash

# Get directory of this file
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Build wasm-pack using clang-9
cd "$DIR/.."
CC=clang-9 wasm-pack build --release -t nodejs

# Install dependencies
mkdir -p "$DIR/../tmp"
cd "$DIR/../tmp"
if [ ! -f package.json ]; then npm init -y >/dev/null 2>&1; fi
if [[ ! -d node_modules/tiny-secp256k1 || ! -d node_modules/bitcoin-ts ]]; then
  npm install --no-save bitcoin-ts tiny-secp256k1
fi

# Copy bench file over
cp "$DIR/dontuse_bench.js" "$DIR/../tmp/bench.js"

# Run bench
node "$DIR/../tmp/bench.js"
