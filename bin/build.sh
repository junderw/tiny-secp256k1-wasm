#!/usr/bin/env bash

set -e

REL_WASM_PATH="./pkg/tiny_secp256k1_wasm_bg.wasm"
IMAGE_TO_RUN="${1:-junderw/tiny-secp256k1-wasm-builder}"

# Get directory of this file
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"/..

docker run \
  -v "$(pwd)":/data \
    `# This volume is for caching builds` \
  -v tiny-secp256k1-wasm-vol:/datacopy \
  --rm \
  $IMAGE_TO_RUN \
  bash -c \
  "\
  \`# Copy over all the data in the repo \`\
  \
  rsync -av \
    --delete --exclude=.git/ --exclude=rust/target/ --exclude=node_modules/ \
    --exclude=tmp/ --exclude=rust/pkg/ \
      /data/ /datacopy/ >/dev/null 2>&1 && \
  cd /datacopy/rust/ && \
  \
  \`# Build with wasm-pack \`\
  \
  wasm-pack build --release -t nodejs && \
  \
  \`# Insert the wrapper and point package.json to the wrapper \`\
  \
  cp ../bin/tiny_secp256k1_wasm.d.ts pkg/tiny_secp256k1_wasm.d.ts && \
  rm pkg/package.json pkg/LICENSE pkg/.gitignore && \
  \
  \`# Shrink the wasm binary \`\
  \
  /wabt/bin/wasm-strip $REL_WASM_PATH && \
  /binaryen/bin/wasm-opt -Oz -o $REL_WASM_PATH $REL_WASM_PATH && \
  \
  \`# Set permissions for pkg and target and copy over to our repo folder \`\
  \
  chown -R $UID:$UID . && \
  rsync -av pkg/ /data/pkg/ >/dev/null 2>&1 && \
  rsync -av Cargo.lock /data/rust/Cargo.lock >/dev/null 2>&1 && \
  rsync -av --delete target/ /data/rust/target/ >/dev/null 2>&1
  "
