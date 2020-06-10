#!/usr/bin/env bash

# Get directory of this file
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd "$DIR"/..

REL_WASM_PATH="./pkg/tiny_secp256k1_wasm_bg.wasm"

IMAGE_TO_RUN="${1:-junderw/tiny-secp256k1-wasm-builder}"

docker run \
  -v "$(pwd)":/data \
  --rm \
  $IMAGE_TO_RUN \
  bash -c \
  "\
  mkdir /datacopy && \
  \
  \`# Copy over all the data in the repo \`\
  \
  rsync -av \
    --exclude=.git/ --exclude=target/ --exclude=node_modules/ \
    --exclude=tmp/ --exclude=pkg/ \
      /data/ /datacopy/ >/dev/null 2>&1 && \
  cd /datacopy && \
  \
  \`# Build with wasm-pack \`\
  \
  wasm-pack build --release -t nodejs && \
  \
  \`# Insert the wrapper and point package.json to the wrapper \`\
  \
  cp bin/wrapper.js pkg/wrapper.js && \
  cp bin/wrapper.d.ts pkg/wrapper.d.ts && \
  rm pkg/package.json pkg/LICENSE pkg/README.md pkg/.gitignore && \
  \
  \`# Shrink the wasm binary \`\
  \
  /wabt/bin/wasm-strip $REL_WASM_PATH && \
  /binaryen/bin/wasm-opt -Oz -o $REL_WASM_PATH $REL_WASM_PATH && \
  \
  \`# Set permissions for pkg and target and copy over to our repo folder \`\
  \
  chown -R $UID:$UID pkg/ && \
  chown -R $UID:$UID target/ && \
  rsync -av pkg/ /data/pkg/ >/dev/null 2>&1 \
  "
