# Docker Build Environment

***ALL PATHS ARE RELATIVE TO THIS DOCKER FOLDER***

## Build the Docker image

```bash
docker build . -t tiny-secp256k1-wasm-builder
# Or pull the image already made
docker pull junderw/tiny-secp256k1-wasm-builder
```

## Run the Docker container (Build the WASM package)

```bash
../bin/build.sh tiny-secp256k1-wasm-builder
# Or don't pass any args and default will be junderw/tiny-secp256k1-wasm-builder
../bin/build.sh
```

- After running the build.sh script the wasm package with JS bindings and wrappers will be in `../pkg`
