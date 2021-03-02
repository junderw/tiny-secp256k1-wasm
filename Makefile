build:
	cargo build --release -p secp256k1-wasm --target wasm32-unknown-unknown
	wasm-bindgen --out-dir pkg --target nodejs target/wasm32-unknown-unknown/release/secp256k1_wasm.wasm
	wasm-opt -O4 pkg/secp256k1_wasm_bg.wasm --output pkg/secp256k1_wasm_bg.wasm

build-debug:
	cargo build -p secp256k1-wasm --target wasm32-unknown-unknown
	wasm-bindgen --out-dir pkg --target nodejs --debug --no-demangle --keep-debug target/wasm32-unknown-unknown/debug/secp256k1_wasm.wasm

clean:
	rm -rf node_modules pkg target 

# TODO: add js format (prettier?)
format:
	cargo-fmt

# TODO: add js linter (same as fmt, prettier?)
lint:
	cargo fmt -- --check
	cargo clippy
