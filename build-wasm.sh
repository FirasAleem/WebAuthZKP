#!/bin/bash

# The script builds and moves the warm folders to the right places
# Run after changes to the Rust code

# Determine the base directory relative to the script location
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Navigate to the RustCode directory relative to the script's location
cd "$BASE_DIR/RustCode" || exit

# Build for web target
wasm-pack build --target web --out-dir web_wasm

# Delete the .gitignore file in the web_wasm folder (needed so it can be pushed)
rm -f web_wasm/.gitignore

# Replace the existing web_wasm folder with the new one
rm -rf "$BASE_DIR/Website/public/web_wasm"
cp -R web_wasm "$BASE_DIR/Website/public/web_wasm"

# Build for nodejs target
wasm-pack build --target nodejs --out-dir node_wasm

# Delete the .gitignore file in the node_wasm folder
rm -f node_wasm/.gitignore

# Replace the existing node_wasm folder with the new one
rm -rf "$BASE_DIR/Website/node_wasm"
cp -R node_wasm "$BASE_DIR/Website/node_wasm"
