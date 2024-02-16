# Use the Rust image to build the Rust code
FROM rust:latest as rust-builder

# Install wasm-pack
RUN cargo install wasm-pack

# Copy the Rust project code
WORKDIR /app/RustCode
COPY RustCode/ .

# Build for web target
RUN wasm-pack build --target web --out-dir /app/public/web_wasm

# Build for nodejs target
RUN wasm-pack build --target nodejs --out-dir /app/node_wasm

# Use the official Node.js image as the base image for the final image
FROM node:16 as node-base

# Set the working directory in the Docker container
WORKDIR /app

# Copy the Node.js website files
COPY Website/ .

# Copy the WASM modules from the Rust build stage
COPY --from=rust-builder /app/public ./public
COPY --from=rust-builder /app/node_wasm ./node_wasm

# Install any dependencies, including those needed by the WASM modules
RUN npm install

# Rebuild sqlite3 specifically
## RUN npm rebuild sqlite3 --build-from-source

# Expose the port your app runs on
EXPOSE 3000

# Command to run your app
CMD ["node", "app.js"]
