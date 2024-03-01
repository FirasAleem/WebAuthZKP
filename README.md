# Final Year Project Repository

The repository contains the code neeeded for my FYP: Verifying WebAuthn Assertions using Zero-Knowledge Proofs.

## Structure

The repository is organized into two main directories:

- `RustCode`: Contains the Rust implementation for the ZKP.
- `Website`: Houses the web interface for registering & authenticating using Passkeys, as well as authenticating using the ZKP

The easier method to run the website is to run it in Docker using the provided Dockerfile; details for this are provided at the bottom.

### RustCode Directory

The `RustCode` directory includes all the necessary Rust code for the Zero-Knowledge Proofs. 

#### Running the Rust Code

To run the Rust code, navigate to the `RustCode` directory and execute the following command:

    cargo run -r
This command compiles the Rust code and runs the resulting executable.

### Website Directory

The `Website` directory contains all the files necessary for the web interface.

#### Setting Up the Website

1. **Install Dependencies**

   First, ensure that you have `npm` installed. Then, run the following command in the `Website` directory to install the required dependencies:

       npm install

2. **Running the Web Server**

   After installing the dependencies, start the web server by running:

       node app.js

   By default, the web server listens on port `3000`. To use a different port, edit line 16 in `Website/app.js`.

### Recompiling Rust to WebAssembly

If you need to recompile the Rust code to WebAssembly for web integration, a convenience script `build-wasm.sh` is provided.

To use the script, run:

    ./build-wasm.sh

This script compiles the Rust code to WebAssembly and copies the necessary files to their correct locations.

### Using Docker

For environments without `npm` or for a more containerized approach, a `Dockerfile` is provided.

#### Building the Docker Image

To build the Docker image, run:

    docker build -t webauth-zkp .

#### Running the Docker Container

After building the image, run the container using:

    docker run -it -p 3000:3000 webauth-zkp

This command maps port `3000` inside the container to port `3000` on your local machine, allowing you to access the web interface through your browser.

