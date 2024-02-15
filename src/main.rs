use base64::prelude::*;
use sha2::{Digest, Sha256};
use std::time::Instant;
//use std::io;

use crate::webauth_circuit::WebAuthZKP;

mod webauth_circuit;

fn main() {
    println!("====== WebAuth ZKP Test Started ======");

    // Example base64 encoded values
    //Private Inputs
    let client_data_json_base64 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTWdOZDVUZ1hJTm1BTDdpZzZSS2M5VDE2dExEQ0R1dnF4OVR3azkxTTNXQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0=";
    let auth_data_base64 = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAA==";
    //let client_data_challenge_base64 = "PasVNAaRp9gjhW3HABuFOmFfMoysqkeO5svtrv5xg3I";

    //Public Inputs
    let challenge_base64 = "MgNd5TgXINmAL7ig6RKc9T16tLDCDuvqx9Twk91M3WA";

    let client_data_json = BASE64_STANDARD
        .decode(client_data_json_base64)
        .expect("Failed to decode base64 client_data_json");

    let auth_data = BASE64_STANDARD
        .decode(auth_data_base64)
        .expect("Failed to decode base64 auth_data");

    // let client_data_challenge = BASE64_URL_SAFE_NO_PAD
    //     .decode(client_data_challenge_base64)
    //     .expect("Failed to decode base64 client_data_challenge");

    let challenge = BASE64_URL_SAFE_NO_PAD
        .decode(challenge_base64)
        .expect("Failed to decode base64 challenge");

    //Generate the message, this will be handled by the run_js method
    // Step 1: Hash the `client_data_json` using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&client_data_json);
    let client_data_json_hash = hasher.finalize();

    // Step 2: Concatenate `auth_data` with the SHA-256 hash of `client_data_json`
    let mut concatenated_data = auth_data.clone();
    concatenated_data.extend_from_slice(&client_data_json_hash);

    // Step 3: Hash the concatenated result again using SHA-256 to produce the final message
    let mut hasher = Sha256::new();
    hasher.update(concatenated_data);
    let message = hasher.finalize().to_vec();

    //Take as User Input instead
    // Prompt user for base64 encoded preimage
    // println!("Enter base64 encoded preimage:");
    // let mut base64_preimage = String::new();
    // io::stdin().read_line(&mut base64_preimage).expect("Failed to read line");
    // base64_preimage = base64_preimage.trim_end().to_string(); // Trim newline character

    // // Prompt user for SHA256 hash in hex format
    // println!("Enter SHA256 hash of preimage in hex format (the original text that was hashed):");
    // let mut sha256_hex_of_hash = String::new();
    // io::stdin().read_line(&mut sha256_hex_of_hash).expect("Failed to read line");
    // sha256_hex_of_hash = sha256_hex_of_hash.trim_end().to_string(); // Trim newline character

    let start = Instant::now();

    let (message, challenge, proof, vk) = WebAuthZKP::run(
        client_data_json,
        auth_data,
        message,
        challenge,
    )
    .unwrap();
    println!("Time to setup and prove: {:?} seconds", start.elapsed());

    let verify = Instant::now();

    let result = WebAuthZKP::verify(message, challenge, proof, vk).unwrap_or_else(|e| {
        println!("Error during verification: {:?}", e);
        false // Assuming verification failure in case of error
    });
    println!("Time to verify: {:?} seconds", verify.elapsed());

    if result {
        println!("Verification succeeded");
    } else {
        println!("Verification failed");
    }

    println!("====== WebAuth ZKP Test Finished ======");
    println!("Total time elapsed: {:?} seconds", start.elapsed());
}
