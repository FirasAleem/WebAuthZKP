use base64::prelude::*;
use sha2::{Digest, Sha256};
//use std::io;
use std::time::Instant;

use crate::webauth_circuit::WebAuthZKP;

mod webauth_circuit;

fn main() {
    println!("====== WebAuth ZKP Test Started ======");

    //Example base64 encoded values
    //Private Inputs
    let client_data_json_base64 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicjJKeFRtWm5PMUk5WE15ZV9KSlRtSE1IVG84SnhRaFozTTRtNWd4Qm9GNCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0=";
    let auth_data_base64 = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA==";

    //Public Inputs
    let challenge_base64 = "r2JxTmZnO1I9XMye_JJTmHMHTo8JxQhZ3M4m5gxBoF4";

    // Prompt for user input:
    // Prompt user for base64 encoded client data JSON
    // println!("Enter base64 encoded client data JSON:");
    // let mut client_data_json_base64 = String::new();
    // io::stdin()
    //     .read_line(&mut client_data_json_base64)
    //     .expect("Failed to read line");
    // let client_data_json_base64 = client_data_json_base64.trim_end().to_string(); // Trim newline character

    // // Prompt user for base64 encoded auth data
    // println!("Enter base64 encoded auth data:");
    // let mut auth_data_base64 = String::new();
    // io::stdin()
    //     .read_line(&mut auth_data_base64)
    //     .expect("Failed to read line");
    // let auth_data_base64 = auth_data_base64.trim_end().to_string(); // Trim newline character

    // // Prompt user for base64 encoded challenge
    // println!("Enter base64 encoded challenge:");
    // let mut challenge_base64 = String::new();
    // io::stdin()
    //     .read_line(&mut challenge_base64)
    //     .expect("Failed to read line");
    // let challenge_base64 = challenge_base64.trim_end().to_string(); // Trim newline character

    let client_data_json = BASE64_STANDARD
        .decode(client_data_json_base64)
        .expect("Failed to decode base64 client_data_json");

    let auth_data = BASE64_STANDARD
        .decode(auth_data_base64)
        .expect("Failed to decode base64 auth_data");

    let challenge = challenge_base64.as_bytes().to_vec();
    //Generate the message, this will be handled by the run_js method
    // Step 1: Hash the `client_data_json` using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&client_data_json);
    let client_data_json_hash = hasher.finalize();

    // Step 2: Concatenate `auth_data` with the SHA-256 hash of `client_data_json`
    let mut concatenated_data = auth_data.clone();
    concatenated_data.extend_from_slice(&client_data_json_hash);

    // Step 3: Hash the concatenated result again using SHA-256 to produce the final message (hash)
    let mut hasher = Sha256::new();
    hasher.update(concatenated_data);
    let message = hasher.finalize().to_vec();

    let start = Instant::now();

    let (message, challenge, proof, vk) =
        WebAuthZKP::run(client_data_json, auth_data, message, challenge).unwrap();
    println!(
        "Time taken to setup and prove: {:?} seconds",
        start.elapsed()
    );
    println!("Message: {:?}", message.to_ascii_lowercase());

    let verify = Instant::now();

    let result = WebAuthZKP::verify(message, challenge, proof, vk).unwrap_or_else(|e| {
        println!("Error during verification: {:?}", e);
        false // Assuming verification failure in case of error
    });
    println!("Time taken to verify: {:?} seconds", verify.elapsed());

    if result {
        println!("Verification succeeded");
    } else {
        println!("Verification failed");
    }

    println!("====== WebAuth ZKP Test Finished ======");
    println!("Total time elapsed: {:?} seconds", start.elapsed());
}
