use ark_bls12_377::{Bls12_377, Fr};
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
//use ark_crypto_primitives::crh::{sha256::Sha256, CRHScheme};
use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use base64::prelude::*;
use rand::thread_rng;
use serde_json::{json, Value};
use serde_wasm_bindgen::to_value;
use sha2::{Digest, Sha256};
use std::str;
use wasm_bindgen::prelude::*;
use web_sys::console;

//use ark_r1cs_std::fields::fp::FpVar;

// use std::any::type_name;

// // Helper function for getting the type name
// fn type_of<T>(_: &T) -> &'static str {
//     type_name::<T>()
// }

//Change this depending on URL of website
static URL: &str = "http://localhost:3000";


#[derive(Clone)]
struct WebAuthCircuit {
    //Private inputs
    client_data_json: Option<Vec<u8>>,
    auth_data: Option<Vec<u8>>,
    client_data_challenge: Option<Vec<u8>>,
    client_data_origin: Option<Vec<u8>>,
    client_data_type: Option<Vec<u8>>,

    //Public Inputs
    message: Option<Vec<u8>>,
    challenge: Option<Vec<u8>>,
}


impl ConstraintSynthesizer<Fr> for WebAuthCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let client_data_var = self
            .client_data_json
            .as_ref()
            .map(|client_data_json| UInt8::new_witness_vec(cs.clone(), client_data_json))
            .unwrap_or_else(|| Err(SynthesisError::AssignmentMissing))?;

        let client_data_challenge_var = self
            .client_data_challenge
            .as_ref()
            .map(|client_data_challenge| UInt8::new_witness_vec(cs.clone(), client_data_challenge))
            .unwrap_or_else(|| Err(SynthesisError::AssignmentMissing))?;

        let client_data_origin_var = self
            .client_data_origin
            .as_ref()
            .map(|client_data_origin| UInt8::new_witness_vec(cs.clone(), client_data_origin))
            .unwrap_or_else(|| Err(SynthesisError::AssignmentMissing))?;

        let client_data_type_var = self
            .client_data_type
            .as_ref()
            .map(|client_data_type| UInt8::new_witness_vec(cs.clone(), client_data_type))
            .unwrap_or_else(|| Err(SynthesisError::AssignmentMissing))?;

        let auth_data_var = self
            .auth_data
            .as_ref()
            .map(|auth_data| UInt8::new_witness_vec(cs.clone(), auth_data))
            .unwrap_or_else(|| Err(SynthesisError::AssignmentMissing))?;

        let message_var = self
            .message
            .as_ref()
            .map(|message| UInt8::new_input_vec(cs.clone(), message))
            .unwrap_or_else(|| Err(SynthesisError::AssignmentMissing))?;

        let challenge_var = self
            .challenge
            .as_ref()
            .map(|challenge| UInt8::new_input_vec(cs.clone(), challenge))
            .unwrap_or_else(|| Err(SynthesisError::AssignmentMissing))?;

        //This is step 1 to get our signature: we hash the JSON client data
        let client_data_hash = Sha256Gadget::digest(&client_data_var)?;

        // Step 2: Convert the hash result to a byte vector to concatenate with the auth_data
        let client_data_hash_bytes = client_data_hash.to_bytes()?;

        // Step 3: Concatenate the hash result with the auth_data
        let mut combined_data = Vec::new();
        combined_data.extend_from_slice(&auth_data_var);
        combined_data.extend_from_slice(&client_data_hash_bytes);

        // Step 4: Hash the combined data
        let computed_message_hash = Sha256Gadget::digest(&combined_data)?;

        // Enforce that the calculated hash equals the provided hash
        computed_message_hash.0.enforce_equal(&message_var)?;

        // Enforce that the client_data_challenge is equal to the challenge
        client_data_challenge_var.enforce_equal(&challenge_var)?;

        let target_origin_bytes = URL.as_bytes();
        let target_origin_var: Vec<UInt8<Fr>> = target_origin_bytes.iter()
            .map(|byte| UInt8::constant(*byte))
            .collect();


        client_data_origin_var.enforce_equal(&target_origin_var)?;

        let target_type_bytes = "webauthn.get".as_bytes();
        let target_type_var: Vec<UInt8<Fr>> = target_type_bytes.iter()
            .map(|byte| UInt8::constant(*byte))
            .collect();

        client_data_type_var.enforce_equal(&target_type_var)?;
        Ok(())
    }
}

pub struct WebAuthZKP;

impl WebAuthZKP {
    pub fn run(
        //Private inputs
        client_data_json: Vec<u8>,
        auth_data: Vec<u8>,

        //Public Inputs
        message: Vec<u8>,
        challenge: Vec<u8>,
    ) -> Result<
        (
            Vec<u8>, // message as Vec<u8>
            Vec<u8>, // challenge as Vec<u8>
            Vec<u8>, // serialized proof
            Vec<u8>, // serialized verifying key
        ),
        SynthesisError,
    > {
        let rng = &mut thread_rng();
        //Get the challenge from the client_data_json
        // Step 1: Decode client_data_json from bytes to a string
        let client_data_json_str =
            str::from_utf8(&client_data_json).map_err(|_| SynthesisError::AssignmentMissing)?;

        // Step 2: Parse the JSON string to access the 'challenge' field
        let parsed_json: Value = serde_json::from_str(client_data_json_str)
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        // Step 3: Get the challenge as base64
        let client_data_challenge_base64 = parsed_json["challenge"]
            .as_str()
            .ok_or(SynthesisError::AssignmentMissing)?;

        // Step 4: Decode the challenge from base64 to bytes
        let client_data_challenge = BASE64_URL_SAFE_NO_PAD
            .decode(client_data_challenge_base64)
            .expect("Failed to decode base64 client_data_challenge");

        //Other checking:
        // Get the origin
        let client_data_origin = parsed_json["origin"]
            .as_str()
            .ok_or(SynthesisError::AssignmentMissing)?;
        // Get the type 
        let client_data_type = parsed_json["type"]
            .as_str()
            .ok_or(SynthesisError::AssignmentMissing)?;

        println!("client_data_origin: {}", client_data_origin);
        println!("client_data_type: {}", client_data_type);

        let circuit = WebAuthCircuit {
            client_data_json: Some(client_data_json),
            auth_data: Some(auth_data),
            client_data_challenge: Some(client_data_challenge),
            client_data_origin: Some(client_data_origin.as_bytes().to_vec()),
            client_data_type: Some(client_data_type.as_bytes().to_vec()),
            message: Some(message.clone()),
            challenge: Some(challenge.clone()),
        };

        // Instantiate a local constraint system and check the validity of the circuit
        println!("Check circuit without proving");
        let cs = ConstraintSystem::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        println!("Is satisfied: {}", cs.is_satisfied().unwrap());
        println!("Num constraints: {}", cs.num_constraints());

        // Setup phase
        println!("Setup");
        let (pk, vk) = Groth16::<Bls12_377>::setup(circuit.clone(), rng)?;
        // println!("Proving Key: {:#?}", pk);
        // println!("Verification Key: {:#?}", vk);

        // Proving phase
        println!("Proving");
        let proof = Groth16::<Bls12_377>::prove(&pk, circuit, rng)?;
        //println!("Proof: {:#?}", proof);
        println!("Proof size: {} bytes", proof.compressed_size());

        //Seriliaze the proof and the verifying key
        let mut serialized_proof: Vec<u8> = Vec::new();
        proof.serialize_compressed(&mut serialized_proof).unwrap();

        let mut serialized_vk: Vec<u8> = Vec::new();
        vk.serialize_compressed(&mut serialized_vk).unwrap();

        Ok((message, challenge, serialized_proof, serialized_vk))
    }

    pub fn verify(
        message: Vec<u8>,
        challenge: Vec<u8>,
        proof_serialized: Vec<u8>,
        vk_serialized: Vec<u8>,
    ) -> Result<bool, SynthesisError> {
        //First deserialize the proof and the verifying key
        let proof = Proof::<Bls12_377>::deserialize_compressed(&proof_serialized[..]).unwrap();
        let vk = VerifyingKey::<Bls12_377>::deserialize_compressed(&vk_serialized[..]).unwrap();

        //Convert the message and challenge to field elements
        let message_fe: Vec<Fr> = message.to_field_elements().unwrap();
        let challenge_fe: Vec<Fr> = challenge.to_field_elements().unwrap();

        //We need to concat the public inputs into a single vector
        let mut public_inputs: Vec<Fr> = Vec::new();
        println!(
            "Number of elements in public_inputs initially: {}",
            public_inputs.len()
        );
        //Add the message to the public inputs vector
        public_inputs.extend(message_fe);
        println!(
            "Number of elements in public_inputs after message: {}",
            public_inputs.len()
        );
        //Add the challenge to the public inputs vector
        public_inputs.extend(challenge_fe);
        println!(
            "Number of elements in public_inputs before passing to verify: {}",
            public_inputs.len()
        );
        //Do the verification
        Groth16::<Bls12_377>::verify(&vk, &public_inputs, &proof)
    }
}

#[wasm_bindgen]
pub fn run_js(
    client_data_json_base64: &str,
    auth_data_base64: &str,
    challenge_base64: &str,
) -> Result<JsValue, JsValue> {
    // Decode the base64 inputs
    let client_data_json = BASE64_STANDARD
        .decode(client_data_json_base64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let auth_data = BASE64_STANDARD
        .decode(auth_data_base64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let challenge = BASE64_URL_SAFE_NO_PAD
        .decode(challenge_base64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

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

    //Now we run the circuit
    let (message, challenge, proof, vk) =
        WebAuthZKP::run(client_data_json, auth_data, message, challenge)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Format the result into JsValue to return to JavaScript
    let output = json!({
        "message": BASE64_URL_SAFE_NO_PAD.encode(&message),
        "challenge": BASE64_URL_SAFE_NO_PAD.encode(&challenge),
        "proof": BASE64_URL_SAFE_NO_PAD.encode(&proof),
        "vk": BASE64_URL_SAFE_NO_PAD.encode(&vk),
    });

    to_value(&output).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn verify_js(
    message_base64: &str,
    challenge_base64: &str,
    proof_base64: &str,
    vk_base64: &str,
) -> Result<bool, JsValue> {
    let message = BASE64_URL_SAFE_NO_PAD
        .decode(message_base64)
        .map_err(|e| e.to_string())?;
    let challenge = BASE64_URL_SAFE_NO_PAD
        .decode(challenge_base64)
        .map_err(|e| e.to_string())?;

    let proof_serialized = BASE64_URL_SAFE_NO_PAD
        .decode(proof_base64)
        .map_err(|e| e.to_string())?;
    let vk_serialized = BASE64_URL_SAFE_NO_PAD
        .decode(vk_base64)
        .map_err(|e| e.to_string())?;

    let result =
        WebAuthZKP::verify(message, challenge, proof_serialized, vk_serialized).map_err(|e| {
            let error_message = format!("Error during verification: {:?}", e);
            console::error_1(&error_message.clone().into());
            JsValue::from_str(&error_message)
        })?;

    if result {
        console::log_1(&"Verification succeeded!".into());
        console::log_1(&"Recompiled in the Docker container".into());
    } else {
        console::log_1(&"Verification failed :(".into());
    }

    Ok(result)
}
