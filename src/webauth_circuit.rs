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
use rand::thread_rng;


#[derive(Clone)]
struct WebAuthCircuit {
    //Private inputs
    client_data_json: Option<Vec<u8>>,
    auth_data: Option<Vec<u8>>,
    client_data_challenge: Option<Vec<u8>>,

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


        Ok(())
    }
}

pub struct WebAuthZKP;

impl WebAuthZKP {
    pub fn run(
        //Private inputs
        client_data_json: Vec<u8>,
        auth_data: Vec<u8>,
        client_data_challenge: Vec<u8>,

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

        let circuit = WebAuthCircuit {
            client_data_json: Some(client_data_json),
            auth_data: Some(auth_data),
            client_data_challenge: Some(client_data_challenge),
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


        Ok((
            message,
            challenge,
            serialized_proof,
            serialized_vk,
        ))    
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
            "Number of elements in public_inputs after hash: {}",
            public_inputs.len()
        );
        //Add the challenge to the public inputs vector
        public_inputs.extend(challenge_fe);
        println!(
            "Number of elements in public_inputs before passing: {}",
            public_inputs.len()
        );
        //Do the verification
        Groth16::<Bls12_377>::verify(&vk, &public_inputs, &proof)
    }
}
