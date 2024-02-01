const crypto = require('crypto');
const cbor = require('cbor');
const asn1 = require('asn1.js');
const BN = require('bn.js');
const EC = require('elliptic').ec;
const ec = new EC('p256');

// Generate a random byte array and convert it to a Base64 string to use as a challenge
function generateChallenge() {
    return base64String = crypto.randomBytes(32).toString('base64');
}


/*  ECDSA Signature Verification Function
    Based off of https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages#ecdsa-verify-signature
    messageHash is the data to be verified, hashed with SHA256 (to match pdf flow)
    signatureBuffer is the signature to be verified as a buffer
    publicKeyBuffer is the public key to be used for verification as a buffer in COSE format */

function verifyECDSASignature(messageHash, signatureBuffer, publicKeyBuffer) {
    // Decode the COSE public key to a form we can use (as an elliptic curve key)
    const publicKey = parseCOSEPublicKey(publicKeyBuffer);
    console.log('publicKey: ', publicKey);

    // Take the hash and turn it into a Big Number object
    const messageHashBN = new BN(messageHash, 16);
    console.log('messageHashBN: ', messageHashBN);

    // Decode the signature into 'r' and 's' values
    const decodedSignature = decodeSignature(signatureBuffer);
    const r = decodedSignature.r;
    const s = decodedSignature.s;

    // Calculate the modular inverse of the signature proof, s: sInv = s^-1 mod n
    const sInv = decodedSignature.s.invm(ec.n);
    console.log('sInv: ', sInv);

    // Recover the random point used during the signing: R' = (h * s1) * G + (r * s1) * pubKey
    // First calculate h * sInv[erse] mod n
    const hTimesSInv = messageHashBN.mul(sInv).umod(ec.n);
    console.log('hTimesSInv: ', hTimesSInv);

    // Then calculate r * sInv[erse] mod n
    const rTimesSInv = decodedSignature.r.mul(sInv).umod(ec.n);
    console.log('rTimesSInv: ', rTimesSInv);

    // Recover the random point R' used during the signing
    // R' = (h * sInv) * G + (r * sInv) * publicKey
    const RPrime = ec.g.mul(hTimesSInv).add(publicKey.pub.mul(rTimesSInv));
    console.log('RPrime: ', RPrime);

    // Take from R' its x-coordinate: r' = R'.x
    const rPrime = RPrime.getX();
    console.log('rPrime (x-coordinate): ', rPrime);

    // Compare r' with r
    return rPrime.eq(r);
}

// Function to parse COSE key, this one returns the key in a format that can be used by the verifyECDSASignature function
function parseCOSEPublicKey(coseBuffer) {
    const coseKey = cbor.decodeFirstSync(coseBuffer);
    const x = coseKey.get(-2); // -2 is the key for the x-coordinate
    const y = coseKey.get(-3); // -3 is the key for the y-coordinate
    return ec.keyFromPublic({ x: x.toString('hex'), y: y.toString('hex') }, 'hex');
}

// Function to decode ECDSA signature into 'r' and 's' values
function decodeSignature(signature) {
    const ECDSASignature = asn1.define('ECDSASignature', function () {
        this.seq().obj(
            this.key('r').int(),
            this.key('s').int()
        );
    });
    const decodedSignature = ECDSASignature.decode(signature, 'der');
    console.log('r: ', BigInt('0x' + (decodedSignature.r.toString(16))));
    console.log('s: ', BigInt('0x' + (decodedSignature.s.toString(16))));
    return decodedSignature;
}

//Comments from original way of doing it
// const dataToBeVerified = Buffer.concat([authenticatorData, clientDataHash]);
// const verifier = crypto.createVerify('SHA256');
// verifier.update(dataToBeVerified); //TODO: do this manually

// const isValid = verifier.verify(publicKey, signature); //verify signature belongs to key
// //ALSO then verify that the created hash matches

// console.log('r: ', BigInt('0x' + (decodedSignature.r.toString(16))));
// console.log('s: ', BigInt('0x' + (decodedSignature.s.toString(16))));
//replaced by decodeSignature function below

/* 
    Sidenote: What is verifier.verify actually doing?
    Well, it does ECDSA (Elliptic Curve Digital Signature Algorithm) signature verirfication.
    It does so by parsing the signature which is made up of 'r' and 's' values.
    It then hashes the data to be verified using the same hash function used to hash the data before signing.
    It then performs a mathematical operation to verify the signature, using r and s, and the public key.
    If the signature is valid, it returns true, otherwise it returns false.
    
*/

//This was the original function to output the key in a nicely formatted way
function parseCOSEPublicKeyforOutput(coseBuffer) {
    // Parse the COSE key with a CBOR library
    const coseKey = cbor.decodeFirstSync(coseBuffer);

    // Extract data from the COSE key
    const keyType = coseKey.get(1); // 1 is the key for 'kty' (key type)
    const algorithm = coseKey.get(3); // 3 is the key for 'alg' (algorithm)
    const curve = coseKey.get(-1); // -1 is the key for 'crv' (elliptic curve)
    const x = coseKey.get(-2); // -2 is the key for the x-coordinate
    const y = coseKey.get(-3); // -3 is the key for the y-coordinate

    return {
        keyType: keyType,
        algorithm: algorithm,
        curve: curve,
        x: x.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
        y: y.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
    };
}


//Print out the public key in the PEM format
function coseToPem(coseKey) {
    // Extract key type, algorithm, x and y coordinates from COSE key
    const kty = coseKey.get(1);
    const alg = coseKey.get(3);
    const crv = coseKey.get(-1);
    const x = coseKey.get(-2);
    const y = coseKey.get(-3);

    // Ensure all necessary fields are present
    if (kty === undefined || alg === undefined || crv === undefined || x === undefined || y === undefined) {
        throw new Error('Missing required COSE key fields');
    }

    // Check if the key is EC2 (ECDSA)
    if (kty !== 2) {
        throw new Error('Unsupported key type');
    }

    // Construct the PEM key
    const publicKey = crypto.createPublicKey({
        key: {
            kty: 'EC',
            crv: 'P-256',
            x: x.toString('base64'),
            y: y.toString('base64')
        },
        format: 'jwk'
    });

    return publicKey.export({ type: 'spki', format: 'pem' });
}

module.exports = {
    generateChallenge,
    verifyECDSASignature,
    parseCOSEPublicKeyforOutput,
    coseToPem
}