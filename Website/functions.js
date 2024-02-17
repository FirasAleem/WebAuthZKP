const crypto = require('crypto');
const cbor = require('cbor');
const asn1 = require('asn1.js');
const BN = require('bn.js');
const EC = require('elliptic').ec;
const ec = new EC('p256');

// Generate a random byte array and convert it to a Base64 string to use as a challenge
// This could in theory be some data you want to sign, but for the purposes of this demo, it's just some random bytes
function generateChallenge() {
    return base64String = crypto.randomBytes(32).toString('base64');
}

/*  ECDSA Signature Verification Function
    Based off of https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages#ecdsa-verify-signature
    messageHash is the data to be verified, hashed with SHA256 (to match pdf flow)
    In ZKP, this will be generated client-side and sent to the server
    signatureBuffer is the signature to be verified as a buffer
    publicKeyBuffer is the public key to be used for verification as a buffer in COSE format */
function verifySignature(messageHash, signatureBuffer, publicKeyBuffer) {
    console.log('Inside verifySignature function')
    console.log('messageHash: ', messageHash);
    const publicKeyInfo = parseCOSEPublicKey(publicKeyBuffer);
    if (publicKeyInfo.type === 'ECDSA') {
        return verifyECDSASignature(messageHash, signatureBuffer, publicKeyBuffer);
    } else if (publicKeyInfo.type === 'RSA') {
        return verifyRSASignature(messageHash, signatureBuffer, publicKeyBuffer);
    } else {
        throw new Error('Unsupported key type for verification');
    }
}

function verifyECDSASignature(messageHash, signatureBuffer, publicKeyBuffer) {
    //console.log('messageHash: ', messageHash);
    //console.log('signatureBuffer: ', signatureBuffer);
    // Decode the COSE public key to a form we can use (as an elliptic curve key)
    const publicKeyFull = parseCOSEPublicKey(publicKeyBuffer);
    const publicKey = publicKeyFull.key;
    console.log('publicKey: ', publicKey);

    // Take the hash and turn it into a Big Number object
    const messageHashBN = new BN(messageHash, 16);
    //console.log('messageHashBN: ', messageHashBN);

    // Decode the signature into 'r' and 's' values
    const decodedSignature = decodeSignature(signatureBuffer);
    const r = decodedSignature.r;
    const s = decodedSignature.s;

    // Calculate the modular inverse of the signature proof, s: sInv = s^-1 mod n
    const sInv = decodedSignature.s.invm(ec.n);
    //console.log('sInv: ', sInv);

    // Recover the random point used during the signing: R' = (h * s1) * G + (r * s1) * pubKey
    // First calculate h * sInv[erse] mod n
    const hTimesSInv = messageHashBN.mul(sInv).umod(ec.n);
    //console.log('hTimesSInv: ', hTimesSInv);

    // Then calculate r * sInv[erse] mod n
    const rTimesSInv = decodedSignature.r.mul(sInv).umod(ec.n);
    //console.log('rTimesSInv: ', rTimesSInv);

    // Recover the random point R' used during the signing
    // R' = (h * sInv) * G + (r * sInv) * publicKey
    const RPrime = ec.g.mul(hTimesSInv).add(publicKey.pub.mul(rTimesSInv));
    //console.log('RPrime: ', RPrime);

    // Take from R' its x-coordinate: r' = R'.x
    const rPrime = RPrime.getX();
    //console.log('rPrime (x-coordinate): ', rPrime);

    // Compare r' with r
    return rPrime.eq(r);
}
function verifyRSASignature(messageHash, signatureBuffer, publicKeyCoseBuffer) {
    // Assuming publicKey is an object with 'n' and 'e' as properties in hex string format
    const publicKeyFull = parseCOSEPublicKey(publicKeyCoseBuffer);

    // Convert 'n' and 'e' from hex string to BigInt
    const nBigInt = BigInt('0x' + publicKeyFull.n);
    const eBigInt = BigInt('0x' + publicKeyFull.e);

    // Convert signature to BigInt
    const signatureBigInt = BigInt('0x' + signatureBuffer.toString('hex'));

    // RSA "decryption": (signature ^ e) % n
    const decryptedBigInt = signatureBigInt ** eBigInt % nBigInt;

    // Convert decrypted BigInt back to Buffer
    let decryptedBuffer = Buffer.from(decryptedBigInt.toString(16), 'hex');

    // Find the hash start after padding
    const hashStartIndex = decryptedBuffer.indexOf(0x00, 1) + 1;
    decryptedBuffer = decryptedBuffer.slice(hashStartIndex); // Extract hash

    // Compare the extracted hash with the provided message hash
    const messageHashBuffer = Buffer.from(messageHash, 'hex');
    console.log('decryptedBuffer: ', decryptedBuffer);
    console.log('messageHashBuffer: ', messageHashBuffer);
    if (decryptedBuffer.equals(messageHashBuffer)) {
        throw new Error("Signature verification failed");
    }
    console.log("Signature verified successfully");
    return true;
}

// Function to parse COSE key, this one returns the key in a format that can be used by the verifySignature function
function parseCOSEPublicKey(coseBuffer) {
    const coseKey = cbor.decodeFirstSync(coseBuffer);
    const kty = coseKey.get(1); // Key Type

    if (kty === 2) { // EC2 key (ECDSA)
        const x = coseKey.get(-2); // X-coordinate
        const y = coseKey.get(-3); // Y-coordinate
        return { type: 'ECDSA', key: ec.keyFromPublic({ x: x.toString('hex'), y: y.toString('hex') }, 'hex') };
    } else if (kty === 3) { // RSA
        const n = coseKey.get(-1); // Modulus
        const e = coseKey.get(-2); // Exponent
        return { type: 'RSA', n: n.toString('hex'), e: e.toString('hex') };
    } else {
        throw new Error('Unsupported key type');
    }
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
    //console.log('decodedSignature: ', decodedSignature);
    console.log('r: ', BigInt('0x' + (decodedSignature.r.toString(16))));
    console.log('s: ', BigInt('0x' + (decodedSignature.s.toString(16))));
    return decodedSignature;
}

//This was the original function to output the key in a nicely formatted way
function parseCOSEPublicKeyforOutput(coseBuffer) {
    // Parse the COSE key with a CBOR library
    const coseKey = cbor.decodeFirstSync(coseBuffer);

    // Extract data from the COSE key
    const keyType = coseKey.get(1); // 1 is the key for 'kty' (key type)

    let output = {
        keyType: keyType,
        algorithm: coseKey.get(3) // 3 is the key for 'alg' (algorithm)
    };
    switch (keyType) {
        case 2: // Key Type 2 indicates EC2 key (ECDSA)
            output.curve = coseKey.get(-1); // -1 is the key for 'crv' (elliptic curve)
            output.x = coseKey.get(-2).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            output.y = coseKey.get(-3).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            break;
        case 3: // Key Type 3 indicates RSA
            output.n = coseKey.get(-1).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); // Modulus
            output.e = coseKey.get(-2).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); // Exponent
            break;
        default:
            throw new Error('Unsupported COSE key type');
    }
    return output;
}

//Print out the public key in the PEM format
function coseToPem(coseKey) {
    const kty = coseKey.get(1); // Key Type

    // For ECDSA keys
    if (kty === 2) {
        const crv = coseKey.get(-1); // Curve
        const x = coseKey.get(-2); // X-coordinate
        const y = coseKey.get(-3); // Y-coordinate

        // Ensure all necessary ECDSA fields are present
        if (x === undefined || y === undefined || crv === undefined) {
            throw new Error('Missing required COSE key fields for ECDSA');
        }

        // Construct ECDSA PEM key
        return crypto.createPublicKey({
            key: {
                kty: 'EC',
                crv: 'P-256',
                x: x.toString('base64'),
                y: y.toString('base64')
            },
            format: 'jwk'
        }).export({ type: 'spki', format: 'pem' });
    }
    // For RSA keys
    else if (kty === 3) {
        const n = coseKey.get(-1); // Modulus
        const e = coseKey.get(-2); // Exponent

        // Ensure all necessary RSA fields are present
        if (n === undefined || e === undefined) {
            throw new Error('Missing required COSE key fields for RSA');
        }

        // Construct RSA PEM key
        return crypto.createPublicKey({
            key: {
                kty: 'RSA',
                n: n.toString('base64'),
                e: e.toString('base64')
            },
            format: 'jwk'
        }).export({ type: 'spki', format: 'pem' });
    } else {
        throw new Error('Unsupported key type');
    }
}

module.exports = {
    generateChallenge,
    verifySignature,
    parseCOSEPublicKeyforOutput,
    coseToPem
}