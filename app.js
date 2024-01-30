const express = require('express');
const crypto = require('crypto');
const db = require('./database');
const session = require('express-session');
const cbor = require('cbor');
const asn1 = require('asn1.js');
const EC = require('elliptic').ec;
const BN = require('bn.js');

const app = express();
const port = 3000;
const rpid = 'localhost'; //change this to the domain name of the website if deployed
const url = `http://localhost:${port}`; //change this to the domain name of the website if deployed

app.use(express.json());
app.use(express.static('public'));

app.get('/favicon.ico', (req, res) => res.status(204).end());

const ec = new EC('p256'); //The curve used for ECDSA later on in verify-login

app.use(session({
    secret: 'MySuperSecretSuperUnsecureKey!', //TODO: store this in a env file
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 300000 // Session expiration time in milliseconds (e.g., 3600000 for 1 hour)
    }
}));


function generateChallenge() {
    // Generate a random byte array and convert it to a Base64 string
    return base64String = crypto.randomBytes(32).toString('base64');

}


app.post('/start-register', (req, res) => {
    const username = req.body.username;
    const challenge = generateChallenge();
    console.log('Challenge right after generation: ', challenge);

    req.session.challenge = challenge;
    req.session.username = username;


    const userAccountId = crypto.randomBytes(64).toString('base64');
    res.json({
        challenge: challenge,
        rp: {
            name: "FISS CORP",
            id: rpid
        },
        user: {
            id: userAccountId,
            name: username,
            displayName: username
        },
        pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 }
        ],
        authenticatorSelection: {
            userVerification: "required",
        },
        attestation: 'direct',
        userVerification: 'required',
        timeout: 300000
    });
});



app.post('/send-credential', async (req, res) => {
    const username = req.body.username;
    console.log('Username: ', username);

    const credential = req.body.credential;
    console.log('Credential on Server: ', credential);

    const unsafeChallenge = req.session.challenge; //this is the URL unsafe version so will  not quite be the same as the one the client sends
    const challenge = unsafeChallenge.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');  //convert to URL safe version

    if (!username || !credential) {
        return res.status(401).send('Username and credential are required');
    }
    // Decode clientDataJSON from the credential
    const clientDataJSON = JSON.parse(Buffer.from(credential.response.clientDataJSON, 'base64').toString('utf8'));
    console.log('Client JSON Parsed On Server: ', clientDataJSON);

    // Verify the challenge matches
    if (clientDataJSON.challenge !== challenge) {
        console.error('Error: Type is not webauthn.create');
        return res.status(402).send('Challenge does not match');
    }
    //Verify the origin matches
    if (clientDataJSON.origin !== url) { //change if hosting on website/different port
        console.error('Error: origin does not match');
        return res.status(403).send('Origin does not match');
    }
    // Verify the type of credential
    if (clientDataJSON.type !== 'webauthn.create') {
        console.error('Error: Type is not webauthn.create');
        return res.status(404).send('Type is not webauthn.create');
    }
    //Decode attestation object from the credential
    const attestationObject = cbor.decodeFirstSync(Buffer.from(credential.response.attestationObject, 'base64'));

    // Extract and decode authenticator data from attestationObject
    const authenticatorData = attestationObject.authData;

    // Extract RP ID Hash (first 32 bytes)
    const rpIdHash = authenticatorData.slice(0, 32);

    // Validate RP ID Hash
    const expectedRpIdHash = crypto.createHash('sha256').update(rpid).digest();
    if (!crypto.timingSafeEqual(Buffer.from(rpIdHash), expectedRpIdHash)) {
        console.error('Error: RP ID Hash does not match');
        return res.status(400).send('RP ID Hash does not match');
    }

    // Extract Flags (1 byte at position 32)
    const flagsByte = authenticatorData.slice(32, 33);
    const flags = flagsByte[0]; // Since slice returns an array, get the first element
    const flagsBinary = flags.toString(2).padStart(8, '0'); // Convert to binary and pad with zeros to ensure 8 bits

    console.log('Flags byte in binary: ', flagsBinary);
    const userPresent = (flags & 0x01) === 0x01; // Bit 0 is UP flag
    const userVerified = (flags & 0x04) === 0x04; // Bit 2 is UV flag
    const backupEligible = (flags & 0x08) === 0x08; // Bit 3 is BE flag
    const backupStatus = (flags & 0x10) === 0x10; // Bit 4 is BS flag
    const atFlag = (flags & 0x40) === 0x40; // Bit 6 is AT flag
    const extensionData = (flags & 0x80) === 0x80; // Bit 7 is ED flag

    console.log('User Present: ', userPresent);
    console.log('User Verified: ', userVerified);
    console.log('Backup Eligible: ', backupEligible);
    console.log('Backup Status: ', backupStatus);
    console.log('AT: ', atFlag);
    console.log('Extension Data: ', extensionData);

    // Extract signCount (4 bytes at position 33)
    const signCountBytes = authenticatorData.slice(33, 37);
    const signCount =
        (signCountBytes[0] << 24) | // Shift the first byte 24 bits to the left
        (signCountBytes[1] << 16) | // Shift the second byte 16 bits to the left
        (signCountBytes[2] << 8) |  // Shift the third byte 8 bits to the left
        signCountBytes[3];          // Fourth byte as is

    console.log('Sign Count: ', signCount);

    // Extract Attested Credential Data (remaining bytes)
    const aaguidBytes = authenticatorData.slice(37, 53);
    const aaguidHex = Array.from(aaguidBytes)
        .map(byte => byte.toString(16).padStart(2, '0')) // Convert each byte to a two-character hex string
        .join('');

    // Insert hyphens to format as UUID
    const formattedAAGUID =
        `${aaguidHex.substring(0, 8)}-${aaguidHex.substring(8, 12)}-${aaguidHex.substring(12, 16)}-${aaguidHex.substring(16, 20)}-${aaguidHex.substring(20)}`;

    console.log('Formatted AAGUID: ', formattedAAGUID);

    const credentialIdLengthBytes = authenticatorData.slice(53, 55); //2 bytes at position 53
    const credentialIdLength =
        (credentialIdLengthBytes[0] << 8) | // Shift the first byte 8 bits to the left
        credentialIdLengthBytes[1];         // Second byte as is

    console.log('Credential ID Length: ', credentialIdLength);
    const credentialId = authenticatorData.slice(55, 55 + credentialIdLength);
    // Convert credentialId to base64 string
    const credentialIdBase64 = credentialId.toString('base64');
    // Print base64 string
    const credentialPublicKey = authenticatorData.slice(55 + credentialIdLength);
    const credentialPublicKeyBase64 = Buffer.from(credentialPublicKey).toString('base64');
    const parsedPublicKey = parseCOSEPublicKeyforOutput(credentialPublicKey);
    console.log('Parsed Public Key: ', parsedPublicKey);

    console.log('Credential ID Length: ', credentialIdLength);
    console.log('Credential ID Base64url: ', credentialIdBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''));
    console.log('Credential Public Key Base64url: ', credentialPublicKeyBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''));

    const attestationFormat = attestationObject.fmt;
    console.log('Attestation Format: ', attestationFormat);

    // Access the 'attStmt' (Attestation Statement)
    const attestationStatement = attestationObject.attStmt;
    console.log('Attestation Statement Algorithm: ', attestationStatement.alg);
    if (attestationStatement.sig) {
        console.log('Attestation Statement Signature: ', Buffer.from(attestationStatement.sig).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''));
    }
    //Store the credential in the database
    // Check if user exists
    db.getUserByUsername(username, (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Internal server error');
        }

        if (!user) {
            // User does not exist, create a new user
            db.addUser(username, (err, userId) => {
                if (err) {
                    console.error('Error adding user:', err);
                    return res.status(500).send('Failed to create user');
                }
                saveAuthenticator(userId);
            });
        } else {
            // User exists, save the authenticator data
            saveAuthenticator(user.id);
        }
    });

    function saveAuthenticator(userId) {
        // Convert credentialId and publicKey to base64URL
        const credentialIdBase64Url = credentialIdBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        const publicKeyBase64Url = credentialPublicKeyBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

        db.addAuthenticator(userId, credentialIdBase64Url, publicKeyBase64Url, signCount, formattedAAGUID, (err) => {
            if (err) {
                console.error('Error adding authenticator:', err);
                return res.status(500).send('Failed to register authenticator');
            }
        });
    }
    console.log('Registration successful!');
    res.json({ status: 'Registration successful' });
});



app.post('/login', async (req, res) => {
    const username = req.body.username;
    req.session.username = username;

    try {
        // Retrieve user data
        db.getUserByUsername(username, (err, user) => {
            if (err || !user) {
                console.error('User not found or database error:', err);
                return res.status(400).send('User not found');
            }

            // Generate new challenge for login
            const challenge = generateChallenge();
            req.session.challenge = challenge;

            // Retrieve authenticators for the user
            db.getAuthenticatorsByUserId(user.id, (authErr, authenticators) => {
                if (authErr) {
                    console.error('Error retrieving authenticators:', authErr);
                    return res.status(500).send('Internal server error');
                }

                if (!authenticators || authenticators.length === 0) {
                    return res.status(404).send('No registered authenticators found for user');
                }
                console.log('Authenticators: ', authenticators);
                const response = {
                    challenge: challenge,
                    allowCredentials: authenticators.map(auth => ({
                        type: 'public-key',
                        id: (auth.credential_id), // Ensure this is Base64 URL-encoded
                        transports: ['usb', 'nfc', 'ble', 'internal']
                    })),
                    timeout: 60000
                }
                // Send challenge and allowCredentials to client
                res.json(response);
            });

        });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).send('Internal server error');
    }
});

app.post('/verify-login', async (req, res) => {
    const { id, rawId, type, response } = req.body;
    const credentialId = id;
    const unsafeChallenge = req.session.challenge; //this is the URL unsafe version so will  not quite be the same as the one the client sends
    const challenge = unsafeChallenge.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');  //convert to URL safe version
    console.log("Request: ", req.body)

    try {
        console.log('Credential ID: ', credentialId);
        db.getAuthenticatorByCredentialId(credentialId, (err, authenticator) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).send('Internal server error');
            }
            if (!authenticator) {
                console.error('Authenticator not found');
                return res.status(404).send('Authenticator not found');
            }
            console.log('Authenticator: ', authenticator);
            console.log('Response from body: ', response);

            // Decode clientDataJSON from the assertion
            const clientDataJSON = JSON.parse(Buffer.from(response.clientDataJSON, 'base64').toString('utf8'));
            console.log('Client Data JSON: ', clientDataJSON);

            console.log('Challenge: ', challenge);
            console.log('Client Data JSON Challenge: ', clientDataJSON.challenge);
            // Validate the challenge
            if (clientDataJSON.challenge !== challenge) {
                console.error('Challenge mismatch');
                return res.status(403).send('Challenge mismatch');
            }

            // Validate the origin
            if (clientDataJSON.origin !== url) {
                console.error('Origin mismatch');
                return res.status(403).send('Origin mismatch');
            }

            console.log('Client Data JSON checks passed');
            console.log('Authenticator Data: ', response.authenticatorData);

            const authenticatorData = Buffer.from(response.authenticatorData, 'base64');
            // Extract RP ID Hash (first 32 bytes)
            const rpIdHash = authenticatorData.slice(0, 32);

            // Validate RP ID Hash
            const expectedRpIdHash = crypto.createHash('sha256').update(rpid).digest();
            if (!crypto.timingSafeEqual(Buffer.from(rpIdHash), expectedRpIdHash)) {
                console.error('Error: RP ID Hash does not match');
                return res.status(400).send('RP ID Hash does not match');
            }

            // Extract Flags (1 byte at position 32)
            //const flags = dataView.getUint8(32);
            const flagsByte = authenticatorData.slice(32, 33);
            const flags = flagsByte[0]; // Since slice returns an array, get the first element
            const flagsBinary = flags.toString(2).padStart(8, '0'); // Convert to binary and pad with zeros to ensure 8 bits
            console.log('Flags byte in binary: ', flagsBinary);
            const userPresent = (flags & 0x01) === 0x01; // Bit 0 is UP flag
            const userVerified = (flags & 0x04) === 0x04; // Bit 2 is UV flag
            const backupEligible = (flags & 0x08) === 0x08; // Bit 3 is BE flag
            const backupStatus = (flags & 0x10) === 0x10; // Bit 4 is BS flag
            const atFlag = (flags & 0x40) === 0x40; // Bit 6 is AT flag
            const extensionData = (flags & 0x80) === 0x80; // Bit 7 is ED flag

            console.log('User Present: ', userPresent);
            console.log('User Verified: ', userVerified);
            console.log('Backup Eligible: ', backupEligible);
            console.log('Backup Status: ', backupStatus);
            console.log('AT: ', atFlag);
            console.log('Extension Data: ', extensionData);
            // Extract signCount (4 bytes at position 33)
            const signCountBytes = authenticatorData.slice(33, 37);
            const signCount =
                (signCountBytes[0] << 24) | // Shift the first byte 24 bits to the left
                (signCountBytes[1] << 16) | // Shift the second byte 16 bits to the left
                (signCountBytes[2] << 8) |  // Shift the third byte 8 bits to the left
                signCountBytes[3];          // Fourth byte as is

            console.log('Sign Count: ', signCount);

            // const signature = Buffer.from(response.signature, 'base64');
            // const publicKey = coseToPem(coseKey);
            // console.log('Public Key Pem: ', publicKey);

            const clientDataString = JSON.stringify(clientDataJSON); // Serialize it back to a string
            console.log('Client Data String: ', clientDataString);
            const clientDataBuffer = Buffer.from(clientDataString); // Convert string to Buffer
            console.log('Client Data Buffer: ', clientDataBuffer);
            const clientDataHash = crypto.createHash('SHA256').update(clientDataBuffer).digest();
            console.log('Client Data Hash: ', clientDataHash);
            const coseKeyBuffer = (Buffer.from(authenticator.public_key, 'base64'));
            console.log('COSE Key Buffer: ', coseKeyBuffer)

            //This code is purely to get a PEM key from the COSE key 
            //console.log('COSE Key Parsed: ', parseCOSEPublicKey(coseKeyBuffer));
            const publicKey = coseToPem(cbor.decodeFirstSync(coseKeyBuffer));
            console.log('Public Key Pem: ', publicKey);


            const dataToBeVerified = Buffer.concat([authenticatorData, clientDataHash])
            const signatureBuffer = Buffer.from(response.signature, 'base64');

            const isValid = verifyECDSASignature(dataToBeVerified, signatureBuffer, coseKeyBuffer);
            console.log('Signature is valid:', isValid);


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
            if (signCount > authenticator.signCount) {
                db.updateSignCount(authenticator.id, signCount, (err, authenticator) => {
                    if (err) {
                        console.error('Error updating sign count:', err);
                        return res.status(500).send('Internal server error');
                    }
                });
            } if (isValid) {
                console.log('Login successful!');
                res.json({ status: 'Login successful' });
            } else {
                console.error('Error: Signature is invalid');
                return res.status(400).send('Signature is invalid');
            }
        });

    } catch (error) {
        console.error('Login verification error:', error);
        res.status(500).send('Error verifying login');
    }
});

// Function to decode ECDSA signature
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

/*  ECDSA Signature Verification Function
    Based off of https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages#ecdsa-verify-signature
    message is the data to be verified
    signatureBuffer is the signature to be verified as a buffer
    publicKeyBuffer is the public key to be used for verification as a buffer in COSE format*/

function verifyECDSASignature(message, signatureBuffer, publicKeyBuffer) {
    // Decode the COSE public key to a form we can use (as an elliptic curve key)
    const publicKey = parseCOSEPublicKey(publicKeyBuffer);
    console.log('publicKey: ', publicKey);

    // Convert message to a Buffer if it's not already
    message = Buffer.isBuffer(message) ? message : Buffer.from(message);

    // Calculate the message hash, with the same cryptographic hash function used during the signing: h = hash(msg) and turn it into a Big Number object
    const messageHash = new BN(crypto.createHash('SHA256').update(message).digest('hex'), 16);


    // Decode the signature into 'r' and 's' values
    const decodedSignature = decodeSignature(signatureBuffer);
    const r = decodedSignature.r;
    const s = decodedSignature.s;

    // Calculate the modular inverse of the signature proof, s: sInv = s^-1 mod n
    const sInv = decodedSignature.s.invm(ec.n);
    console.log('sInv: ', sInv);

    // Recover the random point used during the signing: R' = (h * s1) * G + (r * s1) * pubKey
    // First calculate h * sInv[erse] mod n
    const hTimesSInv = messageHash.mul(sInv).umod(ec.n);
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
// Function to parse COSE key, this one returns the key in a format that can be used by the verifyECDSASignature function
function parseCOSEPublicKey(coseBuffer) {
    const coseKey = cbor.decodeFirstSync(coseBuffer);
    const x = coseKey.get(-2); // -2 is the key for the x-coordinate
    const y = coseKey.get(-3); // -3 is the key for the y-coordinate
    return ec.keyFromPublic({ x: x.toString('hex'), y: y.toString('hex') }, 'hex');
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


app.listen(port, () => {
    console.log(`Server running at ${url}`);
});
