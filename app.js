const express = require('express');
const crypto = require('crypto');
const db = require('./database');
const session = require('express-session');
const cbor = require('cbor');



const app = express();
const port = 3000;
const rpid = 'localhost'; //TODO: change this to the domain name of the website

app.use(express.json());
app.use(express.static('public'));


app.use(session({
    secret: 'MySuperSecretSuperUnsecureKey!', //TODO: store this in a env file
    resave: false,
    saveUninitialized: true,
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


    const userAccountId = crypto.randomBytes(64);
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
        timeout: 60000
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
        console.log('Error: Type is not webauthn.create');
        return res.status(402).send('Challenge does not match');
    }
    //Verify the origin matches
    if (clientDataJSON.origin !== 'http://localhost:3000') { //change if hosting on website/different port
        console.log('Error: origin does not match');
        return res.status(403).send('Origin does not match');
    }
    // Verify the type of credential
    if (clientDataJSON.type !== 'webauthn.create') {
        console.log('Error: Type is not webauthn.create');
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
        console.log('Error: RP ID Hash does not match');
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
    const atFlag = (flags & 0x40) === 0x40; // Bit 6 is AT flag
    console.log('User Present flag set: ', userPresent);
    console.log('User Verified flag set: ', userVerified);
    console.log('AT Flag set: ', atFlag);

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
    const parsedPublicKey = parseCOSEPublicKey(credentialPublicKey);
    console.log('Parsed Public Key: ', parsedPublicKey);

    console.log('Credential ID Length: ', credentialIdLength);
    console.log('Credential ID Base64url: ', credentialIdBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''));
    console.log('Credential Public Key Base64url: ', credentialPublicKeyBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''));

    const attestationFormat = attestationObject.fmt;
    console.log('Attestation Format: ', attestationFormat);

    // Access the 'attStmt' (Attestation Statement)
    const attestationStatement = attestationObject.attStmt;
    console.log('Attestation Statement Algorithm: ', attestationStatement.alg);
    console.log('Attestation Statement Signature: ', Buffer.from(attestationStatement.sig).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''));
    
    // TODO: process and store public key, credential ID, and user ID, possbly sign count and attestation info.


    res.json({ status: 'Registration successful' });
});  

function parseCOSEPublicKey(coseBuffer) {
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





    app.post('/login', (req, res) => {
        const username = req.body.username;
        const user = users[username];

        if (!user) {   
            return res.status(400).send('User not found');
        }

        // Generate new challenge for login
        const challenge = generateChallenge();
        user.challenge = challenge;

        // Send challenge to client
        res.json({
            challenge: challenge,
            allowCredentials: [{
                type: 'public-key',
                id: user.credentialId, // should be stored during registration
                transports: ['usb', 'nfc', 'ble', 'internal']
            }],
            timeout: 60000
        });
    });


    app.listen(port, () => {
        console.log(`Server running at http://localhost:${port}/`);
    });
