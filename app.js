const express = require('express');
const crypto = require('crypto');
const db = require('./database');
const session = require('express-session');
const cbor = require('cbor');
const {
    generateChallenge,
    verifyECDSASignature,
    parseCOSEPublicKeyforOutput,
    coseToPem
} = require('./functions');


const app = express();
const port = 3000;
const rpid = 'localhost'; //change this to the domain name of the website if deployed
const url = `http://localhost:${port}`; //change this to the domain name of the website if deployed

app.use(express.json());
app.use(express.static('public'));

app.get('/favicon.ico', (req, res) => res.status(204).end());


app.use(session({
    secret: 'MySuperSecretSuperUnsecureKey!', //TODO: store this in a env file
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 300000 // Session expiration time in milliseconds (e.g., 3600000 for 1 hour)
    }
}));


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


            const dataToBeVerified = Buffer.concat([authenticatorData, clientDataHash]);
            const dataToBeVerifiedHash = crypto.createHash('SHA256').update(dataToBeVerified).digest('hex');
            const signatureBuffer = Buffer.from(response.signature, 'base64');

            const isValid = verifyECDSASignature(dataToBeVerifiedHash, signatureBuffer, coseKeyBuffer);
            console.log('Signature is valid:', isValid);

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

app.listen(port, () => {
    console.log(`Server running at ${url}`);
});
