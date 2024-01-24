const express = require('express');
const crypto = require('crypto');
const db = require('./database'); // Assuming you have a database.js file
const app = express();
const port = 3000;

app.use(express.json());
app.use(express.static('public'));

function generateChallenge() {
    return crypto.randomBytes(32).toString('base64');
}

app.post('/start-register', (req, res) => {
    const username = req.body.username;
    const challenge = generateChallenge();
    const userAccountId = crypto.randomBytes(64);
    res.json({
        challenge: Buffer.from(challenge, 'base64'),
        rp: { 
            name: "FISS CORP", 
            id: "localhost" 
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
            userVerification: "preferred"
            },
            
        timeout: 60000
    });
});    

app.post('/send-credential', (req, res) => {
    const username = req.body.username;
    const credential = req.body.credential;
    
    if (!username || !credential) {
        return res.status(400).send('Username and credential are required');
    }

    console.log('Credential Info Server: ', credential);

    // TODO: process and store public key, credential ID, and user ID, possbly sign count and attestation info.
    //Need to process ClientDataJSON and AttestationObject. 
    //AttestationObject is a CBOR encoded object containing the attestation statement and authenticator data.

    res.json({ status: 'Registration successful' });
});    



    app.post('/login', (req, res) => {
        const username = req.body.username;
        const user = users[username];

        if (!user) {x   
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
