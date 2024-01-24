    const express = require('express');
    const crypto = require('crypto');
    const db = require('./database'); 

    const app = express();
    const port = 3000;

    app.use(express.json()); // for parsing application/json
    app.use(express.static('public')); // serve static files from 'public' directory

    // Function to generate a random challenge
    function generateChallenge() {
        return crypto.randomBytes(32).toString('base64');
    }

    app.post('/register', (req, res) => {
        const email = req.body.email;
        const userId = req.body.userId;

        if (!email || !userId) {
            return res.status(400).send('Email and user ID are required');
        }

        // Generate challenge
        const challenge = generateChallenge();

        const user = { id: userId, email: email, challenge: challenge };

        // Save user info in SQLite database
        db.addUser(userId, email, "publicKeyPlaceholder", (err) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send('Error saving user data');
            }

            // Send registration data to client
            res.json({
                challenge: Buffer.from(challenge, 'base64'),
                rp: {
                    name: "FISS CORP",
                    id: "localhost"
                },
                user: {
                    id: Buffer.from(userId).toString('base64'),
                    name: email,
                    displayName: userId  
                },
                pubKeyCredParams: [
                    { type: "public-key", alg: -7 },   // ES256
                    { type: "public-key", alg: -257 }  // RS256
                ],
                attestation: 'direct',
                timeout: 60000
            });

            console.log("Registration Request Received");
            console.log("Email:", email);
            console.log("User ID:", userId);
            console.log("Generated Challenge:", challenge);
        });
    });


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
