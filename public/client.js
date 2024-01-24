document.getElementById('register').addEventListener('click', async () => {
    const email = document.getElementById('email').value;
    const userId = document.getElementById('userId').value;

    if (!email || !userId) {
        alert('Email and user ID are required');
        return;
    }

    try {
            const response = await fetch('/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email: email, userId: userId })
            });
            if (!response.ok) {
                throw new Error(`Server responded with status: ${response.status}`);
            }
            
            const options = await response.json();

            const createCredentialOptions = {
                challenge: new Uint8Array(options.challenge),
                rp: options.rp,
                user: {
                    ...options.user,
                    id: new Uint8Array(atob(options.user.id), c => c.charCodeAt(0))
                },
                pubKeyCredParams: options.pubKeyCredParams,
                timeout: options.timeout,
                attestation: options.attestation
            };        
            
            navigator.credentials.create({ publicKey: createCredentialOptions })
            .then((newCredentialInfo) => {
            // Convert the necessary parts of newCredentialInfo to base64
            const credential = {};
            console.log('New Credential Info:', newCredentialInfo);
            credential.id = newCredentialInfo.id;
            credential.rawId = arrayBufferToBase64(newCredentialInfo.rawId);
            credential.type = newCredentialInfo.type;
    
            if (newCredentialInfo.response) {
                const clientDataJSON = arrayBufferToBase64(newCredentialInfo.response.clientDataJSON);
                const attestationObject = arrayBufferToBase64(newCredentialInfo.response.attestationObject);
    
                credential.response = {
                    clientDataJSON,
                    attestationObject
                };
            }
            console.log('New Credential:', credential);

            console.log("Client Data JSON:", atob(credential.response.clientDataJSON));
        }).catch((err) => {
            console.error(err);
        });
    
    // Helper function to convert ArrayBuffer to Base64
    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }
        } catch (err) {
        console.error('Registration error:', err);
    }
});

document.getElementById('login').addEventListener('click', async () => {
    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username: 'user@example.com' })
        });
        const data = await response.json();

        const publicKey = {
            ...data,
            challenge: Uint8Array.from(atob(data.challenge), c => c.charCodeAt(0)),
            allowCredentials: data.allowCredentials.map(cred => ({
                ...cred,
                id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0))
            }))
        };

        const assertion = await navigator.credentials.get({ publicKey });
        console.log('Login assertion:', assertion);

        // Send assertion to server for verification
        // You need to convert ArrayBuffer objects to base64 strings
        // This is just an example, adapt as needed
    } catch (err) {
        console.error('Login error:', err);
    }
});
