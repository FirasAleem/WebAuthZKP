document.getElementById('register').addEventListener('click', async () => {
    const username = document.getElementById('username').value;

    if (!window.PublicKeyCredential) {
        alert("WebAuthn not supported on this browser.");
        return;
    }

    if (!username) {
        alert('User ID is required');
        return;
    }

    try {
        const response = await fetch('/start-register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }

        const options = await response.json();
        const challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
        console.log('Challenge in Client: ', challenge);

        const createCredentialOptions = {
            challenge: challenge,
            rp: options.rp,
            user: {
                id: new Uint8Array(options.user.id.userAccountId),
                name: username,
                displayName: username
            },
            pubKeyCredParams: options.pubKeyCredParams,
            timeout: options.timeout,
            authenticatorSelection: options.authenticatorSelection,
            attestation: options.attestation,
            userVerification: options.userVerification
        };
        console.log('Create Credential Options Challenge: ', createCredentialOptions.challenge);

        const newCredentialInfo = await navigator.credentials.create({ publicKey: createCredentialOptions });
        console.log('New Credential Info: ', newCredentialInfo);

        const JSONarrayBuffer = newCredentialInfo.response.clientDataJSON;
        const decoder = new TextDecoder('utf-8');
        const decoded = decoder.decode(JSONarrayBuffer);
        console.log('Client JSON: ', JSON.parse(decoded));
        const processedCredential = processCredentialInfo(newCredentialInfo);
        console.log('Processed Credential Client: ', processedCredential);

        const regResponse = await fetch('/send-credential', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: username,
                credential: processedCredential
            })
        });

        if (!regResponse.ok) {
            throw new Error(`Server responded with status: ${regResponse.status}`);
        }

        const regResult = await regResponse.json();
        console.log('Registration result:', regResult);


    } catch (err) {
        console.error('Registration error:', err);
    }
});

// Process the newCredentialInfo (e.g., converting ArrayBuffers to Base64)
function processCredentialInfo(credential) {
    const clientDataJSON = arrayBufferToBase64(credential.response.clientDataJSON);
    const attestationObject = arrayBufferToBase64(credential.response.attestationObject);

    return {
        id: credential.id,
        rawId: arrayBufferToBase64(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON,
            attestationObject
        }
    };
}

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

function base64URLtoBase64(input) {
    // Replace Base64URL specific characters with Base64 equivalent
    let base64String = input.replace(/-/g, '+').replace(/_/g, '/');
    // Pad with '=' characters to make the length a multiple of 4 if necessary
    while (base64String.length % 4) {
        base64String += '=';
    }
    return base64String;
}

// Handles Login
document.getElementById('login').addEventListener('click', async () => {
    const username = document.getElementById('username').value;

    if (!window.PublicKeyCredential) {
        alert("WebAuthn not supported on this browser.");
        return;
    }

    if (!username) {
        alert('User ID is required');
        return;
    }

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username })
        });
        if (response.status === 400) {
            const errorText = await response.text(); // Or response.json() if your server sends JSON
            if (errorText.includes('User not found')) {
                alert('User not found. Please register first.');
                return;
            }
        }
        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }
        const data = await response.json();
        console.log('Login data:', data);
        console.log('Login data array:', data.allowCredentials);

        const assertionOptions = {
            publicKey: {
                challenge: Uint8Array.from(atob(data.challenge), c => c.charCodeAt(0)),
                allowCredentials: data.allowCredentials.map(cred => ({
                    ...cred,
                    id: Uint8Array.from(atob(base64URLtoBase64(cred.id)), c => c.charCodeAt(0))
                })),
                timeout: data.timeout
            }
        };

        const assertion = await navigator.credentials.get(assertionOptions);
        console.log('Login assertion:', assertion);

        const loginData = {
            id: assertion.id,
            rawId: arrayBufferToBase64(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: arrayBufferToBase64(assertion.response.authenticatorData),
                clientDataJSON: arrayBufferToBase64(assertion.response.clientDataJSON),
                signature: arrayBufferToBase64(assertion.response.signature),
                userHandle: arrayBufferToBase64(assertion.response.userHandle)
            }
        };
        console.log('Login data:', loginData);

        const regResponse = await fetch('/verify-login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(loginData)
        });
        if (!regResponse.ok) {
            throw new Error(`Server responded with status: ${regResponse.status}`);
        }

        const regResult = await regResponse.json();
        console.log('Authentication result:', regResult);

    } catch (err) {
        console.error('Login error:', err);
    }
});
