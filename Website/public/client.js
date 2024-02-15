import init, { run_js } from './web_wasm/webauth_zkp.js';

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

        const userAccountIdBytes = Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0));

        const createCredentialOptions = {
            challenge: challenge,
            rp: options.rp,
            user: {
                id: userAccountIdBytes,
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
        console.log('Login data in client before sending to server:', loginData);
        console.log('FOR ZKP PRIVATE INPUT, clientDataJSON in base64: ', loginData.response.clientDataJSON);
        console.log('FOR ZKP PRIVATE INPUT, authData in base64: ', loginData.response.authenticatorData);

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

// Handles Login with ZKP
document.getElementById('login-zkp').addEventListener('click', async () => {
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
        //Up until here, it is identical to the login function without the ZKP
        
        await init();
        const clientDataJSON = JSON.parse(new TextDecoder().decode(assertion.response.clientDataJSON));
        const challenge = clientDataJSON.challenge;
        const startTime = performance.now();
        const resultMap = run_js(arrayBufferToBase64(assertion.response.clientDataJSON), arrayBufferToBase64(assertion.response.authenticatorData), challenge);
        const endTime = performance.now();
        console.log(`Execution time: ${endTime - startTime} milliseconds`);

        console.log("Result: ", resultMap);
        const resultObject = Object.fromEntries(resultMap);
        console.log("Result Object: ", resultObject);
        console.log("Result Object Message: ", resultObject.message);

        const loginData = {
            id: assertion.id,
            signature: arrayBufferToBase64(assertion.response.signature),
            proof: resultObject.proof,
            vk: resultObject.vk,
            message: resultObject.message
        };
        console.log('Login data in client before sending to server:', loginData);

        const regResponse = await fetch('/verify-login-zkp', {
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
