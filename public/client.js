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

        const createCredentialOptions = {
            challenge: new Uint8Array(options.challenge),
            rp: options.rp,
            user: {
                id: new Uint8Array(options.user.id.userAccountId),
                name: username,
                displayName: username
            },
            pubKeyCredParams: options.pubKeyCredParams,
            timeout: options.timeout,
            authenticatorSelection: options.authenticatorSelection
        };

        const newCredentialInfo = await navigator.credentials.create({ publicKey: createCredentialOptions });
        const processedCredential = processCredentialInfo(newCredentialInfo);
        console.log('Processed Credential Client: ', processedCredential);
    
        // // Decodes ArrayBuffers
        // const decoder = new TextDecoder('utf-8');
        // var decodedString = decoder.decode(newCredentialInfo.response.clientDataJSON);
        // console.log('Client JSON 1: ', decodedString);

        // const attestationObject = newCredentialInfo.response.attestationObject;

        // // Access client JSON
        // const clientJSON = newCredentialInfo.response.clientDataJSON;
        // decodedString = decoder.decode(clientJSON);
        // console.log('Client JSON 2: ', decodedString);

        // // Return authenticator data ArrayBuffer
        // const authenticatorData = new Uint8Array(newCredentialInfo.response.authenticatorData);
        // const parsedAuthData = parseAuthenticatorData(authenticatorData.buffer);
        // console.log(parsedAuthData);
        // parseAndPrintRpIdHash(authenticatorData.buffer);
        // }});
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

function parseAuthenticatorData(buffer) {
    const dataView = new DataView(buffer);

    // RP ID Hash is the first 32 bytes
    const rpIdHash = buffer.slice(0, 32);

    // Flags is the next byte
    const flags = dataView.getUint8(32);
    const userPresent = (flags & 0x01) === 0x01;
    const userVerified = (flags & 0x04) === 0x04;

    // Signature counter is the next 4 bytes
    const signCount = dataView.getUint32(33, false); // Big-endian

    return {
        rpIdHash,
        userPresent,
        userVerified,
        signCount
    };
}

function parseAndPrintRpIdHash(authenticatorData) {
    const dataView = new DataView(authenticatorData);

    // RP ID Hash is the first 32 bytes of the Authenticator Data
    let rpIdHashHex = '';
    for (let i = 0; i < 32; i++) {
        const byte = dataView.getUint8(i).toString(16).padStart(2, '0');
        rpIdHashHex += byte;
    }

    console.log('RP ID Hash (Hex):', rpIdHashHex);
}

// Handles Login
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
