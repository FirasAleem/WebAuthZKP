from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import base64

def check_key_match(x_b64, y_b64, priv_key_path):
    # Decode the base64 URL-safe encoded values and ensure proper padding
    x_decoded = base64.urlsafe_b64decode(x_b64 + '==')
    y_decoded = base64.urlsafe_b64decode(y_b64 + '==')

    # Combine x and y coordinates into a byte string
    public_key_bytes = b'\x04' + x_decoded + y_decoded

    # Load the public key
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), public_key_bytes
    )

    # Load the private key
    with open(priv_key_path, 'rb') as f:
        private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Data to sign (could be any data)
    data = b"test data"

    # Sign the data with the private key
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )

    # Verify the signature with the public key
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        print("The signature is valid. The keys match.")
    except Exception as e:
        print("The signature is invalid. The keys do not match.", e)

# Prompting user for input
x_base64 = input("Enter the X coordinate in base64: ")
y_base64 = input("Enter the Y coordinate in base64: ")
private_key_path = input("Enter the name of the private key file: ")

check_key_match(x_base64, y_base64, private_key_path)
