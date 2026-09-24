"""Independent check of the Secure Enclave helper's ECIES.

The helper's `wrap` takes a recipient public key, so this generates a P-256 keypair in Python,
asks Swift to seal to it, and opens the result with a different library. Two implementations
agreeing is the evidence that the construction is standard and correctly built. No Secure
Enclave and no fingerprint, so it runs anywhere.

Run through: uv run --with cryptography tests/ecies.py <path-to-passbox-se>
"""

import base64
import json
import subprocess
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"passbox-se-v1"


def seal(helper: str, public_x963: bytes, plaintext: bytes) -> dict:
    request = json.dumps(
        {
            "public_key": base64.b64encode(public_x963).decode(),
            "plaintext": base64.b64encode(plaintext).decode(),
        }
    )
    out = subprocess.run(
        [helper, "wrap"], input=request.encode(), capture_output=True, check=True
    )
    return json.loads(out.stdout)


def open_sealed(private: ec.EllipticCurvePrivateKey, sealed: dict) -> bytes:
    ephemeral_x963 = base64.b64decode(sealed["ephemeral"])
    combined = base64.b64decode(sealed["ciphertext"])

    sender = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_x963)
    shared = private.exchange(ec.ECDH(), sender)

    # CryptoKit's hkdfDerivedSymmetricKey, with the ephemeral public key as the salt
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=ephemeral_x963, info=INFO
    ).derive(shared)

    # AES.GCM .combined is nonce || ciphertext || tag
    return AESGCM(key).decrypt(combined[:12], combined[12:], None)


def main() -> int:
    helper = sys.argv[1]
    private = ec.generate_private_key(ec.SECP256R1())
    public_x963 = private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )

    secret = b"AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLE"
    sealed = seal(helper, public_x963, secret)

    opened = open_sealed(private, sealed)
    assert opened == secret, f"round trip mismatch: {opened!r}"
    print("ok: python opened what swift sealed")

    # A different key must not open it, which is what makes the wrap worth anything
    stranger = ec.generate_private_key(ec.SECP256R1())
    try:
        open_sealed(stranger, sealed)
    except Exception:
        print("ok: a stranger's key is refused")
    else:
        print("FAIL: a stranger's key opened the wrap")
        return 1

    # Flipping one byte of ciphertext must fail the GCM tag rather than return plaintext
    raw = bytearray(base64.b64decode(sealed["ciphertext"]))
    raw[-1] ^= 0x01
    tampered = dict(sealed, ciphertext=base64.b64encode(bytes(raw)).decode())
    try:
        open_sealed(private, tampered)
    except Exception:
        print("ok: a flipped tag byte is refused")
    else:
        print("FAIL: tampered ciphertext was accepted")
        return 1

    # Swapping the ephemeral key must break the agreement
    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    swapped = dict(sealed, ephemeral=base64.b64encode(other).decode())
    try:
        open_sealed(private, swapped)
    except Exception:
        print("ok: a swapped ephemeral key is refused")
    else:
        print("FAIL: a swapped ephemeral key was accepted")
        return 1

    # Two seals of the same plaintext must differ, or the ephemeral key is not ephemeral
    again = seal(helper, public_x963, secret)
    if again["ephemeral"] == sealed["ephemeral"]:
        print("FAIL: the ephemeral key repeated across two seals")
        return 1
    print("ok: each seal uses a fresh ephemeral key")

    return 0


if __name__ == "__main__":
    sys.exit(main())
