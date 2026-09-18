"""Generate an RSA key pair for signing JWTs (RS256) into keys/."""

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"


def main() -> None:
    KEYS_DIR.mkdir(exist_ok=True)
    private_path = KEYS_DIR / "private.pem"
    if private_path.exists():
        print(f"{private_path} already exists; delete it first to rotate keys.")
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (KEYS_DIR / "public.pem").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    print(f"Wrote keys to {KEYS_DIR}")


if __name__ == "__main__":
    main()
