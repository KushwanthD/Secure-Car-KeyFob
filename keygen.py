"""
keygen.py  --  Generate all keys and write clean .env.tx and .env.rx files.

Run once from your project folder:
    python keygen.py

This creates two files in the same folder:
    .env.tx   --  used by transmitter.py
    .env.rx   --  used by receiver.py
"""

import base64
import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def gen_ed25519():
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return seed, pub


def write_env(path: str, values: dict):
    """Write a plain KEY=VALUE .env file -- no comments, no blanks, no unicode."""
    with open(path, "w") as f:
        for k, v in values.items():
            f.write(f"{k}={v}\n")
    print(f"  Written: {path}")


def main():
    master_key      = secrets.token_bytes(32)
    tx_seed, tx_pub = gen_ed25519()
    rx_seed, rx_pub = gen_ed25519()
    tx_serial       = secrets.token_hex(4).upper()
    rx_serial       = secrets.token_hex(4).upper()

    write_env(".env.tx", {
        "FOB_MASTER_KEY_B64":    b64(master_key),
        "FOB_SIGNING_KEY_B64":   b64(tx_seed),
        "FOB_PEER_SIGN_KEY_B64": b64(rx_pub),
        "FOB_DEVICE_ID":         f"TX-SN-{tx_serial}",
    })

    write_env(".env.rx", {
        "FOB_MASTER_KEY_B64":    b64(master_key),
        "FOB_SIGNING_KEY_B64":   b64(rx_seed),
        "FOB_PEER_SIGN_KEY_B64": b64(tx_pub),
        "FOB_DEVICE_ID":         f"RX-SN-{rx_serial}",
    })

    print("\nKeys generated successfully.")


if __name__ == "__main__":
    main()