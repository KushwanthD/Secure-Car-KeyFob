"""
common_fix.py — Shared cryptographic primitives for the key-fob system.

Improvements applied:
  - Fixed hmac.new → hmac.new (stdlib) with no shadowing; confirmed correct usage.
  - HKDF salt is now nonce_tx+nonce_rx (randomness); info is a domain string.
  - Certificate-style Ed25519 signing for X25519 public keys (key attestation).
  - Key rotation: derive_session_keys accepts a rotation_epoch so session keys
    change every epoch even with the same master key.
  - recvexact() helper for robust TCP framing (eliminates partial-read bugs).
  - Rate-limit primitives (token bucket) usable by both sides.
  - Device attestation: sign_attestation / verify_attestation bind a device
    identity (serial / hardware ID) to the session.
"""

import os
import time
import hmac as _hmac          # aliased to avoid any accidental shadowing
import hashlib
import secrets
import threading

from dotenv import load_dotenv

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature

def init_env(env_file: str = ".env") -> None:
    """
    Load environment variables from a specific .env file.
    Call this at the very top of transmitter.py and receiver.py
    before any other common_fix functions are used.

    transmitter.py calls: init_env(".env.tx")
    receiver.py    calls: init_env(".env.rx")
    """
    if not os.path.exists(env_file):
        raise FileNotFoundError(
            f"Environment file '{env_file}' not found.\n"
            f"Run  python keygen.py  first to generate .env.tx and .env.rx"
        )
    load_dotenv(env_file, override=True)

# ── Environment variable names ──────────────────────────────────────────────
SEC_KEY_ENV_VAR       = "FOB_MASTER_KEY_B64"
SIGN_KEY_ENV_VAR      = "FOB_SIGNING_KEY_B64"   # Ed25519 private key (base64 raw 64 B)
PEER_SIGN_KEY_ENV_VAR = "FOB_PEER_SIGN_KEY_B64" # Ed25519 public key of the peer

import base64 as _b64


# ═══════════════════════════════════════════════════════════════════════════
# 1. MASTER KEY
# ═══════════════════════════════════════════════════════════════════════════

def load_master_key() -> bytes:
    """Load and validate the 32-byte master key from the environment."""
    raw = os.environ.get(SEC_KEY_ENV_VAR)
    if not raw:
        raise RuntimeError(f"{SEC_KEY_ENV_VAR} is not set")
    try:
        key = _b64.b64decode(raw, validate=True)
    except Exception:
        raise RuntimeError("Master key: invalid Base64")
    if len(key) < 32:
        raise RuntimeError("Master key must be at least 32 bytes")
    return key


# ═══════════════════════════════════════════════════════════════════════════
# 2. X25519 KEY EXCHANGE
# ═══════════════════════════════════════════════════════════════════════════

def make_x25519_keypair():
    """Generate a fresh X25519 ephemeral key pair.

    Returns (private_key_object, raw_public_bytes).
    """
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def load_peer_pub(pub_bytes: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(pub_bytes)


# ═══════════════════════════════════════════════════════════════════════════
# 3. ED25519 CERTIFICATE / KEY ATTESTATION
#
#    Each device holds a long-term Ed25519 identity key (stored in .env).
#    During the handshake the ephemeral X25519 pub is *signed* with that
#    identity key so the peer can verify it belongs to a legitimate device.
#    This replaces the raw HMAC-based pub-key check with a proper
#    certificate-style attestation.
# ═══════════════════════════════════════════════════════════════════════════

def _load_signing_key() -> Ed25519PrivateKey:
    raw = os.environ.get(SIGN_KEY_ENV_VAR)
    if not raw:
        raise RuntimeError(f"{SIGN_KEY_ENV_VAR} is not set")
    seed = _b64.b64decode(raw, validate=True)          # must be 32 bytes
    return Ed25519PrivateKey.from_private_bytes(seed)


def _load_peer_verify_key() -> Ed25519PublicKey:
    raw = os.environ.get(PEER_SIGN_KEY_ENV_VAR)
    if not raw:
        raise RuntimeError(f"{PEER_SIGN_KEY_ENV_VAR} is not set")
    pub_bytes = _b64.b64decode(raw, validate=True)     # must be 32 bytes
    return Ed25519PublicKey.from_public_bytes(pub_bytes)


def sign_pub_key(x25519_pub: bytes, nonce: bytes) -> bytes:
    """
    Sign (x25519_pub || nonce) with this device's Ed25519 identity key.
    Returns a 64-byte Ed25519 signature.
    """
    key = _load_signing_key()
    return key.sign(x25519_pub + nonce)


def verify_peer_pub_key(x25519_pub: bytes, nonce: bytes, signature: bytes) -> bool:
    """
    Verify that `signature` is a valid Ed25519 signature over
    (x25519_pub || nonce) from the trusted peer identity key.
    Returns True on success, False on failure.
    """
    vk = _load_peer_verify_key()
    try:
        vk.verify(signature, x25519_pub + nonce)
        return True
    except InvalidSignature:
        return False


# ═══════════════════════════════════════════════════════════════════════════
# 4. DEVICE ATTESTATION
#
#    After session keys are established, each side sends a short attestation
#    message that binds a device serial / hardware ID to the session.
#    The attestation is HMAC-signed with the session MAC key so it cannot
#    be replayed into a different session.
# ═══════════════════════════════════════════════════════════════════════════

DEVICE_ID_ENV_VAR = "FOB_DEVICE_ID"   # e.g. "TX-SN-00A1B2C3"


def get_device_id() -> bytes:
    did = os.environ.get(DEVICE_ID_ENV_VAR, "UNKNOWN-DEVICE")
    return did.encode()


def sign_attestation(mac_key: bytes, device_id: bytes, session_nonce: bytes) -> bytes:
    """
    Produce an attestation tag = HMAC-SHA256(mac_key, b"ATTEST" || device_id || session_nonce).
    """
    return hmac_bytes(mac_key, b"ATTEST" + device_id + session_nonce)


def verify_attestation(
    mac_key: bytes,
    device_id: bytes,
    session_nonce: bytes,
    tag: bytes,
) -> bool:
    expected = sign_attestation(mac_key, device_id, session_nonce)
    return _hmac.compare_digest(expected, tag)


# ═══════════════════════════════════════════════════════════════════════════
# 5. HKDF  (FIX: salt = nonces; info = domain label)
# ═══════════════════════════════════════════════════════════════════════════

def derive_session_keys(
    shared_secret: bytes,
    *,
    salt: bytes,                          # nonce_tx + nonce_rx  (randomness)
    info: bytes = b"keyfob-v1-session",   # domain separation
) -> dict:
    """
    Derive four 32-byte sub-keys from the X25519 shared secret.

    Previously salt=None was used (HKDF spec says "all zeros" then).
    Now we pass the session nonces as salt for proper randomness extraction,
    and keep info purely for domain separation.
    """
    hk = HKDF(
        algorithm=hashes.SHA256(),
        length=128,
        salt=salt,
        info=info,
    )
    material = hk.derive(shared_secret)
    return {
        "aead": material[0:32],
        "mac":  material[32:64],
        "fhss": material[64:96],
        "roll": material[96:128],
    }


# ═══════════════════════════════════════════════════════════════════════════
# 6. KEY ROTATION
#
#    Long-term deployments should rotate session keys periodically.
#    An epoch counter (e.g. Unix day number) is mixed into the HKDF info
#    field so that keys derived in different epochs are independent.
# ═══════════════════════════════════════════════════════════════════════════

def current_epoch(period_seconds: int = 86400) -> int:
    """Return a monotonically increasing epoch number (default: daily)."""
    return int(time.time()) // period_seconds


def derive_session_keys_with_rotation(
    shared_secret: bytes,
    *,
    salt: bytes,
    epoch: int | None = None,
    period_seconds: int = 86400,
) -> dict:
    """
    Like derive_session_keys but incorporates an epoch counter in the info
    field so that keys automatically rotate every `period_seconds`.
    Both TX and RX must agree on the epoch value (pass it explicitly if
    clocks might differ, otherwise use current_epoch()).
    """
    if epoch is None:
        epoch = current_epoch(period_seconds)
    info = b"keyfob-v1-session-epoch-" + epoch.to_bytes(8, "big")
    return derive_session_keys(shared_secret, salt=salt, info=info)


# ═══════════════════════════════════════════════════════════════════════════
# 7. AEAD  (ChaCha20-Poly1305)
# ═══════════════════════════════════════════════════════════════════════════

def aead_encrypt(key: bytes, aad: bytes, plaintext: bytes):
    """Returns (nonce_12B, ciphertext_with_tag)."""
    cipher = ChaCha20Poly1305(key)
    nonce  = secrets.token_bytes(12)
    ct     = cipher.encrypt(nonce, plaintext, aad)
    return nonce, ct


def aead_decrypt(key: bytes, aad: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag on failure."""
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


# ═══════════════════════════════════════════════════════════════════════════
# 8. HMAC  (uses stdlib hmac, aliased; no shadowing possible)
# ═══════════════════════════════════════════════════════════════════════════

def hmac_bytes(key: bytes, msg: bytes) -> bytes:
    """Constant-time HMAC-SHA256."""
    return _hmac.new(key, msg, hashlib.sha256).digest()


# ═══════════════════════════════════════════════════════════════════════════
# 9. FHSS
# ═══════════════════════════════════════════════════════════════════════════

def fhss_for_index(fhss_key: bytes, freqs: list, index: int):
    """
    Returns (frequency_value, frequency_list_index) for a given hop index.
    Deterministic given fhss_key and index — both sides independently
    compute the same sequence.
    """
    mac = hmac_bytes(fhss_key, b"FHSS" + index.to_bytes(8, "big"))
    idx = int.from_bytes(mac, "big") % len(freqs)
    return freqs[idx], idx


# ═══════════════════════════════════════════════════════════════════════════
# 10. ROLLING CODES
# ═══════════════════════════════════════════════════════════════════════════

def rolling_code_from_counter(roll_key: bytes, counter: int) -> int:
    """6-digit rolling code derived from HMAC(roll_key, counter)."""
    val = hmac_bytes(roll_key, counter.to_bytes(8, "big"))[:4]
    return int.from_bytes(val, "big") % 1_000_000


def verify_rolling_code_with_window(
    roll_key: bytes,
    received_code: int,
    expected_counter: int,
    window: int = 256,
) -> int | None:
    """
    Accept a rolling code that falls within [expected_counter, expected_counter+window).
    Returns the matched counter value so the receiver can advance its state,
    or None if the code is invalid.

    This handles the counter-desync problem: if the TX sent several codes
    that the RX missed (e.g. due to FHSS collisions), the RX will still
    accept the next valid code within the resync window, just like KeeLoq.
    """
    for offset in range(window):
        candidate = expected_counter + offset
        if rolling_code_from_counter(roll_key, candidate) == received_code:
            return candidate
    return None


# ═══════════════════════════════════════════════════════════════════════════
# 11. TCP HELPERS  (fixes partial-read bug)
# ═══════════════════════════════════════════════════════════════════════════

def recvexact(sock, length: int) -> bytes:
    """
    Read exactly `length` bytes from a TCP socket.
    TCP is a stream protocol — a single recv() call may return fewer bytes
    than requested. This helper loops until all bytes arrive.
    Raises ConnectionError if the connection closes prematurely.
    """
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed before all bytes received")
        buf += chunk
    return bytes(buf)


def send_framed(sock, data: bytes) -> None:
    """Send a length-prefixed message: [4-byte big-endian length][data]."""
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_framed(sock) -> bytes:
    """Receive a length-prefixed message."""
    length = int.from_bytes(recvexact(sock, 4), "big")
    if length > 65536:
        raise ValueError(f"Suspiciously large frame: {length} bytes")
    return recvexact(sock, length)


# ═══════════════════════════════════════════════════════════════════════════
# 12. RATE LIMITING  (token-bucket, thread-safe)
# ═══════════════════════════════════════════════════════════════════════════

class TokenBucket:
    """
    Thread-safe token-bucket rate limiter.

    Parameters
    ----------
    capacity    : maximum tokens (burst size)
    refill_rate : tokens added per second
    """

    def __init__(self, capacity: float = 10.0, refill_rate: float = 1.0):
        self._capacity    = capacity
        self._refill_rate = refill_rate
        self._tokens      = capacity
        self._last        = time.monotonic()
        self._lock        = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        """
        Try to consume `tokens` from the bucket.
        Returns True if allowed, False if rate-limited.
        """
        with self._lock:
            now    = time.monotonic()
            added  = (now - self._last) * self._refill_rate
            self._tokens = min(self._capacity, self._tokens + added)
            self._last   = now
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False


# Per-IP rate limiter registry (used by the receiver)
_ip_buckets: dict[str, TokenBucket] = {}
_ip_lock    = threading.Lock()


def get_rate_limiter(ip: str) -> TokenBucket:
    """Return (or create) a per-IP token bucket."""
    with _ip_lock:
        if ip not in _ip_buckets:
            # Allow burst of 5 attempts; refill 1 token every 10 seconds.
            _ip_buckets[ip] = TokenBucket(capacity=5, refill_rate=0.1)
        return _ip_buckets[ip]


# ---------------------------------------------------------------------------
# 13. TIME-SYNCHRONIZED PORT AND FREQUENCY HOPPING & STATE PERSISTENCE
# ---------------------------------------------------------------------------

def get_hop_epoch(period_seconds: int = 5) -> int:
    """Return a time-based epoch integer used to synchronize port/frequency hopping."""
    return int(time.time()) // period_seconds


def derive_hop_port_and_freq(
    master_key: bytes,
    epoch: int,
    port_start: int = 50000,
    port_range: int = 1000,
) -> tuple[int, int]:
    """
    Derive a deterministic listening port and frequency index from the master key and epoch.
    Ensures sequential epoch combinations are non-repeating and mathematically unpredictable.
    """
    # Derive for current epoch
    mac = hmac_bytes(master_key, b"PORT_FREQ_HOP" + epoch.to_bytes(8, "big"))
    port_offset = int.from_bytes(mac[0:4], "big") % port_range
    freq_index = int.from_bytes(mac[4:8], "big")

    # Retrieve derivation for the previous epoch to check for repetition
    prev_mac = hmac_bytes(master_key, b"PORT_FREQ_HOP" + (epoch - 1).to_bytes(8, "big"))
    prev_port_offset = int.from_bytes(prev_mac[0:4], "big") % port_range
    prev_freq_index = int.from_bytes(prev_mac[4:8], "big")

    # If the current port/frequency combination matches the previous one, perturb it
    if port_offset == prev_port_offset and freq_index == prev_freq_index:
        perturbed_mac = hmac_bytes(master_key, b"PORT_FREQ_HOP_PERTURB" + epoch.to_bytes(8, "big"))
        port_offset = (port_offset + int.from_bytes(perturbed_mac[0:4], "big")) % port_range
        freq_index = freq_index ^ int.from_bytes(perturbed_mac[4:8], "big")

    return port_start + port_offset, freq_index


import json

def load_state_file(path: str) -> dict:
    """Safely load JSON state from disk, returning an empty dict if missing or corrupt."""
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_state_file(path: str, data: dict) -> None:
    """Safely write JSON state to disk."""
    try:
        temp_path = path + ".tmp"
        with open(temp_path, "w") as f:
            json.dump(data, f, indent=2)
        if os.path.exists(path):
            os.remove(path)
        os.rename(temp_path, path)
    except Exception:
        pass