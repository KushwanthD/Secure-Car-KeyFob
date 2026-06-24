# 🔐 Secure Biometric Car Key Fob System

A software simulation of a cryptographically hardened car key fob protocol, designed to eliminate the three most common real-world attacks on keyless entry systems — **replay attacks**, **relay attacks**, and **signal jamming/interception**.

Built as a research and learning project by a Cybersecurity undergraduate, this system implements the same cryptographic primitives used in modern secure communication protocols, applied to the automotive keyless entry problem.

> **Status:** Active development — Phase 1 (cryptographic core) complete. Phase 2 (biometric MFA) planned.

---

## The Problem

Modern car key fobs are trivially attacked:

| Attack | How it works | How common |
|---|---|---|
| **Relay attack** | Two attackers amplify the fob's signal from inside your home to your parked car | Most common method of keyless car theft today |
| **Replay attack** | Attacker records a valid unlock signal and replays it later | Defeated by basic rolling codes, but many cars still lack this |
| **RollJam attack** | Jams the first signal, steals the code, lets the second through — leaving one valid unused code | Works against standard rolling code implementations |
| **Signal jamming** | Blocks the unlock signal so the car never receives it | Used in combination with replay capture |

Most production key fobs use rolling codes from the 1990s with weak or no encryption. This project explores what a modern, properly secured protocol would look like.

---

## Solution Architecture

The system runs a **9-step mutual authentication handshake** before any unlock signal is sent. Every layer is independently verified.

```
TRANSMITTER (Key Fob)                    RECEIVER (Car Unit)
        |                                        |
        |──── HELLO: pub_tx, nonce_tx, ─────────▶|
        |           Ed25519_sig_tx, HMAC         |  ← certificate validation
        |                                        |
        |◀─── ACK:  pub_rx, nonce_rx,  ──────────|
        |           Ed25519_sig_rx, HMAC         |  ← certificate validation
        |                                        |
        |    [Both derive session keys via]      |
        |    [X25519 ECDH + HKDF-SHA256  ]      |
        |                                        |
        |──── FIN:  fin_mac, attest_tx,  ────────▶|
        |           device_id_tx                 |  ← device attestation
        |                                        |
        |◀─── OK:   attest_rx, device_id_rx ─────|  ← device attestation
        |                                        |
        |──── MSG:  AEAD(rolling_code +  ────────▶|
        |           FHSS_index + hop_idx)        |  ← unlock attempt
        |                                        |
        |◀─── UNLOCKED ──────────────────────────|
```

---

## Security Layers

### 1. Mutual Authentication — X25519 + Ed25519
Each session generates a fresh **ephemeral X25519 key pair**. Neither side trusts the other's public key without a valid **Ed25519 signature** from their long-term identity key. This means:
- A man-in-the-middle cannot inject their own X25519 key — they can't forge the Ed25519 signature
- Even if the source code leaks, an attacker needs the private identity key (stored in `.env.tx` / `.env.rx`) to impersonate either device

### 2. Session Key Derivation — HKDF-SHA256
The X25519 shared secret is fed into **HKDF** with the session nonces as salt, deriving four independent 32-byte keys:
- `aead` — for message encryption
- `mac` — for HMAC authentication
- `fhss` — for frequency hop sequence generation
- `roll` — for rolling code generation

Using the nonces as HKDF salt (not as `info`) follows RFC 5869 correctly — randomness goes into salt, domain separation goes into info.

### 3. Authenticated Encryption — ChaCha20-Poly1305
Every unlock message is encrypted and authenticated with **ChaCha20-Poly1305** (the same AEAD cipher used in TLS 1.3). The rolling code, FHSS index, and hop counter are all inside the ciphertext — an attacker who captures the signal sees only random bytes.

### 4. Rolling Codes with Desync Window
Rolling codes are derived as `HMAC-SHA256(roll_key, counter)[:4] % 1,000,000`. The receiver verifies the code and accepts any code within a **256-counter window** to handle desynchronisation (missed signals), then advances past the matched counter — used codes can never be replayed.

### 5. Frequency Hopping Spread Spectrum (FHSS)
The unlock channel hops across 30 frequencies in the 902–960 MHz ISM band in a sequence derived from `HMAC-SHA256(fhss_key, hop_index)`. Both sides independently compute the same sequence. An attacker cannot selectively jam a single frequency because they don't know which one comes next.

### 6. Device Attestation
After key derivation, each device sends `HMAC-SHA256(session_mac_key, "ATTEST" || device_id || session_nonce)`. This binds a hardware serial number to the session. Replaying captured attestation bytes into a new session fails — the session nonce is different.

### 7. Key Rotation
Session keys incorporate a daily epoch counter in the HKDF `info` field. Keys automatically rotate every 24 hours with no coordination required — both sides independently compute `epoch = unix_time // 86400`.

### 8. Rate Limiting
The receiver enforces a **per-IP token bucket**: burst capacity of 5 attempts, refilling at 1 token per 10 seconds. Brute-force attacks are throttled, and the transmitter receives a `RATE_LIMITED` response and backs off exponentially.

### 9. TCP Framing
All messages are length-prefixed (4-byte big-endian header). This eliminates the partial-read bug inherent to treating TCP as a message protocol — `recv(n)` may return fewer than `n` bytes.

---

## What This Protects Against

| Attack | Protection mechanism |
|---|---|
| Replay attack | Nonce uniqueness set + rolling code counter advancement |
| Relay attack | FHSS channel hopping (attacker cannot relay across hopping channels) |
| RollJam attack | Rolling code is inside AEAD ciphertext — jamming gives attacker ciphertext, not a usable code |
| MITM / key injection | Ed25519 certificate validation on both X25519 public keys |
| Brute force | Token bucket rate limiting + 6-digit rolling codes change every attempt |
| Device impersonation | Session-bound device attestation with HMAC |
| Long-term key compromise | Daily key rotation via epoch-based HKDF |
| Partial TCP reads | Length-prefixed framing with `recvexact()` |

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Key exchange | X25519 (ECDH) | Fast, secure, no patent issues |
| Identity / certificates | Ed25519 | Small keys, fast signatures, strong security |
| Key derivation | HKDF-SHA256 | RFC 5869 compliant, proper salt/info separation |
| Encryption | ChaCha20-Poly1305 | TLS 1.3 standard, fast without hardware AES |
| Authentication | HMAC-SHA256 | Rolling codes, attestation, handshake MACs |
| Frequency hopping | HMAC-PRF over ISM band | Deterministic pseudorandom channel sequence |
| Rate limiting | Token bucket | Thread-safe, per-IP, configurable burst |
| Transport | TCP with length-prefix framing | Reliable, no partial-read bugs |
| Secrets management | python-dotenv (.env files) | Keys never in source code |

---

## Project Structure

```
Secure-Car-KeyFob/
├── common_fix.py      # All cryptographic primitives and shared utilities
├── transmitter.py     # Key fob side — initiates authentication and unlock
├── receiver.py        # Car unit side — verifies and grants/denies access
├── keygen.py          # One-time key generation — creates .env.tx and .env.rx
├── .env.tx            # TX secrets (gitignored — never committed)
├── .env.rx            # RX secrets (gitignored — never committed)
└── .gitignore         # Ensures secret files are never accidentally pushed
```

---

## Getting Started

### Prerequisites
```bash
pip install cryptography python-dotenv
```

### 1. Generate keys (run once)
```bash
python keygen.py
```
This creates `.env.tx` and `.env.rx` in your project folder. These files contain your cryptographic keys — **never share or commit them**.

### 2. Start the receiver (Terminal 1)
```bash
python receiver.py
```
Expected output:
```
2026-06-24 | RX | INFO | Receiver listening on 127.0.0.1:65432
```

### 3. Run the transmitter (Terminal 2)
```bash
python transmitter.py
```
Expected output:
```
2026-06-24 | TX | INFO | Mutual authentication complete ✓
2026-06-24 | TX | INFO | 🔓 CAR UNLOCKED (attempt 1)
```

### Configuration options
```bash
python transmitter.py --max-attempts 6 --retry-delay 0.2 --key-rotation-period 86400
python receiver.py --max-attempts 6 --key-rotation-period 86400
```

---

## Security Model and Assumptions

This is a **software simulation** running over TCP on localhost. The security properties described above are cryptographically sound but the following are out of scope for this phase:

- **RF hardware**: FHSS is simulated in software. A real deployment would need an RF transceiver operating in the 902–960 MHz ISM band (e.g. CC1101 module)
- **Secure hardware storage**: Keys are stored in `.env` files. A production system would use a hardware security module (HSM) or ARM TrustZone secure enclave
- **Side-channel attacks**: Timing and power analysis attacks on the crypto implementation are not addressed

---

## Roadmap

### Phase 1 — Cryptographic Core ✅ Complete
- [x] X25519 ephemeral key exchange
- [x] Ed25519 certificate validation
- [x] HKDF-SHA256 session key derivation
- [x] ChaCha20-Poly1305 authenticated encryption
- [x] Rolling codes with 256-counter desync window
- [x] FHSS channel hopping simulation
- [x] Device attestation
- [x] Daily key rotation
- [x] Per-IP rate limiting
- [x] Length-prefixed TCP framing

### Phase 2 — Biometric MFA (Planned)
- [ ] Fingerprint authentication with liveness detection (ISO 30107-3 PAD compliance)
- [ ] Iris scanner integration with anti-spoofing
- [ ] Random MFA challenges — system randomly requests biometric re-authentication during operation to ensure the authorised person is still in control
- [ ] Duress code support — secondary PIN that silently triggers an alert while appearing to unlock normally
- [ ] Hardware prototype on Raspberry Pi + CC1101 RF module

### Phase 3 — Hardware Integration (Planned)
- [ ] Port cryptographic core to embedded C for microcontroller deployment
- [ ] Actual RF transmission in 902–960 MHz ISM band
- [ ] Hardware secure element for key storage
- [ ] UWB distance bounding for relay attack prevention at the physical layer

---

## Why Not Just Use UWB?

The automotive industry is moving toward Ultra-Wideband (UWB) distance bounding (CCC Digital Key 4.0, 2025) as the hardware-layer solution to relay attacks. UWB is excellent but requires expensive chipsets and is not retrofittable to existing vehicles.

This project explores the **software/cryptographic layer** of the same problem — what the protocol above UWB should look like regardless of the physical transport. The cryptographic handshake in this system could sit on top of UWB, BLE, or RF equally well.

---

## References and Further Reading

- [RFC 5869 — HMAC-based Key Derivation Function (HKDF)](https://datatracker.ietf.org/doc/html/rfc5869)
- [RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc8439)
- [CCC Digital Key 4.0 Specification](https://carconnectivity.org/digital-key/)
- [ISO 30107-3 — Biometric Presentation Attack Detection](https://www.iso.org/standard/67892.html)
- [RollJam Attack — Samy Kamkar](https://samy.pl/rolljam/)
- [KeeLoq Rolling Code Analysis](https://www.crypto.ruhr-uni-bochum.de/imperia/md/content/crypto/paper/keeloq.pdf)

---

## Author

**D V Sai Kushwanth**  
B.Tech CSE (Cybersecurity), Jain (Deemed-to-be University)  
[GitHub](https://github.com/) · [LinkedIn](https://linkedin.com/) · kushwanth91782@gmail.com

---

*This project is for educational and research purposes. The cryptographic design reflects real-world security principles and is intended to demonstrate understanding of secure protocol design.*