"""
receiver.py — Key-fob receiver (RX / car side).

Improvements applied vs original:
  ① Certificate validation  : RX verifies TX's Ed25519 signature before trusting its X25519 pub;
                               RX also signs its own pub so TX can verify.
  ② Rate limiting           : Per-IP token bucket; sends RATE_LIMITED so TX knows to back off.
  ③ Key rotation            : Session keys incorporate the same daily epoch as TX.
  ④ Device attestation      : RX verifies TX attestation and sends its own.
  ⑤ Rolling code verified   : Receiver now actually checks the rolling code value.
  ⑥ Counter desync window   : Uses verify_rolling_code_with_window (±256) like KeeLoq.
  ⑦ HKDF salt fix           : salt = nonce_tx+nonce_rx; info = domain label.
  ⑧ TCP framing fix         : all messages use send_framed / recv_framed.
"""

import os
import socket
import logging
import argparse
import hmac as _hmac
import time

import common_fix
common_fix.init_env(".env.rx")  # load RX keys before anything else

from common_fix import (
    load_master_key,
    make_x25519_keypair,
    load_peer_pub,
    derive_session_keys_with_rotation,
    aead_decrypt,
    hmac_bytes,
    fhss_for_index,
    verify_rolling_code_with_window,
    sign_pub_key,
    verify_peer_pub_key,
    get_device_id,
    sign_attestation,
    verify_attestation,
    get_rate_limiter,
    send_framed,
    recv_framed,
)
from cryptography.exceptions import InvalidTag

PROT_VERSION = b"\x02"
MASTER_KEY: bytes | None = None


# ═══════════════════════════════════════════════════════════════════════════
# Per-connection handler
# ═══════════════════════════════════════════════════════════════════════════

def handle_client(conn, addr, args):
    global MASTER_KEY

    peer_ip = addr[0]
    conn.settimeout(10.0)

    # ── Rate limiting (per IP) ───────────────────────────────────────────
    limiter = get_rate_limiter(peer_ip)
    if not limiter.consume():
        logging.warning("Rate limit exceeded for %s — dropping connection", peer_ip)
        try:
            send_framed(conn, b"RATE_LIMITED")
        except Exception:
            pass
        conn.close()
        return

    if MASTER_KEY is None:
        MASTER_KEY = load_master_key()

    logging.info("Connection from %s:%d", peer_ip, addr[1])

    try:
        _handle_authenticated_session(conn, addr, args, limiter)
    except (ConnectionError, ValueError, TimeoutError) as exc:
        logging.error("Session error from %s: %s", peer_ip, exc)
    finally:
        conn.close()


def _handle_authenticated_session(conn, addr, args, limiter):
    """Run the full handshake + message loop for one connection."""

    epoch = int(time.time()) // args.key_rotation_period

    # ── Step 1: receive HELLO ────────────────────────────────────────────
    hello_data = recv_framed(conn)
    if not hello_data.startswith(b"HELLO|"):
        raise ValueError("Expected HELLO frame")

    parts = hello_data.split(b"|")
    if len(parts) != 5:
        raise ValueError("Malformed HELLO frame")

    _, pub_tx_hex, nonce_tx_hex, sig_tx_hex, mac1_hex = parts
    pub_tx   = bytes.fromhex(pub_tx_hex.decode())
    nonce_tx = bytes.fromhex(nonce_tx_hex.decode())
    sig_tx   = bytes.fromhex(sig_tx_hex.decode())
    mac1     = bytes.fromhex(mac1_hex.decode())

    # ── Step 2: certificate validation — verify TX's Ed25519 sig ────────
    if not verify_peer_pub_key(pub_tx, nonce_tx, sig_tx):
        logging.error("TX pub key certificate validation FAILED from %s", addr[0])
        raise ValueError("TX certificate invalid")
    logging.info("TX certificate validated ✓")

    # ── Step 3: verify master-key HMAC on HELLO ──────────────────────────
    if not _hmac.compare_digest(
        hmac_bytes(MASTER_KEY, b"HELLO" + pub_tx + nonce_tx),
        mac1,
    ):
        logging.error("HELLO master-key MAC invalid from %s", addr[0])
        raise ValueError("HELLO MAC invalid")

    logging.info("HELLO verified ✓")

    # ── Step 4: generate RX ephemeral key pair + sign it ─────────────────
    priv_rx, pub_rx = make_x25519_keypair()
    nonce_rx        = os.urandom(16)
    sig_rx          = sign_pub_key(pub_rx, nonce_rx)

    mac2 = hmac_bytes(
        MASTER_KEY,
        b"ACK" + pub_rx + nonce_rx + pub_tx + nonce_tx,
    )

    ack_payload = b"|".join([
        b"ACK",
        pub_rx.hex().encode(),
        nonce_rx.hex().encode(),
        sig_rx.hex().encode(),
        mac2.hex().encode(),
    ])
    send_framed(conn, ack_payload)
    logging.debug("RX → TX : ACK sent")

    # ── Step 5: derive session keys ──────────────────────────────────────
    peer_pub = load_peer_pub(pub_tx)
    shared   = priv_rx.exchange(peer_pub)
    keys     = derive_session_keys_with_rotation(
        shared,
        salt=nonce_tx + nonce_rx,
        epoch=epoch,
    )
    logging.info("Session keys derived (epoch=%d) ✓", epoch)

    # ── Step 6: receive FIN + TX attestation ────────────────────────────
    fin_data = recv_framed(conn)
    if not fin_data.startswith(b"FIN|"):
        raise ValueError("Expected FIN frame")

    fin_parts = fin_data.split(b"|")
    if len(fin_parts) != 4:
        raise ValueError("Malformed FIN frame")

    _, fin_mac_hex, attest_tx_hex, tx_device_id_hex = fin_parts
    fin_mac      = bytes.fromhex(fin_mac_hex.decode())
    attest_tx    = bytes.fromhex(attest_tx_hex.decode())
    tx_device_id = bytes.fromhex(tx_device_id_hex.decode())

    # Verify FIN MAC
    if not _hmac.compare_digest(
        hmac_bytes(keys["mac"], b"FIN"),
        fin_mac,
    ):
        logging.error("FIN MAC invalid from %s", addr[0])
        raise ValueError("FIN MAC invalid")

    # Verify TX device attestation
    session_nonce = nonce_tx + nonce_rx
    if not verify_attestation(keys["mac"], tx_device_id, session_nonce, attest_tx):
        logging.error("TX device attestation FAILED from %s", addr[0])
        raise ValueError("TX attestation invalid")
    logging.info(
        "TX device attestation verified ✓  (device_id=%s)",
        tx_device_id.decode(errors="replace"),
    )

    # ── Step 7: send OK + RX attestation ────────────────────────────────
    rx_device_id = get_device_id()
    attest_rx    = sign_attestation(keys["mac"], rx_device_id, session_nonce)

    ok_payload = b"|".join([
        b"OK",
        attest_rx.hex().encode(),
        rx_device_id.hex().encode(),
    ])
    send_framed(conn, ok_payload)
    logging.debug("RX → TX : OK + attestation sent")

    # ── Step 8: message loop ─────────────────────────────────────────────
    fhss_index     = 0
    tx_counter     = 0      # tracks the minimum counter we'll accept
    seen_nonces    = set()
    attempts       = 0

    while attempts < args.max_attempts:

        # Rate-limit check on each message too
        if not limiter.consume():
            logging.warning("Rate limit exceeded mid-session for %s", addr[0])
            send_framed(conn, b"RATE_LIMITED")
            attempts += 1
            continue

        pkt = recv_framed(conn)
        if not pkt:
            break

        parts = pkt.split(b"|")
        if len(parts) != 3 or parts[0] != b"MSG":
            send_framed(conn, b"LOCKED")
            attempts += 1
            continue

        _, nonce_hex, ct_hex = parts

        try:
            nonce      = bytes.fromhex(nonce_hex.decode())
            ciphertext = bytes.fromhex(ct_hex.decode())
        except ValueError:
            send_framed(conn, b"LOCKED")
            attempts += 1
            continue

        # ── Replay protection: nonce uniqueness ─────────────────────────
        if nonce in seen_nonces:
            logging.warning("Replay detected (duplicate nonce) from %s", addr[0])
            send_framed(conn, b"LOCKED")
            attempts += 1
            continue
        seen_nonces.add(nonce)

        # ── Decrypt ──────────────────────────────────────────────────────
        try:
            plain = aead_decrypt(keys["aead"], PROT_VERSION, nonce, ciphertext)
        except (InvalidTag, Exception):
            logging.warning("AEAD decryption failed from %s", addr[0])
            send_framed(conn, b"LOCKED")
            attempts += 1
            continue

        if len(plain) < 14:
            send_framed(conn, b"LOCKED")
            attempts += 1
            continue

        # ── Parse plaintext ──────────────────────────────────────────────
        received_code = int(plain[0:6].decode())
        freq_index    = int.from_bytes(plain[6:10],  "big")
        hop_idx       = int.from_bytes(plain[10:14], "big")

        # ── ① Rolling code verification with desync window ──────────────
        matched_counter = verify_rolling_code_with_window(
            keys["roll"],
            received_code,
            tx_counter,
            window=256,
        )
        if matched_counter is None:
            logging.warning(
                "Rolling code mismatch (received=%06d) from %s", received_code, addr[0]
            )
            send_framed(conn, b"LOCKED")
            attempts += 1
            continue
        # Advance counter past the matched value to prevent reuse
        tx_counter = matched_counter + 1

        # ── ② FHSS channel verification ──────────────────────────────────
        _, expected_freq_idx = fhss_for_index(keys["fhss"], args.frequencies, fhss_index)

        if freq_index != expected_freq_idx or hop_idx != fhss_index:
            logging.warning(
                "FHSS mismatch | expected hop=%d freq_idx=%d | got hop=%d freq_idx=%d",
                fhss_index, expected_freq_idx, hop_idx, freq_index,
            )
            send_framed(conn, b"LOCKED")
            attempts += 1
            fhss_index += 1
            continue

        # ── All checks passed → UNLOCK ───────────────────────────────────
        logging.info(
            "🔓 CAR UNLOCKED | device=%s | hop=%d | counter=%d",
            tx_device_id.decode(errors="replace"),
            fhss_index,
            matched_counter,
        )
        send_framed(conn, b"UNLOCKED")
        return

    logging.warning("Max attempts exhausted from %s — closing", addr[0])


# ═══════════════════════════════════════════════════════════════════════════
# Server loop
# ═══════════════════════════════════════════════════════════════════════════

def run_server(args):
    logging.info("Receiver listening on %s:%d", args.host, args.port)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.host, args.port))
        s.listen()
        while True:
            conn, addr = s.accept()
            handle_client(conn, addr, args)


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(description="Key-fob receiver")
    p.add_argument("--host",        default="127.0.0.1")
    p.add_argument("--port",        type=int, default=65432)
    p.add_argument("--max-attempts",type=int, default=6)
    p.add_argument("--key-rotation-period", type=int, default=86400,
                   help="Epoch length in seconds for key rotation (default: 1 day)")
    p.add_argument("--frequencies", type=int, nargs="+", default=[
        902, 904, 906, 908, 910, 912, 914, 916, 918, 920,
        922, 924, 926, 928, 930, 932, 934, 936, 938, 940,
        942, 944, 946, 948, 950, 952, 954, 956, 958, 960,
    ])
    return p.parse_args()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s | RX | %(levelname)s | %(message)s",
        force=True,
    )
    run_server(parse_args())