"""
transmitter.py — Key-fob transmitter (TX side).

Improvements applied vs original:
  ① Certificate validation  : TX signs its X25519 pub with Ed25519 identity key;
                               verifies RX's Ed25519 signature before trusting its pub.
  ② Rate limiting           : TX backs off when the receiver signals rate-limit rejection.
  ③ Key rotation            : Session keys incorporate a daily epoch so they auto-rotate.
  ④ Device attestation      : TX sends a session-bound HMAC attestation tag after FIN
                               and verifies the RX's attestation before sending any MSG.
  ⑤ Rolling code verified   : TX packs the code; RX now also checks it (see receiver).
  ⑥ Counter desync window   : TX tracks its counter; RX uses verify_rolling_code_with_window.
  ⑦ HKDF salt fix           : salt = nonce_tx+nonce_rx; info = domain label.
  ⑧ TCP framing fix         : all messages use send_framed / recv_framed.
"""

import os
import socket
import logging
import argparse
import time
import hmac as _hmac

import common_fix
common_fix.init_env(".env.tx")  # load TX keys before anything else

from common_fix import (
    load_master_key,
    make_x25519_keypair,
    load_peer_pub,
    derive_session_keys_with_rotation,
    aead_encrypt,
    hmac_bytes,
    fhss_for_index,
    rolling_code_from_counter,
    sign_pub_key,
    verify_peer_pub_key,
    get_device_id,
    sign_attestation,
    verify_attestation,
    send_framed,
    recv_framed,
)

PROT_VERSION = b"\x02"          # bumped from v1 to reflect the new handshake


# ═══════════════════════════════════════════════════════════════════════════
# Handshake helpers
# ═══════════════════════════════════════════════════════════════════════════

def mutual_auth(sock, master_key: bytes, epoch: int) -> dict | None:
    """
    3-way authenticated key agreement:

      TX → RX : HELLO  pub_tx  nonce_tx  sig_tx  mac1
      RX → TX : ACK    pub_rx  nonce_rx  sig_rx  mac2
      TX → RX : FIN    fin_mac  attest_tx  device_id_tx
      RX → TX : OK     attest_rx  device_id_rx

    sig_*  = Ed25519 signature over (pub || nonce)  — certificate validation
    mac*   = HMAC-SHA256(master_key, role || pub_tx || nonce_tx || pub_rx || nonce_rx)
    attest = HMAC-SHA256(session_mac_key, "ATTEST" || device_id || session_nonce)
    """

    # ── Step 1: generate ephemeral X25519 key pair ──────────────────────
    priv_tx, pub_tx = make_x25519_keypair()
    nonce_tx        = os.urandom(16)

    # Sign our X25519 public key with our Ed25519 identity key
    sig_tx = sign_pub_key(pub_tx, nonce_tx)

    # HMAC over (HELLO || pub_tx || nonce_tx) with master key
    mac1 = hmac_bytes(master_key, b"HELLO" + pub_tx + nonce_tx)

    # ── Step 2: send HELLO ───────────────────────────────────────────────
    hello_payload = b"|".join([
        b"HELLO",
        pub_tx.hex().encode(),
        nonce_tx.hex().encode(),
        sig_tx.hex().encode(),
        mac1.hex().encode(),
    ])
    send_framed(sock, hello_payload)
    logging.debug("TX → RX : HELLO sent")

    # ── Step 3: receive ACK ──────────────────────────────────────────────
    ack_data = recv_framed(sock)
    if not ack_data.startswith(b"ACK|"):
        logging.error("Unexpected response to HELLO: %r", ack_data[:20])
        return None

    parts = ack_data.split(b"|")
    if len(parts) != 5:
        logging.error("Malformed ACK frame")
        return None

    _, pub_rx_hex, nonce_rx_hex, sig_rx_hex, mac2_hex = parts
    pub_rx   = bytes.fromhex(pub_rx_hex.decode())
    nonce_rx = bytes.fromhex(nonce_rx_hex.decode())
    sig_rx   = bytes.fromhex(sig_rx_hex.decode())
    mac2     = bytes.fromhex(mac2_hex.decode())

    # ── Step 4: certificate validation — verify RX's Ed25519 signature ──
    if not verify_peer_pub_key(pub_rx, nonce_rx, sig_rx):
        logging.error("RX pub key certificate validation FAILED")
        return None
    logging.info("RX certificate validated ✓")

    # ── Step 5: verify master-key HMAC on ACK ───────────────────────────
    expected_mac2 = hmac_bytes(
        master_key,
        b"ACK" + pub_rx + nonce_rx + pub_tx + nonce_tx,
    )
    if not _hmac.compare_digest(expected_mac2, mac2):
        logging.error("ACK master-key MAC verification FAILED")
        return None

    # ── Step 6: derive session keys (with epoch-based rotation) ─────────
    peer_pub = load_peer_pub(pub_rx)
    shared   = priv_tx.exchange(peer_pub)
    keys     = derive_session_keys_with_rotation(
        shared,
        salt=nonce_tx + nonce_rx,
        epoch=epoch,
    )
    logging.info("Session keys derived (epoch=%d) ✓", epoch)

    # ── Step 7: send FIN + device attestation ───────────────────────────
    session_nonce = nonce_tx + nonce_rx
    device_id     = get_device_id()
    fin_mac       = hmac_bytes(keys["mac"], b"FIN")
    attest_tx     = sign_attestation(keys["mac"], device_id, session_nonce)

    fin_payload = b"|".join([
        b"FIN",
        fin_mac.hex().encode(),
        attest_tx.hex().encode(),
        device_id.hex().encode(),
    ])
    send_framed(sock, fin_payload)
    logging.debug("TX → RX : FIN + attestation sent")

    # ── Step 8: receive OK + RX attestation ─────────────────────────────
    ok_data = recv_framed(sock)
    if not ok_data.startswith(b"OK|"):
        logging.error("Expected OK, got: %r", ok_data[:20])
        return None

    ok_parts = ok_data.split(b"|")
    if len(ok_parts) != 3:
        logging.error("Malformed OK frame")
        return None

    _, attest_rx_hex, rx_device_id_hex = ok_parts
    attest_rx    = bytes.fromhex(attest_rx_hex.decode())
    rx_device_id = bytes.fromhex(rx_device_id_hex.decode())

    # ── Step 9: verify RX device attestation ────────────────────────────
    if not verify_attestation(keys["mac"], rx_device_id, session_nonce, attest_rx):
        logging.error("RX device attestation FAILED — possible MITM")
        return None
    logging.info(
        "RX device attestation verified ✓  (device_id=%s)",
        rx_device_id.decode(errors="replace"),
    )

    return keys


# ═══════════════════════════════════════════════════════════════════════════
# Main TX loop
# ═══════════════════════════════════════════════════════════════════════════

def run_tx(args):
    master_key = load_master_key()
    logging.info("Master key loaded ✓")

    epoch = int(time.time()) // args.key_rotation_period
    logging.info("Key-rotation epoch: %d", epoch)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10.0)
        s.connect((args.host, args.port))
        logging.info("Connected to receiver %s:%d", args.host, args.port)

        keys = mutual_auth(s, master_key, epoch)
        if not keys:
            logging.error("Mutual authentication failed — aborting")
            return
        logging.info("Mutual authentication complete ✓")

        tx_counter = 0
        fhss_index = 0
        retry_delay = args.retry_delay

        for attempt in range(1, args.max_attempts + 1):
            code     = rolling_code_from_counter(keys["roll"], tx_counter)
            _, f_idx = fhss_for_index(keys["fhss"], args.frequencies, fhss_index)

            # Plaintext layout:
            #   [0:6]   rolling code (ASCII decimal, zero-padded)
            #   [6:10]  frequency list index (4-byte big-endian)
            #   [10:14] fhss_index / hop counter (4-byte big-endian)
            plaintext = (
                f"{code:06d}".encode()
                + f_idx.to_bytes(4, "big")
                + fhss_index.to_bytes(4, "big")
            )

            nonce, ciphertext = aead_encrypt(keys["aead"], PROT_VERSION, plaintext)

            pkt = b"|".join([
                b"MSG",
                nonce.hex().encode(),
                ciphertext.hex().encode(),
            ])
            send_framed(s, pkt)
            logging.debug(
                "Attempt %d/%d | counter=%d | hop=%d | freq_idx=%d",
                attempt, args.max_attempts, tx_counter, fhss_index, f_idx,
            )

            response = recv_framed(s)

            if response == b"UNLOCKED":
                logging.info("🔓 CAR UNLOCKED (attempt %d)", attempt)
                return

            if response == b"RATE_LIMITED":
                # Back off when the receiver signals rate limiting
                retry_delay = min(retry_delay * 2, 30.0)
                logging.warning(
                    "Rate limited by receiver — backing off to %.1fs", retry_delay
                )
            elif response == b"LOCKED":
                retry_delay = args.retry_delay   # reset on normal rejection
                logging.debug("Attempt %d rejected (LOCKED)", attempt)
            else:
                logging.warning("Unknown response: %r", response)

            tx_counter += 1
            fhss_index += 1
            time.sleep(retry_delay)

        logging.warning("Max attempts reached — giving up")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(description="Key-fob transmitter")
    p.add_argument("--host",        default="127.0.0.1")
    p.add_argument("--port",        type=int, default=65432)
    p.add_argument("--max-attempts",type=int, default=6)
    p.add_argument("--retry-delay", type=float, default=0.2,
                   help="Initial delay between attempts (seconds)")
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
        format="%(asctime)s | TX | %(levelname)s | %(message)s",
        force=True,
    )
    run_tx(parse_args())