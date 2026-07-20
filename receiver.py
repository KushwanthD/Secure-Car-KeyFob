"""
receiver.py - Key-fob receiver (RX / car side).

Improvements applied vs original:
  1. Certificate validation  : RX verifies TX's Ed25519 signature before trusting its X25519 pub;
                               RX also signs its own pub so TX can verify.
  2. Rate limiting (Failure) : ONLY triggers after 5 failed authentication attempts from an IP.
                               A successful unlock/lock attempt resets the failure count to 0.
  3. Key rotation            : Session keys incorporate the same daily epoch as TX.
  4. Device attestation      : RX verifies TX attestation and sends its own.
  5. Rolling code verified   : Receiver now actually checks the rolling code value.
  6. Counter desync window   : Uses verify_rolling_code_with_window (256) like KeeLoq.
  7. HKDF salt fix           : salt = nonce_tx+nonce_rx; info = domain label.
  8. TCP framing fix         : all messages use send_framed / recv_framed.
  9. Dynamic Port Hopping     : dynamic socket re-binding to time-synchronized ports (5s epoch).
  10. Counter Persistence      : state saved to receiver_state.json mapping counters by device ID.
  11. Global Nonce Cache      : thread-safe global set protects against multi-session replays.
  12. Clock Skew Tolerance    : checks adjacent key-rotation epochs to avoid DoS on boundaries.
  13. Multi-threaded Server    : concurrent handling of client connections prevents blocking.
  14. Toggle State (Lock/Unlock): toggles between LOCKED and UNLOCKED states upon valid command.
  15. Clean UI                 : suppressed recurring bind/close statements in standard log output.
"""

import os
import socket
import logging
import argparse
import hmac as _hmac
import time
import threading

import common_fix
common_fix.init_env(".env.rx")  # load RX keys before anything else

from common_fix import (
    load_master_key,
    make_x25519_keypair,
    load_peer_pub,
    derive_session_keys_with_rotation,
    aead_encrypt,
    aead_decrypt,
    hmac_bytes,
    fhss_for_index,
    verify_rolling_code_with_window,
    sign_pub_key,
    verify_peer_pub_key,
    get_device_id,
    sign_attestation,
    verify_attestation,
    send_framed,
    recv_framed,
    get_hop_epoch,
    derive_hop_port_and_freq,
    load_state_file,
    save_state_file,
)
from cryptography.exceptions import InvalidTag

PROT_VERSION = b"\x02"
MASTER_KEY: bytes | None = None

# Global state for persistence, replay protection, and thread-safety
STATE_FILE = "receiver_state.json"
state_lock = threading.Lock()
seen_nonces = set()
seen_nonces_lock = threading.Lock()

# Failure-based Rate Limiter State
fail_tracker = {}
fail_lock = threading.Lock()
PENALTY_COOLDOWN = 10.0 # block for 10 seconds after failures
MAX_FAILURES = 5


def is_ip_rate_limited(ip: str) -> bool:
    """Check if the IP is blocked due to too many recent failures."""
    with fail_lock:
        fail_count, last_fail_time = fail_tracker.get(ip, (0, 0.0))
        if fail_count >= MAX_FAILURES:
            # Check if cooldown has elapsed
            if time.time() - last_fail_time < PENALTY_COOLDOWN:
                return True
            else:
                # Cooldown elapsed, reset failures
                fail_tracker[ip] = (0, 0.0)
        return False


def record_failure(ip: str):
    """Record a failed handshake/authentication attempt."""
    with fail_lock:
        fail_count, _ = fail_tracker.get(ip, (0, 0.0))
        fail_tracker[ip] = (fail_count + 1, time.time())
        logging.warning("Failure recorded for %s (count=%d/%d)", ip, fail_count + 1, MAX_FAILURES)


def record_success(ip: str):
    """Reset the failure count on successful authentication."""
    with fail_lock:
        if ip in fail_tracker:
            fail_tracker[ip] = (0, 0.0)


def get_persisted_counter(device_id: str) -> int:
    """Read the last verified counter for a given device ID from persistent storage."""
    with state_lock:
        state = load_state_file(STATE_FILE)
        return state.get("counters", {}).get(device_id, 0)


def save_persisted_counter(device_id: str, counter: int) -> None:
    """Save the updated counter for a given device ID to persistent storage."""
    with state_lock:
        state = load_state_file(STATE_FILE)
        if "counters" not in state:
            state["counters"] = {}
        state["counters"][device_id] = counter
        save_state_file(STATE_FILE, state)


def toggle_car_state() -> str:
    """Toggle the persistent state of the car between LOCKED and UNLOCKED."""
    with state_lock:
        state = load_state_file(STATE_FILE)
        current = state.get("car_state", "LOCKED")
        new_state = "UNLOCKED" if current == "LOCKED" else "LOCKED"
        state["car_state"] = new_state
        save_state_file(STATE_FILE, state)
        return new_state


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------

def handle_client(conn, addr, args, hop_epoch):
    global MASTER_KEY

    peer_ip = addr[0]
    conn.settimeout(10.0)

    # -- Failure-based Rate Limiting --------------------------------------
    if is_ip_rate_limited(peer_ip):
        logging.warning("Connection dropped: IP %s is temporarily blocked due to too many failed attempts.", peer_ip)
        try:
            send_framed(conn, b"RATE_LIMITED")
        except Exception:
            pass
        conn.close()
        return

    if MASTER_KEY is None:
        MASTER_KEY = load_master_key()

    logging.info("Connection received from %s", peer_ip)

    try:
        success = _handle_authenticated_session(conn, addr, args, active_port=None, hop_epoch=hop_epoch)
        if success:
            record_success(peer_ip)
        else:
            record_failure(peer_ip)
    except (ConnectionError, ValueError, TimeoutError) as exc:
        logging.error("Session error from %s: %s", peer_ip, exc)
        record_failure(peer_ip)
    finally:
        conn.close()


def _handle_authenticated_session(conn, addr, args, active_port, hop_epoch):
    """Run the full handshake + message loop for one connection."""
    global seen_nonces

    epoch = int(time.time()) // args.key_rotation_period
    
    # Calculate active port if not passed (used for logging success)
    if active_port is None:
        active_port, _ = derive_hop_port_and_freq(MASTER_KEY, hop_epoch)

    # -- Step 1: receive HELLO --------------------------------------------
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

    # -- Step 2: certificate validation - verify TX's Ed25519 sig --------
    if not verify_peer_pub_key(pub_tx, nonce_tx, sig_tx):
        logging.error("TX pub key certificate validation FAILED from %s", addr[0])
        raise ValueError("TX certificate invalid")

    # -- Step 3: verify master-key HMAC on HELLO --------------------------
    if not _hmac.compare_digest(
        hmac_bytes(MASTER_KEY, b"HELLO" + pub_tx + nonce_tx),
        mac1,
    ):
        logging.error("HELLO master-key MAC invalid from %s", addr[0])
        raise ValueError("HELLO MAC invalid")

    # -- Step 4: generate RX ephemeral key pair + sign it -----------------
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

    # -- Step 5: derive session keys --------------------------------------
    peer_pub = load_peer_pub(pub_tx)
    shared   = priv_rx.exchange(peer_pub)

    # -- Step 6: receive FIN + TX attestation ----------------------------
    fin_data = recv_framed(conn)
    if not fin_data.startswith(b"FIN|"):
        raise ValueError("Expected FIN frame")

    fin_parts = fin_data.split(b"|")
    if len(fin_parts) != 5:
        raise ValueError("Malformed FIN frame")

    _, fin_mac_hex, attest_tx_hex, enc_did_hex, enc_nonce_hex = fin_parts
    fin_mac      = bytes.fromhex(fin_mac_hex.decode())
    attest_tx    = bytes.fromhex(attest_tx_hex.decode())
    enc_did      = bytes.fromhex(enc_did_hex.decode())
    enc_nonce    = bytes.fromhex(enc_nonce_hex.decode())

    # Try current, previous, and next rotation epoch to account for clock skew
    keys = None
    for epoch_offset in (0, -1, 1):
        candidate_epoch = epoch + epoch_offset
        candidate_keys = derive_session_keys_with_rotation(
            shared,
            salt=nonce_tx + nonce_rx,
            epoch=candidate_epoch,
        )
        expected_fin_mac = hmac_bytes(candidate_keys["mac"], b"FIN")
        if _hmac.compare_digest(expected_fin_mac, fin_mac):
            keys = candidate_keys
            break

    if not keys:
        logging.error("FIN MAC invalid from %s (attempted epoch offsets: 0, -1, 1)", addr[0])
        raise ValueError("FIN MAC invalid")

    # Decrypt TX Device ID using the derived session key
    try:
        tx_device_id = aead_decrypt(keys["aead"], b"TX_DID", enc_nonce, enc_did)
    except Exception:
        logging.error("Failed to decrypt TX device ID from %s", addr[0])
        raise ValueError("TX device ID decryption failed")

    # Verify TX device attestation
    session_nonce = nonce_tx + nonce_rx
    if not verify_attestation(keys["mac"], tx_device_id, session_nonce, attest_tx):
        logging.error("TX device attestation FAILED from %s", addr[0])
        raise ValueError("TX attestation invalid")
    logging.info(
        "Device authenticated successfully (device_id=%s)",
        tx_device_id.decode(errors="replace"),
    )

    # -- Step 7: send OK + RX attestation (encrypted device ID) ----------
    rx_device_id = get_device_id()
    enc_rx_nonce, enc_rx_did = aead_encrypt(keys["aead"], b"RX_DID", rx_device_id)
    attest_rx    = sign_attestation(keys["mac"], rx_device_id, session_nonce)

    ok_payload = b"|".join([
        b"OK",
        attest_rx.hex().encode(),
        enc_rx_did.hex().encode(),
        enc_rx_nonce.hex().encode(),
    ])
    send_framed(conn, ok_payload)

    # -- Step 8: message loop ---------------------------------------------
    tx_device_id_str = tx_device_id.decode(errors="replace")
    
    # Load counter dynamically from persistent state
    tx_counter = get_persisted_counter(tx_device_id_str)
    attempts       = 0

    while attempts < args.max_attempts:
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

        # -- Replay protection: nonce uniqueness (using thread-safe global set) --
        with seen_nonces_lock:
            if nonce in seen_nonces:
                logging.warning("Replay detected (duplicate nonce) from %s", addr[0])
                send_framed(conn, b"LOCKED")
                attempts += 1
                continue
            seen_nonces.add(nonce)

        # -- Decrypt ------------------------------------------------------
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

        # -- Parse plaintext ----------------------------------------------
        received_code = int(plain[0:6].decode())
        freq_index    = int.from_bytes(plain[6:10],  "big")
        hop_idx       = int.from_bytes(plain[10:14], "big")

        # -- Rolling code verification with desync window --------------
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
            
        # Advance counter past the matched value and persist it
        tx_counter = matched_counter + 1
        save_persisted_counter(tx_device_id_str, tx_counter)

        # ── ② FHSS channel verification ──────────────────────────────────
        _, expected_freq_idx = fhss_for_index(keys["fhss"], args.frequencies, hop_idx)

        if freq_index != expected_freq_idx:
            logging.warning(
                "FHSS mismatch | expected freq_idx=%d | got freq_idx=%d for hop=%d",
                expected_freq_idx, freq_index, hop_idx,
            )
            send_framed(conn, b"LOCKED")
            attempts += 1
            continue

        # -- All checks passed -> Toggle State and return response --------
        new_state = toggle_car_state()
        freq_mhz = args.frequencies[freq_index] if freq_index < len(args.frequencies) else 902
        logging.info(
            "SUCCESS: Car state toggled to %s [device=%s | hop=%d | counter=%d | freq_idx=%d | freq=%d MHz | port=%d]",
            new_state,
            tx_device_id_str,
            hop_idx,
            matched_counter,
            freq_index,
            freq_mhz,
            active_port,
        )
        send_framed(conn, f"STATE:{new_state}".encode())
        return True

    logging.warning("Max attempts exhausted from %s - closing", addr[0])
    return False


# ---------------------------------------------------------------------------
# Server loop
# ---------------------------------------------------------------------------

def accept_connections(sock, hop_epoch, args):
    """Loop to accept clients on a specific bound socket."""
    while True:
        try:
            conn, addr = sock.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, args, hop_epoch),
                daemon=True
            )
            t.start()
        except socket.timeout:
            # Check if socket was closed (fileno == -1)
            if sock.fileno() == -1:
                break
        except Exception:
            break


def run_server(args):
    global MASTER_KEY
    if MASTER_KEY is None:
        MASTER_KEY = load_master_key()

    logging.info("Receiver listening and active. Dynamic port-hopping active (5s window)...")
    
    current_sockets = {}  # hop_epoch -> socket
    
    try:
        while True:
            # Listen on current epoch and next epoch for seamless handover (5 second period)
            now_epoch = get_hop_epoch(5)
            epochs_to_listen = [now_epoch, now_epoch + 1]
            
            # Close sockets for expired epochs
            for epoch in list(current_sockets.keys()):
                if epoch not in epochs_to_listen:
                    logging.debug("Closing listener socket for expired hop_epoch %d", epoch)
                    sock = current_sockets.pop(epoch)
                    try:
                        sock.close()
                    except Exception:
                        pass
            
            # Start new listeners
            for epoch in epochs_to_listen:
                if epoch not in current_sockets:
                    port, freq_idx = derive_hop_port_and_freq(MASTER_KEY, epoch)
                    logging.debug("Binding listener for hop_epoch %d to port %d (freq_idx %d)", epoch, port, freq_idx)
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        sock.bind((args.host, port))
                        sock.listen()
                        sock.settimeout(1.0)
                        current_sockets[epoch] = sock
                        
                        t = threading.Thread(
                            target=accept_connections,
                            args=(sock, epoch, args),
                            daemon=True
                        )
                        t.start()
                    except Exception as e:
                        logging.debug("Failed to bind hop_epoch %d to port %d: %s", epoch, port, e)
            
            time.sleep(1.0)
    except KeyboardInterrupt:
        logging.info("Receiver shutting down...")
    finally:
        for sock in current_sockets.values():
            try:
                sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Key-fob receiver")
    p.add_argument("--host",        default="127.0.0.1")
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
        level=logging.INFO,
        format="%(asctime)s | RX | %(message)s",
        force=True,
    )
    run_server(parse_args())