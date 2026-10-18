"""
simulate_attacks.py - Live Demonstration Script for Sentinel AI Threat Layer

Simulates and evaluates live metadata profiles:
  1. Normal Owner Unlocks (Fast RTT, clean counters, 0 hops)
  2. Relay Attacks (Simulated forwarding latency & RF jitter)
  3. Brute Force Flooding (Rapid failed handshakes & high failure rates)
  4. Jamming Attacks (Forced channel frequency hops & packet loss retries)
  5. RollJam Attacks (Prior jammed attempts followed by counter desync jump)

Run this during hackathon demos to demonstrate AI defense-in-depth in action!
"""

import time
from sentinel import get_sentinel

def print_banner():
    print("=" * 80)
    print("      SENTINEL AI THREAT LAYER - LIVE ATTACK DETECTION DEMONSTRATION")
    print("   Defense-in-Depth Anomaly Detection & Attack Classification for Key Fobs")
    print("=" * 80)


def run_test_case(name: str, device_id: str, telemetry: dict):
    sentinel = get_sentinel()
    print(f"\n[>>>] Simulating Scenario: {name}")
    print(f"      Device ID       : {device_id}")
    print(f"      Latency (RTT)   : {telemetry.get('duration_ms', 0):.1f} ms")
    print(f"      Jitter          : {telemetry.get('jitter_ms', 0):.1f} ms")
    print(f"      Failure Rate    : {telemetry.get('failure_rate', 0)}")
    print(f"      Counter Gap     : {telemetry.get('counter_gap', 0)}")
    print(f"      FHSS Hop Count  : {telemetry.get('hop_count', 0)}")
    print(f"      Attempts Needed : {telemetry.get('attempts_needed', 1)}")

    # Time execution of AI evaluation
    t0 = time.perf_counter()
    result = sentinel.evaluate_session(device_id, telemetry)
    eval_latency_ms = (time.perf_counter() - t0) * 1000.0

    risk = result["risk_score"]
    level = result["level"]
    action = result["action"]
    attack_type = result["attack_type"]
    confidence = result["confidence"]
    reasons = result["explanations"]

    # Display formatting with visual indicators
    if level == "LOW":
        badge = "[LOW RISK - ALLOWED]"
    elif level == "MEDIUM":
        badge = "[MEDIUM RISK - ADAPTIVE CHALLENGE]"
    else:
        badge = "[HIGH RISK - BLOCKED / ELEVATED DEFENSE]"

    print(f"      Outcome         : {badge}")
    print(f"      Classified Type : {attack_type} (Confidence: {confidence * 100:.1f}%)")
    print(f"      Risk Score      : {risk:.3f} / 1.000")
    print(f"      Action Taken    : {action}")
    print(f"      Inference Time  : {eval_latency_ms:.2f} ms")
    print(f"      Reasoning       : {reasons[0] if reasons else 'Normal'}")


def main():
    print_banner()

    # Scenario 1: Normal Authorized Owner Unlock
    run_test_case(
        name="Legitimate Owner Unlock (Baseline)",
        device_id="TX-OWNER-KEYFOB",
        telemetry={
            "duration_ms": 17.5,
            "jitter_ms": 2.1,
            "failure_rate": 0,
            "counter_gap": 0,
            "hop_count": 0,
            "attempts_needed": 1,
        }
    )

    # Scenario 2: Relay Attack (Forwarding over long-range tunnel)
    run_test_case(
        name="Relay Attack (Amplifier Tunnel - Added 420ms Latency & High Jitter)",
        device_id="TX-RELAY-ATTACK",
        telemetry={
            "duration_ms": 445.0, # Excessive delay introduced by relay hardware
            "jitter_ms": 92.4,
            "failure_rate": 0,
            "counter_gap": 0,
            "hop_count": 0,
            "attempts_needed": 1,
        }
    )

    # Scenario 3: Brute Force Attempt
    run_test_case(
        name="Brute Force Attack (Rapid Burst of Invalid Cryptographic Attempts)",
        device_id="TX-BRUTE-ATTACK",
        telemetry={
            "duration_ms": 22.0,
            "jitter_ms": 6.8,
            "failure_rate": 7, # 7 failures in sliding window
            "counter_gap": 15,
            "hop_count": 0,
            "attempts_needed": 4,
        }
    )

    # Scenario 4: RF Jamming Attack
    run_test_case(
        name="Active RF Jamming Attack (Multiple FHSS Channel Drops & Retries)",
        device_id="TX-JAMMED-VICTIM",
        telemetry={
            "duration_ms": 135.0,
            "jitter_ms": 24.5,
            "failure_rate": 0,
            "counter_gap": 0,
            "hop_count": 4, # 4 frequency hops required
            "attempts_needed": 5,
        }
    )

    # Scenario 5: RollJam Attack (Samy Kamkar technique)
    run_test_case(
        name="RollJam Attack (Preceding Jammed Failures + Stolen Counter Skip)",
        device_id="TX-ROLLJAM-ATTACK",
        telemetry={
            "duration_ms": 32.0,
            "jitter_ms": 9.2,
            "failure_rate": 2, # Prior failed attempts from jammed victim press
            "counter_gap": 5, # 5 counters skipped
            "hop_count": 0,
            "attempts_needed": 1,
        }
    )

    print("\n" + "=" * 80)
    print(" [+] Sentinel AI successfully evaluated all attack vectors in real-time.")
    print(" [+] Cryptographic gates remain the primary security boundary;")
    print("     Sentinel dynamically monitors and tightens defenses against behavioral anomalies.")
    print("=" * 80)


if __name__ == "__main__":
    main()
