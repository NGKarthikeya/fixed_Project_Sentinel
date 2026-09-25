#!/usr/bin/env python3
"""Test Step 2: Detector integration with swarm pheromone publishing."""

import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detectors import reset_detector_state, run_detectors, ZScoreDetector, FrequencyDetector, SequenceDetector
from schemas import Evidence, TelemetryEvent
from swarm import publish_pheromone
import logging

logging.basicConfig(level=logging.INFO, format='%(name)s - %(levelname)s - %(message)s')

print("=" * 80)
print("TEST: Step 2 — Detector Integration with Pheromone Publishing")
print("=" * 80)

# Test 1: ZScoreDetector
print("\n[TEST 1] ZScoreDetector — Anomaly on drift from mean")
print("-" * 80)
reset_detector_state()

# Build up history with consistent scores, then add outlier
event1 = {
    "entity_type": "ip",
    "entity_id": "192.168.1.1",
    "score": 15.0,
    "evidence": [],
    "ts": 1000.0
}

event2 = {
    "entity_type": "ip",
    "entity_id": "192.168.1.1",
    "score": 15.0,
    "evidence": [],
    "ts": 1001.0
}

event3 = {
    "entity_type": "ip",
    "entity_id": "192.168.1.1",
    "score": 16.0,
    "evidence": [],
    "ts": 1002.0
}

event4 = {
    "entity_type": "ip",
    "entity_id": "192.168.1.1",
    "score": 95.0,  # Outlier: way above mean (~15.3)
    "evidence": [],
    "ts": 1003.0
}

print(f"Event 1 (score=15): {run_detectors(event1)['signals'][0]['reason']}")
print(f"Event 2 (score=15): {run_detectors(event2)['signals'][0]['reason']}")
print(f"Event 3 (score=16): {run_detectors(event3)['signals'][0]['reason']}")
result4 = run_detectors(event4)
print(f"Event 4 (score=95): {result4['signals'][0]['reason']}")
print(f"  -> Z-score delta: {result4['total_delta']:.1f} (should be > 0)")
assert result4['total_delta'] > 0, "ZScoreDetector should detect outlier!"
print("✓ ZScoreDetector working correctly")

# Test 2: FrequencyDetector
print("\n[TEST 2] FrequencyDetector — Persistence pattern")
print("-" * 80)
reset_detector_state()

freq_event1 = {
    "entity_type": "user",
    "entity_id": "attacker@gmail.com",
    "score": 25.0,
    "evidence": [
        {"type": "phishing_link", "text": "http://fake-bank.com", "source": "honeypot"},
    ],
    "ts": 1000.0
}

freq_event2 = {
    "entity_type": "user",
    "entity_id": "attacker@gmail.com",
    "score": 30.0,
    "evidence": [
        {"type": "phishing_link", "text": "http://fake-bank.com", "source": "honeypot"},
        {"type": "upi_id", "text": "attacker@okhdfcbank", "source": "honeypot"},
    ],
    "ts": 1001.0
}

print(f"Event 1 (first appearance): {run_detectors(freq_event1)['signals'][1]['reason']}")
result2 = run_detectors(freq_event2)
print(f"Event 2 (repeat with more evidence): {result2['signals'][1]['reason']}")
print(f"  → Frequency delta: {result2['total_delta']:.1f} (should be > 0)")
assert result2['total_delta'] > 0, "FrequencyDetector should detect persistence!"
print("✓ FrequencyDetector working correctly")

# Test 3: SequenceDetector
print("\n[TEST 3] SequenceDetector — Multi-faceted behavior")
print("-" * 80)
reset_detector_state()

seq_event1 = {
    "entity_type": "conversation",
    "entity_id": "conv_12345",
    "score": 40.0,
    "evidence": [
        {"type": "message_text", "text": "Send money to my UPI", "source": "honeypot"},
    ],
    "ts": 1000.0
}

seq_event2 = {
    "entity_type": "conversation",
    "entity_id": "conv_12345",
    "score": 50.0,
    "evidence": [
        {"type": "upi_id", "text": "attacker@axis", "source": "honeypot"},
        {"type": "bank_account", "text": "9876543210", "source": "honeypot"},
    ],
    "ts": 1001.0
}

seq_event3 = {
    "entity_type": "conversation",
    "entity_id": "conv_12345",
    "score": 60.0,
    "evidence": [
        {"type": "phishing_link", "text": "http://fake-otp.com", "source": "honeypot"},
        {"type": "device_fingerprint", "text": "chrome-windows", "source": "honeypot"},
        {"type": "geoip", "text": "Nigeria", "source": "honeypot"},
    ],
    "ts": 1002.0
}

print(f"Event 1 (1 type): {run_detectors(seq_event1)['signals'][2]['reason']}")
print(f"Event 2 (2 types): {run_detectors(seq_event2)['signals'][2]['reason']}")
result3 = run_detectors(seq_event3)
print(f"Event 3 (4 types = multi-faceted): {result3['signals'][2]['reason']}")
print(f"  → Sequence delta: {result3['total_delta']:.1f} (should be > 0)")
assert result3['total_delta'] > 0, "SequenceDetector should detect multi-faceted behavior!"
print("✓ SequenceDetector working correctly")

# Test 4: Integration with swarm.publish_pheromone
print("\n[TEST 4] Integration: Detector signals in pheromone publishing")
print("-" * 80)
reset_detector_state()

# Simulate a telemetry event through the full pipeline
telemetry_dict = {
    "entity_type": "ip",
    "entity_id": "10.0.0.50",
    "score": 35.0,
    "evidence": [
        {"type": "failed_login", "text": "5 attempts", "source": "honeypot"},
        {"type": "phishing_link", "text": "http://malicious.com", "source": "honeypot"},
    ],
    "ts": 2000.0
}

# Send multiple events to build up history
for i, base_score in enumerate([15, 18, 20, 75]):  # Last one is outlier
    event = {
        "entity_type": "ip",
        "entity_id": "10.0.0.50",
        "score": base_score,
        "evidence": telemetry_dict["evidence"][:1],
        "ts": 2000.0 + i
    }
    result = publish_pheromone(event)
    if i == 3:
        print(f"Event {i+1} (score={base_score} — outlier):")
        print(f"  Base score: {result['published']['base_score']}")
        print(f"  Detector delta: +{result['published']['detector_delta']:.1f}")
        print(f"  Enriched score: {result['published']['enriched_score']:.1f}")
        print(f"  Signals: {len(result['published']['detector_signals'])} detected")
        for sig in result['published']['detector_signals']:
            if sig.get('score_delta', 0) > 0:
                print(f"    > {sig['signal_type']}: +{sig['score_delta']:.1f}")
        assert result['published']['enriched_score'] > result['published']['base_score'], \
            "Enriched score should be higher than base score!"

print("✓ Pheromone publishing with detector enrichment working correctly")

print("\n" + "=" * 80)
print("✓ ALL TESTS PASSED — Step 2 Complete")
print("=" * 80)
