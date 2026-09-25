#!/usr/bin/env python3
"""Test Step 3: Correlation Engine with time-window aggregation and multi-entity correlation."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import time
import json
from correlation import (
    _map_evidence_to_mitre,
    _deduplicate_evidence,
    _correlate_entities,
    evaluate_correlation,
    DEFAULT_WINDOW_SECONDS
)
from storage import add_pheromone, get_pheromones_snapshot
import logging

logging.basicConfig(level=logging.INFO, format='%(name)s - %(levelname)s - %(message)s')

print("=" * 80)
print("TEST: Step 3 — Correlation Engine with Time-Window Aggregation")
print("=" * 80)

# Test 1: MITRE Mapping (Expanded)
print("\n[TEST 1] MITRE Mapping — Expanded keyword matching")
print("-" * 80)

evidence_creds = [
    {"type": "login_attempt", "text": "3 failed password attempts", "source": "honeypot"},
    {"type": "credential", "text": "user@example.com", "source": "detector"}
]

evidence_lateral = [
    {"type": "network", "text": "RDP probe on port 3389", "source": "honeypot"}
]

evidence_phish = [
    {"type": "link", "text": "http://fake-paypal.com", "source": "honeypot"},
    {"type": "email", "text": "urgent account verification needed", "source": "detector"}
]

print(f"Credentials evidence: {_map_evidence_to_mitre(evidence_creds)}")
assert "T1556" in _map_evidence_to_mitre(evidence_creds), "Should detect credential technique"

print(f"Lateral movement evidence: {_map_evidence_to_mitre(evidence_lateral)}")
assert "T1021" in _map_evidence_to_mitre(evidence_lateral), "Should detect lateral movement"

print(f"Phishing evidence: {_map_evidence_to_mitre(evidence_phish)}")
assert "T1566" in _map_evidence_to_mitre(evidence_phish), "Should detect phishing"

print("✓ MITRE mapping working correctly")

# Test 2: Evidence Deduplication
print("\n[TEST 2] Evidence Deduplication")
print("-" * 80)

evidence_with_dupes = [
    {"type": "phishing_link", "text": "http://fake.com", "source": "honeypot"},
    {"type": "phishing_link", "text": "http://fake.com", "source": "honeypot"},  # Duplicate
    {"type": "upi_id", "text": "attacker@axis", "source": "detector"},
    {"type": "upi_id", "text": "attacker@axis", "source": "detector"},  # Duplicate
    {"type": "bank_account", "text": "9876543210", "source": "honeypot"},
]

deduped = _deduplicate_evidence(evidence_with_dupes)
print(f"Input: {len(evidence_with_dupes)} items")
print(f"Output: {len(deduped)} items (deduplicated)")
assert len(deduped) == 3, "Should have exactly 3 unique items"
print("✓ Deduplication working correctly")

# Test 3: Multi-Entity Correlation (Time-Window based)
print("\n[TEST 3] Multi-Entity Correlation — Time-window grouping")
print("-" * 80)

base_time = time.time()

# Create multi-entity scenario: IP + User + Domain all with shared evidence in same window
phishing_evidence = [
    {"type": "phishing_link", "text": "http://malicious.com", "source": "detector"}
]

# IP shows phishing link
add_pheromone("ip", "192.168.1.1", 50.0, phishing_evidence, ts=base_time)

# User clicked that same link
add_pheromone("user", "victim@company.com", 45.0, phishing_evidence, ts=base_time + 2)

# Domain is malicious
add_pheromone("domain", "malicious.com", 55.0, phishing_evidence, ts=base_time + 1)

pheromones = get_pheromones_snapshot()
print(f"Generated {len(pheromones)} pheromones within {DEFAULT_WINDOW_SECONDS}s window")

clusters = _correlate_entities(pheromones, DEFAULT_WINDOW_SECONDS)
print(f"Correlated into {len(clusters)} cluster(s)")

for entity_set, cluster in clusters:
    if len(cluster) > 1:
        print(f"  Cluster: {entity_set}")
        print(f"    Entities: {len(cluster)}")
        print(f"    Avg score: {sum(p['score'] for p in cluster) / len(cluster):.1f}")
        print(f"    Shared evidence: {len(cluster[0].get('evidence', []))}")

assert len(clusters) > 0, "Should have at least one cluster"
print("✓ Multi-entity correlation working correctly")

# Test 4: Incident Creation with Aggregated Scoring
print("\n[TEST 4] Incident Creation with Time-Window Aggregation")
print("-" * 80)

# Use a fresh test by just adding new pheromones with high scores
import storage as storage_module
storage_module._pheromones.clear()  # Clear in-memory pheromones

base_time = time.time()

# Simulate coordinated attack: multiple entities with escalating scores
evidence_payload = [
    {"type": "phishing_link", "text": "http://phish.net", "source": "honeypot"},
    {"type": "device_fingerprint", "text": "Device A", "source": "detector"},
]

# Entity 1: IP with initial score
add_pheromone("ip", "10.1.1.1", 40.0, evidence_payload[:1], ts=base_time)

# Entity 2: Same user different time but shared evidence
add_pheromone("user", "alice@corp.com", 50.0, evidence_payload, ts=base_time + 1)

# Entity 3: Malware detected (higher score)
add_pheromone("process", "malware.exe", 70.0, evidence_payload[:1], ts=base_time + 2)

print(f"Pheromones created: {len(get_pheromones_snapshot())}")

incidents = evaluate_correlation(create_threshold=55.0, window_seconds=DEFAULT_WINDOW_SECONDS)
print(f"Incidents created: {len(incidents)}")

for inc in incidents:
    print(f"  Incident #{inc['id']}:")
    print(f"    Score: {inc['score']:.1f}")
    print(f"    Entities: {len(inc['entities'])}")
    print(f"    MITRE: {inc.get('mitre', [])}")
    print(f"    Type: {inc.get('correlation_type', 'unknown')}")

assert len(incidents) > 0, "Should create incidents when score exceeds threshold"
print("✓ Incident creation working correctly")

# Test 5: Threshold Testing (single-entity)
print("\n[TEST 5] Threshold Testing — Below and above threshold")
print("-" * 80)

# Clear pheromones for fresh test
storage_module._pheromones.clear()

# Add pheromone below threshold
add_pheromone("ip", "10.2.2.2", 30.0, [], ts=time.time())

# Evaluate with threshold 60
incidents_low = evaluate_correlation(create_threshold=60.0)
print(f"Score 30 with threshold 60: {len(incidents_low)} incidents (expected 0)")
assert len(incidents_low) == 0, "Should not create incident below threshold"

# Add another pheromone above threshold
add_pheromone("ip", "10.2.2.3", 75.0, [], ts=time.time())

incidents_high = evaluate_correlation(create_threshold=60.0)
print(f"Added score 75: {len(incidents_high)} incidents (expected 1)")
assert len(incidents_high) == 1, "Should create incident above threshold"

print("✓ Threshold testing working correctly")

print("\n" + "=" * 80)
print("✓ ALL TESTS PASSED — Step 3 Complete")
print("=" * 80)
