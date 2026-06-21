#!/usr/bin/env python3
"""
Simple Test for Post-Quantum TLS 1.3 Handshake Simulator
QuantumCrypt-AI - June 2026
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_tls13_handshake_simulator_2026_june import (
    TLS13HandshakeSimulator,
    TLS13HandshakeState,
    PQCipherSuite,
    PQKeyExchangeMode,
    KyberKEMSimulator,
    DilithiumSignatureSimulator
)

def test_kyber():
    print("Testing Kyber KEM...")
    for level in [512, 768, 1024]:
        kem = KyberKEMSimulator(level)
        pk, sk = kem.keygen()
        ss1, ct = kem.encaps(pk)
        ss2 = kem.decaps(ct, sk)
        if ss1 != ss2:
            print(f"  FAILED: Kyber-{level}")
            return False
        print(f"  Kyber-{level}: OK (pk={len(pk)}, ct={len(ct)})")
    return True

def test_dilithium():
    print("Testing Dilithium...")
    dil = DilithiumSignatureSimulator()
    pk, sk = dil.keygen()
    msg = b"Test message"
    sig = dil.sign(msg, sk)
    if not dil.verify(msg, sig, pk):
        print("  FAILED: Signature verification")
        return False
    print(f"  Dilithium: OK (sig={len(sig)} bytes)")
    return True

def test_handshake():
    print("Testing TLS 1.3 Handshake...")
    sim = TLS13HandshakeSimulator()
    result = sim.run_handshake()
    
    if not result.success:
        print(f"  FAILED: {result.error_message}")
        return False
    
    if result.final_state != TLS13HandshakeState.HANDSHAKE_COMPLETE:
        print(f"  FAILED: Wrong state {result.final_state}")
        return False
    
    print(f"  Success: {result.success}")
    print(f"  Cipher: {result.selected_cipher_suite.value}")
    print(f"  Time: {result.metrics.total_handshake_time_ms:.2f}ms")
    print(f"  Messages: {len(result.messages)}")
    print(f"  Master Secret: {len(result.master_secret)} bytes")
    return True

def test_hybrid():
    print("Testing Hybrid Mode...")
    sim = TLS13HandshakeSimulator(key_exchange_mode=PQKeyExchangeMode.HYBRID_X25519_KYBER)
    result = sim.run_handshake()
    print(f"  Hybrid Success: {result.success}")
    return result.success

def main():
    print("="*60)
    print("QuantumCrypt-AI - PQ TLS 1.3 Simulator Tests")
    print("="*60)
    
    tests = [
        ("Kyber KEM", test_kyber),
        ("Dilithium Signature", test_dilithium),
        ("TLS 1.3 Handshake", test_handshake),
        ("Hybrid Mode", test_hybrid),
    ]
    
    passed = 0
    start = time.time()
    
    for name, test in tests:
        print(f"\n--- {name} ---")
        if test():
            passed += 1
            print(f"  ✓ PASSED")
        else:
            print(f"  ✗ FAILED")
    
    elapsed = (time.time() - start) * 1000
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed}/{len(tests)} passed in {elapsed:.2f}ms")
    print("="*60)
    
    return passed == len(tests)

if __name__ == "__main__":
    sys.exit(0 if main() else 1)
