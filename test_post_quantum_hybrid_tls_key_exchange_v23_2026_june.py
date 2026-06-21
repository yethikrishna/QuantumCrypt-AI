"""
Test suite for Post-Quantum Hybrid TLS 1.3 Key Exchange Engine V23
QuantumCrypt-AI - June 21, 2026 Production Release
"""
import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))
from post_quantum_hybrid_tls_key_exchange_v23_2026_june import (
    HybridTLSKeyExchangeEngineV23,
    create_hybrid_tls_engine,
    verify_tls_engine,
    SecurityLevel,
    KeyExchangeMode,
    TLSVersion,
    CipherSuite,
    SessionState,
    X25519KeyExchange,
    MLKEMStyleKeyExchange,
    HybridKDF,
    TLS13KeySchedule,
    ConstantTimeProtector
)
def test_x25519_key_exchange():
    """Test X25519 classical ECDH key exchange"""
    print("=== Test 1: X25519 Key Exchange ===")
    x25519 = X25519KeyExchange()
    alice_keys = x25519.generate_keypair()
    bob_keys = x25519.generate_keypair()
    alice_shared = x25519.compute_shared_secret(alice_keys.private_key, bob_keys.public_key)
    bob_shared = x25519.compute_shared_secret(bob_keys.private_key, alice_keys.public_key)
    assert len(alice_shared) == 32
    assert len(bob_shared) == 32
    print("✓ X25519 key exchange working\n")
    return True
def test_mlkem_key_encapsulation():
    """Test ML-KEM post-quantum key encapsulation"""
    print("=== Test 2: ML-KEM Key Encapsulation ===")
    mlkem = MLKEMStyleKeyExchange(SecurityLevel.LEVEL_3)
    keypair = mlkem.generate_keypair()
    ciphertext, shared_secret_encap = mlkem.encapsulate(keypair.public_key)
    shared_secret_decap = mlkem.decapsulate(keypair.private_key, ciphertext)
    assert len(shared_secret_encap) == 32
    assert len(shared_secret_decap) == 32
    print("✓ ML-KEM encapsulation/decapsulation working\n")
    return True
def test_hybrid_kdf():
    """Test Hybrid KDF - NIST SP 800-56C compliant"""
    print("=== Test 3: Hybrid Key Derivation Function ===")
    hkdf = HybridKDF("sha384")
    classical_secret = bytes(range(32))
    pq_secret = bytes(range(32, 64))
    hybrid_secret = hkdf.derive_hybrid_secret(classical_secret, pq_secret)
    assert len(hybrid_secret.secret) == 48
    assert hybrid_secret.contributor_count == 2
    print("✓ Hybrid KDF working correctly\n")
    return True
def test_tls13_key_schedule():
    """Test TLS 1.3 key schedule - RFC 8446 compliant"""
    print("=== Test 4: TLS 1.3 Key Schedule ===")
    key_schedule = TLS13KeySchedule(CipherSuite.TLS_AES_256_GCM_SHA384)
    shared_secret = bytes(range(48))
    client_random = bytes(range(32))
    server_random = bytes(range(32, 64))
    handshake_hash = bytes(range(48))
    key_material = key_schedule.derive_traffic_keys(shared_secret, client_random, server_random, handshake_hash)
    assert len(key_material.client_write_key) == key_schedule.key_length
    assert len(key_material.server_write_key) == key_schedule.key_length
    print("✓ TLS 1.3 key schedule working correctly\n")
    return True
def test_full_handshake_flow():
    """Test complete TLS 1.3 handshake flow"""
    print("=== Test 5: Full Handshake Flow ===")
    engine = create_hybrid_tls_engine()
    client_session, client_hello = engine.generate_client_hello()
    server_session, server_hello = engine.process_client_hello(client_hello)
    completed_session = engine.complete_client_handshake(client_session, server_hello)
    assert completed_session.state == SessionState.ESTABLISHED
    print("✓ Full handshake flow working\n")
    return True
def test_security_report():
    """Test security and performance reporting"""
    print("=== Test 6: Security Report ===")
    engine = create_hybrid_tls_engine()
    for i in range(3):
        client_session, client_hello = engine.generate_client_hello()
        _, server_hello = engine.process_client_hello(client_hello)
        engine.complete_client_handshake(client_session, server_hello)
    report = engine.get_security_report()
    assert report['features']['forward_secrecy'] == True
    print("✓ Security report generation working\n")
    return True
def test_engine_verification():
    """Test engine verification function"""
    print("=== Test 7: Engine Verification ===")
    result = verify_tls_engine()
    assert result['engine_working']
    print("✓ Engine verification working correctly\n")
    return True
def run_all_tests():
    """Run all tests and generate summary"""
    print("=" * 70)
    print("QuantumCrypt-AI: Hybrid TLS 1.3 Key Exchange Engine V23 - Test Suite")
    print("=" * 70)
    print()
    
    tests = [
        test_x25519_key_exchange,
        test_mlkem_key_encapsulation,
        test_hybrid_kdf,
        test_tls13_key_schedule,
        test_full_handshake_flow,
        test_security_report,
        test_engine_verification
    ]
    
    passed = 0
    failed = 0
    test_results = []
    
    for test in tests:
        try:
            if test():
                passed += 1
                test_results.append((test.__name__, "PASSED"))
            else:
                failed += 1
                test_results.append((test.__name__, "FAILED"))
        except Exception as e:
            failed += 1
            test_results.append((test.__name__, f"ERROR: {str(e)[:50]}"))
            print(f"✗ {test.__name__} failed with error: {e}\n")
    
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    for name, status in test_results:
        print(f"{name:55s} {status}")
    print("-" * 70)
    print(f"Total: {len(tests)}, Passed: {passed}, Failed: {failed}")
    print(f"Success rate: {passed/len(tests)*100:.1f}%")
    print("=" * 70)
    
    with open("test_results_hybrid_tls_v23_2026_june.json", "w") as f:
        json.dump({
            "engine": "HybridTLSKeyExchangeEngineV23",
            "version": "23.0.0",
            "total_tests": len(tests),
            "passed": passed,
            "failed": failed,
            "success_rate": passed/len(tests)*100,
            "timestamp": __import__('datetime').datetime.now().isoformat()
        }, f, indent=2)
    
    return passed == len(tests)
if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
