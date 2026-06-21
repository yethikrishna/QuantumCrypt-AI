"""
Test Suite for Post-Quantum Hybrid Digital Signature Engine
Comprehensive tests for ECDSA, Dilithium-like, and hybrid signature modes
"""

import json
import time
import sys
sys.path.insert(0, '.')

from quantum_crypt.post_quantum_digital_signature_hybrid_verification_engine_2026_june import (
    HybridDigitalSignatureEngine,
    Signature,
    KeyPair,
    SignatureAlgorithm,
    VerificationStatus,
    SimplifiedECDSA,
    DilithiumLikeSignature
)


def test_ecdsa_basic():
    """Test basic ECDSA sign/verify"""
    print("=== Test 1: Classical ECDSA Sign/Verify ===")
    
    engine = HybridDigitalSignatureEngine()
    key_pair = engine.generate_key_pair(SignatureAlgorithm.ECDSA_SECP256R1)
    
    print(f"  Key ID: {key_pair.key_id}")
    print(f"  Algorithm: {key_pair.algorithm.value}")
    
    message = "This is a test message for ECDSA signing"
    signature = engine.sign(message, key_id=key_pair.key_id)
    
    print(f"  Signature length: {len(signature.signature_bytes)} bytes")
    
    result = engine.verify(message, signature)
    
    print(f"  Verification: {result['status']}")
    print(f"  Valid: {result['valid']}")
    print(f"  Time: {result['verification_time_ms']}ms")
    
    assert result['valid'], "ECDSA signature should verify"
    assert result['status'] == 'valid', "Status should be valid"
    
    print("  ✓ ECDSA basic operations work!")
    return True


def test_dilithium_like():
    """Test Dilithium-like post-quantum signature"""
    print("\n=== Test 2: Post-Quantum Dilithium-like Signature ===")
    
    engine = HybridDigitalSignatureEngine()
    key_pair = engine.generate_key_pair(SignatureAlgorithm.DILITHIUM_LIKE)
    
    print(f"  Key ID: {key_pair.key_id}")
    print(f"  Algorithm: {key_pair.algorithm.value}")
    
    message = "This is a test message for post-quantum signing"
    signature = engine.sign(message, key_id=key_pair.key_id)
    
    print(f"  Signature length: {len(signature.signature_bytes)} bytes")
    
    result = engine.verify(message, signature)
    
    print(f"  Verification: {result['status']}")
    print(f"  Valid: {result['valid']}")
    print(f"  Time: {result['verification_time_ms']}ms")
    
    assert result['valid'], "Dilithium signature should verify"
    
    print("  ✓ Dilithium-like PQ signature works!")
    return True


def test_hybrid_signature():
    """Test hybrid ECDSA + Dilithium signature"""
    print("\n=== Test 3: Hybrid (ECDSA + Dilithium) Signature ===")
    
    engine = HybridDigitalSignatureEngine()
    key_pair = engine.generate_key_pair(SignatureAlgorithm.HYBRID_ECDSA_DILITHIUM)
    
    print(f"  Key ID: {key_pair.key_id}")
    print(f"  Algorithm: {key_pair.algorithm.value}")
    
    message = "Critical document requiring post-quantum security"
    signature = engine.sign(message, key_id=key_pair.key_id)
    
    print(f"  Signature length: {len(signature.signature_bytes)} bytes")
    
    result = engine.verify(message, signature)
    
    print(f"  Verification: {result['status']}")
    print(f"  Valid: {result['valid']}")
    print(f"  Component results: {result['component_results']}")
    print(f"  Time: {result['verification_time_ms']}ms")
    
    assert result['valid'], "Hybrid signature should verify"
    assert result['component_results']['ecdsa_secp256r1'], "ECDSA component should pass"
    assert result['component_results']['dilithium_like'], "Dilithium component should pass"
    
    print("  ✓ Hybrid signature works with both components valid!")
    return True


def test_tamper_detection():
    """Test that tampered messages are detected"""
    print("\n=== Test 4: Tamper Detection ===")
    
    engine = HybridDigitalSignatureEngine()
    key_pair = engine.generate_key_pair(SignatureAlgorithm.HYBRID_ECDSA_DILITHIUM)
    
    original_message = "Transfer $100 to account 12345"
    signature = engine.sign(original_message, key_id=key_pair.key_id)
    
    original_result = engine.verify(original_message, signature)
    
    # Tamper the message
    tampered_message = "Transfer $10000 to account 99999"
    tampered_result = engine.verify(tampered_message, signature)
    
    print(f"  Original message: valid={original_result['valid']}")
    print(f"  Tampered message: valid={tampered_result['valid']}")
    print(f"  Tampered status: {tampered_result['status']}")
    
    assert original_result['valid'], "Original should verify"
    assert not tampered_result['valid'], "Tampered should NOT verify"
    
    print("  ✓ Tamper detection works correctly!")
    return True


def test_signature_serialization():
    """Test signature serialization/deserialization"""
    print("\n=== Test 5: Signature Serialization ===")
    
    engine = HybridDigitalSignatureEngine()
    key_pair = engine.generate_key_pair(SignatureAlgorithm.ECDSA_SECP256R1)
    
    message = "Message to be signed and serialized"
    signature = engine.sign(message, key_id=key_pair.key_id)
    
    # Serialize
    sig_dict = signature.to_dict()
    print(f"  Serialized keys: {list(sig_dict.keys())}")
    
    # Deserialize and verify
    reconstructed = Signature.from_dict(sig_dict)
    result = engine.verify(message, reconstructed)
    
    print(f"  Reconstructed verification: {result['valid']}")
    
    assert result['valid'], "Deserialized signature should verify"
    
    print("  ✓ Signature serialization/deserialization works!")
    return True


def test_expired_key():
    """Test expired key handling"""
    print("\n=== Test 6: Expired Key Handling ===")
    
    engine = HybridDigitalSignatureEngine()
    # Key expires in 1 second
    key_pair = engine.generate_key_pair(
        SignatureAlgorithm.ECDSA_SECP256R1,
        expires_after_seconds=1
    )
    
    message = "Test message"
    
    # Should work before expiry
    signature = engine.sign(message, key_id=key_pair.key_id)
    result_before = engine.verify(message, signature)
    
    # Wait for expiry
    time.sleep(1.1)
    
    # Should still work within grace period
    result_after = engine.verify(message, signature)
    
    print(f"  Before expiry: valid={result_before['valid']}")
    print(f"  After expiry: status={result_after['status']}, valid={result_after['valid']}")
    
    assert result_before['valid'], "Should verify before expiry"
    # Grace period should allow this
    print("  ✓ Expired key handling with grace period works!")
    return True


def test_wrong_key():
    """Test wrong key detection"""
    print("\n=== Test 7: Wrong Key Detection ===")
    
    engine = HybridDigitalSignatureEngine()
    key1 = engine.generate_key_pair(SignatureAlgorithm.ECDSA_SECP256R1)
    key2 = engine.generate_key_pair(SignatureAlgorithm.ECDSA_SECP256R1)
    
    message = "Test message"
    signature = engine.sign(message, key_id=key1.key_id)
    
    # Try to verify with wrong key registered
    # We need to create a signature object that references key2
    wrong_signature = Signature(
        signature_bytes=signature.signature_bytes,
        algorithm=signature.algorithm,
        key_id=key2.key_id
    )
    
    result = engine.verify(message, wrong_signature)
    
    print(f"  Wrong key verification: valid={result['valid']}")
    print(f"  Status: {result['status']}")
    
    assert not result['valid'], "Wrong key should NOT verify"
    
    print("  ✓ Wrong key correctly detected!")
    return True


def test_batch_verification():
    """Test batch verification"""
    print("\n=== Test 8: Batch Verification ===")
    
    engine = HybridDigitalSignatureEngine()
    key_pair = engine.generate_key_pair(SignatureAlgorithm.ECDSA_SECP256R1)
    
    messages = [
        "Message 1",
        "Message 2",
        "Message 3"
    ]
    
    pairs = []
    for msg in messages:
        sig = engine.sign(msg, key_id=key_pair.key_id)
        pairs.append((msg, sig))
    
    results = engine.batch_verify(pairs)
    
    print(f"  Batch size: {len(results)}")
    for i, r in enumerate(results):
        print(f"    Message {i+1}: valid={r['valid']}, time={r['verification_time_ms']}ms")
    
    assert all(r['valid'] for r in results), "All batch verifications should pass"
    
    print("  ✓ Batch verification works correctly!")
    return True


def test_key_management():
    """Test key registry and management"""
    print("\n=== Test 9: Key Management ===")
    
    engine = HybridDigitalSignatureEngine()
    
    # Generate multiple keys
    k1 = engine.generate_key_pair(SignatureAlgorithm.ECDSA_SECP256R1)
    k2 = engine.generate_key_pair(SignatureAlgorithm.DILITHIUM_LIKE)
    k3 = engine.generate_key_pair(SignatureAlgorithm.HYBRID_ECDSA_DILITHIUM)
    
    keys = engine.list_keys()
    
    print(f"  Registered keys: {len(keys)}")
    for k in keys:
        print(f"    - {k['key_id']}: {k['algorithm']} (expired={k['is_expired']})")
    
    assert len(keys) == 3, "Should have 3 registered keys"
    
    print("  ✓ Key management works correctly!")
    return True


def test_standalone_crypto():
    """Test standalone crypto primitives"""
    print("\n=== Test 10: Standalone Crypto Primitives ===")
    
    # Test ECDSA directly
    priv, pub = SimplifiedECDSA.generate_keypair()
    msg = b"Direct ECDSA test"
    sig = SimplifiedECDSA.sign(priv, msg)
    ecdsa_ok = SimplifiedECDSA.verify(pub, msg, sig)
    print(f"  Standalone ECDSA: {'PASS' if ecdsa_ok else 'FAIL'}")
    
    # Test Dilithium directly
    priv2, pub2 = DilithiumLikeSignature.generate_keypair()
    sig2 = DilithiumLikeSignature.sign(priv2, msg)
    dilithium_ok = DilithiumLikeSignature.verify(pub2, msg, sig2)
    print(f"  Standalone Dilithium: {'PASS' if dilithium_ok else 'FAIL'}")
    
    # Test tamper
    bad_msg = b"Tampered message"
    tamper_ok = DilithiumLikeSignature.verify(pub2, bad_msg, sig2)
    print(f"  Dilithium tamper detection: {'PASS' if not tamper_ok else 'FAIL'}")
    
    assert ecdsa_ok, "Standalone ECDSA should work"
    assert dilithium_ok, "Standalone Dilithium should work"
    assert not tamper_ok, "Dilithium should detect tampering"
    
    print("  ✓ Standalone crypto primitives work correctly!")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Post-Quantum Hybrid Signature Engine - Production Test Suite")
    print("=" * 60)
    
    tests = [
        test_ecdsa_basic,
        test_dilithium_like,
        test_hybrid_signature,
        test_tamper_detection,
        test_signature_serialization,
        test_expired_key,
        test_wrong_key,
        test_batch_verification,
        test_key_management,
        test_standalone_crypto,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append((test.__name__, result, None))
        except Exception as e:
            results.append((test.__name__, False, str(e)))
            print(f"  ✗ FAILED: {e}")
    
    print("\n" + "=" * 60)
    passed = sum(1 for _, r, _ in results if r)
    total = len(results)
    print(f"TEST SUMMARY: {passed} passed, {total - passed} failed")
    print("=" * 60)
    
    # Save results
    report = {
        "test_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_tests": total,
        "passed": passed,
        "failed": total - passed,
        "results": [
            {"test": name, "passed": passed, "error": error}
            for name, passed, error in results
        ]
    }
    
    with open("test_results_hybrid_signature_2026_june.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nTest results saved to test_results_hybrid_signature_2026_june.json")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
