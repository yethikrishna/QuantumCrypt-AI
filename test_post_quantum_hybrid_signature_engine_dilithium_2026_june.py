"""
Test Suite for Post-Quantum Hybrid Digital Signature Engine
CRYSTALS-Dilithium Style Lattice-Based Cryptography

12 comprehensive tests covering all functionality
"""
import sys
import time
from quantum_crypt.post_quantum_hybrid_signature_engine_dilithium_2026_june import (
    HybridSignatureEngine, SecurityLevel, SignatureStatus
)

TEST_RESULTS = []

def run_test(name, test_func):
    """Run a test and record results"""
    print(f"\n{'=' * 60}")
    print(f"TEST: {name}")
    print(f"{'=' * 60}")
    try:
        result = test_func()
        print(f"  ✓ PASSED: {name}")
        TEST_RESULTS.append((name, True, None))
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {name}")
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()
        TEST_RESULTS.append((name, False, str(e)))
        return False


def test_engine_initialization():
    """Test engine initialization with all security levels"""
    engine2 = HybridSignatureEngine(SecurityLevel.LEVEL_2)
    engine3 = HybridSignatureEngine(SecurityLevel.LEVEL_3)
    engine5 = HybridSignatureEngine(SecurityLevel.LEVEL_5)
    
    assert engine2.n == 256
    assert engine2.k == 4
    assert engine2.l == 4
    
    assert engine3.k == 6
    assert engine3.l == 5
    
    assert engine5.k == 8
    assert engine5.l == 7
    
    print("  All security levels initialized correctly")
    print(f"  Level 2: n={engine2.n}, k={engine2.k}, l={engine2.l}")
    print(f"  Level 3: n={engine3.n}, k={engine3.k}, l={engine3.l}")
    print(f"  Level 5: n={engine5.n}, k={engine5.k}, l={engine5.l}")
    return True


def test_key_pair_generation():
    """Test key pair generation"""
    engine = HybridSignatureEngine()
    key_pair = engine.generate_key_pair("test_key_001")
    
    assert key_pair.key_id == "test_key_001"
    assert key_pair.security_level == SecurityLevel.LEVEL_3
    assert len(key_pair.public_key["classical"]) == 32
    assert len(key_pair.public_key["pq_public_t"]) == 6
    
    print(f"  Key ID: {key_pair.key_id}")
    print(f"  Security Level: {key_pair.security_level.value}")
    print(f"  Classical public key length: {len(key_pair.public_key['classical'])} bytes")
    print(f"  Lattice public key dimension: {len(key_pair.public_key['pq_public_t'])} polynomials")
    return True


def test_basic_sign_and_verify():
    """Test basic signature generation and verification"""
    engine = HybridSignatureEngine()
    engine.generate_key_pair("test_key")
    
    message = "This is a test message for post-quantum signing"
    signature = engine.sign("test_key", message)
    result = engine.verify(signature, message)
    
    print(f"  Hash match: {result.message_hash_match}")
    print(f"  Classical valid: {result.classical_valid}")
    print(f"  PQ valid: {result.pq_valid}")
    print(f"  Is valid: {result.is_valid}")
    
    assert result.message_hash_match == True
    assert result.classical_valid == True
    assert result.pq_valid == True
    assert result.is_valid == True
    assert result.status == SignatureStatus.VALID
    
    print(f"  Signature verified successfully in {result.verification_time_ms}ms")
    return True


def test_tampered_message_detection():
    """Test detection of tampered messages"""
    engine = HybridSignatureEngine()
    engine.generate_key_pair("test_key")
    
    message = "Original message"
    signature = engine.sign("test_key", message)
    result = engine.verify(signature, "Tampered message")
    
    assert result.message_hash_match == False
    assert result.is_valid == False
    
    print(f"  Tampered message correctly rejected")
    print(f"  Hash match: {result.message_hash_match}")
    print(f"  Valid: {result.is_valid}")
    return True


def test_wrong_key_verification():
    """Test verification with wrong key"""
    engine = HybridSignatureEngine()
    engine.generate_key_pair("key_a")
    engine.generate_key_pair("key_b")
    
    message = "Test message"
    signature = engine.sign("key_a", message)
    
    # Manually change key_id
    signature.key_id = "key_b"
    result = engine.verify(signature, message)
    
    assert result.classical_valid == False
    assert result.is_valid == False
    
    print(f"  Wrong key correctly rejected")
    print(f"  Classical valid: {result.classical_valid}")
    return True


def test_key_revocation():
    """Test key revocation functionality"""
    engine = HybridSignatureEngine()
    engine.generate_key_pair("revocable_key")
    
    message = "Test message"
    signature = engine.sign("revocable_key", message)
    
    # Revoke the key
    engine.revoke_key("revocable_key")
    
    result = engine.verify(signature, message)
    
    assert result.status == SignatureStatus.REVOKED
    assert result.is_valid == False
    
    print(f"  Key revoked successfully")
    print(f"  Revoked status: {result.status.value}")
    return True


def test_batch_verification():
    """Test batch signature verification"""
    engine = HybridSignatureEngine()
    engine.generate_key_pair("batch_key")
    
    messages = [
        "Message 1",
        "Message 2",
        "Message 3",
        "Message 4"
    ]
    
    signatures = [(engine.sign("batch_key", msg), msg) for msg in messages]
    results = engine.batch_verify(signatures)
    
    assert len(results) == 4
    assert all(r.is_valid for r in results)
    
    print(f"  All {len(results)} signatures verified in batch")
    return True


def test_different_security_levels():
    """Test all security levels work correctly"""
    for level in [SecurityLevel.LEVEL_2, SecurityLevel.LEVEL_3, SecurityLevel.LEVEL_5]:
        engine = HybridSignatureEngine(level)
        engine.generate_key_pair(f"key_{level.value}")
        
        message = f"Test at security level {level.value}"
        signature = engine.sign(f"key_{level.value}", message)
        result = engine.verify(signature, message)
        
        assert result.is_valid == True
        assert result.security_level == level
        
        print(f"  Security level {level.value}: OK")
    
    return True


def test_signature_serialization():
    """Test signature serialization to JSON format"""
    engine = HybridSignatureEngine()
    engine.generate_key_pair("serial_key")
    
    signature = engine.sign("serial_key", "Test message")
    serialized = engine.serialize_signature(signature)
    
    assert "signature_id" in serialized
    assert "classical_signature_hex" in serialized
    assert "pq_signature" in serialized
    assert len(serialized["classical_signature_hex"]) == 64  # 32 bytes = 64 hex chars
    
    import json
    json_str = json.dumps(serialized)
    
    print(f"  Signature serialized successfully")
    print(f"  JSON length: {len(json_str)} chars")
    return True


def test_security_metrics():
    """Test security metrics reporting"""
    engine = HybridSignatureEngine(SecurityLevel.LEVEL_5)
    engine.generate_key_pair("metrics_key")
    engine.revoke_key("revoked_metrics")
    
    metrics = engine.get_security_metrics()
    
    assert metrics["security_level"] == "level_5"
    assert metrics["estimated_security_bits"] == 256
    assert metrics["nist_compliant"] == True
    
    print(f"  Security Level: {metrics['security_level']}")
    print(f"  Estimated bits: {metrics['estimated_security_bits']}")
    print(f"  Active keys: {metrics['active_keys']}")
    print(f"  Revoked keys: {metrics['revoked_keys']}")
    print(f"  NIST compliant: {metrics['nist_compliant']}")
    return True


def test_polynomial_operations():
    """Test polynomial operations"""
    engine = HybridSignatureEngine()
    
    poly1 = engine._sample_small_polynomial()
    poly2 = engine._sample_small_polynomial()
    
    assert len(poly1) == 256
    assert len(poly2) == 256
    
    added = engine._polynomial_add(poly1, poly2)
    assert len(added) == 256
    
    norm = engine._polynomial_norm(poly1)
    assert norm >= 0
    
    print(f"  Polynomial operations working")
    print(f"  Polynomial length: {len(poly1)}")
    print(f"  Sample norm: {norm}")
    return True


def test_performance_benchmark():
    """Test performance benchmark"""
    engine = HybridSignatureEngine()
    engine.generate_key_pair("perf_key")
    
    message = "Performance test message" * 10
    
    # Benchmark signing
    sign_times = []
    for _ in range(5):
        start = time.time()
        sig = engine.sign("perf_key", message)
        sign_times.append((time.time() - start) * 1000)
    
    # Benchmark verification
    verify_times = []
    for _ in range(5):
        start = time.time()
        engine.verify(sig, message)
        verify_times.append((time.time() - start) * 1000)
    
    avg_sign = sum(sign_times) / len(sign_times)
    avg_verify = sum(verify_times) / len(verify_times)
    
    print(f"  Average sign time: {avg_sign:.2f} ms")
    print(f"  Average verify time: {avg_verify:.2f} ms")
    
    # Performance assertions (generous bounds for this implementation)
    assert avg_sign < 5000  # < 5 seconds
    assert avg_verify < 5000
    
    return True


def main():
    """Run all tests"""
    print("=" * 70)
    print("POST-QUANTUM HYBRID SIGNATURE ENGINE - TEST SUITE")
    print("CRYSTALS-Dilithium Style Lattice-Based Cryptography")
    print("=" * 70)
    
    tests = [
        ("Engine Initialization", test_engine_initialization),
        ("Key Pair Generation", test_key_pair_generation),
        ("Basic Sign & Verify", test_basic_sign_and_verify),
        ("Tampered Message Detection", test_tampered_message_detection),
        ("Wrong Key Verification", test_wrong_key_verification),
        ("Key Revocation", test_key_revocation),
        ("Batch Verification", test_batch_verification),
        ("Different Security Levels", test_different_security_levels),
        ("Signature Serialization", test_signature_serialization),
        ("Security Metrics", test_security_metrics),
        ("Polynomial Operations", test_polynomial_operations),
        ("Performance Benchmark", test_performance_benchmark),
    ]
    
    for name, func in tests:
        run_test(name, func)
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, p, _ in TEST_RESULTS if p)
    total = len(TEST_RESULTS)
    
    for name, passed_flag, error in TEST_RESULTS:
        status = "✓ PASS" if passed_flag else "✗ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ ALL TESTS PASSED - Module is production-ready!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
