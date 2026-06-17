#!/usr/bin/env python3
"""
Test Suite for Quantum-Safe Digital Signature Verifier
June 2026 Production Release - QuantumCrypt-AI
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quantum_crypt.quantum_safe_signature_verifier_2026_june import (
    QuantumSafeSigner,
    SecurityLevel,
    HashAlgorithm,
    SignatureKeyPair,
    SignatureResult,
    VerificationResult
)
def test_key_generation():
    """Test key pair generation"""
    print("Test 1: Key pair generation...")
    signer = QuantumSafeSigner()
    
    key_pair = signer.generate_key_pair()
    
    assert len(key_pair.public_key) > 0, "Public key should not be empty"
    assert len(key_pair.private_key) > 0, "Private key should not be empty"
    assert key_pair.security_level == SecurityLevel.L5
    assert key_pair.hash_alg == HashAlgorithm.SHA3_256
    
    print(f"  ✓ Public key size: {len(key_pair.public_key)} bytes")
    print(f"  ✓ Private key size: {len(key_pair.private_key)} bytes")
    print("  ✓ PASSED")
def test_sign_and_verify():
    """Test basic sign and verify workflow"""
    print("\nTest 2: Sign and verify...")
    signer = QuantumSafeSigner()
    
    key_pair = signer.generate_key_pair()
    message = b"Hello, Quantum World! This is a test message."
    
    # Sign
    sig_result = signer.sign(message, key_pair)
    
    assert len(sig_result.signature) > 0, "Signature should not be empty"
    assert sig_result.message_hash is not None
    
    # Verify
    verify_result = signer.verify(message, sig_result, key_pair.public_key)
    
    assert verify_result.is_valid == True, "Signature should verify"
    assert verify_result.message_authentic == True
    
    print(f"  ✓ Signature size: {len(sig_result.signature)} bytes")
    print(f"  ✓ Sign time: {sig_result.timestamp * 1000:.2f}ms")
    print(f"  ✓ Verify time: {verify_result.verification_time * 1000:.2f}ms")
    print("  ✓ PASSED")
def test_tampered_message():
    """Test detection of tampered messages"""
    print("\nTest 3: Tampered message detection...")
    signer = QuantumSafeSigner()
    
    key_pair = signer.generate_key_pair()
    message = b"Original message"
    
    sig_result = signer.sign(message, key_pair)
    
    # Try to verify with tampered message
    tampered = b"Tampered message!!!"
    verify_result = signer.verify(tampered, sig_result, key_pair.public_key)
    
    assert verify_result.is_valid == False, "Tampered message should NOT verify"
    assert verify_result.message_authentic == False
    
    print("  ✓ Tampered message correctly rejected")
    print("  ✓ PASSED")
def test_wrong_public_key():
    """Test verification with wrong public key"""
    print("\nTest 4: Wrong public key rejection...")
    signer = QuantumSafeSigner()
    
    key_pair1 = signer.generate_key_pair()
    key_pair2 = signer.generate_key_pair()  # Different key
    
    message = b"Test message"
    sig_result = signer.sign(message, key_pair1)
    
    # Verify with wrong public key
    verify_result = signer.verify(message, sig_result, key_pair2.public_key)
    
    assert verify_result.is_valid == False, "Wrong public key should fail"
    
    print("  ✓ Wrong public key correctly rejected")
    print("  ✓ PASSED")
def test_different_security_levels():
    """Test all security levels"""
    print("\nTest 5: Different security levels...")
    
    for level in [SecurityLevel.L1, SecurityLevel.L3, SecurityLevel.L5]:
        signer = QuantumSafeSigner(security_level=level)
        key_pair = signer.generate_key_pair()
        message = f"Test at level {level.value}".encode()
        
        sig = signer.sign(message, key_pair)
        result = signer.verify(message, sig, key_pair.public_key)
        
        assert result.is_valid == True, f"Level {level.value} failed"
        print(f"  ✓ Security Level {level.value}: {len(sig.signature)} bytes signature")
    
    print("  ✓ All security levels working")
    print("  ✓ PASSED")
def test_different_hash_algorithms():
    """Test different hash algorithms"""
    print("\nTest 6: Different hash algorithms...")
    
    for alg in [HashAlgorithm.SHA2_256, HashAlgorithm.SHA3_256]:
        signer = QuantumSafeSigner(hash_alg=alg)
        key_pair = signer.generate_key_pair()
        message = f"Test with {alg.value}".encode()
        
        sig = signer.sign(message, key_pair)
        result = signer.verify(message, sig, key_pair.public_key)
        
        assert result.is_valid == True, f"Hash {alg.value} failed"
        print(f"  ✓ {alg.value}: verified successfully")
    
    print("  ✓ All hash algorithms working")
    print("  ✓ PASSED")
def test_batch_verify():
    """Test batch verification"""
    print("\nTest 7: Batch verification...")
    signer = QuantumSafeSigner()
    
    key_pair = signer.generate_key_pair()
    
    messages = [
        b"Message 1",
        b"Message 2",
        b"Message 3"
    ]
    
    signatures = [signer.sign(m, key_pair) for m in messages]
    public_keys = [key_pair.public_key] * 3
    
    results = signer.batch_verify(messages, signatures, public_keys)
    
    assert len(results) == 3
    assert all(r.is_valid for r in results)
    
    print(f"  ✓ Batch verified {len(results)} signatures")
    print("  ✓ PASSED")
def test_public_key_fingerprint():
    """Test public key fingerprint generation"""
    print("\nTest 8: Public key fingerprint...")
    signer = QuantumSafeSigner()
    
    key_pair = signer.generate_key_pair()
    fingerprint = signer.get_public_key_fingerprint(key_pair.public_key)
    
    assert len(fingerprint) == 16, "Fingerprint should be 16 hex chars"
    assert all(c in '0123456789abcdef' for c in fingerprint)
    
    print(f"  ✓ Fingerprint: {fingerprint}")
    print("  ✓ PASSED")
def test_security_report():
    """Test security report generation"""
    print("\nTest 9: Security report...")
    signer = QuantumSafeSigner()
    
    report = signer.get_security_report()
    
    assert report['quantum_resistant'] == True
    assert report['stateless'] == True
    assert 'nist_security_bits' in report
    assert 'parameters' in report
    
    print(f"  ✓ Algorithm: {report['algorithm']}")
    print(f"  ✓ NIST bits: {report['nist_security_bits']}")
    print(f"  ✓ Quantum resistant: {report['quantum_resistant']}")
    print("  ✓ PASSED")
def test_edge_cases():
    """Test edge cases"""
    print("\nTest 10: Edge cases...")
    signer = QuantumSafeSigner()
    
    key_pair = signer.generate_key_pair()
    
    # Empty message
    empty_sig = signer.sign(b"", key_pair)
    empty_result = signer.verify(b"", empty_sig, key_pair.public_key)
    assert empty_result.is_valid == True, "Empty message should work"
    
    # Very long message
    long_msg = b"A" * 10000
    long_sig = signer.sign(long_msg, key_pair)
    long_result = signer.verify(long_msg, long_sig, key_pair.public_key)
    assert long_result.is_valid == True, "Long message should work"
    
    print("  ✓ Empty message handled")
    print("  ✓ Long message (10KB) handled")
    print("  ✓ PASSED")
def run_benchmark():
    """Run performance benchmark"""
    print("\n=== BENCHMARK ===")
    
    signer = QuantumSafeSigner()
    result = signer.benchmark(iterations=50)
    
    print(f"  Sign avg:   {result['sign_time_avg_ms']:.3f}ms")
    print(f"  Verify avg: {result['verify_time_avg_ms']:.3f}ms")
    print(f"  Signature:  {result['signature_size_bytes']} bytes")
    print(f"  Public key: {result['public_key_size_bytes']} bytes")
    print("  ✓ Benchmark complete")
def main():
    print("=" * 60)
    print("Quantum-Safe Digital Signature Verifier - Test Suite")
    print("QuantumCrypt-AI June 2026 Production Release")
    print("=" * 60)
    
    all_passed = True
    
    try:
        test_key_generation()
        test_sign_and_verify()
        test_tampered_message()
        test_wrong_public_key()
        test_different_security_levels()
        test_different_hash_algorithms()
        test_batch_verify()
        test_public_key_fingerprint()
        test_security_report()
        test_edge_cases()
        run_benchmark()
    except AssertionError as e:
        print(f"\n  ✗ FAILED: {e}")
        all_passed = False
    except Exception as e:
        print(f"\n  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ ALL TESTS PASSED - Production Ready")
    else:
        print("✗ SOME TESTS FAILED")
    print("=" * 60)
    
    return 0 if all_passed else 1
if __name__ == "__main__":
    sys.exit(main())
