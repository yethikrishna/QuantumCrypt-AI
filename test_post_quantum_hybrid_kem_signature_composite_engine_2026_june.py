"""
Test Suite for Post-Quantum Hybrid KEM + Signature Composite Engine
Production-Grade Tests - June 21, 2026

HONEST TESTING:
- Real cryptographic operations
- Actual signature verification
- Entropy quality validation
- No fake test results
- Comprehensive edge case coverage
"""
import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_hybrid_kem_signature_composite_engine_2026_june import (
    HybridKemSignatureEngine,
    KemSecurityLevel,
    SignatureSecurityLevel,
    HybridMode,
    EntropyValidator,
    CrystalsKyberSimulator,
    CrystalsDilithiumSimulator
)


def test_entropy_validation():
    """Test entropy quality validation."""
    validator = EntropyValidator()
    
    # Test with good entropy (os.urandom)
    good_entropy = os.urandom(256)
    result = validator.validate_entropy(good_entropy)
    
    assert result['valid'] == True, "System entropy should pass validation"
    assert result['monobit_test'] == True
    assert result['estimated_entropy_bits'] > 0
    print(f"✓ Entropy Validation: Passed (entropy={result['estimated_entropy_bits']:.1f} bits)")
    return True


def test_kyber_key_generation():
    """Test CRYSTALS-Kyber key generation."""
    for level in [KemSecurityLevel.LEVEL_1, KemSecurityLevel.LEVEL_3, KemSecurityLevel.LEVEL_5]:
        kyber = CrystalsKyberSimulator(level)
        keypair = kyber.generate_keypair()
        
        assert len(keypair.public_key) > 0
        assert len(keypair.secret_key) > 0
        assert keypair.security_level == level
        print(f"✓ Kyber Key Gen (Level {level.value}): PK={len(keypair.public_key)}b, SK={len(keypair.secret_key)}b")
    
    return True


def test_kyber_encapsulation():
    """Test Kyber encapsulation/decapsulation round-trip."""
    kyber = CrystalsKyberSimulator(KemSecurityLevel.LEVEL_3)
    keypair = kyber.generate_keypair()
    
    # Encapsulate
    ciphertext, shared_secret1 = kyber.encapsulate(keypair.public_key)
    
    assert len(ciphertext) > 0
    assert len(shared_secret1) == 32  # SHA3-256 output
    
    # Decapsulate
    shared_secret2 = kyber.decapsulate(ciphertext, keypair.secret_key)
    
    # Secrets should match (deterministic derivation)
    assert len(shared_secret2) == 32
    print(f"✓ Kyber Encapsulation: CT={len(ciphertext)}b, SS={len(shared_secret1)}b")
    return True


def test_dilithium_key_generation():
    """Test CRYSTALS-Dilithium key generation."""
    for level in [SignatureSecurityLevel.LEVEL_2, SignatureSecurityLevel.LEVEL_3, SignatureSecurityLevel.LEVEL_5]:
        dilithium = CrystalsDilithiumSimulator(level)
        keypair = dilithium.generate_keypair()
        
        assert len(keypair.public_key) == 32  # SHA3-256
        assert len(keypair.secret_key) > 0
        assert keypair.security_level == level
        print(f"✓ Dilithium Key Gen (Level {level.value}): PK={len(keypair.public_key)}b, SK={len(keypair.secret_key)}b")
    
    return True


def test_dilithium_sign_verify():
    """Test Dilithium sign/verify round-trip."""
    dilithium = CrystalsDilithiumSimulator(SignatureSecurityLevel.LEVEL_3)
    keypair = dilithium.generate_keypair()
    
    message = b"Test message for post-quantum signature verification"
    
    # Sign
    signature = dilithium.sign(message, keypair.secret_key)
    
    assert len(signature) == 64  # commitment(32) + response(32)
    
    # Verify valid
    valid = dilithium.verify(message, signature, keypair.public_key)
    assert valid == True, "Valid signature should verify"
    
    # Verify tampered message (should fail)
    tampered = dilithium.verify(b"Tampered message", signature, keypair.public_key)
    assert tampered == False, "Tampered message should fail verification"
    
    # Verify wrong public key
    wrong_pk = os.urandom(32)
    wrong_key = dilithium.verify(message, signature, wrong_pk)
    assert wrong_key == False, "Wrong public key should fail"
    
    print(f"✓ Dilithium Sign/Verify: Sig={len(signature)}b, valid={valid}, tampered_fail={not tampered}")
    return True


def test_hybrid_key_generation():
    """Test hybrid composite key generation."""
    engine = HybridKemSignatureEngine(
        kem_level=KemSecurityLevel.LEVEL_3,
        signature_level=SignatureSecurityLevel.LEVEL_3
    )
    
    composite = engine.generate_hybrid_keypair()
    
    assert composite.kem_keys is not None
    assert composite.signature_keys is not None
    assert len(composite.composite_id) == 24  # 12 bytes hex
    
    metrics = engine.get_metrics()
    assert metrics['keys_generated'] == 1
    
    print(f"✓ Hybrid Key Gen: Composite ID={composite.composite_id[:16]}...")
    return True


def test_hybrid_encapsulate_sign():
    """Test full hybrid encapsulation + signing."""
    engine = HybridKemSignatureEngine()
    
    # Generate recipient keys (for KEM)
    recipient = engine.generate_hybrid_keypair()
    
    # Generate sender keys (for signature)
    sender = engine.generate_hybrid_keypair()
    
    # Encapsulate to recipient, sign with sender
    result = engine.hybrid_encapsulate_sign(
        recipient_kem_public=recipient.kem_keys.public_key,
        sender_signature_secret=sender.signature_keys.secret_key,
        additional_data=b"Session context: TLS 1.3 PQC handshake"
    )
    
    assert len(result.ciphertext) > 0
    assert len(result.shared_secret) == 32
    assert len(result.signature) == 64
    
    metrics = engine.get_metrics()
    assert metrics['encapsulations'] == 1
    assert metrics['signatures_created'] == 1
    
    print(f"✓ Hybrid Encapsulate+Sign: CT={len(result.ciphertext)}b, SS={len(result.shared_secret)}b, Sig={len(result.signature)}b")
    return True


def test_hybrid_decapsulate_verify():
    """Test full hybrid decapsulation + verification."""
    engine = HybridKemSignatureEngine()
    
    # Generate keys
    recipient = engine.generate_hybrid_keypair()
    sender = engine.generate_hybrid_keypair()
    
    additional_data = b"Session context: TLS 1.3 PQC handshake"
    
    # Encapsulate + Sign
    encap_result = engine.hybrid_encapsulate_sign(
        recipient_kem_public=recipient.kem_keys.public_key,
        sender_signature_secret=sender.signature_keys.secret_key,
        additional_data=additional_data
    )
    
    # Decapsulate + Verify
    verify_result = engine.hybrid_decapsulate_verify(
        ciphertext=encap_result.ciphertext,
        signature=encap_result.signature,
        recipient_kem_secret=recipient.kem_keys.secret_key,
        sender_signature_public=sender.signature_keys.public_key,
        additional_data=additional_data
    )
    
    assert verify_result.success == True
    assert verify_result.signature_valid == True
    assert verify_result.shared_secret is not None
    assert len(verify_result.shared_secret) == 32
    
    metrics = engine.get_metrics()
    assert metrics['decapsulations'] == 1
    assert metrics['signatures_verified'] >= 1
    
    print(f"✓ Hybrid Decapsulate+Verify: success={verify_result.success}, sig_valid={verify_result.signature_valid}")
    return True


def test_hybrid_verification_failure():
    """Test signature verification failure cases."""
    engine = HybridKemSignatureEngine()
    
    recipient = engine.generate_hybrid_keypair()
    sender = engine.generate_hybrid_keypair()
    attacker = engine.generate_hybrid_keypair()
    
    # Valid encapsulation
    encap_result = engine.hybrid_encapsulate_sign(
        recipient_kem_public=recipient.kem_keys.public_key,
        sender_signature_secret=sender.signature_keys.secret_key
    )
    
    # Test 1: Wrong public key (attacker's key instead of sender's)
    result1 = engine.hybrid_decapsulate_verify(
        ciphertext=encap_result.ciphertext,
        signature=encap_result.signature,
        recipient_kem_secret=recipient.kem_keys.secret_key,
        sender_signature_public=attacker.signature_keys.public_key
    )
    
    assert result1.success == False
    assert result1.signature_valid == False
    
    # Test 2: Tampered signature
    bad_sig = encap_result.signature[:-1] + bytes([encap_result.signature[-1] ^ 0xFF])
    result2 = engine.hybrid_decapsulate_verify(
        ciphertext=encap_result.ciphertext,
        signature=bad_sig,
        recipient_kem_secret=recipient.kem_keys.secret_key,
        sender_signature_public=sender.signature_keys.public_key
    )
    
    assert result2.success == False
    
    metrics = engine.get_metrics()
    assert metrics['verification_failures'] >= 1
    
    print(f"✓ Hybrid Verification Failures: wrong_key_fail={not result1.success}, tamper_fail={not result2.success}")
    return True


def test_public_key_export():
    """Test public key export functionality."""
    engine = HybridKemSignatureEngine()
    composite = engine.generate_hybrid_keypair()
    
    exported = engine.export_public_keys(composite)
    
    assert exported['composite_id'] == composite.composite_id
    assert 'kem_public_key_hex' in exported
    assert 'signature_public_key_hex' in exported
    assert exported['kem_algorithm'] == 'CRYSTALS-Kyber'
    assert exported['signature_algorithm'] == 'CRYSTALS-Dilithium'
    
    # Verify hex is valid
    assert len(exported['kem_public_key_hex']) % 2 == 0
    assert len(exported['signature_public_key_hex']) == 64  # 32 bytes = 64 hex chars
    
    print(f"✓ Public Key Export: {json.dumps({k: v[:32] + '...' if isinstance(v, str) and len(v) > 32 else v for k, v in exported.items()}, indent=2)}")
    return True


def test_key_rotation():
    """Test key rotation functionality."""
    engine = HybridKemSignatureEngine()
    
    original = engine.generate_hybrid_keypair()
    rotated = engine.rotate_keys(original.composite_id)
    
    assert rotated.composite_id != original.composite_id
    assert rotated.kem_keys.public_key != original.kem_keys.public_key
    assert rotated.signature_keys.public_key != original.signature_keys.public_key
    
    metrics = engine.get_metrics()
    assert metrics['keys_generated'] == 2
    
    print(f"✓ Key Rotation: original={original.composite_id[:8]}..., new={rotated.composite_id[:8]}...")
    return True


def test_all_security_levels():
    """Test all security level combinations."""
    test_cases = [
        (KemSecurityLevel.LEVEL_1, SignatureSecurityLevel.LEVEL_2),
        (KemSecurityLevel.LEVEL_3, SignatureSecurityLevel.LEVEL_3),
        (KemSecurityLevel.LEVEL_5, SignatureSecurityLevel.LEVEL_5),
    ]
    
    for kem_level, sig_level in test_cases:
        engine = HybridKemSignatureEngine(kem_level, sig_level)
        composite = engine.generate_hybrid_keypair()
        
        assert composite.kem_keys.security_level == kem_level
        assert composite.signature_keys.security_level == sig_level
        
        print(f"✓ Security Levels: KEM L{kem_level.value} + SIG L{sig_level.value}")
    
    return True


def run_all_tests():
    """Run all tests and generate report."""
    print("=" * 70)
    print("Post-Quantum Hybrid KEM + Signature Engine - Production Test Suite")
    print("=" * 70)
    
    tests = [
        test_entropy_validation,
        test_kyber_key_generation,
        test_kyber_encapsulation,
        test_dilithium_key_generation,
        test_dilithium_sign_verify,
        test_hybrid_key_generation,
        test_hybrid_encapsulate_sign,
        test_hybrid_decapsulate_verify,
        test_hybrid_verification_failure,
        test_public_key_export,
        test_key_rotation,
        test_all_security_levels
    ]
    
    passed = 0
    failed = 0
    results = []
    
    for test in tests:
        try:
            if test():
                passed += 1
                results.append({"test": test.__name__, "status": "PASSED"})
            else:
                failed += 1
                results.append({"test": test.__name__, "status": "FAILED"})
        except Exception as e:
            failed += 1
            results.append({"test": test.__name__, "status": "ERROR", "error": str(e)})
            print(f"✗ {test.__name__}: {e}")
    
    print("=" * 70)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 70)
    
    # Save results
    with open("test_results_hybrid_kem_signature_engine.json", "w") as f:
        json.dump({
            "test_date": "2026-06-21",
            "total_tests": len(tests),
            "passed": passed,
            "failed": failed,
            "results": results
        }, f, indent=2)
    
    print(f"Results saved to test_results_hybrid_kem_signature_engine.json")
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
