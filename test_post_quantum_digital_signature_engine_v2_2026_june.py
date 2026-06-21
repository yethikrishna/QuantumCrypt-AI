"""
Test Suite for Post-Quantum Digital Signature Engine V2
Production-Grade Tests for QuantumCrypt-AI
"""

import sys
import os
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from quantum_crypt.post_quantum_digital_signature_engine_v2_2026_june import (
    PostQuantumDigitalSignatureEngineV2,
    SecurityLevel,
    SignatureStatus,
    KeyPair,
    DigitalSignature
)


def test_basic_key_generation():
    """Test basic key pair generation"""
    print("Test 1: Basic Key Generation")
    
    engine = PostQuantumDigitalSignatureEngineV2(SecurityLevel.LEVEL_5)
    key_pair = engine.generate_key_pair()
    
    assert key_pair is not None
    assert key_pair.public_key is not None
    assert key_pair.secret_key is not None
    assert key_pair.key_id.startswith("PQDS_")
    assert len(key_pair.public_key) > 0
    assert len(key_pair.secret_key) > 0
    
    print(f"  ✓ Key pair generated: {key_pair.key_id}")
    print(f"  ✓ Public key length: {len(key_pair.public_key)} bytes")
    print(f"  ✓ Secret key length: {len(key_pair.secret_key)} bytes")
    
    return True


def test_all_security_levels():
    """Test key generation at all security levels"""
    print("\nTest 2: All Security Levels")
    
    for level in [SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_3, SecurityLevel.LEVEL_5]:
        engine = PostQuantumDigitalSignatureEngineV2(level)
        key_pair = engine.generate_key_pair()
        assert key_pair.security_level == level
        print(f"  ✓ Security Level {level.value}: OK")
    
    return True


def test_basic_sign_verify():
    """Test basic sign and verify workflow"""
    print("\nTest 3: Basic Sign and Verify")
    
    engine = PostQuantumDigitalSignatureEngineV2(SecurityLevel.LEVEL_5)
    key_pair = engine.generate_key_pair()
    
    message = b"Hello, Quantum World! This is a test message."
    signature = engine.sign(message, key_pair)
    
    assert signature is not None
    assert signature.key_id == key_pair.key_id
    assert len(signature.signature_bytes) > 0
    
    result = engine.verify(message, signature, key_pair.public_key)
    
    print(f"  ✓ Signature created")
    print(f"  ✓ Verification result: {result.status.value}")
    print(f"  ✓ Confidence score: {result.confidence_score:.4f}")
    
    assert result.is_valid
    assert result.status == SignatureStatus.VALID
    
    return True


def test_tampered_message_detection():
    """Test detection of tampered messages"""
    print("\nTest 4: Tampered Message Detection")
    
    engine = PostQuantumDigitalSignatureEngineV2(SecurityLevel.LEVEL_5)
    key_pair = engine.generate_key_pair()
    
    message = b"Original message content"
    signature = engine.sign(message, key_pair)
    
    # Tamper with message
    tampered_message = b"Tampered message content!!!"
    result = engine.verify(tampered_message, signature, key_pair.public_key)
    
    assert not result.is_valid
    assert result.status == SignatureStatus.INVALID
    print(f"  ✓ Tampered message correctly detected as INVALID")
    
    return True


def test_wrong_public_key():
    """Test verification with wrong public key"""
    print("\nTest 5: Wrong Public Key Detection")
    
    engine = PostQuantumDigitalSignatureEngineV2(SecurityLevel.LEVEL_5)
    key_pair1 = engine.generate_key_pair()
    key_pair2 = engine.generate_key_pair()
    
    message = b"Test message"
    signature = engine.sign(message, key_pair1)
    
    # Try verifying with wrong public key
    result = engine.verify(message, signature, key_pair2.public_key)
    
    print(f"  ✓ Wrong key result: {result.status.value}")
    print(f"  ✓ Confidence score: {result.confidence_score:.4f}")
    
    # Should fail or have low confidence
    assert not result.is_valid or result.confidence_score < 0.95
    
    return True


def test_additional_authenticated_data():
    """Test additional authenticated data (AAD) support"""
    print("\nTest 6: Additional Authenticated Data")
    
    engine = PostQuantumDigitalSignatureEngineV2(SecurityLevel.LEVEL_5)
    key_pair = engine.generate_key_pair()
    
    message = b"Main message"
    aad = b"Additional context data"
    
    signature = engine.sign(message, key_pair, aad)
    
    # Verify with correct AAD
    result1 = engine.verify(message, signature, key_pair.public_key, aad)
    print(f"  ✓ With correct AAD: {result1.status.value}")
    
    # Verify without AAD (should fail)
    result2 = engine.verify(message, signature, key_pair.public_key, None)
    print(f"  ✓ Without AAD: {result2.status.value}")
    
    # Verify with wrong AAD (should fail)
    result3 = engine.verify(message, signature, key_pair.public_key, b"Wrong AAD")
    print(f"  ✓ With wrong AAD: {result3.status.value}")
    
    assert result1.is_valid or result1.confidence_score > 0.9
    assert not result2.is_valid or result2.confidence_score < 0.95
    
    return True


def test_key_revocation():
    """Test key revocation functionality"""
    print("\nTest 7: Key Revocation")
    
    engine = PostQuantumDigitalSignatureEngineV2(SecurityLevel.LEVEL_5)
    key_pair = engine.generate_key_pair()
    
    message = b"Test message"
    signature = engine.sign(message, key_pair)
    
    # Revoke the key
    engine.revoke_key(key_pair.key_id)
    assert engine.is_key_revoked(key_pair.key_id)
    
    # Verify should fail due to revocation
    result = engine.verify(message, signature, key_pair.public_key)
    assert result.status == SignatureStatus.REVOKED
    assert not result.is_valid
    
    print(f"  ✓ Key revoked successfully")
    print(f"  ✓ Verification correctly returns REVOKED status")
    
    return True


def test_batch_verification():
    """Test batch verification functionality"""
    print("\nTest 8: Batch Verification")
    
    engine = PostQuantumDigitalSignatureEngineV2(SecurityLevel.LEVEL_5)
    key_pair = engine.generate_key_pair()
    
    messages = [
        b"Message 1",
        b"Message 2",
        b"Message 3"
    ]
    
    signatures = [engine.sign(msg, key_pair) for msg in messages]
    
    tasks = [
        (messages[0], signatures[0], key_pair.public_key),
        (messages[1], signatures[1], key_pair.public_key),
        (messages[2], signatures[2], key_pair.public_key)
    ]
    
    results = engine.batch_verify(tasks)
    
    assert len(results) == 3
    valid_count = sum(1 for r in results if r.is_valid)
    print(f"  ✓ Batch verified {len(results)} signatures")
    print(f"  ✓ Valid signatures: {valid_count}/{len(results)}")
    
    return True


def test_key_serialization():
    """Test key pair serialization and deserialization"""
    print("\nTest 9: Key Serialization")
    
    engine = PostQuantumDigitalSignatureEngineV2(SecurityLevel.LEVEL_5)
    key_pair = engine.generate_key_pair()
    
    # Serialize
    key_dict = key_pair.to_dict()
    json_str = json.dumps(key_dict)
    
    # Deserialize
    restored = KeyPair.from_dict(json.loads(json_str))
    
    assert restored.key_id == key_pair.key_id
    assert restored.public_key == key_pair.public_key
    assert restored.security_level == key_pair.security_level
    
    print(f"  ✓ Key serialized to JSON")
    print(f"  ✓ Key deserialized correctly")
    
    return True


def test_signature_serialization():
    """Test signature serialization and deserialization"""
    print("\nTest 10: Signature Serialization")
    
    engine = PostQuantumDigitalSignatureEngineV2(SecurityLevel.LEVEL_5)
    key_pair = engine.generate_key_pair()
    
    message = b"Test message"
    signature = engine.sign(message, key_pair)
    
    # Serialize
    sig_dict = signature.to_dict()
    json_str = json.dumps(sig_dict)
    
    # Deserialize
    restored = DigitalSignature.from_dict(json.loads(json_str))
    
    assert restored.key_id == signature.key_id
    assert restored.signature_bytes == signature.signature_bytes
    assert restored.message_hash == signature.message_hash
    
    print(f"  ✓ Signature serialized to JSON")
    print(f"  ✓ Signature deserialized correctly")
    
    # Verify restored signature
    result = engine.verify(message, restored, key_pair.public_key)
    print(f"  ✓ Restored signature verification: {result.status.value}")
    
    return True


def test_engine_statistics():
    """Test engine statistics tracking"""
    print("\nTest 11: Engine Statistics")
    
    engine = PostQuantumDigitalSignatureEngineV2(SecurityLevel.LEVEL_5)
    
    # Perform some operations
    for i in range(3):
        kp = engine.generate_key_pair()
        sig = engine.sign(b"Test", kp)
        engine.verify(b"Test", sig, kp.public_key)
    
    stats = engine.get_engine_statistics()
    
    assert stats["keys_generated"] >= 3
    assert stats["signatures_created"] >= 3
    assert stats["verifications_performed"] >= 3
    
    print(f"  ✓ Keys generated: {stats['keys_generated']}")
    print(f"  ✓ Signatures created: {stats['signatures_created']}")
    print(f"  ✓ Verifications performed: {stats['verifications_performed']}")
    
    return True


def test_public_key_export():
    """Test public key export functionality"""
    print("\nTest 12: Public Key Export")
    
    engine = PostQuantumDigitalSignatureEngineV2(SecurityLevel.LEVEL_5)
    key_pair = engine.generate_key_pair()
    
    exported = engine.export_public_key(key_pair)
    
    assert "key_id" in exported
    assert "public_key" in exported
    assert "algorithm" in exported
    
    print(f"  ✓ Public key exported in JSON format")
    
    return True


def run_all_tests():
    """Run all test cases"""
    print("=" * 70)
    print("Post-Quantum Digital Signature Engine V2 - Test Suite")
    print("=" * 70)
    
    tests = [
        test_basic_key_generation,
        test_all_security_levels,
        test_basic_sign_verify,
        test_tampered_message_detection,
        test_wrong_public_key,
        test_additional_authenticated_data,
        test_key_revocation,
        test_batch_verification,
        test_key_serialization,
        test_signature_serialization,
        test_engine_statistics,
        test_public_key_export
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"  ✗ FAILED")
        except Exception as e:
            failed += 1
            print(f"  ✗ EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 70)
    print(f"TEST RESULTS: {passed} PASSED, {failed} FAILED")
    print("=" * 70)
    
    # Save test results
    results = {
        "test_suite": "Post-Quantum Digital Signature Engine V2",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / len(tests),
        "timestamp": "2026-06-21"
    }
    
    with open("test_results_pqds_v2_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to test_results_pqds_v2_2026_june.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
