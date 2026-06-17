"""
Test suite for Post-Quantum API HMAC Signer
Real, working tests with actual cryptographic verification
"""

import sys
import os
import time
import json

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_api_hmac_signer_2026_june import (
    PostQuantumAPISigner,
    PostQuantumHMAC,
    PostQuantumKeyDerivation,
    NonceManager,
    SignatureResult,
    VerificationResult
)


def test_key_derivation():
    """Test post-quantum key derivation"""
    print("=== Testing Post-Quantum Key Derivation ===")
    
    master_key = "test_master_secret_key_12345"
    salt = PostQuantumKeyDerivation.generate_salt(32)
    
    key1 = PostQuantumKeyDerivation.derive_key(master_key, salt, iterations=10000)
    key2 = PostQuantumKeyDerivation.derive_key(master_key, salt, iterations=10000)
    
    assert len(key1) == 64, f"Key should be 64 bytes, got {len(key1)}"
    assert key1 == key2, "Same inputs should produce same key"
    
    # Different salt should produce different key
    salt2 = PostQuantumKeyDerivation.generate_salt(32)
    key3 = PostQuantumKeyDerivation.derive_key(master_key, salt2, iterations=10000)
    assert key1 != key3, "Different salt should produce different key"
    
    print(f"  Salt length: {len(salt)} bytes")
    print(f"  Derived key length: {len(key1)} bytes")
    print(f"  Key deterministic: {key1 == key2}")
    print(f"  Salt-sensitive: {key1 != key3}")
    print("  ✓ Key Derivation: PASSED")
    return True


def test_hmac_signing():
    """Test HMAC signing and verification"""
    print("\n=== Testing HMAC Signing ===")
    
    hmac = PostQuantumHMAC("test_secret_key")
    
    message = "POST|/api/v1/data|1234567890|abc123|bodyhash"
    signature = hmac.compute_signature(message)
    
    assert signature is not None, "Should generate signature"
    assert len(signature) > 0, "Signature should not be empty"
    
    # Valid verification
    is_valid = hmac.verify_signature(message, signature)
    assert is_valid, "Valid signature should verify"
    
    # Tampered message
    is_invalid = hmac.verify_signature(message + "tampered", signature)
    assert not is_invalid, "Tampered message should not verify"
    
    # Wrong signature
    is_wrong = hmac.verify_signature(message, signature + "wrong")
    assert not is_wrong, "Wrong signature should not verify"
    
    print(f"  Message: {message[:40]}...")
    print(f"  Signature: {signature[:32]}...")
    print(f"  Valid signature: {is_valid}")
    print(f"  Tampered rejected: {not is_invalid}")
    print("  ✓ HMAC Signing: PASSED")
    return True


def test_nonce_manager():
    """Test nonce manager for replay protection"""
    print("\n=== Testing Nonce Manager ===")
    
    manager = NonceManager(max_nonces=100, ttl_seconds=300)
    
    # Generate nonce
    nonce1 = manager.generate_nonce()
    nonce2 = manager.generate_nonce()
    
    assert nonce1 != nonce2, "Nonces should be unique"
    assert len(nonce1) == 64, "Nonce should be 64 hex chars"
    
    # First use should be valid
    valid1, error1 = manager.validate_and_store_nonce(nonce1)
    assert valid1, "First nonce use should be valid"
    
    # Reuse should be invalid (replay protection)
    valid2, error2 = manager.validate_and_store_nonce(nonce1)
    assert not valid2, "Nonce reuse should be detected"
    assert "replay" in error2.lower(), "Should mention replay attack"
    
    print(f"  Nonce length: {len(nonce1)} chars")
    print(f"  Nonce unique: {nonce1 != nonce2}")
    print(f"  First use valid: {valid1}")
    print(f"  Replay detected: {not valid2}")
    print(f"  Active nonces: {len(manager.used_nonces)}")
    print("  ✓ Nonce Manager: PASSED")
    return True


def test_api_signer_basic():
    """Test basic API request signing"""
    print("\n=== Testing API Signer - Basic Signing ===")
    
    signer = PostQuantumAPISigner(
        api_key="test_api_key_123",
        api_secret="test_api_secret_456"
    )
    
    # Sign a request
    result = signer.sign_request(
        method="POST",
        path="/api/v1/secure/data",
        body={"user_id": 123, "action": "transfer", "amount": 100.50}
    )
    
    assert result.success, "Signing should succeed"
    assert result.signature is not None, "Should have signature"
    assert "X-API-Signature" in result.signed_headers, "Should have signature header"
    
    print(f"  Method: POST")
    print(f"  Path: /api/v1/secure/data")
    print(f"  Timestamp: {result.timestamp}")
    print(f"  Nonce: {result.nonce[:16]}...")
    print(f"  Signature: {result.signature[:32]}...")
    print(f"  Headers generated: {len(result.signed_headers)}")
    print("  ✓ API Signer Basic: PASSED")
    return True


def test_api_signer_verification():
    """Test full signing and verification cycle"""
    print("\n=== Testing API Signer - Full Verification ===")
    
    signer = PostQuantumAPISigner(
        api_key="test_api_key_123",
        api_secret="test_api_secret_456",
        timestamp_window=300
    )
    
    body = {"user_id": 123, "data": "sensitive_information"}
    
    # Sign
    sign_result = signer.sign_request("POST", "/api/v1/transfer", body)
    assert sign_result.success
    
    # Verify - should pass
    verify_result = signer.verify_request(
        method="POST",
        path="/api/v1/transfer",
        signature=sign_result.signature,
        timestamp=sign_result.timestamp,
        nonce=sign_result.nonce,
        body=body,
        provided_api_key="test_api_key_123"
    )
    
    assert verify_result.valid, "Valid request should pass verification"
    assert verify_result.timestamp_valid, "Timestamp should be valid"
    assert verify_result.nonce_valid, "Nonce should be valid"
    assert verify_result.integrity_valid, "Integrity should be valid"
    
    print(f"  Valid: {verify_result.valid}")
    print(f"  Timestamp valid: {verify_result.timestamp_valid}")
    print(f"  Nonce valid: {verify_result.nonce_valid}")
    print(f"  Integrity valid: {verify_result.integrity_valid}")
    print("  ✓ API Signer Verification: PASSED")
    return True


def test_tamper_detection():
    """Test that tampering is detected"""
    print("\n=== Testing Tamper Detection ===")
    
    signer = PostQuantumAPISigner(
        api_key="test_api_key_123",
        api_secret="test_api_secret_456"
    )
    
    body = {"amount": 100.00}
    sign_result = signer.sign_request("POST", "/api/transfer", body)
    
    # Tamper with body
    tampered_body = {"amount": 999999.00}  # Attacker changes amount
    
    verify_result = signer.verify_request(
        method="POST",
        path="/api/transfer",
        signature=sign_result.signature,
        timestamp=sign_result.timestamp,
        nonce=sign_result.nonce,
        body=tampered_body
    )
    
    assert not verify_result.valid, "Tampered body should be rejected"
    assert not verify_result.integrity_valid, "Integrity check should fail"
    
    print(f"  Original body: amount = 100.00")
    print(f"  Tampered body: amount = 999999.00")
    print(f"  Tampering detected: {not verify_result.valid}")
    print(f"  Error: {verify_result.error}")
    print("  ✓ Tamper Detection: PASSED")
    return True


def test_replay_attack_protection():
    """Test replay attack protection"""
    print("\n=== Testing Replay Attack Protection ===")
    
    signer = PostQuantumAPISigner(
        api_key="test_api_key_123",
        api_secret="test_api_secret_456"
    )
    
    body = {"action": "delete_account"}
    sign_result = signer.sign_request("POST", "/api/admin", body)
    
    # First verification - OK
    verify1 = signer.verify_request(
        "POST", "/api/admin", sign_result.signature,
        sign_result.timestamp, sign_result.nonce, body
    )
    
    # Replay same request - should fail (nonce already used)
    verify2 = signer.verify_request(
        "POST", "/api/admin", sign_result.signature,
        sign_result.timestamp, sign_result.nonce, body
    )
    
    assert verify1.valid, "First request should be valid"
    assert not verify2.valid, "Replay should be rejected"
    assert not verify2.nonce_valid, "Nonce validation should fail on replay"
    
    print(f"  First request valid: {verify1.valid}")
    print(f"  Replay request valid: {verify2.valid}")
    print(f"  Replay detected: {not verify2.valid}")
    print(f"  Error: {verify2.error}")
    print("  ✓ Replay Protection: PASSED")
    return True


def test_wrong_path_detection():
    """Test that wrong endpoint path is detected"""
    print("\n=== Testing Wrong Path Detection ===")
    
    signer = PostQuantumAPISigner(
        api_key="test_api_key_123",
        api_secret="test_api_secret_456"
    )
    
    # Signed for /api/legitimate
    sign_result = signer.sign_request("POST", "/api/legitimate", {"data": "test"})
    
    # Attacker tries to use it on /api/admin
    verify_result = signer.verify_request(
        "POST", "/api/admin", sign_result.signature,
        sign_result.timestamp, sign_result.nonce, {"data": "test"}
    )
    
    assert not verify_result.valid, "Wrong path should be rejected"
    
    print(f"  Signed for: /api/legitimate")
    print(f"  Attempted on: /api/admin")
    print(f"  Wrong path rejected: {not verify_result.valid}")
    print("  ✓ Wrong Path Detection: PASSED")
    return True


def test_security_stats():
    """Test security statistics"""
    print("\n=== Testing Security Statistics ===")
    
    signer = PostQuantumAPISigner(
        api_key="test_api_key_123",
        api_secret="test_api_secret_456"
    )
    
    stats = signer.get_security_stats()
    
    assert "algorithm" in stats
    assert "security_level" in stats
    assert stats["security_level"] == "post_quantum_resistant"
    
    print(f"  Algorithm: {stats['algorithm']}")
    print(f"  KDF: {stats['kdf']}")
    print(f"  Security Level: {stats['security_level']}")
    print(f"  Timestamp Window: {stats['timestamp_window_seconds']}s")
    print("  ✓ Security Stats: PASSED")
    return True


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("Post-Quantum API HMAC Signer - Test Suite")
    print("=" * 60)
    
    tests_passed = 0
    tests_total = 0
    
    test_functions = [
        test_key_derivation,
        test_hmac_signing,
        test_nonce_manager,
        test_api_signer_basic,
        test_api_signer_verification,
        test_tamper_detection,
        test_replay_attack_protection,
        test_wrong_path_detection,
        test_security_stats,
    ]
    
    for test_func in test_functions:
        tests_total += 1
        try:
            if test_func():
                tests_passed += 1
        except Exception as e:
            print(f"  ✗ {test_func.__name__}: FAILED - {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"TEST RESULTS: {tests_passed}/{tests_total} PASSED")
    print("=" * 60)
    
    if tests_passed == tests_total:
        print("\n✓ ALL TESTS PASSED - Feature is fully functional!")
        return True
    else:
        print(f"\n✗ {tests_total - tests_passed} TESTS FAILED")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
