#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure JWT Token Engine
Production-grade testing with real authentication scenarios
"""

import json
import sys
import time
from datetime import datetime

# Add the module path
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_secure_jwt_token_engine_2026_june import (
    PostQuantumJWTEngine,
    AlgorithmType,
    TokenStatus,
    TokenClaims,
    TokenValidationResult,
    PQKeyPair
)


def test_engine_initialization():
    """Test basic engine initialization"""
    print("Test 1: Engine Initialization")
    
    engine = PostQuantumJWTEngine(issuer="QuantumCrypt-Test")
    
    assert engine is not None
    assert engine.issuer == "QuantumCrypt-Test"
    assert len(engine.key_store) > 0
    
    metrics = engine.get_security_metrics()
    assert metrics["quantum_resistant"] == True
    assert metrics["active_signing_keys"] > 0
    
    print("  ✓ Engine initialized successfully")
    print(f"  ✓ Issuer: {engine.issuer}")
    print(f"  ✓ Active signing keys: {metrics['active_signing_keys']}")
    print(f"  ✓ Quantum resistant: {metrics['quantum_resistant']}")
    return True


def test_token_generation_basic():
    """Test basic token generation"""
    print("\nTest 2: Basic Token Generation")
    
    engine = PostQuantumJWTEngine()
    
    token = engine.generate_token(
        subject="user-12345",
        audience="api-service",
        roles=["user", "editor"],
        permissions=["read:data", "write:data"]
    )
    
    assert token is not None
    assert len(token) > 0
    assert token.count(".") == 2  # JWT format: header.payload.signature
    
    parts = token.split(".")
    assert len(parts[0]) > 0  # header
    assert len(parts[1]) > 0  # payload
    assert len(parts[2]) > 0  # signature
    
    print("  ✓ Token generated successfully")
    print(f"  ✓ Token length: {len(token)} characters")
    print(f"  ✓ Format: Valid JWT (3 parts)")
    return True


def test_token_validation_valid():
    """Test validation of a valid token"""
    print("\nTest 3: Valid Token Validation")
    
    engine = PostQuantumJWTEngine()
    
    token = engine.generate_token(
        subject="test-user",
        audience="test-api",
        roles=["admin"],
        custom_claims={"user_id": "u-001", "tenant": "acme"}
    )
    
    result = engine.validate_token(token, audience="test-api")
    
    assert result.is_valid == True
    assert result.status == TokenStatus.VALID
    assert result.claims is not None
    assert result.claims.sub == "test-user"
    assert result.claims.aud == "test-api"
    assert "admin" in result.claims.roles
    assert result.claims.quantum_resistant == True
    
    print("  ✓ Token validation passed")
    print(f"  ✓ Status: {result.status.value}")
    print(f"  ✓ Subject: {result.claims.sub}")
    print(f"  ✓ Quantum resistant: {result.claims.quantum_resistant}")
    print(f"  ✓ Algorithm: {result.claims.pq_algorithm}")
    return True


def test_token_validation_expired():
    """Test validation of an expired token"""
    print("\nTest 4: Expired Token Validation")
    
    engine = PostQuantumJWTEngine()
    
    # Generate token that expired in the past
    token = engine.generate_token(
        subject="test-user",
        lifetime_seconds=-3600  # Expired 1 hour ago
    )
    
    result = engine.validate_token(token)
    
    assert result.is_valid == False
    assert result.status == TokenStatus.EXPIRED
    
    print("  ✓ Expired token correctly rejected")
    print(f"  ✓ Status: {result.status.value}")
    print(f"  ✓ Error: {result.error_message}")
    return True


def test_token_validation_tampered():
    """Test validation of a tampered token"""
    print("\nTest 5: Tampered Token Validation")
    
    engine = PostQuantumJWTEngine()
    
    token = engine.generate_token(subject="legitimate-user")
    
    # Tamper with the token (modify payload)
    parts = token.split(".")
    tampered_token = f"{parts[0]}.tampered_payload.{parts[2]}"
    
    result = engine.validate_token(tampered_token)
    
    assert result.is_valid == False
    assert result.status in [TokenStatus.INVALID_SIGNATURE, TokenStatus.MALFORMED]
    
    print("  ✓ Tampered token correctly rejected")
    print(f"  ✓ Status: {result.status.value}")
    print("  ✓ Signature verification working correctly")
    return True


def test_token_validation_wrong_signature():
    """Test validation with wrong signature"""
    print("\nTest 6: Wrong Signature Validation")
    
    engine = PostQuantumJWTEngine()
    
    token = engine.generate_token(subject="user")
    
    # Replace signature with invalid one
    parts = token.split(".")
    bad_token = f"{parts[0]}.{parts[1]}.invalid_signature_12345"
    
    result = engine.validate_token(bad_token)
    
    assert result.is_valid == False
    assert result.status == TokenStatus.INVALID_SIGNATURE
    
    print("  ✓ Wrong signature correctly rejected")
    print(f"  ✓ Status: {result.status.value}")
    print("  ✓ Post-quantum signature verification active")
    return True


def test_token_revocation():
    """Test token revocation functionality"""
    print("\nTest 7: Token Revocation")
    
    engine = PostQuantumJWTEngine()
    
    token = engine.generate_token(subject="user-to-revoke")
    
    # Validate before revocation
    result1 = engine.validate_token(token)
    assert result1.is_valid == True
    
    # Revoke the token
    revoke_success = engine.revoke_token(token)
    assert revoke_success == True
    
    # Validate after revocation
    result2 = engine.validate_token(token)
    assert result2.is_valid == False
    assert result2.status == TokenStatus.REVOKED
    
    print("  ✓ Token revoked successfully")
    print(f"  ✓ Before revocation: VALID")
    print(f"  ✓ After revocation: {result2.status.value}")
    return True


def test_token_info_decoding():
    """Test token info decoding"""
    print("\nTest 8: Token Info Decoding")
    
    engine = PostQuantumJWTEngine()
    
    token = engine.generate_token(
        subject="info-test",
        roles=["reader", "writer"],
        custom_claims={"scope": "api:access"}
    )
    
    info = engine.get_token_info(token)
    
    assert info is not None
    assert "header" in info
    assert "payload" in info
    assert info["header"]["pq_secure"] == True
    assert info["payload"]["sub"] == "info-test"
    assert info["payload"]["quantum_resistant"] == True
    
    print("  ✓ Token info decoded successfully")
    print(f"  ✓ Algorithm: {info['header']['alg']}")
    print(f"  ✓ PQ Secure: {info['header']['pq_secure']}")
    print(f"  ✓ Signature length: {info['signature_length']} chars")
    return True


def test_different_algorithms():
    """Test token generation with different post-quantum algorithms"""
    print("\nTest 9: Multiple Post-Quantum Algorithms")
    
    engine = PostQuantumJWTEngine()
    
    algorithms = [
        AlgorithmType.DILITHIUM_3,
        AlgorithmType.HYBRID_DILITHIUM_HMAC,
        AlgorithmType.DILITHIUM_5,
    ]
    
    for algo in algorithms:
        token = engine.generate_token(
            subject=f"user-{algo.value}",
            algorithm=algo
        )
        result = engine.validate_token(token)
        
        assert result.is_valid == True
        assert result.claims.pq_algorithm == algo.value
        
        print(f"  ✓ {algo.value}: VALID")
    
    print(f"  ✓ All {len(algorithms)} post-quantum algorithms working")
    return True


def test_key_rotation():
    """Test key rotation functionality"""
    print("\nTest 10: Key Rotation")
    
    engine = PostQuantumJWTEngine()
    initial_key_count = len(engine.key_store)
    
    new_keys = engine.rotate_keys()
    
    assert len(new_keys) > 0
    assert len(engine.key_store) > initial_key_count
    
    print(f"  ✓ Initial keys: {initial_key_count}")
    print(f"  ✓ New keys generated: {len(new_keys)}")
    print(f"  ✓ Total keys now: {len(engine.key_store)}")
    print("  ✓ Quantum-safe key rotation working")
    return True


def test_malformed_token():
    """Test handling of malformed tokens"""
    print("\nTest 11: Malformed Token Handling")
    
    engine = PostQuantumJWTEngine()
    
    test_cases = [
        "",  # Empty
        "not.a.jwt.token",  # Too many parts
        "only.two",  # Too few parts
        "invalid.base64.here",  # Bad encoding
    ]
    
    for bad_token in test_cases:
        result = engine.validate_token(bad_token)
        assert result.is_valid == False
        assert result.status == TokenStatus.MALFORMED
    
    print(f"  ✓ All {len(test_cases)} malformed token cases handled")
    print("  ✓ Graceful error handling working")
    return True


def test_custom_claims():
    """Test custom claims preservation"""
    print("\nTest 12: Custom Claims")
    
    engine = PostQuantumJWTEngine()
    
    custom_data = {
        "user_id": "usr_abc123",
        "organization": "quantum_corp",
        "clearance_level": 5,
        "features": ["mfa", "sso", "pq_auth"],
        "metadata": {"last_login": "2026-06-20", "ip": "10.0.0.1"}
    }
    
    token = engine.generate_token(
        subject="custom-user",
        custom_claims=custom_data
    )
    
    result = engine.validate_token(token)
    
    assert result.is_valid == True
    assert result.claims.custom_claims["user_id"] == "usr_abc123"
    assert result.claims.custom_claims["organization"] == "quantum_corp"
    assert result.claims.custom_claims["clearance_level"] == 5
    
    print("  ✓ Custom claims preserved through signing/validation")
    print(f"  ✓ user_id: {result.claims.custom_claims['user_id']}")
    print(f"  ✓ organization: {result.claims.custom_claims['organization']}")
    print(f"  ✓ Nested data preserved")
    return True


def test_security_metrics():
    """Test security metrics reporting"""
    print("\nTest 13: Security Metrics")
    
    engine = PostQuantumJWTEngine()
    
    # Generate some tokens
    for i in range(5):
        engine.generate_token(subject=f"user-{i}")
    
    # Revoke one
    token = engine.generate_token(subject="revoked")
    engine.revoke_token(token)
    
    metrics = engine.get_security_metrics()
    
    assert metrics["unique_tokens_issued"] >= 6
    assert metrics["revoked_tokens"] == 1
    assert metrics["quantum_resistant"] == True
    assert metrics["security_level"] == "NIST Post-Quantum Standard"
    
    print(f"  ✓ Tokens issued: {metrics['unique_tokens_issued']}")
    print(f"  ✓ Revoked tokens: {metrics['revoked_tokens']}")
    print(f"  ✓ Security level: {metrics['security_level']}")
    print(f"  ✓ Key rotation period: {metrics['key_rotation_days']} days")
    return True


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("POST-QUANTUM SECURE JWT ENGINE - PRODUCTION TEST SUITE")
    print("=" * 60)
    print(f"Test Time: {datetime.now().isoformat()}")
    print()
    
    tests = [
        test_engine_initialization,
        test_token_generation_basic,
        test_token_validation_valid,
        test_token_validation_expired,
        test_token_validation_tampered,
        test_token_validation_wrong_signature,
        test_token_revocation,
        test_token_info_decoding,
        test_different_algorithms,
        test_key_rotation,
        test_malformed_token,
        test_custom_claims,
        test_security_metrics,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  ✗ FAILED: {str(e)}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Write results
    result = {
        "test_timestamp": datetime.now().isoformat(),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": (passed / len(tests)) * 100,
        "module": "post_quantum_secure_jwt_token_engine_2026_june",
        "quantum_resistant": True,
        "algorithms_supported": len(AlgorithmType)
    }
    
    with open("/home/user/autonomous-developer/QuantumCrypt-AI/test_results_secure_jwt_token_engine.json", "w") as f:
        json.dump(result, f, indent=2)
    
    print(f"Results written to test_results_secure_jwt_token_engine.json")
    print(f"Success Rate: {result['success_rate']:.1f}%")
    print(f"Algorithms Supported: {result['algorithms_supported']}")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
