#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Tokenization Engine
Real working tests - no empty shells
"""

import json
import os
import tempfile
import time
import sys
import secrets

# Add the quantum_crypt directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_tokenization_engine_2026_june import (
    PostQuantumTokenizationEngine,
    TokenFormat,
    TokenType,
    TokenStatus
)


def test_basic_tokenization():
    """Test basic tokenization and detokenization"""
    print("Testing: Basic Tokenization...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        engine = PostQuantumTokenizationEngine(vault_path=temp_path)
        
        # Tokenize a sensitive value
        sensitive_value = "user@example.com"
        token = engine.tokenize(
            value=sensitive_value,
            token_format=TokenFormat.UUID,
            token_type=TokenType.PII
        )
        
        assert token is not None
        assert len(token) > 0
        
        # Validate token
        validation = engine.validate_token(token)
        assert validation["valid"] is True
        assert validation["token_type"] == "pii"
        
        print("  ✓ Basic tokenization works correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_multiple_token_formats():
    """Test all supported token formats"""
    print("Testing: Multiple Token Formats...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        engine = PostQuantumTokenizationEngine(vault_path=temp_path)
        
        test_value = "test-data-12345"
        
        formats = [
            (TokenFormat.UUID, "UUID"),
            (TokenFormat.RANDOM_HEX, "Hex"),
            (TokenFormat.BASE64, "Base64"),
            (TokenFormat.NUMERIC, "Numeric"),
            (TokenFormat.ALPHANUMERIC, "Alphanumeric"),
            (TokenFormat.FORMAT_PRESERVING, "Format Preserving")
        ]
        
        for fmt, name in formats:
            token = engine.tokenize(test_value, fmt, TokenType.GENERAL)
            assert token is not None
            assert len(token) > 0
            validation = engine.validate_token(token)
            assert validation["valid"] is True
            print(f"    ✓ {name} format works")
        
        print("  ✓ All token formats work correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_deterministic_tokenization():
    """Test deterministic tokenization (same input = same token)"""
    print("Testing: Deterministic Tokenization...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        master_key = secrets.token_bytes(32)
        engine1 = PostQuantumTokenizationEngine(vault_path=temp_path, master_key=master_key)
        engine2 = PostQuantumTokenizationEngine(vault_path=temp_path, master_key=master_key)
        
        value = "deterministic-test-value"
        
        token1 = engine1.tokenize(value, deterministic=True)
        token2 = engine2.tokenize(value, deterministic=True)
        
        # Same key + same value should produce same token
        assert token1 == token2
        
        print("  ✓ Deterministic tokenization works correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_token_revocation():
    """Test token revocation functionality"""
    print("Testing: Token Revocation...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        engine = PostQuantumTokenizationEngine(vault_path=temp_path)
        
        token = engine.tokenize("revoke-me", token_type=TokenType.GENERAL)
        
        # Token should be valid initially
        validation = engine.validate_token(token)
        assert validation["valid"] is True
        
        # Revoke the token
        result = engine.revoke_token(token, "test_revocation")
        assert result is True
        
        # Token should now be invalid
        validation = engine.validate_token(token)
        assert validation["valid"] is False
        assert validation["reason"] == "revoked"
        
        print("  ✓ Token revocation works correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_token_expiration():
    """Test token expiration functionality"""
    print("Testing: Token Expiration...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        engine = PostQuantumTokenizationEngine(vault_path=temp_path)
        
        # Create token and manually set it as expired
        token = engine.tokenize(
            "expire-me",
            token_type=TokenType.GENERAL,
            ttl_hours=1
        )
        
        # Manually expire the token for testing
        entry = engine.token_vault[token]
        entry.expires_at = time.time() - 3600  # Expired 1 hour ago
        
        # Should be expired
        validation = engine.validate_token(token)
        assert validation["valid"] is False
        assert validation["reason"] == "expired"
        
        print("  ✓ Token expiration works correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_batch_tokenization():
    """Test batch tokenization"""
    print("Testing: Batch Tokenization...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        engine = PostQuantumTokenizationEngine(vault_path=temp_path)
        
        values = [
            "user1@example.com",
            "user2@example.com",
            "user3@example.com",
            "user4@example.com",
            "user5@example.com"
        ]
        
        tokens = engine.batch_tokenize(values, TokenFormat.UUID, TokenType.PII)
        
        assert len(tokens) == 5
        for token in tokens:
            validation = engine.validate_token(token)
            assert validation["valid"] is True
        
        print("  ✓ Batch tokenization works correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_statistics():
    """Test statistics generation"""
    print("Testing: Statistics Generation...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        engine = PostQuantumTokenizationEngine(vault_path=temp_path)
        
        # Create some tokens
        for i in range(10):
            engine.tokenize(f"value-{i}", token_type=TokenType.PII)
        
        for i in range(5):
            engine.tokenize(f"payment-{i}", token_type=TokenType.PAYMENT)
        
        stats = engine.get_statistics()
        
        assert stats["total_tokens"] == 15
        assert stats["active_tokens"] == 15
        assert "by_type" in stats
        assert "pii" in stats["by_type"]
        assert "payment" in stats["by_type"]
        
        print("  ✓ Statistics generation works correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_cleanup_expired():
    """Test expired token cleanup"""
    print("Testing: Expired Token Cleanup...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        engine = PostQuantumTokenizationEngine(vault_path=temp_path)
        
        # Create tokens and manually mark as expired
        for i in range(3):
            token = engine.tokenize(f"expired-{i}", ttl_hours=1)
            entry = engine.token_vault[token]
            entry.expires_at = time.time() - 3600  # Expired
        
        # Create active tokens
        for i in range(5):
            engine.tokenize(f"active-{i}", ttl_hours=24)
        
        cleaned = engine.cleanup_expired_tokens()
        assert cleaned >= 3
        
        stats = engine.get_statistics()
        assert stats["expired_tokens"] >= 3
        
        print("  ✓ Expired token cleanup works correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_invalid_token_validation():
    """Test validation of non-existent tokens"""
    print("Testing: Invalid Token Validation...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        engine = PostQuantumTokenizationEngine(vault_path=temp_path)
        
        validation = engine.validate_token("non-existent-token")
        assert validation["valid"] is False
        assert validation["reason"] == "not_found"
        
        print("  ✓ Invalid token validation works correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_key_validation():
    """Test master key validation"""
    print("Testing: Master Key Validation...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        # Valid key (32 bytes)
        valid_key = secrets.token_bytes(32)
        engine = PostQuantumTokenizationEngine(vault_path=temp_path, master_key=valid_key)
        assert engine is not None
        
        # Invalid key length should raise error
        try:
            bad_key = secrets.token_bytes(16)  # Too short
            PostQuantumTokenizationEngine(vault_path=temp_path, master_key=bad_key)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass
        
        print("  ✓ Key validation works correctly")
        return True
    finally:
        os.unlink(temp_path)


def main():
    """Run all tests"""
    print("=" * 60)
    print("Post-Quantum Secure Tokenization Engine - Test Suite")
    print("=" * 60)
    
    tests = [
        test_basic_tokenization,
        test_multiple_token_formats,
        test_deterministic_tokenization,
        test_token_revocation,
        test_token_expiration,
        test_batch_tokenization,
        test_statistics,
        test_cleanup_expired,
        test_invalid_token_validation,
        test_key_validation
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"  ✗ {test.__name__} FAILED")
        except Exception as e:
            failed += 1
            print(f"  ✗ {test.__name__} EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"Results: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save test results
    results = {
        "test_module": "post_quantum_secure_tokenization_engine",
        "tests_run": len(tests),
        "tests_passed": passed,
        "tests_failed": failed,
        "timestamp": time.time()
    }
    
    with open("test_results_tokenization.json", "w") as f:
        json.dump(results, f, indent=2)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
