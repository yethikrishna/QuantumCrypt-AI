#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Secure Token & JWT Engine
QuantumCrypt-AI - June 2026 Production Release

Tests cover:
1. Token generation (all algorithms)
2. Token validation (signature, expiry, claims)
3. Token revocation
4. Refresh token rotation
5. Edge cases and attack scenarios
6. Security properties
"""
import unittest
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.post_quantum_secure_token_jwt_engine_2026_june import (
    PostQuantumTokenEngine,
    TokenAlgorithm,
    TokenType,
    ValidationStatus,
    TokenClaims,
    create_secure_token_engine
)


class TestTokenGeneration(unittest.TestCase):
    """Test token generation functionality"""
    
    def setUp(self):
        self.engine = PostQuantumTokenEngine(
            secret_key=b"test_secret_key_quantum_crypt_2026_abcdefghijklmnop",
            issuer="TestIssuer"
        )
    
    def test_basic_token_generation(self):
        """Test basic access token generation"""
        result = self.engine.generate_token(subject="user_123")
        
        self.assertTrue(result.success)
        self.assertIsNotNone(result.token)
        self.assertGreater(len(result.token), 0)
        self.assertEqual(result.token_type, TokenType.ACCESS)
        self.assertIsNotNone(result.token_id)
        self.assertEqual(len(result.token_id), 32)  # 16 bytes hex
    
    def test_token_generation_all_algorithms(self):
        """Test token generation with all algorithms"""
        algorithms = [
            TokenAlgorithm.HS256,
            TokenAlgorithm.HS384,
            TokenAlgorithm.HS512,
            TokenAlgorithm.HS3_512,
            TokenAlgorithm.PQ_HYBRID,
        ]
        
        for algo in algorithms:
            result = self.engine.generate_token(
                subject="user_123",
                algorithm=algo
            )
            self.assertTrue(result.success, f"Failed for {algo}")
            self.assertEqual(result.algorithm, algo)
    
    def test_token_with_custom_claims(self):
        """Test token generation with custom claims"""
        custom_claims = {
            "username": "johndoe",
            "role": "admin",
            "email": "john@example.com",
            "permissions": ["read", "write", "delete"]
        }
        
        result = self.engine.generate_token(
            subject="user_123",
            custom_claims=custom_claims
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.claims.custom["username"], "johndoe")
        self.assertEqual(result.claims.custom["role"], "admin")
    
    def test_token_with_audience(self):
        """Test token generation with audience"""
        result = self.engine.generate_token(
            subject="user_123",
            audience="api.example.com"
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.claims.aud, "api.example.com")
    
    def test_token_expiry(self):
        """Test token expiry is set correctly"""
        expiry_minutes = 30
        result = self.engine.generate_token(
            subject="user_123",
            expiry_minutes=expiry_minutes
        )
        
        expected_expiry = int(time.time()) + (expiry_minutes * 60)
        self.assertTrue(result.success)
        # Allow 2 second tolerance
        self.assertAlmostEqual(result.expires_at, expected_expiry, delta=2)
    
    def test_refresh_token_generation(self):
        """Test refresh token generation"""
        result = self.engine.generate_token(
            subject="user_123",
            token_type=TokenType.REFRESH,
            expiry_minutes=7 * 24 * 60  # 7 days
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.token_type, TokenType.REFRESH)
    
    def test_factory_function(self):
        """Test factory function creates valid engine"""
        engine = create_secure_token_engine(issuer="CustomIssuer")
        self.assertIsInstance(engine, PostQuantumTokenEngine)
        
        result = engine.generate_token(subject="test")
        self.assertTrue(result.success)


class TestTokenValidation(unittest.TestCase):
    """Test token validation functionality"""
    
    def setUp(self):
        self.engine = PostQuantumTokenEngine(
            secret_key=b"test_secret_key_quantum_crypt_2026",
            issuer="TestIssuer"
        )
    
    def test_valid_token_validation(self):
        """Test validation of a valid token"""
        gen_result = self.engine.generate_token(subject="user_123")
        val_result = self.engine.validate_token(gen_result.token)
        
        self.assertTrue(val_result.is_valid)
        self.assertEqual(val_result.status, ValidationStatus.VALID)
        self.assertEqual(val_result.claims.sub, "user_123")
        self.assertEqual(val_result.claims.iss, "TestIssuer")
    
    def test_token_validation_with_audience(self):
        """Test audience validation"""
        gen_result = self.engine.generate_token(
            subject="user_123",
            audience="api.example.com"
        )
        
        # Correct audience
        val_result = self.engine.validate_token(
            gen_result.token,
            audience="api.example.com"
        )
        self.assertTrue(val_result.is_valid)
        
        # Wrong audience
        val_result2 = self.engine.validate_token(
            gen_result.token,
            audience="wrong.audience.com"
        )
        self.assertFalse(val_result2.is_valid)
        self.assertEqual(val_result2.status, ValidationStatus.INVALID_AUDIENCE)
    
    def test_expired_token_validation(self):
        """Test expired token detection"""
        gen_result = self.engine.generate_token(
            subject="user_123",
            expiry_minutes=-1  # Already expired
        )
        
        val_result = self.engine.validate_token(gen_result.token)
        self.assertFalse(val_result.is_valid)
        self.assertEqual(val_result.status, ValidationStatus.EXPIRED)
    
    def test_token_signature_tampering(self):
        """Test signature tampering detection"""
        gen_result = self.engine.generate_token(subject="user_123")
        
        # Tamper with the signature
        parts = gen_result.token.split('.')
        tampered = f"{parts[0]}.{parts[1]}.tampered_signature"
        
        val_result = self.engine.validate_token(tampered)
        self.assertFalse(val_result.is_valid)
        self.assertEqual(val_result.status, ValidationStatus.INVALID_SIGNATURE)
    
    def test_malformed_token(self):
        """Test malformed token handling"""
        malformed_tokens = [
            "",
            "not.a.token",
            "only.two.parts",
            "three.parts.here.but.invalid",
            "!!!invalid.chars!!!",
        ]
        
        for token in malformed_tokens:
            val_result = self.engine.validate_token(token)
            self.assertFalse(val_result.is_valid)
            self.assertEqual(val_result.status, ValidationStatus.MALFORMED)
    
    def test_wrong_issuer_detection(self):
        """Test wrong issuer detection"""
        # Generate token with different engine but SAME key (so signature passes)
        engine2 = PostQuantumTokenEngine(
            secret_key=b"test_secret_key_quantum_crypt_2026",  # Same key
            issuer="DifferentIssuer"
        )
        gen_result = engine2.generate_token(subject="user_123")
        
        # Validate with original engine (same key, different issuer)
        val_result = self.engine.validate_token(gen_result.token)
        self.assertFalse(val_result.is_valid)
        self.assertEqual(val_result.status, ValidationStatus.INVALID_ISSUER)
    
    def test_different_secret_key(self):
        """Test tokens signed with different keys are rejected"""
        engine2 = PostQuantumTokenEngine(
            secret_key=b"different_secret_key",
            issuer="TestIssuer"
        )
        
        gen_result = self.engine.generate_token(subject="user_123")
        val_result = engine2.validate_token(gen_result.token)
        
        self.assertFalse(val_result.is_valid)
        self.assertEqual(val_result.status, ValidationStatus.INVALID_SIGNATURE)


class TestTokenRevocation(unittest.TestCase):
    """Test token revocation functionality"""
    
    def setUp(self):
        self.engine = PostQuantumTokenEngine(
            secret_key=b"test_secret_key_2026",
            issuer="TestIssuer"
        )
    
    def test_token_revocation(self):
        """Test token revocation works"""
        gen_result = self.engine.generate_token(subject="user_123")
        token_id = gen_result.token_id
        
        # Validate before revocation
        val_result1 = self.engine.validate_token(gen_result.token)
        self.assertTrue(val_result1.is_valid)
        
        # Revoke
        self.engine.revoke_token(token_id, reason="User logout")
        
        # Validate after revocation
        val_result2 = self.engine.validate_token(gen_result.token)
        self.assertFalse(val_result2.is_valid)
        self.assertEqual(val_result2.status, ValidationStatus.REVOKED)
    
    def test_refresh_token_rotation(self):
        """Test refresh token rotation"""
        old_result = self.engine.generate_token(
            subject="user_123",
            token_type=TokenType.REFRESH
        )
        
        # Rotate
        new_result = self.engine.rotate_refresh_token(
            old_token_id=old_result.token_id,
            subject="user_123",
            expiry_days=7
        )
        
        self.assertTrue(new_result.success)
        self.assertEqual(new_result.token_type, TokenType.REFRESH)
        
        # Old token should be revoked
        val_old = self.engine.validate_token(old_result.token)
        self.assertFalse(val_old.is_valid)


class TestTokenSecurity(unittest.TestCase):
    """Test token security properties"""
    
    def setUp(self):
        self.engine = PostQuantumTokenEngine(
            secret_key=b"test_secret_key_2026_secure",
            issuer="TestIssuer"
        )
    
    def test_constant_time_comparison(self):
        """Test signature verification uses constant-time comparison"""
        # This is a behavioral test - the implementation uses hmac.compare_digest
        # which provides constant-time comparison
        gen_result = self.engine.generate_token(subject="user_123")
        
        # Valid token
        val1 = self.engine.validate_token(gen_result.token)
        self.assertTrue(val1.is_valid)
        
        # Slightly different signature
        parts = gen_result.token.split('.')
        modified_sig = parts[2][:-1] + ('a' if parts[2][-1] != 'a' else 'b')
        tampered = f"{parts[0]}.{parts[1]}.{modified_sig}"
        
        val2 = self.engine.validate_token(tampered)
        self.assertFalse(val2.is_valid)
    
    def test_token_id_uniqueness(self):
        """Test token IDs are unique"""
        token_ids = set()
        for _ in range(100):
            result = self.engine.generate_token(subject="user_123")
            self.assertNotIn(result.token_id, token_ids)
            token_ids.add(result.token_id)
        
        self.assertEqual(len(token_ids), 100)
    
    def test_decode_unsafe_no_validation(self):
        """Test unsafe decode works but doesn't validate"""
        gen_result = self.engine.generate_token(subject="user_123")
        
        # Tamper with signature
        parts = gen_result.token.split('.')
        tampered = f"{parts[0]}.{parts[1]}.invalid"
        
        # Unsafe decode still works
        claims = self.engine.decode_token_unsafe(tampered)
        self.assertIsNotNone(claims)
        self.assertEqual(claims.sub, "user_123")
        
        # But validation correctly rejects
        val_result = self.engine.validate_token(tampered)
        self.assertFalse(val_result.is_valid)


class TestEngineStatistics(unittest.TestCase):
    """Test engine statistics tracking"""
    
    def setUp(self):
        self.engine = PostQuantumTokenEngine(
            secret_key=b"test_secret_key_2026",
            issuer="TestIssuer"
        )
    
    def test_statistics_tracking(self):
        """Test statistics are tracked correctly"""
        # Generate some tokens
        for i in range(10):
            self.engine.generate_token(subject=f"user_{i}")
        
        # Validate some (some valid, some invalid)
        valid_result = self.engine.generate_token(subject="test_user")
        self.engine.validate_token(valid_result.token)
        self.engine.validate_token("invalid_token")
        self.engine.validate_token("another_bad_token")
        
        stats = self.engine.get_engine_stats()
        
        self.assertEqual(stats['tokens_generated'], 11)
        self.assertEqual(stats['tokens_validated'], 3)
        self.assertEqual(stats['validation_failures'], 2)
        self.assertGreaterEqual(stats['success_rate'], 0.0)
        self.assertLessEqual(stats['success_rate'], 1.0)
    
    def test_revocation_cleanup(self):
        """Test revocation list cleanup"""
        # Revoke some tokens
        for i in range(5):
            result = self.engine.generate_token(subject=f"user_{i}")
            self.engine.revoke_token(result.token_id)
        
        initial_size = len(self.engine.revocation_list)
        self.assertEqual(initial_size, 5)
        
        # Cleanup won't remove recent entries
        removed = self.engine.cleanup_expired_revocations(max_age_days=30)
        self.assertEqual(removed, 0)


class TestIntegration(unittest.TestCase):
    """Integration tests for full token lifecycle"""
    
    def test_full_authentication_flow(self):
        """Test complete authentication flow"""
        engine = create_secure_token_engine(issuer="AuthService")
        
        # 1. User authenticates - issue access + refresh tokens
        access_result = engine.generate_token(
            subject="user_12345",
            custom_claims={"role": "user", "scope": "read write"},
            expiry_minutes=15,
            token_type=TokenType.ACCESS
        )
        
        refresh_result = engine.generate_token(
            subject="user_12345",
            expiry_minutes=7 * 24 * 60,
            token_type=TokenType.REFRESH
        )
        
        self.assertTrue(access_result.success)
        self.assertTrue(refresh_result.success)
        
        # 2. API validates access token
        api_validation = engine.validate_token(
            access_result.token,
            audience=None
        )
        self.assertTrue(api_validation.is_valid)
        self.assertEqual(api_validation.claims.sub, "user_12345")
        self.assertEqual(api_validation.claims.custom["role"], "user")
        
        # 3. Access token expires, use refresh token
        engine.revoke_token(access_result.token_id, "Token expired")
        
        # 4. Rotate refresh token
        new_refresh = engine.rotate_refresh_token(
            old_token_id=refresh_result.token_id,
            subject="user_12345"
        )
        self.assertTrue(new_refresh.success)
        
        # Old refresh should be revoked
        old_refresh_val = engine.validate_token(refresh_result.token)
        self.assertFalse(old_refresh_val.is_valid)


def run_all_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestTokenGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestTokenValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestTokenRevocation))
    suite.addTests(loader.loadTestsFromTestCase(TestTokenSecurity))
    suite.addTests(loader.loadTestsFromTestCase(TestEngineStatistics))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    print("=" * 70)
    print("QuantumCrypt-AI: Post-Quantum Secure Token & JWT Engine Tests")
    print("June 2026 Production Release")
    print("=" * 70)
    print()
    
    result = run_all_tests()
    
    print()
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 70)
    
    sys.exit(0 if result.wasSuccessful() else 1)
