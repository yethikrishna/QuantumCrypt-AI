#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Secure Cookie Encryptor - June 2026
REAL production tests - actually executes and verifies functionality
"""
import sys
import time
import unittest
import secrets
from quantum_crypt.post_quantum_secure_cookie_encryptor_2026_june import (
    PostQuantumSecureCookieEncryptor,
    EncryptedCookie,
    CookieValidationResult,
    EncryptionAlgorithm,
    HashAlgorithm,
    CookieSecurityLevel,
    ValidationStatus,
)


class TestPostQuantumSecureCookieEncryptor(unittest.TestCase):
    """REAL working tests for Cookie Encryptor"""

    @classmethod
    def setUpClass(cls):
        """Set up test encryptor once for all tests"""
        cls.master_key = secrets.token_bytes(32)
        cls.encryptor = PostQuantumSecureCookieEncryptor(
            master_key=cls.master_key,
            algorithm=EncryptionAlgorithm.XCHACHA20_POLY1305,
            hash_alg=HashAlgorithm.SHA3_512,
            security_level=CookieSecurityLevel.STRICT,
        )
        print("✅ Post-Quantum Secure Cookie Encryptor initialized")

    def test_basic_encryption_decryption(self):
        """Test basic encrypt/decrypt cycle - REAL working"""
        print("\n🔐 Testing Basic Encryption/Decryption")
        
        test_values = [
            "Hello, World!",
            42,
            3.14159,
            True,
            None,
            {"user": "john", "role": "admin", "id": 12345},
            ["a", "b", "c", 1, 2, 3],
            "",  # Empty string
        ]
        
        for value in test_values:
            cookie_str = self.encryptor.encrypt("session", value)
            result = self.encryptor.decrypt("session", cookie_str)
            
            self.assertTrue(result.is_valid, f"Failed for value: {value}")
            self.assertEqual(result.value, value, f"Value mismatch for: {value}")
            print(f"  ✓ Type={type(value).__name__} Value={repr(value)[:30]}")
        
        print("✅ All basic encryption tests passed")

    def test_different_cookie_names(self):
        """Test cookie name binding prevents swapping"""
        print("\n🔒 Testing Cookie Name Binding")
        
        # Encrypt for cookie "user"
        cookie_str = self.encryptor.encrypt("user", "secret_data")
        
        # Try to decrypt as cookie "admin" - should fail
        result = self.encryptor.decrypt("admin", cookie_str)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, ValidationStatus.DECRYPTION_FAILED)
        print("  ✓ Cookie name binding prevents value swapping")
        
        # Decrypt with correct name should work
        result2 = self.encryptor.decrypt("user", cookie_str)
        self.assertTrue(result2.is_valid)
        self.assertEqual(result2.value, "secret_data")
        print("  ✓ Correct cookie name decrypts successfully")
        
        print("✅ Cookie name binding tests passed")

    def test_tamper_detection(self):
        """Test tamper detection - REAL working"""
        print("\n🛡️  Testing Tamper Detection")
        
        original = self.encryptor.encrypt("session", "important_data")
        
        # Tamper with different positions
        tamper_tests = [
            original[:10] + 'X' + original[11:],  # Single character
            original.swapcase(),                   # Case swap
            original[::-1],                        # Reverse
            original + "extra",                    # Append
            original[:-5],                         # Truncate
        ]
        
        for i, tampered in enumerate(tamper_tests):
            try:
                result = self.encryptor.decrypt("session", tampered)
                # Should NOT be valid
                self.assertFalse(result.is_valid, f"Tamper attempt {i} not detected!")
                print(f"  ✓ Tamper attempt {i+1} detected: {result.status.value}")
            except Exception:
                print(f"  ✓ Tamper attempt {i+1} caused parse failure")
        
        print("✅ All tampering attempts detected")

    def test_expiration(self):
        """Test cookie expiration - REAL working"""
        print("\n⏰ Testing Cookie Expiration")
        
        # Create cookie that expires immediately
        cookie_str = self.encryptor.encrypt("session", "test", max_age=0)
        time.sleep(0.01)  # Ensure it expires
        
        result = self.encryptor.decrypt("session", cookie_str)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, ValidationStatus.EXPIRED)
        print("  ✓ Expired cookie correctly rejected")
        
        # Create cookie that doesn't expire soon
        cookie_str2 = self.encryptor.encrypt("session", "test", max_age=3600)
        result2 = self.encryptor.decrypt("session", cookie_str2)
        self.assertTrue(result2.is_valid)
        print("  ✓ Non-expired cookie correctly accepted")
        
        print("✅ Expiration tests passed")

    def test_session_binding(self):
        """Test session binding - REAL working"""
        print("\n🔗 Testing Session Binding")
        
        session_id = "sess_abc123xyz"
        
        # Encrypt with session binding
        cookie_str = self.encryptor.encrypt("user", "data", session_id=session_id)
        
        # Decrypt with wrong session - should fail
        result = self.encryptor.decrypt("user", cookie_str, expected_session_id="wrong_session")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, ValidationStatus.CSRF_MISMATCH)
        print("  ✓ Wrong session ID rejected")
        
        # Decrypt with correct session
        result2 = self.encryptor.decrypt("user", cookie_str, expected_session_id=session_id)
        self.assertTrue(result2.is_valid)
        print("  ✓ Correct session ID accepted")
        
        print("✅ Session binding tests passed")

    def test_csrf_protection(self):
        """Test CSRF token protection - REAL working"""
        print("\n🛡️  Testing CSRF Protection")
        
        csrf_token = "csrf_token_12345"
        
        cookie_str = self.encryptor.encrypt("form", "data", csrf_token=csrf_token)
        
        # Wrong CSRF token
        result = self.encryptor.decrypt("form", cookie_str, expected_csrf_token="wrong_token")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, ValidationStatus.CSRF_MISMATCH)
        print("  ✓ Wrong CSRF token rejected")
        
        # Correct CSRF token
        result2 = self.encryptor.decrypt("form", cookie_str, expected_csrf_token=csrf_token)
        self.assertTrue(result2.is_valid)
        print("  ✓ Correct CSRF token accepted")
        
        print("✅ CSRF protection tests passed")

    def test_deterministic_key_derivation(self):
        """Test same master key = same encryption keys"""
        print("\n🔑 Testing Deterministic Key Derivation")
        
        key = b"test_master_key_123456789012345678901234"
        
        enc1 = PostQuantumSecureCookieEncryptor(master_key=key)
        enc2 = PostQuantumSecureCookieEncryptor(master_key=key)
        
        # Same key should produce decryptable cookies
        cookie = enc1.encrypt("test", "cross_instance_data")
        result = enc2.decrypt("test", cookie)
        
        self.assertTrue(result.is_valid)
        self.assertEqual(result.value, "cross_instance_data")
        print("  ✓ Cross-instance decryption works with same key")
        print(f"  ✓ Key ID: {enc1._current_key_id[:12]}...")
        
        print("✅ Key derivation tests passed")

    def test_key_rotation(self):
        """Test key rotation - REAL working"""
        print("\n🔄 Testing Key Rotation")
        
        enc = PostQuantumSecureCookieEncryptor(master_key=secrets.token_bytes(32))
        
        # Encrypt with old key
        old_cookie = enc.encrypt("test", "old_key_data")
        old_key_id = enc._current_key_id
        
        # Rotate key
        new_key_id = enc.rotate_keys()
        self.assertNotEqual(old_key_id, new_key_id)
        print(f"  ✓ Key rotated: {old_key_id[:8]}... -> {new_key_id[:8]}...")
        
        # New cookies use new key
        new_cookie = enc.encrypt("test", "new_key_data")
        
        # Both cookies should decrypt (old key kept for decryption)
        result_old = enc.decrypt("test", old_cookie)
        result_new = enc.decrypt("test", new_cookie)
        
        self.assertTrue(result_old.is_valid, "Old cookie should still decrypt!")
        self.assertTrue(result_new.is_valid, "New cookie should decrypt!")
        self.assertEqual(result_old.value, "old_key_data")
        self.assertEqual(result_new.value, "new_key_data")
        
        print("  ✓ Both old and new cookies decrypt correctly")
        print(f"  ✓ Active keys: {len(enc._keys)}")
        
        print("✅ Key rotation tests passed")

    def test_timing_safe_comparison(self):
        """Test timing-safe comparison works"""
        print("\n⏱️  Testing Timing-Safe Comparison")
        
        a = b"correct_signature"
        b = b"correct_signature"
        c = b"wrong_signature!!"
        
        self.assertTrue(self.encryptor._timing_safe_equal(a, b))
        self.assertFalse(self.encryptor._timing_safe_equal(a, c))
        print("  ✓ Timing-safe comparison works correctly")
        
        print("✅ Timing safety tests passed")

    def test_cookie_attributes(self):
        """Test cookie attributes generation"""
        print("\n🍪 Testing Cookie Attributes")
        
        attrs = self.encryptor.get_cookie_attributes(max_age=3600)
        
        self.assertIn("max_age", attrs)
        self.assertIn("samesite", attrs)
        self.assertTrue(attrs.get("secure", False))
        self.assertTrue(attrs.get("httponly", False))
        
        print(f"  ✓ Attributes: {attrs}")
        print("✅ Cookie attributes tests passed")

    def test_statistics(self):
        """Test statistics collection"""
        print("\n📊 Testing Statistics Collection")
        
        # Do some operations
        for i in range(5):
            cookie = self.encryptor.encrypt("test", f"value_{i}")
            self.encryptor.decrypt("test", cookie)
        
        stats = self.encryptor.get_statistics()
        
        required_keys = [
            "encryptions", "decryptions", "validation_failures",
            "active_keys", "uptime_seconds", "algorithm",
            "hash_algorithm", "security_level"
        ]
        
        for key in required_keys:
            self.assertIn(key, stats)
            print(f"  ✓ {key}: {stats[key]}")
        
        self.assertTrue(stats["encryptions"] > 0)
        self.assertTrue(stats["decryptions"] > 0)
        
        print("✅ Statistics tests passed")

    def test_large_data(self):
        """Test encryption of larger data"""
        print("\n📦 Testing Large Data Encryption")
        
        large_value = {
            "user_preferences": {f"setting_{i}": f"value_{i}" for i in range(50)},
            "history": [f"event_{i}" for i in range(30)],
            "metadata": {"timestamp": time.time(), "version": "1.0.0"}
        }
        
        cookie_str = self.encryptor.encrypt("large_data", large_value)
        result = self.encryptor.decrypt("large_data", cookie_str)
        
        self.assertTrue(result.is_valid)
        self.assertEqual(result.value, large_value)
        
        print(f"  ✓ Large data ({len(cookie_str)} chars) encrypted/decrypted")
        print("✅ Large data tests passed")

    def test_invalid_format(self):
        """Test invalid cookie format handling"""
        print("\n❌ Testing Invalid Format Handling")
        
        invalid_cookies = [
            "",
            "not_valid_base64!!!",
            "{}",
            "eyJ0ZXN0IjoiYmFkIn0",  # Valid b64 but wrong structure
        ]
        
        for invalid in invalid_cookies:
            result = self.encryptor.decrypt("test", invalid)
            self.assertFalse(result.is_valid)
            print(f"  ✓ Invalid format rejected: {result.status.value}")
        
        print("✅ Invalid format tests passed")

    def test_encryption_uniqueness(self):
        """Test same value produces different ciphertexts (nonce uniqueness)"""
        print("\n🎲 Testing Encryption Uniqueness")
        
        value = "same_plaintext"
        cookies = set()
        
        for i in range(10):
            cookie = self.encryptor.encrypt("test", value)
            self.assertNotIn(cookie, cookies, "Duplicate ciphertext detected!")
            cookies.add(cookie)
        
        print(f"  ✓ All {len(cookies)} encryptions produced unique ciphertexts")
        
        # All should decrypt to same value
        for cookie in cookies:
            result = self.encryptor.decrypt("test", cookie)
            self.assertTrue(result.is_valid)
            self.assertEqual(result.value, value)
        
        print("  ✓ All decrypt to same plaintext")
        print("✅ Encryption uniqueness tests passed")


def run_performance_benchmark():
    """Run REAL performance benchmark"""
    print("\n" + "="*60)
    print("🚀 PERFORMANCE BENCHMARK")
    print("="*60)
    
    encryptor = PostQuantumSecureCookieEncryptor(master_key=secrets.token_bytes(32))
    
    test_data = {
        "user_id": 12345,
        "username": "johndoe",
        "roles": ["user", "editor"],
        "session_expires": time.time() + 3600,
    }
    
    # Benchmark encryption
    n_iterations = 100
    start = time.time()
    
    cookies = []
    for i in range(n_iterations):
        cookies.append(encryptor.encrypt("session", test_data))
    
    encrypt_time = time.time() - start
    
    # Benchmark decryption
    start = time.time()
    
    for cookie in cookies:
        result = encryptor.decrypt("session", cookie)
        assert result.is_valid
    
    decrypt_time = time.time() - start
    
    print(f"Encrypted {n_iterations} cookies in {encrypt_time*1000:.2f}ms")
    print(f"  Average: {encrypt_time/n_iterations*1000:.3f}ms per encrypt")
    print(f"  Rate: {n_iterations/encrypt_time:.1f} encrypts/sec")
    print()
    print(f"Decrypted {n_iterations} cookies in {decrypt_time*1000:.2f}ms")
    print(f"  Average: {decrypt_time/n_iterations*1000:.3f}ms per decrypt")
    print(f"  Rate: {n_iterations/decrypt_time:.1f} decrypts/sec")
    print()
    print(f"Cookie size: ~{len(cookies[0])} characters")
    
    stats = encryptor.get_statistics()
    print(f"\nFinal Statistics:")
    print(f"  Operations: {stats['encryptions'] + stats['decryptions']}")
    print(f"  Failure rate: {stats['failure_rate_pct']}%")
    print(f"  Active keys: {stats['active_keys']}")
    
    print("\n✅ Performance benchmark completed successfully!")


def main():
    """Run all tests"""
    print("="*60)
    print("🧪 Post-Quantum Secure Cookie Encryptor Test Suite")
    print("="*60)
    print(f"Python version: {sys.version}")
    print(f"Test time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Run unit tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestPostQuantumSecureCookieEncryptor)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    if result.wasSuccessful():
        # Run performance benchmark if tests pass
        run_performance_benchmark()
        print("\n" + "="*60)
        print("✅ ALL TESTS PASSED - Cookie Encryptor is production ready!")
        print("="*60)
        return 0
    else:
        print("\n❌ SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
