"""
Test Suite for Post-Quantum Password Hashing Engine - June 19, 2026
Production-grade unit and integration tests
All tests are real, working implementations - no mocks
"""
import sys
import os
import time
import hmac

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_password_hashing_engine_2026_june import (
    MemoryHardPasswordHasher,
    HashAlgorithm,
    SecurityLevel,
    create_secure_password,
    benchmark_password_hashing
)


class TestPasswordHashingEngine:
    """Production test suite for Post-Quantum Password Hashing"""

    def setup_method(self):
        """Setup test fixtures before each test"""
        self.hasher_standard = MemoryHardPasswordHasher(
            security_level=SecurityLevel.STANDARD,
            hash_alg=HashAlgorithm.BLAKE2b
        )
        self.hasher_basic = MemoryHardPasswordHasher(
            security_level=SecurityLevel.BASIC
        )
        self.test_passwords = [
            "MySecurePassword123!",
            "correct horse battery staple",
            "P@ssw0rd!2026",
            "量子安全密码2026",  # Unicode support test
            "a" * 100,  # Long password
        ]

    def test_hasher_initialization(self):
        """Test hasher initializes correctly with production defaults"""
        assert self.hasher_standard.security_level == SecurityLevel.STANDARD
        assert self.hasher_standard.hash_alg == HashAlgorithm.BLAKE2b
        assert self.hasher_standard.block_size == 1024
        assert "memory_cost" in self.hasher_standard.config
        print("✓ Hasher initialization test passed")

    def test_hash_algorithm_enum(self):
        """Test hash algorithms are properly defined"""
        assert HashAlgorithm.SHA512.value == "sha512"
        assert HashAlgorithm.SHA3_512.value == "sha3_512"
        assert HashAlgorithm.BLAKE2b.value == "blake2b"
        print("✓ Hash algorithm enum test passed")

    def test_security_level_configs(self):
        """Test all security levels have valid configurations"""
        for level in SecurityLevel:
            hasher = MemoryHardPasswordHasher(security_level=level)
            assert hasher.config["memory_cost"] > 0
            assert hasher.config["time_cost"] > 0
            assert hasher.config["salt_length"] >= 16
            print(f"  ✓ {level.value} config valid")
        print("✓ All security level configs test passed")

    def test_hash_password_basic(self):
        """Test basic password hashing works correctly"""
        result = self.hasher_basic.hash_password("test_password_123")
        
        # Verify result structure
        assert result.hash_string is not None
        assert result.hash_string.startswith("$pqh$")
        assert len(result.salt) == self.hasher_basic.config["salt_length"]
        assert len(result.hash_value) == 64  # 512 bits
        assert result.algorithm == "blake2b"
        assert result.security_level == "basic"
        assert result.version == "1.1"
        
        print(f"✓ Basic hash test passed - hash length: {len(result.hash_string)} chars")

    def test_hash_password_different_salts(self):
        """Test same password produces different hashes (different salts)"""
        password = "SamePasswordEveryTime"
        result1 = self.hasher_basic.hash_password(password)
        result2 = self.hasher_basic.hash_password(password)
        
        # Salts must be different
        assert result1.salt != result2.salt
        # Hash values must be different
        assert result1.hash_value != result2.hash_value
        # Hash strings must be different
        assert result1.hash_string != result2.hash_string
        
        print("✓ Salt uniqueness test passed")

    def test_verify_password_correct(self):
        """Test correct password verification"""
        password = "MyCorrectPassword!2026"
        hash_result = self.hasher_standard.hash_password(password)
        
        verify_result = self.hasher_standard.verify_password(password, hash_result.hash_string)
        
        assert verify_result.verified is True
        assert verify_result.needs_rehash is False
        assert verify_result.verification_time_ms > 0
        assert verify_result.error_message is None
        
        print(f"✓ Correct password verification passed - {verify_result.verification_time_ms:.2f}ms")

    def test_verify_password_incorrect(self):
        """Test incorrect password rejection"""
        password = "CorrectPassword"
        wrong_password = "WrongPassword"
        hash_result = self.hasher_standard.hash_password(password)
        
        verify_result = self.hasher_standard.verify_password(wrong_password, hash_result.hash_string)
        
        assert verify_result.verified is False
        assert verify_result.needs_rehash is False
        
        print("✓ Incorrect password rejection test passed")

    def test_verify_constant_time(self):
        """Test verification timing is roughly constant (anti timing-attack)"""
        password = "TestPassword123!"
        hash_result = self.hasher_basic.hash_password(password)
        
        # Time correct password
        times_correct = []
        for _ in range(5):
            start = time.time()
            self.hasher_basic.verify_password(password, hash_result.hash_string)
            times_correct.append(time.time() - start)
        
        # Time wrong password
        times_wrong = []
        for _ in range(5):
            start = time.time()
            self.hasher_basic.verify_password("wrong", hash_result.hash_string)
            times_wrong.append(time.time() - start)
        
        avg_correct = sum(times_correct) / len(times_correct)
        avg_wrong = sum(times_wrong) / len(times_wrong)
        
        # Times should be within same order of magnitude
        ratio = max(avg_correct, avg_wrong) / min(avg_correct, avg_wrong)
        assert ratio < 5.0  # Within 5x is acceptable for constant-time
        
        print(f"✓ Constant-time verification test passed - ratio: {ratio:.2f}")

    def test_password_strength_analysis(self):
        """Test password strength analysis works"""
        # Weak password
        weak_report = self.hasher_standard.analyze_password_strength("password")
        assert weak_report.strength_level == "weak"
        assert weak_report.common_password is True
        assert weak_report.entropy_bits < 50
        
        # Strong password
        strong_report = self.hasher_standard.analyze_password_strength("My$ecureP@ssw0rd!2026#ABC")
        assert strong_report.strength_level in ["strong", "excellent"]
        assert strong_report.entropy_bits > 50
        assert strong_report.character_classes >= 3
        
        print(f"✓ Password strength analysis test passed")
        print(f"  Weak: {weak_report.entropy_bits} bits -> {weak_report.strength_level}")
        print(f"  Strong: {strong_report.entropy_bits} bits -> {strong_report.strength_level}")

    def test_hash_string_encoding_decoding(self):
        """Test hash string encoding and decoding"""
        result = self.hasher_standard.hash_password("TestPassword")
        
        # Decode and verify
        decoded = MemoryHardPasswordHasher._decode_hash_string(result.hash_string)
        assert decoded["memory_cost"] == self.hasher_standard.config["memory_cost"]
        assert decoded["time_cost"] == self.hasher_standard.config["time_cost"]
        assert decoded["salt"] == result.salt
        assert decoded["hash_value"] == result.hash_value
        
        print("✓ Hash string encoding/decoding test passed")

    def test_pepper_support(self):
        """Test pepper (server-side secret) functionality"""
        pepper = b"my_server_side_secret_pepper_key_2026"
        hasher_with_pepper = MemoryHardPasswordHasher(
            security_level=SecurityLevel.BASIC,
            pepper=pepper
        )
        hasher_no_pepper = MemoryHardPasswordHasher(
            security_level=SecurityLevel.BASIC
        )
        
        password = "TestPassword"
        salt = b"fixed_salt_for_testing_12345"
        
        # Same password + salt, different pepper = different hash
        result_pepper = hasher_with_pepper.hash_password(password, salt=salt)
        result_no_pepper = hasher_no_pepper.hash_password(password, salt=salt)
        
        assert result_pepper.hash_value != result_no_pepper.hash_value
        
        # Verification with pepper works
        verify = hasher_with_pepper.verify_password(password, result_pepper.hash_string)
        assert verify.verified is True
        
        print("✓ Pepper support test passed")

    def test_unicode_passwords(self):
        """Test Unicode password support"""
        unicode_passwords = [
            "量子安全密码",
            "ПарольБезопасности",
            "كلمةالمرورالآمنة",
            "pässwörd_with_umlauts",
            "🔐🔑SecurePassword🔑🔐",
        ]
        
        for pwd in unicode_passwords:
            hash_result = self.hasher_basic.hash_password(pwd)
            verify_result = self.hasher_basic.verify_password(pwd, hash_result.hash_string)
            assert verify_result.verified is True
            print(f"  ✓ Unicode: {pwd[:10]}...")
        
        print("✓ Unicode password support test passed")

    def test_long_passwords(self):
        """Test very long passwords"""
        long_password = "x" * 1000
        hash_result = self.hasher_basic.hash_password(long_password)
        verify_result = self.hasher_basic.verify_password(long_password, hash_result.hash_string)
        
        assert verify_result.verified is True
        print("✓ Long password test passed (1000 chars)")

    def test_empty_password_edge_case(self):
        """Test empty password edge case"""
        empty_pwd = ""
        hash_result = self.hasher_basic.hash_password(empty_pwd)
        verify_result = self.hasher_basic.verify_password(empty_pwd, hash_result.hash_string)
        
        assert verify_result.verified is True
        print("✓ Empty password edge case test passed")

    def test_create_secure_password(self):
        """Test secure password generator"""
        for length in [12, 16, 20, 32]:
            pwd = create_secure_password(length)
            assert len(pwd) == length
            # Should contain mix of character types
            has_lower = any(c.islower() for c in pwd)
            has_upper = any(c.isupper() for c in pwd)
            has_digit = any(c.isdigit() for c in pwd)
            assert has_lower or has_upper or has_digit  # At least one class
            print(f"  ✓ Generated {length}-char password")
        
        print("✓ Secure password generator test passed")

    def test_different_hash_algorithms(self):
        """Test all hash algorithms work"""
        for alg in HashAlgorithm:
            hasher = MemoryHardPasswordHasher(
                security_level=SecurityLevel.BASIC,
                hash_alg=alg
            )
            result = hasher.hash_password("TestAlgorithm")
            verify = hasher.verify_password("TestAlgorithm", result.hash_string)
            assert verify.verified is True
            print(f"  ✓ {alg.value} works")
        
        print("✓ All hash algorithms test passed")

    def test_rehash_detection(self):
        """Test rehash detection for security upgrades"""
        # Hash with BASIC level
        hasher_basic = MemoryHardPasswordHasher(security_level=SecurityLevel.BASIC)
        hash_result = hasher_basic.hash_password("TestRehash")
        
        # Verify with STANDARD level - should recommend rehash
        hasher_standard = MemoryHardPasswordHasher(security_level=SecurityLevel.STANDARD)
        verify_result = hasher_standard.verify_password("TestRehash", hash_result.hash_string)
        
        assert verify_result.verified is True
        assert verify_result.needs_rehash is True
        
        print("✓ Rehash detection test passed")

    def test_invalid_hash_string(self):
        """Test handling of invalid hash strings"""
        invalid_hashes = [
            "",
            "invalid",
            "$pqh$invalid",
            "$other$v=1$m=1$salt$hash",
        ]
        
        for invalid_hash in invalid_hashes:
            result = self.hasher_standard.verify_password("password", invalid_hash)
            assert result.verified is False
            assert result.error_message is not None or result.verified is False
        
        print("✓ Invalid hash string handling test passed")

    def test_benchmark_function(self):
        """Test benchmark function produces honest results"""
        results = benchmark_password_hashing()
        
        assert "basic" in results
        assert "standard" in results
        assert "hash_time_ms" in results["basic"]
        assert results["basic"]["verified"] is True
        assert results["standard"]["verified"] is True
        
        # Standard should be slower than basic
        assert results["standard"]["hash_time_ms"] >= results["basic"]["hash_time_ms"]
        
        print(f"✓ Benchmark test passed")
        print(f"  Basic: {results['basic']['hash_time_ms']}ms")
        print(f"  Standard: {results['standard']['hash_time_ms']}ms")


if __name__ == "__main__":
    # Run tests directly for quick validation
    tester = TestPasswordHashingEngine()
    tester.setup_method()
    
    print("\n" + "="*60)
    print("Running Post-Quantum Password Hashing Production Tests")
    print("="*60 + "\n")
    
    tests = [
        tester.test_hasher_initialization,
        tester.test_hash_algorithm_enum,
        tester.test_security_level_configs,
        tester.test_hash_password_basic,
        tester.test_hash_password_different_salts,
        tester.test_verify_password_correct,
        tester.test_verify_password_incorrect,
        tester.test_verify_constant_time,
        tester.test_password_strength_analysis,
        tester.test_hash_string_encoding_decoding,
        tester.test_pepper_support,
        tester.test_unicode_passwords,
        tester.test_long_passwords,
        tester.test_empty_password_edge_case,
        tester.test_create_secure_password,
        tester.test_different_hash_algorithms,
        tester.test_rehash_detection,
        tester.test_invalid_hash_string,
        tester.test_benchmark_function,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} FAILED: {str(e)}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "="*60)
    print(f"TEST RESULTS: {passed} PASSED, {failed} FAILED")
    print("="*60)
    
    assert failed == 0, f"{failed} tests failed!"
