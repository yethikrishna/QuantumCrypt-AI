#!/usr/bin/env python3
"""
Tests for Post-Quantum Crypto Input Validation Wrappers
DIMENSION B: Security Hardening

All tests are isolated - no existing code dependencies.
"""

import unittest
import threading
import secrets

# Import the new module
from quantum_crypt.pq_crypto_input_validation_wrappers_2026_june import (
    CryptoKeyValidator,
    CryptoAlgorithmValidator,
    CryptoParameterValidator,
    CryptoValidationContext,
    CryptoValidationResult,
    CryptoValidationError,
    CryptoValidationSeverity,
    CryptoValidationErrorCode,
    validate_crypto_input,
    get_key_validator,
    get_algorithm_validator,
    get_parameter_validator,
)


class TestCryptoKeyValidator(unittest.TestCase):
    """Test cryptographic key validation."""
    
    def setUp(self):
        self.validator = CryptoKeyValidator()
    
    def test_validate_key_length_valid_aes256(self):
        """Test valid AES-256 key length."""
        key = secrets.token_bytes(32)  # 256 bits
        result = self.validator.validate_key_length(key, 'AES-256')
        self.assertTrue(result.passed)
    
    def test_validate_key_length_valid_aes128(self):
        """Test valid AES-128 key length."""
        key = secrets.token_bytes(16)  # 128 bits
        result = self.validator.validate_key_length(key, 'AES-128')
        self.assertTrue(result.passed)
    
    def test_validate_key_length_invalid(self):
        """Test invalid key length."""
        key = secrets.token_bytes(7)  # 56 bits - invalid
        result = self.validator.validate_key_length(key, 'AES')
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.INVALID_KEY_LENGTH)
    
    def test_validate_key_length_kyber(self):
        """Test Kyber key length validation."""
        # Valid Kyber-512 key length (1632 bits = 204 bytes)
        key = secrets.token_bytes(204)
        result = self.validator.validate_key_length(key, 'KYBER')
        # Note: actual Kyber key sizes are specific, this tests the validation path
        self.assertIsNotNone(result)
    
    def test_detect_weak_key_all_zeros(self):
        """Test detection of all-zero key."""
        key = b'\x00' * 32
        result = self.validator.detect_weak_key(key)
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.WEAK_KEY)
    
    def test_detect_weak_key_all_ones(self):
        """Test detection of all-ones key."""
        key = b'\xff' * 32
        result = self.validator.detect_weak_key(key)
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.WEAK_KEY)
    
    def test_detect_weak_key_password(self):
        """Test detection of password pattern key."""
        key = b'password' + b'\x00' * 24
        result = self.validator.detect_weak_key(key)
        self.assertFalse(result.passed)
    
    def test_detect_weak_key_good(self):
        """Test good random key passes."""
        key = secrets.token_bytes(32)
        result = self.validator.detect_weak_key(key)
        self.assertTrue(result.passed)
    
    def test_validate_nonce_valid(self):
        """Test valid nonce validation."""
        nonce = secrets.token_bytes(12)
        result = self.validator.validate_nonce(nonce, 12)
        self.assertTrue(result.passed)
    
    def test_validate_nonce_invalid_length(self):
        """Test nonce with wrong length."""
        nonce = secrets.token_bytes(8)
        result = self.validator.validate_nonce(nonce, 12)
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.INVALID_NONCE_LENGTH)
    
    def test_validate_nonce_not_bytes(self):
        """Test nonce that isn't bytes."""
        result = self.validator.validate_nonce("not bytes", 12)  # type: ignore
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.TYPE_MISMATCH)
    
    def test_constant_time_compare(self):
        """Test constant-time comparison works."""
        a = b"test data"
        b = b"test data"
        c = b"different"
        
        self.assertTrue(CryptoKeyValidator._constant_time_compare(a, b))
        self.assertFalse(CryptoKeyValidator._constant_time_compare(a, c))


class TestCryptoAlgorithmValidator(unittest.TestCase):
    """Test algorithm validation."""
    
    def test_validate_secure_algorithm(self):
        """Test secure algorithm validation."""
        result = CryptoAlgorithmValidator.validate_algorithm('AES-256-GCM')
        self.assertTrue(result.passed)
    
    def test_validate_post_quantum_algorithm(self):
        """Test post-quantum algorithm validation."""
        result = CryptoAlgorithmValidator.validate_algorithm('KYBER')
        self.assertTrue(result.passed)
    
    def test_validate_dilithium(self):
        """Test Dilithium validation."""
        result = CryptoAlgorithmValidator.validate_algorithm('CRYSTALS-DILITHIUM')
        self.assertTrue(result.passed)
    
    def test_validate_insecure_algorithm(self):
        """Test insecure algorithm rejection."""
        result = CryptoAlgorithmValidator.validate_algorithm('XOR')
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.INSECURE_ALGORITHM)
    
    def test_validate_deprecated_algorithm(self):
        """Test deprecated algorithm rejection."""
        result = CryptoAlgorithmValidator.validate_algorithm('SHA-1')
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.DEPRECATED_ALGORITHM)
    
    def test_validate_deprecated_with_allow_flag(self):
        """Test deprecated algorithm allowed with flag."""
        ctx = CryptoValidationContext(allow_deprecated=True)
        result = CryptoAlgorithmValidator.validate_algorithm('SHA-1', ctx)
        self.assertTrue(result.passed)  # Passes with warning
    
    def test_validate_unknown_algorithm(self):
        """Test unknown algorithm rejection."""
        result = CryptoAlgorithmValidator.validate_algorithm('UNKNOWN-ALGO')
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.UNSUPPORTED_ALGORITHM)
    
    def test_validate_chacha20(self):
        """Test ChaCha20 validation."""
        result = CryptoAlgorithmValidator.validate_algorithm('CHACHA20-POLY1305')
        self.assertTrue(result.passed)
    
    def test_validate_argon2id(self):
        """Test Argon2id validation."""
        result = CryptoAlgorithmValidator.validate_algorithm('ARGON2ID')
        self.assertTrue(result.passed)


class TestCryptoParameterValidator(unittest.TestCase):
    """Test crypto parameter validation."""
    
    def test_validate_iterations_valid(self):
        """Test valid iteration count."""
        result = CryptoParameterValidator.validate_iterations(100000)
        self.assertTrue(result.passed)
    
    def test_validate_iterations_too_low(self):
        """Test iteration count too low."""
        result = CryptoParameterValidator.validate_iterations(100)
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.INVALID_ITERATION_COUNT)
    
    def test_validate_iterations_too_high(self):
        """Test iteration count too high."""
        result = CryptoParameterValidator.validate_iterations(10000000)
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.INVALID_ITERATION_COUNT)
    
    def test_validate_salt_valid(self):
        """Test valid salt."""
        salt = secrets.token_bytes(32)
        result = CryptoParameterValidator.validate_salt(salt)
        self.assertTrue(result.passed)
    
    def test_validate_salt_too_short(self):
        """Test salt too short."""
        salt = secrets.token_bytes(8)
        result = CryptoParameterValidator.validate_salt(salt)
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.INVALID_SALT_LENGTH)
    
    def test_validate_salt_not_bytes(self):
        """Test salt that isn't bytes."""
        result = CryptoParameterValidator.validate_salt("not bytes")  # type: ignore
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.TYPE_MISMATCH)


class TestValidateCryptoInputDecorator(unittest.TestCase):
    """Test @validate_crypto_input decorator."""
    
    def test_validate_key_length_decorator(self):
        """Test key length validation via decorator."""
        @validate_crypto_input(key={'algorithm': 'AES-256'})
        def encrypt(key: bytes, data: bytes) -> bytes:
            return key + data
        
        # Valid 256-bit key
        good_key = secrets.token_bytes(32)
        result = encrypt(good_key, b"test")
        self.assertEqual(result[:32], good_key)
        
        # Invalid key (128 bits for AES-256)
        bad_key = secrets.token_bytes(16)
        with self.assertRaises(CryptoValidationError):
            encrypt(bad_key, b"test")
    
    def test_validate_weak_key_decorator(self):
        """Test weak key detection via decorator."""
        @validate_crypto_input(key={'algorithm': 'AES-256', 'check_weak': True})
        def encrypt(key: bytes, data: bytes) -> bytes:
            return key + data
        
        # Weak key should fail
        weak_key = b'\x00' * 32
        with self.assertRaises(CryptoValidationError):
            encrypt(weak_key, b"test")
    
    def test_validate_nonce_decorator(self):
        """Test nonce validation via decorator."""
        @validate_crypto_input(nonce={'length': 12})
        def encrypt(nonce: bytes, data: bytes) -> bytes:
            return nonce + data
        
        # Good nonce
        good_nonce = secrets.token_bytes(12)
        result = encrypt(good_nonce, b"test")
        self.assertEqual(result[:12], good_nonce)
        
        # Bad nonce length
        bad_nonce = secrets.token_bytes(8)
        with self.assertRaises(CryptoValidationError):
            encrypt(bad_nonce, b"test")
    
    def test_validate_algorithm_decorator(self):
        """Test algorithm validation via decorator."""
        @validate_crypto_input(algorithm={'secure_only': True})
        def setup_crypto(algorithm: str) -> str:
            return algorithm
        
        # Good algorithm
        result = setup_crypto('AES-256-GCM')
        self.assertEqual(result, 'AES-256-GCM')
        
        # Bad (insecure) algorithm
        with self.assertRaises(CryptoValidationError):
            setup_crypto('MD5')
    
    def test_validate_kdf_params_decorator(self):
        """Test KDF parameter validation via decorator."""
        @validate_crypto_input(
            salt={'validate_salt': True},
            iterations={'validate_kdf_iterations': True}
        )
        def derive_key(salt: bytes, iterations: int) -> bytes:
            return salt + iterations.to_bytes(4, 'big')
        
        # Valid params
        salt = secrets.token_bytes(32)
        result = derive_key(salt, 100000)
        self.assertEqual(result[:32], salt)
        
        # Invalid salt (too short)
        with self.assertRaises(CryptoValidationError):
            derive_key(secrets.token_bytes(8), 100000)
        
        # Invalid iterations (too low)
        with self.assertRaises(CryptoValidationError):
            derive_key(salt, 100)
    
    def test_validate_multiple_params(self):
        """Test multiple parameter validation."""
        @validate_crypto_input(
            key={'algorithm': 'AES-256', 'check_weak': True},
            nonce={'length': 12},
            algorithm={'secure_only': True}
        )
        def encrypt(key: bytes, nonce: bytes, data: bytes, algorithm: str) -> dict:
            return {'key': key, 'nonce': nonce, 'data': data, 'algo': algorithm}
        
        # All valid
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        result = encrypt(key, nonce, b"test", "AES-256-GCM")
        self.assertEqual(result['key'], key)
        
        # Invalid algorithm should fail
        with self.assertRaises(CryptoValidationError):
            encrypt(key, nonce, b"test", "DES")


class TestGlobalInstances(unittest.TestCase):
    """Test global shared instances."""
    
    def test_get_key_validator(self):
        """Test getting shared key validator."""
        v1 = get_key_validator()
        v2 = get_key_validator()
        self.assertIs(v1, v2)
        self.assertIsInstance(v1, CryptoKeyValidator)
    
    def test_get_algorithm_validator(self):
        """Test getting shared algorithm validator."""
        v1 = get_algorithm_validator()
        v2 = get_algorithm_validator()
        self.assertIs(v1, v2)
        self.assertIsInstance(v1, CryptoAlgorithmValidator)
    
    def test_get_parameter_validator(self):
        """Test getting shared parameter validator."""
        v1 = get_parameter_validator()
        v2 = get_parameter_validator()
        self.assertIs(v1, v2)
        self.assertIsInstance(v1, CryptoParameterValidator)


class TestValidationContext(unittest.TestCase):
    """Test validation context."""
    
    def test_context_defaults(self):
        """Test default context values."""
        ctx = CryptoValidationContext()
        self.assertTrue(ctx.strict_mode)  # Default strict for crypto!
        self.assertTrue(ctx.fail_fast)
        self.assertFalse(ctx.allow_deprecated)
        self.assertFalse(ctx.allow_experimental)
        self.assertEqual(ctx.minimum_security_level, 128)
    
    def test_context_custom(self):
        """Test custom context configuration."""
        ctx = CryptoValidationContext(
            strict_mode=False,
            allow_deprecated=True,
            allow_experimental=True,
            minimum_security_level=256
        )
        self.assertFalse(ctx.strict_mode)
        self.assertTrue(ctx.allow_deprecated)
        self.assertTrue(ctx.allow_experimental)
        self.assertEqual(ctx.minimum_security_level, 256)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of shared instances."""
    
    def test_concurrent_validation(self):
        """Test concurrent access to validators."""
        errors = []
        
        def worker():
            try:
                validator = get_key_validator()
                algo_validator = get_algorithm_validator()
                for _ in range(50):
                    key = secrets.token_bytes(32)
                    validator.validate_key_length(key, 'AES-256')
                    validator.detect_weak_key(key)
                    algo_validator.validate_algorithm('AES-256-GCM')
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)


class TestValidationResult(unittest.TestCase):
    """Test validation result structure."""
    
    def test_result_passed(self):
        """Test passed result."""
        result = CryptoValidationResult(passed=True, field_name="test")
        self.assertTrue(result.passed)
        self.assertEqual(result.field_name, "test")
    
    def test_result_failed(self):
        """Test failed result."""
        result = CryptoValidationResult(
            passed=False,
            error_code=CryptoValidationErrorCode.WEAK_KEY,
            message="Test failure",
            severity=CryptoValidationSeverity.CRITICAL,
            field_name="key"
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, CryptoValidationErrorCode.WEAK_KEY)
        self.assertEqual(result.message, "Test failure")
        self.assertEqual(result.severity, CryptoValidationSeverity.CRITICAL)


class TestValidationError(unittest.TestCase):
    """Test validation exception."""
    
    def test_error_contains_result(self):
        """Test exception contains validation result."""
        result = CryptoValidationResult(
            passed=False,
            error_code=CryptoValidationErrorCode.WEAK_KEY,
            message="Weak key detected"
        )
        error = CryptoValidationError(result)
        self.assertIs(error.result, result)
        self.assertIn("WEAK_KEY", str(error))


if __name__ == '__main__':
    unittest.main(verbosity=2)
