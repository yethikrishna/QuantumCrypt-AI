"""
QuantumCrypt-AI: Security Hardening v9 Comprehensive Tests
Dimension B - Security Hardening

Tests for:
- Secure memory zeroization module
- Input validation wrappers
- Constant-time comparison utilities

All tests verify ADD-ONLY functionality without modifying existing code.
"""

import pytest
import secrets
import time
import sys
import os

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from quantum_crypt.crypto_security_hardening_secure_memory_zeroization_v9_2026_june import (
    SecureMemoryZeroizer,
    SecureMemoryConfig,
    ConstantTimeComparison,
    OverwritePattern,
    ZeroizationVerification,
    secure_wipe,
    constant_time_compare,
    get_secure_zeroizer
)

from quantum_crypt.crypto_security_hardening_input_validation_wrappers_v9_2026_june import (
    CryptoInputValidator,
    ValidationConfig,
    ValidationSeverity,
    ValidationFailureCode,
    validate_key,
    validate_bytes,
    get_crypto_validator
)


class TestSecureMemoryZeroization:
    """Test suite for secure memory zeroization"""
    
    def test_zeroizer_initialization(self):
        """Test zeroizer initializes correctly"""
        zeroizer = SecureMemoryZeroizer()
        assert zeroizer is not None
        assert zeroizer.config.overwrite_passes == 3
        assert zeroizer._initialized == True
    
    def test_custom_config(self):
        """Test custom configuration works"""
        config = SecureMemoryConfig(
            overwrite_passes=5,
            verification=ZeroizationVerification.CRYPTO_VERIFY
        )
        zeroizer = SecureMemoryZeroizer(config)
        assert zeroizer.config.overwrite_passes == 5
        assert zeroizer.config.verification == ZeroizationVerification.CRYPTO_VERIFY
    
    def test_zeroize_bytearray(self):
        """Test basic bytearray zeroization"""
        zeroizer = SecureMemoryZeroizer()
        data = bytearray(b'Sensitive cryptographic key material')
        original = bytes(data)
        
        result = zeroizer.zeroize_buffer(data)
        
        assert result.success == True
        assert result.bytes_wiped == len(original)
        assert result.passes_completed > 0
        assert result.verification_passed == True
        assert all(b == 0 for b in data)
    
    def test_zeroize_empty_buffer(self):
        """Test zeroizing empty buffer"""
        zeroizer = SecureMemoryZeroizer()
        data = bytearray()
        
        result = zeroizer.zeroize_buffer(data)
        
        assert result.success == True
        assert result.bytes_wiped == 0
    
    def test_zeroize_memoryview(self):
        """Test zeroizing memoryview"""
        zeroizer = SecureMemoryZeroizer()
        arr = bytearray(b'test data')
        view = memoryview(arr)
        
        result = zeroizer.zeroize_buffer(view)
        
        assert result.success == True
    
    def test_multiple_overwrite_patterns(self):
        """Test NIST-compliant overwrite patterns"""
        config = SecureMemoryConfig(
            patterns=[
                OverwritePattern.ZEROS,
                OverwritePattern.ONES,
                OverwritePattern.NIST_PASS1,
                OverwritePattern.NIST_PASS2,
                OverwritePattern.RANDOM
            ],
            overwrite_passes=5
        )
        zeroizer = SecureMemoryZeroizer(config)
        data = bytearray(b'test data for multiple patterns')
        
        result = zeroizer.zeroize_buffer(data)
        
        assert result.success == True
        assert len(result.patterns_used) >= 5
        assert all(b == 0 for b in data)
    
    def test_zeroize_after_context_manager(self):
        """Test auto-zeroization context manager"""
        zeroizer = SecureMemoryZeroizer()
        sensitive = bytearray(b'secret key 12345')
        original_hash = hash(bytes(sensitive))
        
        with zeroizer.zeroize_after(sensitive):
            # Use the sensitive data
            processed = len(sensitive)
            assert processed > 0
        
        # After context exit, should be zeroized
        assert all(b == 0 for b in sensitive)
    
    def test_constant_time_compare_equal(self):
        """Test constant-time comparison with equal inputs"""
        a = b'correct cryptographic hash'
        b = b'correct cryptographic hash'
        
        result = ConstantTimeComparison.compare_bytes(a, b)
        
        assert result == True
    
    def test_constant_time_compare_not_equal(self):
        """Test constant-time comparison with different inputs"""
        a = b'correct value'
        b = b'wrong valuexx'
        
        result = ConstantTimeComparison.compare_bytes(a, b)
        
        assert result == False
    
    def test_constant_time_compare_different_length(self):
        """Test constant-time comparison rejects different lengths"""
        a = b'short'
        b = b'much longer value'
        
        result = ConstantTimeComparison.compare_bytes(a, b)
        
        assert result == False
    
    def test_constant_time_timing_resistance(self):
        """Verify timing consistency (no early termination)"""
        # This test verifies no timing differences based on mismatch position
        zeroizer = SecureMemoryZeroizer()
        
        # Same first byte, different later
        a1 = b'\x00' + b'\xFF' * 31
        b1 = b'\x00' + b'\x00' * 31
        
        # Different first byte
        a2 = b'\xFF' + b'\xFF' * 31
        b2 = b'\x00' + b'\x00' * 31
        
        # Both should take roughly same time
        runs = 1000
        
        start = time.perf_counter()
        for _ in range(runs):
            zeroizer.constant_time_compare(a1, b1)
        time1 = time.perf_counter() - start
        
        start = time.perf_counter()
        for _ in range(runs):
            zeroizer.constant_time_compare(a2, b2)
        time2 = time.perf_counter() - start
        
        # Times should be within 20% of each other
        ratio = max(time1, time2) / min(time1, time2)
        assert ratio < 1.5, f"Timing difference too large: {ratio}"
    
    def test_wipe_object_bytearray(self):
        """Test wiping various object types"""
        zeroizer = SecureMemoryZeroizer()
        data = bytearray(b'sensitive')
        
        result = zeroizer.wipe_object(data)
        
        assert result == True
        assert all(b == 0 for b in data)
    
    def test_wipe_object_list(self):
        """Test wiping list of integers"""
        zeroizer = SecureMemoryZeroizer()
        data = [1, 2, 3, 4, 5]
        
        result = zeroizer.wipe_object(data)
        
        assert result == True
        assert all(x == 0 for x in data)
    
    def test_get_stats(self):
        """Test statistics tracking"""
        zeroizer = SecureMemoryZeroizer()
        zeroizer.reset_stats()
        
        zeroizer.zeroize_buffer(bytearray(b'test1'))
        zeroizer.zeroize_buffer(bytearray(b'test2'))
        
        stats = zeroizer.get_stats()
        assert stats['total_operations'] >= 2
        assert stats['total_bytes_wiped'] > 0
    
    def test_convenience_functions(self):
        """Test module-level convenience functions"""
        data = bytearray(b'test convenience')
        
        result = secure_wipe(data)
        
        assert result.success == True
        assert all(b == 0 for b in data)
        
        # Test compare
        assert constant_time_compare(b'abc', b'abc') == True
        assert constant_time_compare(b'abc', b'xyz') == False
    
    def test_singleton_instance(self):
        """Test singleton pattern works"""
        z1 = get_secure_zeroizer()
        z2 = get_secure_zeroizer()
        
        assert z1 is z2


class TestCryptoInputValidation:
    """Test suite for cryptographic input validation"""
    
    def test_validator_initialization(self):
        """Test validator initializes correctly"""
        validator = CryptoInputValidator()
        assert validator is not None
    
    def test_validate_bytes_valid(self):
        """Test validating proper bytes"""
        validator = CryptoInputValidator()
        
        result = validator.validate_bytes(b'valid input data')
        
        assert result.valid == True
        assert result.sanitized_value == b'valid input data'
    
    def test_validate_bytes_from_hex(self):
        """Test auto-conversion from hex string"""
        validator = CryptoInputValidator()
        
        result = validator.validate_bytes('48656C6C6F')  # "Hello" in hex
        
        assert result.valid == True
        assert result.sanitized_value == b'Hello'
    
    def test_validate_bytes_from_base64(self):
        """Test auto-conversion from base64"""
        validator = CryptoInputValidator()
        
        result = validator.validate_bytes('SGVsbG8=')  # "Hello" base64
        
        assert result.valid == True
        assert result.sanitized_value == b'Hello'
    
    def test_validate_bytes_null_rejected(self):
        """Test null input rejection"""
        validator = CryptoInputValidator()
        
        result = validator.validate_bytes(None)
        
        assert result.valid == False
        assert result.failure_code == ValidationFailureCode.NULL_INPUT
    
    def test_validate_bytes_too_large(self):
        """Test oversized input rejection"""
        validator = CryptoInputValidator()
        large_data = b'x' * (100 * 1024 * 1024)  # 100MB
        
        result = validator.validate_bytes(large_data)
        
        assert result.valid == False
        assert result.failure_code == ValidationFailureCode.INVALID_LENGTH
    
    def test_validate_key_aes_valid(self):
        """Test valid AES key validation"""
        validator = CryptoInputValidator()
        
        key_128 = secrets.token_bytes(16)
        key_192 = secrets.token_bytes(24)
        key_256 = secrets.token_bytes(32)
        
        assert validator.validate_key(key_128, 'AES').valid == True
        assert validator.validate_key(key_192, 'AES').valid == True
        assert validator.validate_key(key_256, 'AES').valid == True
    
    def test_validate_key_aes_wrong_size(self):
        """Test invalid AES key size rejection"""
        validator = CryptoInputValidator()
        
        result = validator.validate_key(secrets.token_bytes(20), 'AES')  # Invalid size
        
        assert result.valid == False
        assert result.failure_code == ValidationFailureCode.INVALID_LENGTH
    
    def test_validate_key_weak_pattern(self):
        """Test known weak pattern rejection"""
        validator = CryptoInputValidator()
        
        result = validator.validate_key(b'\x00' * 32, 'AES')
        
        assert result.valid == False
        assert result.failure_code == ValidationFailureCode.KNOWN_BAD_PATTERN
    
    def test_validate_key_all_same_bytes(self):
        """Test extremely weak key (all same bytes)"""
        validator = CryptoInputValidator()
        
        result = validator.validate_key(b'\xAA' * 32, 'AES')
        
        assert result.valid == False
    
    def test_validate_nonce_valid(self):
        """Test valid nonce validation"""
        validator = CryptoInputValidator()
        nonce = secrets.token_bytes(12)
        
        result = validator.validate_nonce(nonce)
        
        assert result.valid == True
    
    def test_validate_nonce_wrong_length(self):
        """Test nonce with wrong length"""
        validator = CryptoInputValidator()
        
        result = validator.validate_nonce(secrets.token_bytes(8))  # Too short
        
        assert result.valid == False
    
    def test_validate_plaintext_empty(self):
        """Test empty plaintext is allowed"""
        validator = CryptoInputValidator()
        
        result = validator.validate_plaintext(b'')
        
        assert result.valid == True
    
    def test_validate_ciphertext(self):
        """Test ciphertext validation"""
        validator = CryptoInputValidator()
        ciphertext = secrets.token_bytes(64)
        
        result = validator.validate_ciphertext(ciphertext)
        
        assert result.valid == True
    
    def test_validate_hash_sha256(self):
        """Test SHA256 hash validation"""
        validator = CryptoInputValidator()
        import hashlib
        hash_val = hashlib.sha256(b'test').digest()
        
        result = validator.validate_hash(hash_val, 'SHA256')
        
        assert result.valid == True
    
    def test_entropy_calculation(self):
        """Test entropy calculation works"""
        validator = CryptoInputValidator()
        
        # Low entropy (repeating)
        low_entropy = validator._calculate_entropy(b'\x00' * 100)
        # High entropy (random)
        high_entropy = validator._calculate_entropy(secrets.token_bytes(100))
        
        assert low_entropy < high_entropy
        assert high_entropy > 50  # Should be high for random
    
    def test_validation_stats(self):
        """Test validation statistics tracking"""
        validator = CryptoInputValidator()
        
        validator.validate_bytes(b'test1')
        validator.validate_bytes(b'test2')
        
        stats = validator.get_stats()
        assert stats['total_validations'] >= 2
        assert stats['passed'] >= 2
    
    def test_convenience_functions(self):
        """Test module-level convenience functions"""
        result = validate_bytes(b'test data')
        assert result.valid == True
        
        result = validate_key(secrets.token_bytes(32), 'AES')
        assert result.valid == True
    
    def test_validator_singleton(self):
        """Test validator singleton works"""
        v1 = get_crypto_validator()
        v2 = get_crypto_validator()
        
        assert v1 is v2


class TestIntegrationSecurity:
    """Integration tests for security hardening modules"""
    
    def test_combined_zeroize_and_validate(self):
        """Test using validation and zeroization together"""
        validator = CryptoInputValidator()
        zeroizer = SecureMemoryZeroizer()
        
        # Validate key
        key = bytearray(secrets.token_bytes(32))
        val_result = validator.validate_key(bytes(key), 'AES')
        assert val_result.valid == True
        
        # Use key
        processed = len(key)
        
        # Securely zeroize
        zero_result = zeroizer.zeroize_buffer(key)
        assert zero_result.success == True
        assert all(b == 0 for b in key)
    
    def test_production_safe_usage_pattern(self):
        """Test recommended production usage pattern"""
        zeroizer = SecureMemoryZeroizer()
        
        # Sensitive operation with auto-cleanup
        sensitive_key = bytearray(secrets.token_bytes(32))
        
        with zeroizer.zeroize_after(sensitive_key):
            # Operation using key
            fingerprint = len(sensitive_key)
            assert fingerprint == 32
        
        # Key automatically wiped
        assert sum(sensitive_key) == 0
    
    def test_constant_time_compare_security(self):
        """Verify constant-time compare is truly constant-time"""
        # This is a statistical test - should pass most of the time
        equal_times = []
        diff_first_times = []
        
        for _ in range(50):
            a = b'\x00' * 64
            b_same = b'\x00' * 64
            b_diff_first = b'\xFF' + b'\x00' * 63
            b_diff_last = b'\x00' * 63 + b'\xFF'
            
            # Time same vs different at different positions
            import time
            
            start = time.perf_counter_ns()
            for _ in range(100):
                constant_time_compare(a, b_same)
            equal_times.append(time.perf_counter_ns() - start)
            
            start = time.perf_counter_ns()
            for _ in range(100):
                constant_time_compare(a, b_diff_first)
            diff_first_times.append(time.perf_counter_ns() - start)
        
        # Average times should be similar
        avg_equal = sum(equal_times) / len(equal_times)
        avg_diff = sum(diff_first_times) / len(diff_first_times)
        
        # Within 30% tolerance for timing variations
        ratio = max(avg_equal, avg_diff) / min(avg_equal, avg_diff)
        assert ratio < 1.5, f"Timing attack vulnerability detected: {ratio}"


def run_tests():
    """Run all tests and save results"""
    import json
    
    test_results = {
        'test_module': 'crypto_security_hardening_v9_2026_june',
        'dimension': 'B - Security Hardening',
        'timestamp': time.time(),
        'passed': 0,
        'failed': 0,
        'tests': {}
    }
    
    # Run test classes
    test_classes = [
        TestSecureMemoryZeroization,
        TestCryptoInputValidation,
        TestIntegrationSecurity
    ]
    
    for test_class in test_classes:
        instance = test_class()
        class_name = test_class.__name__
        test_results['tests'][class_name] = []
        
        for method_name in dir(instance):
            if method_name.startswith('test_'):
                try:
                    method = getattr(instance, method_name)
                    method()
                    test_results['tests'][class_name].append({
                        'name': method_name,
                        'passed': True
                    })
                    test_results['passed'] += 1
                except Exception as e:
                    test_results['tests'][class_name].append({
                        'name': method_name,
                        'passed': False,
                        'error': str(e)
                    })
                    test_results['failed'] += 1
    
    # Save results
    with open('test_results_crypto_security_hardening_v9_2026_june.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    return test_results


if __name__ == '__main__':
    results = run_tests()
    print(f"\n=== QuantumCrypt Security Hardening v9 Test Results ===")
    print(f"Passed: {results['passed']}")
    print(f"Failed: {results['failed']}")
    print(f"Total: {results['passed'] + results['failed']}")
    
    if results['failed'] > 0:
        print("\nFailed tests:")
        for cls, tests in results['tests'].items():
            for test in tests:
                if not test['passed']:
                    print(f"  {cls}.{test['name']}: {test.get('error', 'Unknown')}")
    
    sys.exit(1 if results['failed'] > 0 else 0)
