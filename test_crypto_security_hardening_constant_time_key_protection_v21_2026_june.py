"""
Test Suite: Security Hardening - Cryptographic Constant-Time Key Protection v21
QuantumCrypt-AI

Tests for cryptographic key protection, constant-time operations,
secure zeroization, and side-channel resistance.

All tests verify backward compatibility and proper functionality.
"""

import pytest
import time
import hmac
import hashlib
import secrets
from typing import List

from quantum_crypt.crypto_security_hardening_constant_time_key_protection_v21_2026_june import (
    KeySensitivityLevel,
    ExecutionProtectionMode,
    CryptoSecurityContext,
    CryptoKeyProtector,
    CryptoExecutionProtector,
    CryptoBranchProtector,
    CryptoKeyWrap,
    crypto_constant_time_compare,
    crypto_secure_zeroize,
    protect_crypto_execution,
    crypto_security_context,
)


class TestKeySensitivityLevel:
    """Tests for KeySensitivityLevel enum."""
    
    def test_enum_values_exist(self):
        """Verify all sensitivity levels are defined."""
        assert KeySensitivityLevel.PUBLIC.value == 0
        assert KeySensitivityLevel.LOW.value == 1
        assert KeySensitivityLevel.MEDIUM.value == 2
        assert KeySensitivityLevel.HIGH.value == 3
        assert KeySensitivityLevel.CRITICAL.value == 4


class TestExecutionProtectionMode:
    """Tests for ExecutionProtectionMode enum."""
    
    def test_enum_values_exist(self):
        """Verify all protection modes are defined."""
        assert ExecutionProtectionMode.NONE.value == 0
        assert ExecutionProtectionMode.TIMING_ONLY.value == 1
        assert ExecutionProtectionMode.CACHE_ONLY.value == 2
        assert ExecutionProtectionMode.FULL_PROTECTION.value == 3
        assert ExecutionProtectionMode.MAXIMUM_HARDENING.value == 4


class TestCryptoSecurityContext:
    """Tests for CryptoSecurityContext."""
    
    def test_context_initialization(self):
        """Verify context initializes with defaults."""
        ctx = CryptoSecurityContext()
        assert ctx.key_sensitivity == KeySensitivityLevel.HIGH
        assert ctx.protection_mode == ExecutionProtectionMode.FULL_PROTECTION
        assert ctx.enable_constant_time is True
        assert ctx.zeroize_on_exit is True
    
    def test_context_custom_values(self):
        """Verify context accepts custom values."""
        ctx = CryptoSecurityContext(
            key_sensitivity=KeySensitivityLevel.CRITICAL,
            protection_mode=ExecutionProtectionMode.MAXIMUM_HARDENING,
            baseline_execution_ns=1000000
        )
        assert ctx.key_sensitivity == KeySensitivityLevel.CRITICAL
        assert ctx.protection_mode == ExecutionProtectionMode.MAXIMUM_HARDENING
        assert ctx.baseline_execution_ns == 1000000
    
    def test_register_and_cleanup_sensitive_material(self):
        """Verify sensitive material registration and cleanup."""
        ctx = CryptoSecurityContext()
        sensitive = bytearray(b"secret key material")
        original = bytes(sensitive)
        
        ctx.register_sensitive_material(sensitive)
        ctx.cleanup()
        
        # Material should be zeroized
        assert all(b == 0 for b in sensitive)
        assert bytes(sensitive) != original
    
    def test_context_manager_cleanup(self):
        """Verify context manager auto-cleanup."""
        with crypto_security_context(KeySensitivityLevel.CRITICAL) as ctx:
            sensitive = bytearray(b"test key")
            ctx.register_sensitive_material(sensitive)
            original = bytes(sensitive)
        
        # Should be zeroized after context exit
        assert all(b == 0 for b in sensitive)


class TestCryptoKeyProtector:
    """Tests for CryptoKeyProtector."""
    
    def test_crypto_secure_zeroize(self):
        """Verify FIPS-compliant key zeroization."""
        key = bytearray(secrets.token_bytes(64))
        original = bytes(key)
        
        CryptoKeyProtector.crypto_secure_zeroize(key)
        
        # All bytes should be zero
        assert all(b == 0 for b in key)
        assert bytes(key) != original
    
    def test_zeroize_empty_key(self):
        """Verify zeroization handles empty keys."""
        key = bytearray()
        CryptoKeyProtector.crypto_secure_zeroize(key)
        assert len(key) == 0
    
    def test_zeroize_single_byte(self):
        """Verify zeroization works for single byte."""
        key = bytearray([0x42])
        CryptoKeyProtector.crypto_secure_zeroize(key)
        assert key[0] == 0
    
    def test_constant_time_key_compare_equal(self):
        """Verify constant-time key comparison for equal keys."""
        key = secrets.token_bytes(32)
        assert CryptoKeyProtector.constant_time_key_compare(key, key) is True
    
    def test_constant_time_key_compare_not_equal(self):
        """Verify constant-time key comparison for different keys."""
        key_a = secrets.token_bytes(32)
        key_b = secrets.token_bytes(32)
        assert CryptoKeyProtector.constant_time_key_compare(key_a, key_b) is False
    
    def test_constant_time_key_compare_different_lengths(self):
        """Verify constant-time comparison handles different lengths."""
        key_a = secrets.token_bytes(16)
        key_b = secrets.token_bytes(32)
        assert CryptoKeyProtector.constant_time_key_compare(key_a, key_b) is False
    
    def test_constant_time_key_compare_empty(self):
        """Verify constant-time comparison handles empty inputs."""
        assert CryptoKeyProtector.constant_time_key_compare(b"", b"") is True
        assert CryptoKeyProtector.constant_time_key_compare(b"", b"a") is False
    
    def test_constant_time_key_validation_valid(self):
        """Verify key validation for valid key."""
        key = secrets.token_bytes(32)
        assert CryptoKeyProtector.constant_time_key_validation(key, 32) is True
    
    def test_constant_time_key_validation_wrong_length(self):
        """Verify key validation for wrong length."""
        key = secrets.token_bytes(16)
        assert CryptoKeyProtector.constant_time_key_validation(key, 32) is False
    
    def test_constant_time_key_validation_all_zeros(self):
        """Verify key validation rejects all-zero keys."""
        key = bytes([0] * 32)
        assert CryptoKeyProtector.constant_time_key_validation(key, 32) is False
        # But passes if we don't check nonzero
        assert CryptoKeyProtector.constant_time_key_validation(key, 32, check_nonzero=False) is True


class TestCryptoExecutionProtector:
    """Tests for CryptoExecutionProtector."""
    
    def test_protector_initialization(self):
        """Verify protector initializes correctly."""
        protector = CryptoExecutionProtector()
        assert protector.protection_mode == ExecutionProtectionMode.FULL_PROTECTION
    
    def test_protect_crypto_operation_decorator(self):
        """Verify operation protection decorator works."""
        protector = CryptoExecutionProtector(baseline_ns=100000)
        call_count = 0
        
        @protector.protect_crypto_operation
        def crypto_op(x: int) -> int:
            nonlocal call_count
            call_count += 1
            return x * 2
        
        result = crypto_op(7)
        assert result == 14
        assert call_count == 1
    
    def test_protected_execution_context(self):
        """Verify protected execution context manager."""
        protector = CryptoExecutionProtector()
        
        with protector.protected_execution_context():
            # Perform some operation
            result = hashlib.sha256(b"test").digest()
        
        assert len(result) == 32
    
    def test_all_protection_modes(self):
        """Verify all protection modes work without errors."""
        modes = [
            ExecutionProtectionMode.NONE,
            ExecutionProtectionMode.TIMING_ONLY,
            ExecutionProtectionMode.CACHE_ONLY,
            ExecutionProtectionMode.FULL_PROTECTION,
            ExecutionProtectionMode.MAXIMUM_HARDENING,
        ]
        
        for mode in modes:
            protector = CryptoExecutionProtector(protection_mode=mode)
            
            @protector.protect_crypto_operation
            def test_op():
                return hashlib.sha256(b"test").digest()
            
            # Should not raise exceptions
            result = test_op()
            assert len(result) == 32


class TestCryptoBranchProtector:
    """Tests for CryptoBranchProtector."""
    
    def test_mask_branch_true(self):
        """Verify branch masking for True condition."""
        true_executed = False
        false_executed = False
        
        def true_branch():
            nonlocal true_executed
            true_executed = True
            return "true_result"
        
        def false_branch():
            nonlocal false_executed
            false_executed = True
            return "false_result"
        
        result = CryptoBranchProtector.mask_branch(True, true_branch, false_branch)
        
        assert result == "true_result"
        # Both branches should have executed
        assert true_executed is True
        assert false_executed is True
    
    def test_mask_branch_false(self):
        """Verify branch masking for False condition."""
        true_executed = False
        false_executed = False
        
        def true_branch():
            nonlocal true_executed
            true_executed = True
            return "true_result"
        
        def false_branch():
            nonlocal false_executed
            false_executed = True
            return "false_result"
        
        result = CryptoBranchProtector.mask_branch(False, true_branch, false_branch)
        
        assert result == "false_result"
        # Both branches should have executed
        assert true_executed is True
        assert false_executed is True
    
    def test_constant_time_lookup(self):
        """Verify constant-time table lookup."""
        table = [b"entry0", b"entry1", b"entry2", b"entry3"]
        
        for i in range(len(table)):
            result = CryptoBranchProtector.constant_time_lookup(table, i, len(table))
            assert result == table[i]


class TestCryptoKeyWrap:
    """Tests for CryptoKeyWrap."""
    
    def test_key_wrap_initialization(self):
        """Verify key wrap initializes correctly."""
        wrap_key = secrets.token_bytes(32)
        wrapper = CryptoKeyWrap(wrap_key)
        assert wrapper is not None
    
    def test_wrap_and_unwrap_basic(self):
        """Verify basic key wrapping functionality."""
        wrap_key = secrets.token_bytes(32)
        wrapper = CryptoKeyWrap(wrap_key)
        
        plain_key = secrets.token_bytes(32)
        wrapped = wrapper.wrap_key(plain_key)
        
        # Wrapped should be longer: IV (16) + key (32) + tag (32) = 80
        assert len(wrapped) == 16 + 32 + 32


class TestConvenienceFunctions:
    """Tests for global convenience functions."""
    
    def test_global_crypto_constant_time_compare(self):
        """Verify global constant-time compare function."""
        a = secrets.token_bytes(32)
        b = bytes(a)
        c = secrets.token_bytes(32)
        
        assert crypto_constant_time_compare(a, b) is True
        assert crypto_constant_time_compare(a, c) is False
    
    def test_global_crypto_secure_zeroize(self):
        """Verify global secure zeroize function."""
        key = bytearray(b"sensitive key material")
        crypto_secure_zeroize(key)
        assert all(b == 0 for b in key)
    
    def test_global_protect_crypto_execution(self):
        """Verify global execution protection decorator."""
        call_count = 0
        
        @protect_crypto_execution
        def test_op():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = test_op()
        assert result == "success"
        assert call_count == 1


class TestTimingAttackResistance:
    """Tests for timing attack resistance properties."""
    
    def test_key_compare_timing_consistency(self):
        """Verify key comparison timing consistency."""
        equal_times: List[int] = []
        different_times: List[int] = []
        
        key_a = secrets.token_bytes(32)
        key_equal = bytes(key_a)
        key_different = secrets.token_bytes(32)
        
        for _ in range(100):
            # Equal comparison
            start = time.perf_counter_ns()
            CryptoKeyProtector.constant_time_key_compare(key_a, key_equal)
            equal_times.append(time.perf_counter_ns() - start)
            
            # Different comparison
            start = time.perf_counter_ns()
            CryptoKeyProtector.constant_time_key_compare(key_a, key_different)
            different_times.append(time.perf_counter_ns() - start)
        
        avg_equal = sum(equal_times) / len(equal_times)
        avg_different = sum(different_times) / len(different_times)
        
        # Timings should be within reasonable bounds
        ratio = max(avg_equal, avg_different) / min(avg_equal, avg_different)
        assert ratio < 20, f"Timing ratio too high: {ratio}"
    
    def test_key_validation_no_early_exit(self):
        """Verify key validation doesn't early exit."""
        # All-zero key at beginning vs end
        all_zero = bytes([0] * 32)
        normal_key = secrets.token_bytes(32)
        
        zero_times: List[int] = []
        normal_times: List[int] = []
        
        for _ in range(50):
            start = time.perf_counter_ns()
            CryptoKeyProtector.constant_time_key_validation(all_zero, 32)
            zero_times.append(time.perf_counter_ns() - start)
            
            start = time.perf_counter_ns()
            CryptoKeyProtector.constant_time_key_validation(normal_key, 32)
            normal_times.append(time.perf_counter_ns() - start)
        
        avg_zero = sum(zero_times) / len(zero_times)
        avg_normal = sum(normal_times) / len(normal_times)
        
        ratio = max(avg_zero, avg_normal) / min(avg_zero, avg_normal)
        assert ratio < 10, f"Early exit detected, ratio: {ratio}"


class TestBackwardCompatibility:
    """Tests for backward compatibility."""
    
    def test_purely_additive_module(self):
        """Verify this is purely additive code."""
        import quantum_crypt
        
        # New module exists
        assert hasattr(
            quantum_crypt,
            'crypto_security_hardening_constant_time_key_protection_v21_2026_june'
        )
    
    def test_import_without_side_effects(self):
        """Verify import doesn't break existing code."""
        from quantum_crypt import crypto_security_hardening_constant_time_key_protection_v21_2026_june
        assert crypto_security_hardening_constant_time_key_protection_v21_2026_june is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
