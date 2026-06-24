"""
Tests for Security Hardening: Post-Quantum Constant-Time Key Protection v31
DIMENSION B - Security Hardening

These tests verify the PQ key protection features work correctly.
All tests are ADD-ONLY - no existing code is modified.
"""

import pytest
import secrets
import threading
import hmac
import hashlib
from typing import List

from quantum_crypt.crypto_security_hardening_pq_constant_time_key_protection_v31_2026_june import (
    KeySensitivityLevel,
    PQAlgorithmType,
    FaultDetectionMode,
    PQKeyProtectionConfig,
    PQKeyMaterial,
    ConstantTimePQOperations,
    FaultResistantOperation,
    create_protected_key,
    pq_constant_time_compare,
    secure_pq_key_zeroize,
    wrap_pq_sensitive_operation,
)


class TestKeySensitivityLevel:
    """Tests for key sensitivity enumeration."""
    
    def test_sensitivity_levels_exist(self):
        """Verify all sensitivity levels are defined."""
        levels = list(KeySensitivityLevel)
        assert KeySensitivityLevel.PUBLIC in levels
        assert KeySensitivityLevel.INTERNAL in levels
        assert KeySensitivityLevel.SENSITIVE in levels
        assert KeySensitivityLevel.CRITICAL in levels
        assert KeySensitivityLevel.EPHEMERAL in levels
    
    def test_sensitivity_order(self):
        """Verify levels are properly ordered."""
        assert KeySensitivityLevel.PUBLIC.value < KeySensitivityLevel.INTERNAL.value
        assert KeySensitivityLevel.INTERNAL.value < KeySensitivityLevel.SENSITIVE.value
        assert KeySensitivityLevel.SENSITIVE.value < KeySensitivityLevel.CRITICAL.value


class TestPQAlgorithmType:
    """Tests for PQ algorithm type enumeration."""
    
    def test_algorithm_types_exist(self):
        """Verify all algorithm types are defined."""
        types_list = list(PQAlgorithmType)
        assert PQAlgorithmType.LATTICE in types_list
        assert PQAlgorithmType.CODE_BASED in types_list
        assert PQAlgorithmType.HASH_BASED in types_list
        assert PQAlgorithmType.HYBRID in types_list


class TestFaultDetectionMode:
    """Tests for fault detection mode enumeration."""
    
    def test_fault_modes_exist(self):
        """Verify all fault detection modes are defined."""
        modes = list(FaultDetectionMode)
        assert FaultDetectionMode.NONE in modes
        assert FaultDetectionMode.CHECKSUM in modes
        assert FaultDetectionMode.DOUBLE_CHECK in modes
        assert FaultDetectionMode.FULL_REDUNDANCY in modes


class TestPQKeyProtectionConfig:
    """Tests for key protection configuration."""
    
    def test_default_config(self):
        """Verify default configuration."""
        config = PQKeyProtectionConfig()
        assert config.sensitivity_level == KeySensitivityLevel.SENSITIVE
        assert config.algorithm_type == PQAlgorithmType.LATTICE
        assert config.fault_detection == FaultDetectionMode.DOUBLE_CHECK
        assert config.enable_constant_time == True
        assert config.max_key_usage_count == 10000
    
    def test_custom_config(self):
        """Verify custom configuration."""
        config = PQKeyProtectionConfig(
            sensitivity_level=KeySensitivityLevel.CRITICAL,
            algorithm_type=PQAlgorithmType.HASH_BASED,
            fault_detection=FaultDetectionMode.FULL_REDUNDANCY,
            max_key_usage_count=1000,
        )
        assert config.sensitivity_level == KeySensitivityLevel.CRITICAL
        assert config.algorithm_type == PQAlgorithmType.HASH_BASED
        assert config.fault_detection == FaultDetectionMode.FULL_REDUNDANCY
        assert config.max_key_usage_count == 1000


class TestPQKeyMaterial:
    """Tests for protected key material wrapper."""
    
    def test_key_creation(self):
        """Verify key material creation works."""
        key_data = secrets.token_bytes(32)
        key = PQKeyMaterial(key_data)
        
        assert key._destroyed == False
        assert key._usage_count == 0
    
    def test_get_bytes(self):
        """Verify key bytes retrieval works."""
        original = secrets.token_bytes(64)
        key = PQKeyMaterial(original)
        
        retrieved = key.get_bytes()
        
        assert retrieved == original
        assert key._usage_count == 1
    
    def test_constant_time_compare_equal(self):
        """Verify constant-time comparison for equal keys."""
        key_data = secrets.token_bytes(32)
        key = PQKeyMaterial(key_data)
        
        assert key.constant_time_compare(key_data) == True
    
    def test_constant_time_compare_not_equal(self):
        """Verify constant-time comparison for non-equal keys."""
        key_data = secrets.token_bytes(32)
        key = PQKeyMaterial(key_data)
        
        different = bytearray(key_data)
        different[0] ^= 1
        
        assert key.constant_time_compare(bytes(different)) == False
    
    def test_constant_time_compare_different_lengths(self):
        """Verify different length comparison doesn't leak timing."""
        key_data = secrets.token_bytes(32)
        key = PQKeyMaterial(key_data)
        
        # Both should work without errors
        assert key.constant_time_compare(key_data[:16]) == False
        assert key.constant_time_compare(key_data + b'extra') == False
    
    def test_secure_derive_subkey(self):
        """Verify subkey derivation works."""
        master_key = secrets.token_bytes(32)
        key = PQKeyMaterial(master_key)
        
        subkey1 = key.secure_derive_subkey(b'context1', 32)
        subkey2 = key.secure_derive_subkey(b'context2', 32)
        subkey3 = key.secure_derive_subkey(b'context1', 32)
        
        assert len(subkey1) == 32
        assert len(subkey2) == 32
        assert subkey1 != subkey2  # Different contexts give different keys
        assert subkey1 == subkey3  # Same context gives same key
    
    def test_derive_subkey_different_lengths(self):
        """Verify subkey derivation with various lengths."""
        key = PQKeyMaterial(secrets.token_bytes(32))
        
        for length in [16, 32, 64, 128]:
            subkey = key.secure_derive_subkey(b'test', length)
            assert len(subkey) == length
    
    def test_destroy(self):
        """Verify key destruction works."""
        key_data = secrets.token_bytes(100)
        key = PQKeyMaterial(key_data)
        
        key.destroy()
        
        assert key._destroyed == True
        assert all(b == 0 for b in key._key_data)
    
    def test_destroy_idempotent(self):
        """Verify multiple destroy calls are safe."""
        key = PQKeyMaterial(secrets.token_bytes(32))
        
        key.destroy()
        key.destroy()  # Should not raise
        
        assert key._destroyed == True
    
    def test_access_after_destroy_raises(self):
        """Verify accessing destroyed key raises error."""
        key = PQKeyMaterial(secrets.token_bytes(32))
        key.destroy()
        
        with pytest.raises(ValueError, match="destroyed"):
            key.get_bytes()
    
    def test_get_stats(self):
        """Verify statistics reporting."""
        key = PQKeyMaterial(secrets.token_bytes(64))
        key.get_bytes()
        key.get_bytes()
        
        stats = key.get_stats()
        
        assert stats['key_length'] == 64
        assert stats['usage_count'] == 2
        assert stats['destroyed'] == False
        assert 'sensitivity_level' in stats
        assert 'algorithm_type' in stats
    
    def test_thread_safety(self):
        """Verify key material is thread-safe."""
        key = PQKeyMaterial(secrets.token_bytes(32))
        num_threads = 10
        ops_per_thread = 50
        
        errors = []
        
        def worker():
            try:
                for _ in range(ops_per_thread):
                    key.get_bytes()
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert key._usage_count == num_threads * ops_per_thread
    
    def test_custom_sensitivity_level(self):
        """Verify custom sensitivity level works."""
        config = PQKeyProtectionConfig(sensitivity_level=KeySensitivityLevel.CRITICAL)
        key = PQKeyMaterial(secrets.token_bytes(32), config)
        
        stats = key.get_stats()
        assert stats['sensitivity_level'] == 'CRITICAL'


class TestConstantTimePQOperations:
    """Tests for constant-time PQ operations."""
    
    def test_constant_time_select_true(self):
        """Verify selection when condition is True."""
        a = b'hello'
        b = b'world'
        
        result = ConstantTimePQOperations.constant_time_select(True, a, b)
        assert result == a
    
    def test_constant_time_select_false(self):
        """Verify selection when condition is False."""
        a = b'hello'
        b = b'world'
        
        result = ConstantTimePQOperations.constant_time_select(False, a, b)
        assert result == b
    
    def test_constant_time_select_mismatched_lengths_raises(self):
        """Verify mismatched lengths raise error."""
        with pytest.raises(ValueError, match="same length"):
            ConstantTimePQOperations.constant_time_select(True, b'short', b'longer')
    
    def test_constant_time_byte_select(self):
        """Verify byte-level selection."""
        assert ConstantTimePQOperations.constant_time_byte_select(True, 0xAA, 0xBB) == 0xAA
        assert ConstantTimePQOperations.constant_time_byte_select(False, 0xAA, 0xBB) == 0xBB
    
    def test_secure_array_copy_true(self):
        """Verify array copy when condition is True."""
        src = b'test data'
        dst = bytearray(len(src))
        
        ConstantTimePQOperations.secure_array_copy(src, dst, True)
        
        assert bytes(dst) == src
    
    def test_secure_array_copy_false(self):
        """Verify no copy when condition is False."""
        src = b'new data'
        dst = bytearray(b'original')
        
        ConstantTimePQOperations.secure_array_copy(src, dst, False)
        
        assert bytes(dst) == b'original'
    
    def test_constant_time_lookup(self):
        """Verify constant-time table lookup."""
        table = [b'entry0', b'entry1', b'entry2', b'entry3']
        
        for i in range(len(table)):
            result = ConstantTimePQOperations.constant_time_lookup(table, i)
            assert result == table[i]
    
    def test_constant_time_lookup_empty(self):
        """Verify lookup with empty table."""
        result = ConstantTimePQOperations.constant_time_lookup([], 0)
        assert result == b''


class TestFaultResistantOperation:
    """Tests for fault-resistant operation wrapper."""
    
    def test_none_mode(self):
        """Verify NONE mode just executes normally."""
        protector = FaultResistantOperation(FaultDetectionMode.NONE)
        
        call_count = [0]
        
        def op():
            call_count[0] += 1
            return b'result'
        
        result = protector.execute(op)
        
        assert result == b'result'
        assert call_count[0] == 1
    
    def test_double_check_mode_success(self):
        """Verify DOUBLE_CHECK mode when results match."""
        protector = FaultResistantOperation(FaultDetectionMode.DOUBLE_CHECK)
        
        def op():
            return b'consistent result'
        
        result = protector.execute(op)
        
        assert result == b'consistent result'
    
    def test_full_redundancy_majority(self):
        """Verify FULL_REDUNDANCY with majority agreement."""
        protector = FaultResistantOperation(FaultDetectionMode.FULL_REDUNDANCY)
        
        call_count = [0]
        
        def op():
            call_count[0] += 1
            return b'stable'
        
        result = protector.execute(op)
        
        assert result == b'stable'
        assert call_count[0] == 3  # Triple execution
    
    def test_with_args(self):
        """Verify operation with arguments."""
        protector = FaultResistantOperation(FaultDetectionMode.DOUBLE_CHECK)
        
        def add(a, b):
            return a + b
        
        result = protector.execute(add, 2, 3)
        
        assert result == 5


class TestConvenienceFunctions:
    """Tests for top-level convenience functions."""
    
    def test_create_protected_key(self):
        """Verify protected key creation."""
        key_data = secrets.token_bytes(32)
        key = create_protected_key(key_data, KeySensitivityLevel.CRITICAL)
        
        assert isinstance(key, PQKeyMaterial)
        assert key.get_bytes() == key_data
        
        stats = key.get_stats()
        assert stats['sensitivity_level'] == 'CRITICAL'
    
    def test_pq_constant_time_compare(self):
        """Verify convenience compare function."""
        assert pq_constant_time_compare(b'test', b'test') == True
        assert pq_constant_time_compare(b'test', b'TEST') == False
        assert pq_constant_time_compare(b'short', b'longer') == False
    
    def test_secure_pq_key_zeroize(self):
        """Verify key zeroization function."""
        buf = bytearray(b'secret key material')
        original = bytes(buf)
        
        secure_pq_key_zeroize(buf)
        
        assert all(b == 0 for b in buf)
        assert bytes(buf) != original
    
    def test_secure_pq_key_zeroize_empty(self):
        """Verify zeroize handles empty buffers."""
        buf = bytearray()
        secure_pq_key_zeroize(buf)  # Should not raise
        assert len(buf) == 0
    
    def test_wrap_pq_sensitive_operation(self):
        """Verify decorator works."""
        call_count = [0]
        
        @wrap_pq_sensitive_operation(FaultDetectionMode.DOUBLE_CHECK)
        def sensitive_op(x):
            call_count[0] += 1
            return x * 2
        
        result = sensitive_op(5)
        
        assert result == 10
        assert call_count[0] >= 2  # At least double execution


class TestApiStability:
    """Tests for API stability markers."""
    
    def test_all_exports_have_stability(self):
        """Verify all exports have stability markers."""
        from quantum_crypt.crypto_security_hardening_pq_constant_time_key_protection_v31_2026_june import (
            __all__, __api_stability__
        )
        
        for export in __all__:
            assert export in __api_stability__, f"Missing stability for {export}"
    
    def test_valid_stability_values(self):
        """Verify stability values are valid."""
        from quantum_crypt.crypto_security_hardening_pq_constant_time_key_protection_v31_2026_june import (
            __api_stability__
        )
        
        valid = {'STABLE', 'EXPERIMENTAL', 'DEPRECATED'}
        for stability in __api_stability__.values():
            assert stability in valid, f"Invalid stability: {stability}"


class TestIntegrationWithExistingCode:
    """Integration tests - verify new code doesn't conflict."""
    
    def test_import_without_conflict(self):
        """Verify module imports cleanly."""
        # This should not raise any import errors
        import quantum_crypt.crypto_security_hardening_pq_constant_time_key_protection_v31_2026_june
        assert True  # If we get here, import succeeded


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
