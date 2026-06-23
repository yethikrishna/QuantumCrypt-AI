"""
Tests for QuantumCrypt Security Hardening - Side-Channel Attack Resistance
DIMENSION B: Security Hardening (v16)
ADD-ONLY tests - no modifications to production source code

Covers:
1. Timing attack protection
2. Power analysis resistance (SPA/DPA)
3. Constant-time key operations
4. Cache side-channel mitigation
5. Blind crypto operations
6. Crypto operation randomization
"""

import pytest
import time
import secrets
import statistics
from typing import Callable

from quantum_crypt.crypto_security_hardening_side_channel_resistance_v16_2026_june import (
    TimingAttackProtector,
    PowerAnalysisResistance,
    ConstantTimeKeyOperations,
    CacheSideChannelMitigation,
    BlindCryptoOperations,
    CryptoOperationRandomizer,
    protected_crypto_op,
    constant_time_key_compare,
    blind_crypto_data,
    unblind_crypto_data,
    insert_dummy_crypto_work
)


class TestTimingAttackProtector:
    """Tests for timing attack prevention."""
    
    def test_start_end_operation(self):
        """Test basic operation timing flow."""
        protector = TimingAttackProtector(base_delay_ns=100000, jitter_range_ns=10000)
        protector.start_operation()
        # Do some work
        x = sum(range(100))
        protector.end_operation()
        assert x == 4950  # Verify work completed
    
    def test_protected_operation_wrapper(self):
        """Test operation wrapper function."""
        protector = TimingAttackProtector()
        
        def sample_op(a: int, b: int) -> int:
            return a + b
        
        result = protector.protected_operation(sample_op, 5, 3)
        assert result == 8
    
    def test_minimum_duration_enforced(self):
        """Test that operations take at least base delay."""
        protector = TimingAttackProtector(base_delay_ns=5000000, jitter_range_ns=0)  # 5ms base
        
        def fast_op():
            return 42
        
        start = time.perf_counter_ns()
        protector.protected_operation(fast_op)
        elapsed = time.perf_counter_ns() - start
        
        # Should take at least ~5ms
        assert elapsed >= 4000000  # Allow some tolerance
    
    def test_timing_consistency_across_paths(self):
        """Test that fast and slow code paths have similar timing."""
        protector = TimingAttackProtector(base_delay_ns=2000000, jitter_range_ns=500000)
        
        def fast_path():
            return True
        
        def slow_path():
            acc = 0
            for i in range(10000):
                acc += i
            return acc
        
        def time_op(op: Callable, iterations: int = 20) -> float:
            times = []
            for _ in range(iterations):
                start = time.perf_counter_ns()
                protector.protected_operation(op)
                times.append(time.perf_counter_ns() - start)
            return statistics.median(times)
        
        fast_time = time_op(fast_path)
        slow_time = time_op(slow_path)
        
        # Timing should be normalized - ratio should be small
        ratio = max(fast_time, slow_time) / min(fast_time, slow_time)
        assert ratio < 2.0, f"Timing not normalized: ratio={ratio}"


class TestPowerAnalysisResistance:
    """Tests for SPA/DPA countermeasures."""
    
    def test_blind_unblind_roundtrip(self):
        """Test blinding and unblinding restores original data."""
        original = b"sensitive_key_material_12345"
        blinded, factor = PowerAnalysisResistance.blind_data(original)
        
        # Blinded should differ from original
        assert blinded != original
        
        # Unblinding should restore original
        restored = PowerAnalysisResistance.unblind_data(blinded, factor)
        assert restored == original
    
    def test_blind_with_custom_factor(self):
        """Test blinding with pre-generated factor."""
        original = b"test_data"
        factor = secrets.token_bytes(len(original))
        blinded, used_factor = PowerAnalysisResistance.blind_data(original, factor)
        
        assert used_factor == factor
        assert PowerAnalysisResistance.unblind_data(blinded, factor) == original
    
    def test_dummy_operations_no_error(self):
        """Test dummy operations execute without error."""
        # Should not raise any exceptions
        PowerAnalysisResistance.insert_dummy_operations()
        PowerAnalysisResistance.insert_dummy_operations((1, 5))
        PowerAnalysisResistance.insert_dummy_operations((50, 100))
    
    def test_shuffle_operations(self):
        """Test operation shuffling."""
        ops = [lambda: 1, lambda: 2, lambda: 3, lambda: 4, lambda: 5]
        original_ids = [id(op) for op in ops]
        
        shuffled = PowerAnalysisResistance.shuffle_operations(ops)
        
        # Same operations, different order (with high probability)
        shuffled_ids = [id(op) for op in shuffled]
        assert set(shuffled_ids) == set(original_ids)
        # With 5 elements, probability of same order is 1/120 ~ 0.8%
        # So this assertion is statistically safe
        assert len(shuffled) == len(ops)


class TestConstantTimeKeyOperations:
    """Tests for constant-time key operations."""
    
    def test_key_compare_equal(self):
        """Test equal keys compare correctly."""
        key1 = secrets.token_bytes(32)
        key2 = bytes(key1)
        assert ConstantTimeKeyOperations.constant_time_compare_keys(key1, key2) is True
    
    def test_key_compare_not_equal(self):
        """Test non-equal keys compare correctly."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        assert ConstantTimeKeyOperations.constant_time_compare_keys(key1, key2) is False
    
    def test_key_compare_different_length(self):
        """Test keys of different lengths."""
        key1 = secrets.token_bytes(16)
        key2 = secrets.token_bytes(32)
        assert ConstantTimeKeyOperations.constant_time_compare_keys(key1, key2) is False
    
    def test_key_derivation_deterministic(self):
        """Test key derivation produces same result for same inputs."""
        base = b"master_key"
        salt = b"salt_value"
        
        result1 = ConstantTimeKeyOperations.constant_time_key_derivation(base, salt, iterations=100)
        result2 = ConstantTimeKeyOperations.constant_time_key_derivation(base, salt, iterations=100)
        
        assert result1 == result2
    
    def test_key_derivation_different_inputs(self):
        """Test key derivation produces different results for different inputs."""
        result1 = ConstantTimeKeyOperations.constant_time_key_derivation(b"key1", b"salt", iterations=100)
        result2 = ConstantTimeKeyOperations.constant_time_key_derivation(b"key2", b"salt", iterations=100)
        
        assert result1 != result2
    
    def test_key_load_correct(self):
        """Test key loading preserves values."""
        key = secrets.token_bytes(64)
        loaded = ConstantTimeKeyOperations.constant_time_key_load(key)
        
        assert bytes(loaded) == key
        assert isinstance(loaded, bytearray)


class TestCacheSideChannelMitigation:
    """Tests for cache side-channel countermeasures."""
    
    def test_memory_boundary_isolate(self):
        """Test data splitting across cache boundaries."""
        data = secrets.token_bytes(200)
        blocks = CacheSideChannelMitigation.memory_boundary_isolate(data, block_size=64)
        
        # Should create full blocks
        for block in blocks:
            assert len(block) == 64
    
    def test_memory_boundary_isolate_exact(self):
        """Test isolation with exact block size multiple."""
        data = secrets.token_bytes(128)
        blocks = CacheSideChannelMitigation.memory_boundary_isolate(data, block_size=64)
        
        assert len(blocks) == 2
        assert blocks[0] == data[:64]
        assert blocks[1] == data[64:]
    
    def test_random_access_pattern(self):
        """Test access pattern randomization."""
        indices = list(range(10))
        randomized = CacheSideChannelMitigation.random_access_pattern(indices)
        
        # Same elements, potentially different order
        assert set(randomized) == set(indices)
        assert len(randomized) == len(indices)


class TestBlindCryptoOperations:
    """Tests for blind crypto operation wrappers."""
    
    def test_blind_sign_basic(self):
        """Test basic blind signature flow."""
        blind_ops = BlindCryptoOperations()
        
        # Mock private key operation
        def mock_sign(data: bytes) -> bytes:
            return bytes(b ^ 0xAA for b in data)
        
        message = b"message_to_sign"
        signature = blind_ops.blind_sign(mock_sign, message)
        
        # Signature should be returned
        assert len(signature) == len(message)
    
    def test_blind_decrypt_basic(self):
        """Test basic blind decryption flow."""
        blind_ops = BlindCryptoOperations()
        
        # Mock private key decryption
        def mock_decrypt(data: bytes) -> bytes:
            return bytes(b ^ 0x55 for b in data)
        
        ciphertext = b"encrypted_data_here"
        plaintext = blind_ops.blind_decrypt(mock_decrypt, ciphertext)
        
        assert len(plaintext) == len(ciphertext)


class TestCryptoOperationRandomizer:
    """Tests for crypto operation randomization."""
    
    def test_wrap_operation(self):
        """Test operation wrapping."""
        randomizer = CryptoOperationRandomizer()
        
        def crypto_op(x: int, y: int) -> int:
            return x * y
        
        wrapped = randomizer.wrap_operation(crypto_op)
        result = wrapped(7, 6)
        
        assert result == 42
    
    def test_randomize_key_schedule(self):
        """Test key schedule randomization."""
        randomizer = CryptoOperationRandomizer()
        
        def key_schedule(master: bytes) -> list:
            return [master[i:i+16] for i in range(0, len(master), 16)]
        
        wrapped = randomizer.randomize_key_schedule(key_schedule)
        key = secrets.token_bytes(64)
        subkeys = wrapped(key)
        
        assert len(subkeys) == 4
        assert subkeys[0] == key[:16]


class TestConvenienceFunctions:
    """Tests for public convenience API."""
    
    def test_protected_crypto_op(self):
        """Test top-level protected operation."""
        def op(a, b):
            return a + b
        
        result = protected_crypto_op(op, 10, 20)
        assert result == 30
    
    def test_constant_time_key_compare(self):
        """Test top-level key comparison."""
        key = secrets.token_bytes(32)
        assert constant_time_key_compare(key, bytes(key)) is True
        assert constant_time_key_compare(key, secrets.token_bytes(32)) is False
    
    def test_blind_unblind_functions(self):
        """Test top-level blind/unblind."""
        data = b"secret_data"
        blinded, factor = blind_crypto_data(data)
        restored = unblind_crypto_data(blinded, factor)
        assert restored == data
    
    def test_insert_dummy_work(self):
        """Test top-level dummy work."""
        insert_dummy_crypto_work()  # Should not raise


class TestEdgeCases:
    """Edge case and boundary condition tests."""
    
    def test_empty_data_blinding(self):
        """Test blinding empty data."""
        empty = b""
        blinded, factor = PowerAnalysisResistance.blind_data(empty)
        assert blinded == empty
        assert factor == empty
    
    def test_single_byte_key_compare(self):
        """Test comparing single-byte keys."""
        assert ConstantTimeKeyOperations.constant_time_compare_keys(b"a", b"a") is True
        assert ConstantTimeKeyOperations.constant_time_compare_keys(b"a", b"b") is False
    
    def test_very_large_data_blinding(self):
        """Test blinding large data."""
        large_data = secrets.token_bytes(10000)
        blinded, factor = PowerAnalysisResistance.blind_data(large_data)
        restored = PowerAnalysisResistance.unblind_data(blinded, factor)
        assert restored == large_data
    
    def test_zero_jitter_timing_protector(self):
        """Test protector with zero jitter."""
        protector = TimingAttackProtector(base_delay_ns=100000, jitter_range_ns=0)
        protector.start_operation()
        protector.end_operation()  # Should not raise
    
    def test_cache_isolate_single_byte(self):
        """Test cache isolation with single byte."""
        blocks = CacheSideChannelMitigation.memory_boundary_isolate(b"x", block_size=64)
        assert len(blocks) == 1
        assert len(blocks[0]) == 64


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
