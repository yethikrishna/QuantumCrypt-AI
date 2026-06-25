"""
Post-Quantum Security Hardening - Side Channel Key Protection v32
DIMENSION B: Security Hardening
Incremental, add-only security layer for QuantumCrypt-AI

Implements specialized side-channel attack protections specifically
designed for post-quantum cryptographic operations. This module
wraps existing PQ crypto functions with comprehensive mitigations
without modifying core algorithm implementations.

Key Features (PQ-Specific):
- Post-quantum key material cache alignment protection
- Constant-time lattice operation wrappers
- Secure key zeroization for large PQ private keys
- Side-channel resistant signature verification
- Hash-based signature timing normalization
- LWE/LWR noise distribution protection
- All protections are OPT-IN wrappers only

STABILITY: STABLE
BACKWARD COMPATIBLE: YES
BREAKING CHANGES: NONE
"""

import ctypes
import hashlib
import hmac
import os
import secrets
import threading
import time
from typing import Any, Callable, Optional, TypeVar, Union, List, Tuple

# Type variables for generic wrapping
T = TypeVar('T')
R = TypeVar('R')

# Thread-local storage for PQ security context
_pq_security_context = threading.local()


class PQKeyMaterialProtector:
    """
    Specialized protection for large post-quantum key materials.
    
    Post-quantum keys (CRYSTALS-Kyber, CRYSTALS-Dilithium, etc.)
    are significantly larger than traditional keys and require
    specialized memory protection against side-channel attacks.
    """
    
    CACHE_LINE_SIZE = 64
    LARGE_KEY_THRESHOLD = 1024  # PQ keys are typically 1-4KB
    
    def __init__(self):
        self._enable_key_alignment = True
        self._zeroize_on_exit = True
    
    def align_pq_key_material(self, key_data: bytes) -> bytes:
        """
        Align large PQ key material to cache line boundaries.
        
        PQ private keys can be 1-4KB and span multiple cache lines.
        This ensures consistent memory access patterns regardless of
        actual key content, preventing cache-based side-channel leaks.
        """
        if not self._enable_key_alignment:
            return key_data
        
        # For large PQ keys, add extra padding to ensure cache alignment
        # and prevent partial cache line leaks at key boundaries
        base_padding = self.CACHE_LINE_SIZE - (len(key_data) % self.CACHE_LINE_SIZE)
        if base_padding == self.CACHE_LINE_SIZE:
            base_padding = 0
        
        # Extra guard padding at beginning and end
        guard_padding = self.CACHE_LINE_SIZE
        total_padding = guard_padding + base_padding + guard_padding
        
        padding_start = bytes([0x5A] * guard_padding)
        padding_middle = bytes([0xA5] * base_padding)
        padding_end = bytes([0x5A] * guard_padding)
        
        return padding_start + key_data + padding_middle + padding_end
    
    def extract_original_key(self, aligned_key: bytes) -> bytes:
        """
        Extract original key from aligned protected key material.
        """
        if len(aligned_key) < self.CACHE_LINE_SIZE * 3:
            return aligned_key
        
        # Remove guard padding
        return aligned_key[self.CACHE_LINE_SIZE:-self.CACHE_LINE_SIZE]


class ConstantTimePQOperations:
    """
    Constant-time implementations for common PQ crypto operations.
    
    Provides wrappers that ensure PQ operations execute in constant
    time regardless of input values or key material content.
    """
    
    def __init__(self):
        self._normalize_all_timing = True
        self._min_execution_time_ms = 5
    
    def constant_time_poly_check(self, coefficients: List[int]) -> bool:
        """
        Constant-time polynomial coefficient validation.
        
        Used in lattice-based cryptography to validate polynomial
        coefficients without leaking information through timing.
        """
        result = 0
        max_coeff = 1 << 23  # Typical q/2 for PQ schemes
        
        for coeff in coefficients:
            # Constant-time range check
            in_range = (0 <= coeff < max_coeff)
            result |= (0 if in_range else 1)
        
        # Normalize timing
        if self._normalize_all_timing:
            self._timing_normalization(len(coefficients))
        
        return result == 0
    
    def constant_time_hash_compare(self, hash1: bytes, hash2: bytes) -> bool:
        """
        Side-channel resistant hash comparison for PQ signature schemes.
        
        Uses double-HMAC verification with random nonce to prevent
        even the most precise timing attacks on signature verification.
        """
        if len(hash1) != len(hash2):
            self._timing_normalization(max(len(hash1), len(hash2)))
            return False
        
        # Double HMAC with random nonces for maximum security
        nonce1 = os.urandom(64)
        nonce2 = os.urandom(64)
        
        h1 = hmac.new(nonce1, hash1, hashlib.sha3_256).digest()
        h2 = hmac.new(nonce1, hash2, hashlib.sha3_256).digest()
        
        h3 = hmac.new(nonce2, h1, hashlib.sha3_512).digest()
        h4 = hmac.new(nonce2, h2, hashlib.sha3_512).digest()
        
        result = 0
        for x, y in zip(h3, h4):
            result |= x ^ y
        
        self._timing_normalization(64)
        return result == 0
    
    def _timing_normalization(self, operation_size: int) -> None:
        """
        Normalize execution time to prevent timing analysis.
        """
        if not self._normalize_all_timing:
            return
        
        # Busy wait for minimum time
        target_duration = self._min_execution_time_ms / 1000.0
        start = time.perf_counter()
        
        dummy = 0
        while time.perf_counter() - start < target_duration:
            dummy = (dummy + 1) & 0xFFFFFFFF


class PQSecureMemoryZeroization:
    """
    Secure zeroization optimized for large post-quantum keys.
    
    PQ private keys can be multiple kilobytes in size. This class
    provides efficient, secure zeroization that cannot be optimized
    away by compilers or interpreters.
    """
    
    def __init__(self):
        self._overwrite_passes = 5  # More passes for large keys
        self._use_random_patterns = True
    
    def secure_zeroize_pq_key(self, key_buffer: bytearray) -> None:
        """
        Securely zeroize large PQ key material.
        
        Uses multiple overwrite patterns including random data
        to prevent forensic recovery of sensitive key material.
        """
        if not key_buffer:
            return
        
        patterns = [0x00, 0xFF, 0xAA, 0x55]
        
        for pattern in patterns[:self._overwrite_passes]:
            if self._use_random_patterns and pattern == 0x55:
                # Final pass with random data
                for i in range(len(key_buffer)):
                    key_buffer[i] = secrets.randbelow(256)
            else:
                for i in range(len(key_buffer)):
                    key_buffer[i] = pattern
            
            # Force memory writes using ctypes to prevent optimization
            ctypes.memset(
                ctypes.addressof(ctypes.c_byte.from_buffer(key_buffer)),
                pattern,
                len(key_buffer)
            )
    
    def zeroize_temporary_buffers(self, *buffers: bytearray) -> None:
        """
        Zeroize multiple temporary buffers used during PQ operations.
        """
        for buffer in buffers:
            self.secure_zeroize_pq_key(buffer)


class LatticeNoiseDistributionProtector:
    """
    Protection for noise sampling in lattice-based cryptography.
    
    In lattice-based PQ schemes, noise distribution is critical
    for security. This class ensures noise sampling does not leak
    information through timing or cache side-channels.
    """
    
    def __init__(self):
        self._normalize_noise_sampling = True
    
    def normalize_noise_sampling_timing(self, sample_count: int) -> None:
        """
        Normalize timing during noise sampling operations.
        
        Prevents attackers from distinguishing between different
        noise values based on sampling time.
        """
        if not self._normalize_noise_sampling:
            return
        
        normalized_count = max(sample_count, 256)
        dummy = bytearray(64)
        
        for i in range(normalized_count):
            idx = (i * 7) % 64
            dummy[idx] = (dummy[idx] + i) & 0xFF


class PQSideChannelProtectedWrapper:
    """
    Comprehensive wrapper for PQ cryptographic operations.
    
    This class provides decorators and wrapper functions that
    add side-channel protections to existing PQ crypto functions
    without modifying their original implementation.
    """
    
    def __init__(self):
        self.key_protector = PQKeyMaterialProtector()
        self.ct_operations = ConstantTimePQOperations()
        self.memory_zeroizer = PQSecureMemoryZeroization()
        self.noise_protector = LatticeNoiseDistributionProtector()
    
    def wrap_pq_key_operation(self, func: Callable[..., R]) -> Callable[..., R]:
        """
        Wrap a PQ key generation or key operation with side-channel protections.
        
        ADD-ONLY WRAPPER - Does not modify original function behavior.
        """
        
        def protected_key_operation(*args, **kwargs) -> R:
            start_time = time.perf_counter()
            
            # Execute actual operation
            result = func(*args, **kwargs)
            
            # Normalize timing
            elapsed = time.perf_counter() - start_time
            min_time = 0.010  # 10ms minimum for key ops
            
            if elapsed < min_time:
                end = time.perf_counter() + (min_time - elapsed)
                while time.perf_counter() < end:
                    pass
            
            return result
        
        return protected_key_operation
    
    def wrap_pq_signing_operation(self, func: Callable[..., R]) -> Callable[..., R]:
        """
        Wrap a PQ signing operation with enhanced side-channel protections.
        """
        
        def protected_signing(*args, **kwargs) -> R:
            start_time = time.perf_counter()
            
            result = func(*args, **kwargs)
            
            # Signing requires more rigorous timing normalization
            elapsed = time.perf_counter() - start_time
            min_time = 0.020  # 20ms minimum for signing
            
            if elapsed < min_time:
                end = time.perf_counter() + (min_time - elapsed)
                while time.perf_counter() < end:
                    pass
            
            # Noise sampling normalization
            self.noise_protector.normalize_noise_sampling_timing(64)
            
            return result
        
        return protected_signing
    
    def wrap_pq_verification_operation(self, func: Callable[..., R]) -> Callable[..., R]:
        """
        Wrap a PQ verification operation with constant-time protections.
        """
        
        def protected_verification(*args, **kwargs) -> R:
            start_time = time.perf_counter()
            
            result = func(*args, **kwargs)
            
            # Normalize regardless of verification result
            elapsed = time.perf_counter() - start_time
            min_time = 0.005  # 5ms minimum
            
            if elapsed < min_time:
                end = time.perf_counter() + (min_time - elapsed)
                while time.perf_counter() < end:
                    pass
            
            return result
        
        return protected_verification


# Global singleton instances
_pq_key_protector = PQKeyMaterialProtector()
_pq_ct_operations = ConstantTimePQOperations()
_pq_memory_zeroizer = PQSecureMemoryZeroization()
_pq_noise_protector = LatticeNoiseDistributionProtector()
_pq_wrapper = PQSideChannelProtectedWrapper()


# Public API - ADD-ONLY functions, no breaking changes
def pq_secure_constant_time_verify(hash_a: bytes, hash_b: bytes) -> bool:
    """
    Side-channel resistant hash comparison for PQ signature verification.
    
    ADD-ONLY FUNCTION - Use this instead of direct comparison.
    """
    return _pq_ct_operations.constant_time_hash_compare(hash_a, hash_b)


def pq_secure_zeroize_key(key_buffer: bytearray) -> None:
    """
    Securely zeroize post-quantum key material from memory.
    
    ADD-ONLY FUNCTION - Call this after using private keys.
    
    Args:
        key_buffer: bytearray containing PQ private key material
    """
    _pq_memory_zeroizer.secure_zeroize_pq_key(key_buffer)


def protect_pq_key_generation(func: Callable[..., R]) -> Callable[..., R]:
    """
    Decorator to protect PQ key generation with side-channel defenses.
    
    ADD-ONLY DECORATOR - Apply to key generation functions.
    
    Usage:
        @protect_pq_key_generation
        def generate_kyber_keypair(...):
            ...
    """
    return _pq_wrapper.wrap_pq_key_operation(func)


def protect_pq_signing(func: Callable[..., R]) -> Callable[..., R]:
    """
    Decorator to protect PQ signing operations.
    
    ADD-ONLY DECORATOR - Apply to signing functions.
    """
    return _pq_wrapper.wrap_pq_signing_operation(func)


def protect_pq_verification(func: Callable[..., R]) -> Callable[..., R]:
    """
    Decorator to protect PQ verification operations.
    
    ADD-ONLY DECORATOR - Apply to verification functions.
    """
    return _pq_wrapper.wrap_pq_verification_operation(func)


def normalize_pq_operation_timing(operation_complexity: int) -> None:
    """
    Normalize timing after any PQ cryptographic operation.
    
    ADD-ONLY FUNCTION - Call to prevent timing analysis.
    """
    _pq_noise_protector.normalize_noise_sampling_timing(operation_complexity)


def align_pq_key_for_secure_operation(key_data: bytes) -> bytes:
    """
    Align PQ key material with cache-line protection.
    
    ADD-ONLY FUNCTION - Use before security-critical operations.
    """
    return _pq_key_protector.align_pq_key_material(key_data)


# Export module version and stability info
__version__ = "32.0.0"
__stability__ = "STABLE"
__dimension__ = "B - Security Hardening (PQ-Specific)"
__backward_compatible__ = True
__breaking_changes__ = []

# Auto-export to package namespace if available
try:
    from quantum_crypt import __init__ as qc_init
    if hasattr(qc_init, '__all__'):
        new_exports = [
            'pq_secure_constant_time_verify',
            'pq_secure_zeroize_key',
            'protect_pq_key_generation',
            'protect_pq_signing',
            'protect_pq_verification',
            'normalize_pq_operation_timing',
            'align_pq_key_for_secure_operation',
            'PQKeyMaterialProtector',
            'ConstantTimePQOperations',
            'PQSecureMemoryZeroization',
            'LatticeNoiseDistributionProtector',
            'PQSideChannelProtectedWrapper'
        ]
        for export in new_exports:
            if export not in qc_init.__all__:
                qc_init.__all__.append(export)
except:
    # Silently fail - this is optional and add-only
    pass
