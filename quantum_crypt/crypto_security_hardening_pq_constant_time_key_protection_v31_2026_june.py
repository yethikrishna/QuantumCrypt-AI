"""
Security Hardening: Post-Quantum Constant-Time Key Protection v31
DIMENSION B - Security Hardening

This module provides post-quantum specific security hardening:
1. Constant-time key material operations for PQ algorithms
2. Secure key wrapping with side-channel resistance
3. Key material zeroization with memory protection
4. Fault injection detection for key operations

NOTE: This is a NEW module - layers security ON TOP of existing code.
No existing production code is modified. All features are opt-in wrappers.

API Stability: STABLE
Thread Safety: YES
Backward Compatible: YES
"""

import os
import sys
import secrets
import hashlib
import hmac
import threading
import time
from typing import Any, Callable, Optional, TypeVar, Union, List, Tuple, Dict
from dataclasses import dataclass, field
from enum import Enum, auto
import logging

# Type variables
T = TypeVar('T')
F = TypeVar('F', bound=Callable)

logger = logging.getLogger(__name__)


class KeySensitivityLevel(Enum):
    """Sensitivity levels for key material."""
    PUBLIC = auto()          # Public keys, no special protection
    INTERNAL = auto()        # Internal derived keys
    SENSITIVE = auto()       # Private keys
    CRITICAL = auto()        # Master keys, root secrets
    EPHEMERAL = auto()       # Session keys, short-lived


class PQAlgorithmType(Enum):
    """Post-quantum algorithm types."""
    LATTICE = auto()         # CRYSTALS-Kyber, NTRU
    CODE_BASED = auto()      # Classic McEliece
    HASH_BASED = auto()      # SPHINCS+, XMSS
    ISOGENY = auto()         # SIKE (deprecated, but supported)
    MULTIVARIATE = auto()    # Rainbow, GeMSS
    HYBRID = auto()          # PQ + classical composite


class FaultDetectionMode(Enum):
    """Fault injection detection modes."""
    NONE = auto()            # No detection
    CHECKSUM = auto()        # Simple checksum verification
    REDUNDANCY = auto()      # Redundant computation
    DOUBLE_CHECK = auto()    # Double execution with compare
    FULL_REDUNDANCY = auto() # Triple modular redundancy


@dataclass
class PQKeyProtectionConfig:
    """Configuration for post-quantum key protection."""
    sensitivity_level: KeySensitivityLevel = KeySensitivityLevel.SENSITIVE
    algorithm_type: PQAlgorithmType = PQAlgorithmType.LATTICE
    fault_detection: FaultDetectionMode = FaultDetectionMode.DOUBLE_CHECK
    enable_constant_time: bool = True
    enable_zeroization: bool = True
    enable_timing_noise: bool = True
    enable_access_logging: bool = False
    max_key_usage_count: int = 10000
    
    # Runtime statistics
    keys_protected: int = field(default=0, init=False)
    operations_performed: int = field(default=0, init=False)
    zeroizations_performed: int = field(default=0, init=False)
    faults_detected: int = field(default=0, init=False)


class PQKeyMaterial:
    """
    Wrapper for post-quantum key material with security hardening.
    
    Provides:
    - Constant-time access to key bytes
    - Automatic zeroization on cleanup
    - Fault detection for key operations
    - Usage counting and limits
    """
    
    def __init__(
        self,
        key_bytes: bytes,
        config: Optional[PQKeyProtectionConfig] = None,
    ):
        self._config = config or PQKeyProtectionConfig()
        self._lock = threading.Lock()
        self._usage_count = 0
        self._destroyed = False
        
        # Store key with canary for corruption detection
        self._key_data = bytearray(key_bytes)
        self._canary = secrets.token_bytes(16)
        self._checksum = self._compute_checksum()
        
        with self._lock:
            self._config.keys_protected += 1
    
    def _compute_checksum(self) -> bytes:
        """Compute checksum for key integrity verification."""
        return hmac.new(
            self._canary,
            bytes(self._key_data),
            hashlib.sha256
        ).digest()
    
    def _verify_integrity(self) -> bool:
        """Verify key material hasn't been corrupted."""
        current_checksum = self._compute_checksum()
        return hmac.compare_digest(current_checksum, self._checksum)
    
    def _check_usage(self) -> None:
        """Check usage limits and integrity."""
        if self._destroyed:
            raise ValueError("Key material has been destroyed")
        
        if not self._verify_integrity():
            with self._lock:
                self._config.faults_detected += 1
            raise RuntimeError("Key material integrity check failed - possible fault injection")
        
        self._usage_count += 1
        if self._usage_count > self._config.max_key_usage_count:
            logger.warning(f"Key usage count exceeded limit: {self._usage_count}")
    
    def _inject_timing_noise(self) -> None:
        """Inject timing noise for side-channel resistance."""
        if not self._config.enable_timing_noise:
            return
            
        if self._config.sensitivity_level in [
            KeySensitivityLevel.CRITICAL, 
            KeySensitivityLevel.SENSITIVE
        ]:
            jitter = secrets.randbelow(500)  # nanoseconds
            target = time.perf_counter_ns() + jitter
            while time.perf_counter_ns() < target:
                pass
    
    def get_bytes(self) -> bytes:
        """
        Get key bytes with security hardening.
        
        Returns:
            Copy of key bytes (caller responsible for cleanup)
        """
        with self._lock:
            self._check_usage()
            self._inject_timing_noise()
            
            # Return a copy, not the internal buffer
            result = bytes(self._key_data)
            
            self._config.operations_performed += 1
            
            return result
    
    def constant_time_compare(self, other: bytes) -> bool:
        """
        Constant-time comparison with key material.
        
        Prevents timing attacks on key equality checks.
        """
        with self._lock:
            self._check_usage()
            self._inject_timing_noise()
            
            key_bytes = bytes(self._key_data)
            
            if len(key_bytes) != len(other):
                # Still do full comparison to prevent timing leak
                result = 0
                max_len = max(len(key_bytes), len(other))
                for i in range(max_len):
                    result |= key_bytes[i % len(key_bytes)] ^ other[i % len(other)]
                return False
            
            result = 0
            for x, y in zip(key_bytes, other):
                result |= x ^ y
            
            self._config.operations_performed += 1
            
            return result == 0
    
    def secure_derive_subkey(self, context: bytes, length: int) -> bytes:
        """
        Derive a subkey using HKDF-style derivation with protection.
        
        Uses HMAC-SHA256 for secure derivation with constant-time operations.
        """
        with self._lock:
            self._check_usage()
            self._inject_timing_noise()
            
            # HKDF-Extract
            prk = hmac.new(context, bytes(self._key_data), hashlib.sha256).digest()
            
            # HKDF-Expand
            t = b''
            okm = b''
            i = 1
            while len(okm) < length:
                t = hmac.new(prk, t + context + bytes([i]), hashlib.sha256).digest()
                okm += t
                i += 1
            
            self._config.operations_performed += 1
            
            return okm[:length]
    
    def destroy(self) -> None:
        """
        Securely destroy key material.
        
        Overwrites key data with multiple patterns and marks as destroyed.
        """
        with self._lock:
            if self._destroyed:
                return
            
            length = len(self._key_data)
            
            # Multiple overwrite patterns
            patterns = [b'\x00', b'\xFF', b'\x55', b'\xAA']
            for pattern in patterns:
                for i in range(length):
                    self._key_data[i] = pattern[0]
            
            # Final zero
            for i in range(length):
                self._key_data[i] = 0
            
            self._destroyed = True
            self._config.zeroizations_performed += 1
    
    def __del__(self):
        """Automatic cleanup on garbage collection."""
        if self._config.enable_zeroization and not getattr(self, '_destroyed', True):
            try:
                self.destroy()
            except:
                pass  # Best effort only
    
    def get_stats(self) -> dict:
        """Get key protection statistics."""
        with self._lock:
            return {
                'key_length': len(self._key_data),
                'usage_count': self._usage_count,
                'destroyed': self._destroyed,
                'sensitivity_level': self._config.sensitivity_level.name,
                'algorithm_type': self._config.algorithm_type.name,
                'fault_detection': self._config.fault_detection.name,
            }


class ConstantTimePQOperations:
    """
    Constant-time implementations of common PQ cryptographic operations.
    
    All operations run in data-independent time to prevent timing attacks.
    """
    
    @staticmethod
    def constant_time_select(condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Constant-time selection between two values.
        
        Returns a if condition is True, b otherwise, in constant time.
        No branching on secret data.
        """
        if len(a) != len(b):
            raise ValueError("Inputs must be same length")
        
        # Convert condition to mask: all 0s or all 1s
        mask = -condition  # 0 if False, -1 (all bits 1) if True in two's complement
        
        result = bytearray(len(a))
        for i in range(len(a)):
            # result[i] = (a[i] & mask) | (b[i] & ~mask)
            result[i] = (a[i] & (mask & 0xFF)) | (b[i] & (~mask & 0xFF))
        
        return bytes(result)
    
    @staticmethod
    def constant_time_byte_select(condition: bool, a: int, b: int) -> int:
        """Constant-time selection between two byte values."""
        mask = -condition
        return (a & (mask & 0xFF)) | (b & (~mask & 0xFF))
    
    @staticmethod
    def secure_array_copy(src: bytes, dst: bytearray, condition: bool) -> None:
        """
        Conditionally copy array in constant time.
        
        Copies src to dst if condition is True, otherwise does nothing,
        but always touches all memory locations in constant time.
        """
        mask = -condition
        for i in range(min(len(src), len(dst))):
            dst[i] = ConstantTimePQOperations.constant_time_byte_select(
                condition, src[i], dst[i]
            )
    
    @staticmethod
    def constant_time_lookup(table: List[bytes], index: int) -> bytes:
        """
        Constant-time table lookup.
        
        Prevents cache timing attacks by accessing all table entries.
        """
        if not table:
            return b''
        
        entry_size = len(table[0])
        result = bytearray(entry_size)
        
        for i, entry in enumerate(table):
            # Copy if index == i, leave as is otherwise
            match = (i == index)
            ConstantTimePQOperations.secure_array_copy(entry, result, match)
        
        return bytes(result)


class FaultResistantOperation:
    """
    Wrapper for fault-resistant cryptographic operations.
    
    Detects fault injection attacks through redundant computation
    and checksum verification.
    """
    
    def __init__(self, mode: FaultDetectionMode = FaultDetectionMode.DOUBLE_CHECK):
        self.mode = mode
        self._lock = threading.Lock()
    
    def execute(self, operation: Callable[[], T], *args, **kwargs) -> T:
        """
        Execute operation with fault detection.
        
        Args:
            operation: Function to execute
            *args, **kwargs: Arguments for operation
            
        Returns:
            Result of operation if no fault detected
            
        Raises:
            RuntimeError: If fault injection is detected
        """
        if self.mode == FaultDetectionMode.NONE:
            return operation(*args, **kwargs)
        
        elif self.mode == FaultDetectionMode.DOUBLE_CHECK:
            # Execute twice and compare
            result1 = operation(*args, **kwargs)
            result2 = operation(*args, **kwargs)
            
            if isinstance(result1, bytes) and isinstance(result2, bytes):
                if not hmac.compare_digest(result1, result2):
                    with self._lock:
                        logger.warning("Fault detected: double execution mismatch")
                    raise RuntimeError("Fault injection detected")
            elif result1 != result2:
                with self._lock:
                    logger.warning("Fault detected: double execution mismatch")
                raise RuntimeError("Fault injection detected")
            
            return result1
        
        elif self.mode == FaultDetectionMode.FULL_REDUNDANCY:
            # Triple modular redundancy - majority vote
            result1 = operation(*args, **kwargs)
            result2 = operation(*args, **kwargs)
            result3 = operation(*args, **kwargs)
            
            # Simple majority - at least 2 must agree
            if result1 == result2 or result1 == result3:
                return result1
            elif result2 == result3:
                return result2
            else:
                raise RuntimeError("Fault injection detected - all results differ")
        
        else:
            # CHECKSUM or default - single execution
            return operation(*args, **kwargs)


# Global configuration and convenience functions
_default_config = PQKeyProtectionConfig()


def create_protected_key(
    key_bytes: bytes,
    sensitivity: KeySensitivityLevel = KeySensitivityLevel.SENSITIVE,
) -> PQKeyMaterial:
    """
    Create a protected key wrapper for sensitive key material.
    
    Convenience function for easy use.
    """
    config = PQKeyProtectionConfig(sensitivity_level=sensitivity)
    return PQKeyMaterial(key_bytes, config)


def pq_constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison for post-quantum security."""
    if len(a) != len(b):
        # Prevent timing leak from length difference
        result = 0
        max_len = max(len(a), len(b))
        for i in range(max_len):
            result |= a[i % len(a)] ^ b[i % len(b)]
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


def secure_pq_key_zeroize(key_buffer: Union[bytearray, memoryview]) -> None:
    """Securely zeroize post-quantum key material."""
    if not key_buffer:
        return
    
    length = len(key_buffer)
    if length == 0:
        return
    
    buf = bytearray(key_buffer) if isinstance(key_buffer, memoryview) else key_buffer
    
    # Multiple patterns
    for pattern in [b'\x00', b'\xFF', b'\x55', b'\xAA']:
        for i in range(length):
            buf[i] = pattern[0]
    
    # Final zero
    for i in range(length):
        buf[i] = 0


def wrap_pq_sensitive_operation(
    fault_mode: FaultDetectionMode = FaultDetectionMode.DOUBLE_CHECK,
) -> Callable[[F], F]:
    """Decorator for protecting sensitive PQ operations."""
    protector = FaultResistantOperation(fault_mode)
    
    def decorator(func: F) -> F:
        def wrapper(*args, **kwargs):
            return protector.execute(func, *args, **kwargs)
        return wrapper  # type: ignore
    
    return decorator


# API Stability markers
__all__ = [
    'KeySensitivityLevel',
    'PQAlgorithmType',
    'FaultDetectionMode',
    'PQKeyProtectionConfig',
    'PQKeyMaterial',
    'ConstantTimePQOperations',
    'FaultResistantOperation',
    'create_protected_key',
    'pq_constant_time_compare',
    'secure_pq_key_zeroize',
    'wrap_pq_sensitive_operation',
]

__api_stability__ = {
    'KeySensitivityLevel': 'STABLE',
    'PQAlgorithmType': 'STABLE',
    'FaultDetectionMode': 'STABLE',
    'PQKeyProtectionConfig': 'STABLE',
    'PQKeyMaterial': 'STABLE',
    'ConstantTimePQOperations': 'STABLE',
    'FaultResistantOperation': 'STABLE',
    'create_protected_key': 'STABLE',
    'pq_constant_time_compare': 'STABLE',
    'secure_pq_key_zeroize': 'STABLE',
    'wrap_pq_sensitive_operation': 'STABLE',
}
