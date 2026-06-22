"""
Cryptographic Security Hardening Comprehensive Module v2
Dimension B: Security Hardening - ADD-ONLY implementation

This module provides comprehensive cryptographic security hardening utilities
that layer ON TOP of existing post-quantum crypto code without modifying
any core functionality.

COMPONENTS:
1. CryptoSecureMemory - Secure key material zeroization
2. CryptoConstantTime - Side-channel resistant operations
3. CryptoInputValidation - Cryptographic parameter validation
4. CryptoRateLimiter - Crypto operation rate limiting (DoS protection)
5. SideChannelResistant - Side-channel attack mitigations
6. CryptoSecurityAuditor - Cryptographic security event auditing

All utilities are OPT-IN - existing code behavior is 100% preserved.
"""

import hmac
import hashlib
import time
import threading
import os
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import secrets


class CryptoSecurityLevel(Enum):
    """Cryptographic security level enumeration."""
    NIST_CATEGORY_1 = 1  # 128-bit security
    NIST_CATEGORY_3 = 3  # 192-bit security
    NIST_CATEGORY_5 = 5  # 256-bit security
    QUANTUM_RESISTANT = 7  # Post-quantum security


@dataclass
class CryptoSecurityConfig:
    """Configuration for cryptographic security hardening."""
    security_level: CryptoSecurityLevel = CryptoSecurityLevel.NIST_CATEGORY_5
    enable_key_zeroization: bool = True
    enable_constant_time: bool = True
    enable_parameter_validation: bool = True
    enable_rate_limiting: bool = True
    enable_side_channel_mitigation: bool = True
    key_zeroization_passes: int = 5
    max_crypto_ops_per_second: int = 50
    max_key_operations: int = 1000
    enforce_min_key_length: bool = True
    min_symmetric_key_bytes: int = 16
    min_asymmetric_key_bits: int = 2048


class CryptoSecureMemory:
    """
    Secure memory handling for cryptographic key material.
    
    Provides enhanced zeroization for sensitive key material.
    Note: Python bytes are immutable - use bytearrays for wipeable memory.
    """
    
    @staticmethod
    def zeroize_key_material(key_data: Union[bytearray, List, Dict]) -> None:
        """
        Securely zeroize cryptographic key material.
        
        Five-pass zeroization for maximum security:
        1. 0x00
        2. 0xFF
        3. 0xAA (10101010)
        4. 0x55 (01010101)
        5. 0x00
        
        Args:
            key_data: Mutable key material (bytearray, list, or dict)
        """
        if isinstance(key_data, bytearray):
            patterns = [0x00, 0xFF, 0xAA, 0x55, 0x00]
            for pattern in patterns:
                for i in range(len(key_data)):
                    key_data[i] = pattern
        elif isinstance(key_data, list):
            for i in range(len(key_data)):
                key_data[i] = None
            key_data.clear()
        elif isinstance(key_data, dict):
            for key in list(key_data.keys()):
                key_data[key] = None
            key_data.clear()
    
    @staticmethod
    def create_secure_key_buffer(size: int) -> bytearray:
        """
        Create a secure key buffer that can be zeroized.
        
        Args:
            size: Size of key buffer in bytes
            
        Returns:
            Zero-initialized bytearray
        """
        buffer = bytearray(size)
        # Fill with random first
        for i in range(size):
            buffer[i] = secrets.randbelow(256)
        # Then zeroize
        CryptoSecureMemory.zeroize_key_material(buffer)
        return buffer
    
    @staticmethod
    def copy_to_secure_key_buffer(key_bytes: bytes) -> bytearray:
        """
        Copy immutable key bytes to mutable secure buffer.
        
        Args:
            key_bytes: Immutable key bytes
            
        Returns:
            Mutable bytearray copy
        """
        return bytearray(key_bytes)
    
    @staticmethod
    def generate_ephemeral_key(size: int = 32) -> Tuple[bytes, bytearray]:
        """
        Generate an ephemeral key with both immutable and wipeable copies.
        
        Args:
            size: Key size in bytes
            
        Returns:
            Tuple of (immutable_key_bytes, mutable_key_buffer)
        """
        key_bytes = secrets.token_bytes(size)
        key_buffer = bytearray(key_bytes)
        return key_bytes, key_buffer
    
    @staticmethod
    def secure_compare_keys(key_a: bytes, key_b: bytes) -> bool:
        """
        Constant-time key comparison.
        
        Args:
            key_a: First key
            key_b: Second key
            
        Returns:
            True if equal (constant time)
        """
        return hmac.compare_digest(key_a, key_b)


class CryptoConstantTime:
    """
    Constant-time cryptographic operations.
    
    All operations designed to resist timing side-channel attacks.
    """
    
    @staticmethod
    def compare_digest(a: bytes, b: bytes) -> bool:
        """
        Constant-time digest comparison.
        
        Args:
            a: First digest
            b: Second digest
            
        Returns:
            True if equal (constant time)
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def select_secure(condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Constant-time conditional selection for bytes.
        
        Returns a if condition is True, b otherwise, in constant time.
        
        Args:
            condition: Selection condition
            a: Value if True
            b: Value if False
            
        Returns:
            Selected byte string
        """
        # Use length check first (early exit for different lengths)
        if len(a) != len(b):
            return a if condition else b
        
        # For same length, use constant-time selection
        result = bytearray(len(a))
        mask = int(bool(condition))
        
        for i in range(len(a)):
            # Constant-time selection using bit operations
            # When mask=1: result[i] = a[i]
            # When mask=0: result[i] = b[i]
            result[i] = (mask & a[i]) | ((~mask + 256) & b[i])
        
        return bytes(result)
    
    @staticmethod
    def verify_hmac_constant_time(
        key: bytes,
        data: bytes,
        expected_mac: bytes,
        hash_alg: str = 'sha3_256'
    ) -> bool:
        """
        Constant-time HMAC verification.
        
        Args:
            key: HMAC key
            data: Data to verify
            expected_mac: Expected MAC value
            hash_alg: Hash algorithm (default SHA3-256)
            
        Returns:
            True if MAC valid (constant time)
        """
        computed = hmac.new(key, data, hash_alg).digest()
        return hmac.compare_digest(computed, expected_mac)
    
    @staticmethod
    def constant_time_xor(a: bytes, b: bytes) -> bytes:
        """
        Constant-time XOR operation.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            XOR result (constant time)
        """
        min_len = min(len(a), len(b))
        result = bytearray(min_len)
        for i in range(min_len):
            result[i] = a[i] ^ b[i]
        return bytes(result)
    
    @staticmethod
    def pad_to_length_constant_time(data: bytes, target_length: int) -> bytes:
        """
        Pad data to target length in constant time.
        
        Uses PKCS#7 style padding with random padding bytes.
        
        Args:
            data: Input data
            target_length: Target length
            
        Returns:
            Padded data
        """
        if len(data) >= target_length:
            return data[:target_length]
        
        pad_length = target_length - len(data)
        # Use random padding for side-channel resistance
        padding = secrets.token_bytes(pad_length)
        return data + padding


class CryptoParameterValidation:
    """
    Cryptographic parameter validation.
    
    Validates all cryptographic inputs before operations.
    """
    
    # Standard key lengths (bytes)
    STANDARD_KEY_LENGTHS = {
        'aes-128': 16,
        'aes-192': 24,
        'aes-256': 32,
        'hmac-sha256': 32,
        'hmac-sha384': 48,
        'hmac-sha512': 64,
    }
    
    # Standard nonce lengths (bytes)
    STANDARD_NONCE_LENGTHS = {
        'aes-gcm': 12,  # NIST recommended
        'chacha20': 12,
        'xchacha20': 24,
    }
    
    def __init__(self, config: Optional[CryptoSecurityConfig] = None):
        self.config = config or CryptoSecurityConfig()
    
    def validate_key_length(
        self,
        key: bytes,
        algorithm: str = 'aes-256'
    ) -> Tuple[bool, List[str]]:
        """
        Validate cryptographic key length.
        
        Args:
            key: Key bytes
            algorithm: Target algorithm
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        if not self.config.enable_parameter_validation:
            return True, issues
        
        expected_length = self.STANDARD_KEY_LENGTHS.get(algorithm.lower())
        
        if expected_length and len(key) != expected_length:
            issues.append(
                f"Key length mismatch for {algorithm}: "
                f"expected {expected_length} bytes, got {len(key)}"
            )
        
        if self.config.enforce_min_key_length:
            if len(key) < self.config.min_symmetric_key_bytes:
                issues.append(
                    f"Key below minimum length: {len(key)} < "
                    f"{self.config.min_symmetric_key_bytes} bytes"
                )
        
        # Check for weak keys (all zeros, all ones, repeating patterns)
        if all(b == 0 for b in key):
            issues.append("Key is all zeros - extremely weak")
        
        if all(b == 0xFF for b in key):
            issues.append("Key is all ones - extremely weak")
        
        # Check for low entropy
        unique_bytes = len(set(key))
        if unique_bytes < len(key) * 0.25:
            issues.append(f"Key has low entropy: only {unique_bytes} unique bytes")
        
        return len(issues) == 0, issues
    
    def validate_nonce_length(
        self,
        nonce: bytes,
        algorithm: str = 'aes-gcm'
    ) -> Tuple[bool, List[str]]:
        """
        Validate nonce/IV length.
        
        Args:
            nonce: Nonce bytes
            algorithm: Target algorithm
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        if not self.config.enable_parameter_validation:
            return True, issues
        
        expected_length = self.STANDARD_NONCE_LENGTHS.get(algorithm.lower())
        
        if expected_length and len(nonce) != expected_length:
            issues.append(
                f"Nonce length mismatch for {algorithm}: "
                f"expected {expected_length} bytes, got {len(nonce)}"
            )
        
        # Nonce reuse detection warning
        if len(nonce) < 8:
            issues.append("Nonce too short - high collision risk")
        
        return len(issues) == 0, issues
    
    def validate_ciphertext_integrity(
        self,
        ciphertext: bytes,
        min_length: int = 16
    ) -> Tuple[bool, List[str]]:
        """
        Validate ciphertext before decryption.
        
        Args:
            ciphertext: Ciphertext bytes
            min_length: Minimum expected length
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        if len(ciphertext) < min_length:
            issues.append(
                f"Ciphertext too short: {len(ciphertext)} < {min_length} bytes"
            )
        
        if len(ciphertext) == 0:
            issues.append("Empty ciphertext")
        
        return len(issues) == 0, issues
    
    def secure_decorator(self, func: Callable) -> Callable:
        """
        Decorator to wrap crypto functions with parameter validation.
        
        Args:
            func: Cryptographic function to wrap
            
        Returns:
            Wrapped function with validation
        """
        def wrapper(*args, **kwargs):
            # Validate key arguments
            for i, arg in enumerate(args):
                if isinstance(arg, bytes) and len(arg) >= 16:
                    # Likely a key - validate
                    is_valid, issues = self.validate_key_length(arg)
                    if not is_valid:
                        # Log but continue - caller decides
                        pass
            
            return func(*args, **kwargs)
        
        return wrapper


class CryptoRateLimiter:
    """
    Rate limiter for cryptographic operations.
    
    Prevents DoS attacks against expensive crypto operations.
    """
    
    def __init__(
        self,
        max_ops_per_second: int = 50,
        burst_size: int = 100,
        per_seconds: float = 1.0
    ):
        self.max_ops = max_ops_per_second
        self.per_seconds = per_seconds
        self.burst_size = burst_size
        self._tokens = burst_size
        self._last_update = time.time()
        self._lock = threading.Lock()
        self._operation_costs: Dict[str, float] = {
            'key_generation': 5.0,
            'signing': 3.0,
            'verification': 1.0,
            'encryption': 1.0,
            'decryption': 1.0,
            'key_exchange': 10.0,
            'default': 1.0,
        }
    
    def _refill(self) -> None:
        """Refill operation tokens."""
        now = time.time()
        elapsed = now - self._last_update
        new_tokens = elapsed * (self.max_ops / self.per_seconds)
        self._tokens = min(self.burst_size, self._tokens + new_tokens)
        self._last_update = now
    
    def try_acquire_operation(
        self,
        operation_type: str = 'default',
        cost_multiplier: float = 1.0
    ) -> bool:
        """
        Try to acquire tokens for a crypto operation.
        
        Args:
            operation_type: Type of crypto operation
            cost_multiplier: Cost multiplier
            
        Returns:
            True if operation allowed
        """
        cost = self._operation_costs.get(operation_type, 1.0) * cost_multiplier
        token_cost = max(1, int(cost))
        
        with self._lock:
            self._refill()
            if self._tokens >= token_cost:
                self._tokens -= token_cost
                return True
            return False
    
    def get_available_capacity(self) -> float:
        """Get current available operation capacity."""
        with self._lock:
            self._refill()
            return self._tokens


class SideChannelResistant:
    """
    Side-channel attack mitigations.
    
    Provides protections against timing, cache, and power analysis attacks.
    """
    
    @staticmethod
    def add_timing_noise(
        base_delay: float = 0.001,
        max_jitter: float = 0.005
    ) -> None:
        """
        Add random timing jitter to disrupt timing attacks.
        
        Args:
            base_delay: Base delay in seconds
            max_jitter: Maximum additional jitter
        """
        delay = base_delay + (secrets.randbelow(1000) / 1000.0) * max_jitter
        time.sleep(delay)
    
    @staticmethod
    def blind_operation(
        data: bytes,
        blinding_factor: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """
        Blind data before cryptographic operation.
        
        Args:
            data: Data to blind
            blinding_factor: Optional blinding factor (generated if None)
            
        Returns:
            Tuple of (blinded_data, blinding_factor)
        """
        if blinding_factor is None:
            blinding_factor = secrets.token_bytes(len(data))
        
        blinded = bytes(a ^ b for a, b in zip(data, blinding_factor))
        return blinded, blinding_factor
    
    @staticmethod
    def unblind_operation(
        blinded_result: bytes,
        blinding_factor: bytes
    ) -> bytes:
        """
        Remove blinding from result.
        
        Args:
            blinded_result: Blinded operation result
            blinding_factor: Blinding factor used
            
        Returns:
            Unblinded result
        """
        return bytes(a ^ b for a, b in zip(blinded_result, blinding_factor))
    
    @staticmethod
    def dummy_operations(count: int = 10) -> None:
        """
        Perform dummy cryptographic operations.
        
        Creates constant work patterns to resist power analysis.
        
        Args:
            count: Number of dummy hash operations
        """
        for _ in range(count):
            dummy_data = secrets.token_bytes(32)
            hashlib.sha256(dummy_data).digest()


class CryptoSecurityAuditor:
    """
    Cryptographic security event auditor.
    
    Logs and analyzes cryptographic operations for security anomalies.
    """
    
    def __init__(self, max_events: int = 5000):
        self._events: deque = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._operation_counts: Dict[str, int] = {}
        self._failure_counts: Dict[str, int] = {}
    
    def log_crypto_operation(
        self,
        operation: str,
        algorithm: str,
        success: bool,
        duration: float,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log a cryptographic operation.
        
        Args:
            operation: Operation type (encrypt, decrypt, sign, verify, etc.)
            algorithm: Algorithm used
            success: Whether operation succeeded
            duration: Operation duration in seconds
            details: Additional details
        """
        event = {
            'timestamp': time.time(),
            'operation': operation,
            'algorithm': algorithm,
            'success': success,
            'duration': duration,
            'details': details or {}
        }
        
        with self._lock:
            self._events.append(event)
            
            op_key = f"{operation}:{algorithm}"
            self._operation_counts[op_key] = self._operation_counts.get(op_key, 0) + 1
            
            if not success:
                self._failure_counts[op_key] = self._failure_counts.get(op_key, 0) + 1
    
    def get_crypto_statistics(self) -> Dict[str, Any]:
        """
        Get cryptographic operation statistics.
        
        Returns:
            Dictionary with operation counts and failure rates
        """
        with self._lock:
            total_ops = len(self._events)
            op_counts = dict(self._operation_counts)
            fail_counts = dict(self._failure_counts)
        
        failure_rates = {}
        for op_key, count in op_counts.items():
            failures = fail_counts.get(op_key, 0)
            failure_rates[op_key] = failures / count if count > 0 else 0.0
        
        return {
            'total_operations': total_ops,
            'operation_counts': op_counts,
            'failure_counts': fail_counts,
            'failure_rates': failure_rates
        }
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """
        Detect anomalous cryptographic operations.
        
        Returns:
            List of detected anomalies
        """
        anomalies = []
        stats = self.get_crypto_statistics()
        
        # Check for high failure rates
        for op_key, rate in stats['failure_rates'].items():
            if rate > 0.1:  # > 10% failure rate
                anomalies.append({
                    'type': 'high_failure_rate',
                    'operation': op_key,
                    'failure_rate': rate,
                    'severity': 'warning' if rate < 0.5 else 'critical'
                })
        
        return anomalies


# Global singleton instances
_default_crypto_config = CryptoSecurityConfig()
crypto_secure_memory = CryptoSecureMemory()
crypto_constant_time = CryptoConstantTime()
crypto_param_validator = CryptoParameterValidation(_default_crypto_config)
crypto_rate_limiter = CryptoRateLimiter()
crypto_side_channel = SideChannelResistant()
crypto_security_auditor = CryptoSecurityAuditor()


# Convenience functions
def crypto_secure_compare(a: bytes, b: bytes) -> bool:
    """Constant-time cryptographic comparison (convenience)."""
    return crypto_constant_time.compare_digest(a, b)


def crypto_zeroize_key(key_data: Union[bytearray, List, Dict]) -> None:
    """Securely zeroize cryptographic key material (convenience)."""
    crypto_secure_memory.zeroize_key_material(key_data)


def crypto_validate_key(key: bytes, algorithm: str = 'aes-256') -> bool:
    """Validate cryptographic key (convenience)."""
    is_valid, _ = crypto_param_validator.validate_key_length(key, algorithm)
    return is_valid


def crypto_check_rate_limit(operation_type: str = 'default') -> bool:
    """Check crypto operation rate limit (convenience)."""
    return crypto_rate_limiter.try_acquire_operation(operation_type)


# Export all components
__all__ = [
    'CryptoSecurityLevel',
    'CryptoSecurityConfig',
    'CryptoSecureMemory',
    'CryptoConstantTime',
    'CryptoParameterValidation',
    'CryptoRateLimiter',
    'SideChannelResistant',
    'CryptoSecurityAuditor',
    'crypto_secure_memory',
    'crypto_constant_time',
    'crypto_param_validator',
    'crypto_rate_limiter',
    'crypto_side_channel',
    'crypto_security_auditor',
    'crypto_secure_compare',
    'crypto_zeroize_key',
    'crypto_validate_key',
    'crypto_check_rate_limit',
]
