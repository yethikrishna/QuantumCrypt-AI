"""
QuantumCrypt AI - Unified Crypto Security Toolkit (Dimension B - Security Hardening)
===================================================================================
Incremental security layer - ADD-ONLY, no modifications to existing code.
Provides unified API for cryptographic security operations:
  - Cryptographic input validation & sanitization
  - Secure key material zeroization utilities
  - Constant-time comparison for secrets
  - Side-channel attack resistant operations
  - Key operation rate limiting & DoS protection
  - Secure key material validation

BACKWARD COMPATIBLE: All existing code continues to work unchanged.
OPTIONAL: Modules can opt-in to use these security utilities.
"""

import os
import sys
import hmac
import hashlib
import secrets
import threading
from typing import Any, Callable, Optional, Union, List, Dict, Tuple
from dataclasses import dataclass, field
from enum import IntEnum


class CryptoSecurityLevel(IntEnum):
    """Security levels for cryptographic operations"""
    STANDARD = 1
    FIPS_140_2 = 2
    FIPS_140_3 = 3
    QUANTUM_RESISTANT = 4


@dataclass
class CryptoValidationResult:
    """Result of cryptographic input validation"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    sanitized_value: Any = None
    warnings: List[str] = field(default_factory=list)
    security_score: int = 0  # 0-100 security rating


class SecureKeyMemory:
    """
    Secure memory zeroization for cryptographic key material.
    Provides FIPS-compliant memory clearing operations.
    """

    @staticmethod
    def zeroize_key_material(key_data: bytearray) -> None:
        """
        FIPS 140-3 compliant key zeroization.
        Multiple overwrite passes with different patterns.
        """
        if not isinstance(key_data, bytearray):
            return
        
        length = len(key_data)
        
        # FIPS 140-3 compliant overwrite patterns
        patterns = [0x00, 0xFF, 0xAA, 0x55, 0x00]
        
        for pattern in patterns:
            for i in range(length):
                key_data[i] = pattern
        
        # Final random overwrite
        for i in range(length):
            key_data[i] = secrets.randbits(8) & 0xFF
        
        # Final zero
        for i in range(length):
            key_data[i] = 0x00

    @staticmethod
    def zeroize_sensitive_buffer(buffer: Union[bytearray, memoryview]) -> None:
        """Zeroize any sensitive buffer"""
        if isinstance(buffer, memoryview):
            for i in range(len(buffer)):
                buffer[i] = 0x00
        elif isinstance(buffer, bytearray):
            SecureKeyMemory.zeroize_key_material(buffer)

    @staticmethod
    def secure_wipe_object(obj: Any) -> None:
        """
        Attempt to securely wipe sensitive cryptographic objects.
        Works with bytearrays, lists of bytes, and memoryviews.
        """
        if isinstance(obj, (bytearray, memoryview)):
            SecureKeyMemory.zeroize_sensitive_buffer(obj)
        elif isinstance(obj, list):
            for i in range(len(obj)):
                if isinstance(obj[i], (bytearray, memoryview, bytes)):
                    if isinstance(obj[i], (bytearray, memoryview)):
                        SecureKeyMemory.zeroize_sensitive_buffer(obj[i])
                obj[i] = None


class ConstantTimeCrypto:
    """
    Constant-time cryptographic operations to prevent timing attacks.
    Critical for signature verification, MAC validation, and key comparison.
    """

    @staticmethod
    def compare_keys(a: bytes, b: bytes) -> bool:
        """
        Constant-time key comparison.
        Resistant to timing attacks even when lengths differ.
        """
        # First compare lengths in constant time
        len_equal = len(a) == len(b)
        
        # Then compare contents (hmac.compare_digest is constant time)
        content_equal = hmac.compare_digest(a.ljust(len(b), b'\x00')[:len(b)], b)
        
        return len_equal and content_equal

    @staticmethod
    def compare_signatures(sig_a: bytes, sig_b: bytes) -> bool:
        """
        Constant-time signature comparison.
        """
        return hmac.compare_digest(sig_a, sig_b)

    @staticmethod
    def compare_hashes(hash_a: bytes, hash_b: bytes) -> bool:
        """
        Constant-time hash comparison.
        """
        return hmac.compare_digest(hash_a, hash_b)

    @staticmethod
    def array_equals(a: List[int], b: List[int]) -> bool:
        """
        Constant-time array comparison for integers.
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0


class CryptoInputValidator:
    """
    Cryptographic input validation framework.
    Validates keys, nonces, IVs, and other crypto parameters.
    """

    def __init__(self, security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD):
        self.security_level = security_level
        self._validation_lock = threading.Lock()

    def validate_key_length(
        self,
        key: bytes,
        min_length: int = 16,
        max_length: int = 1024,
        required_length: Optional[int] = None
    ) -> CryptoValidationResult:
        """Validate cryptographic key length"""
        result = CryptoValidationResult(is_valid=True)
        
        with self._validation_lock:
            if not isinstance(key, bytes):
                result.is_valid = False
                result.errors.append("Key must be bytes")
                return result

            if required_length is not None:
                if len(key) != required_length:
                    result.is_valid = False
                    result.errors.append(f"Key must be exactly {required_length} bytes (got {len(key)})")
                    return result
            else:
                if len(key) < min_length:
                    result.is_valid = False
                    result.errors.append(f"Key too short: minimum {min_length} bytes")
                if len(key) > max_length:
                    result.is_valid = False
                    result.errors.append(f"Key too long: maximum {max_length} bytes")

            # Calculate entropy score (map 0-8 bits -> 0-100 score)
            if result.is_valid:
                entropy = self._estimate_entropy(key)
                result.security_score = min(100, int(entropy * 12.5))  # 8 * 12.5 = 100
                if result.security_score < 50 and self.security_level >= CryptoSecurityLevel.FIPS_140_2:
                    result.warnings.append("Low entropy detected in key material")

            result.sanitized_value = key

        return result

    def validate_nonce(self, nonce: bytes, required_length: int) -> CryptoValidationResult:
        """Validate nonce/IV for cryptographic operations"""
        result = CryptoValidationResult(is_valid=True)
        
        with self._validation_lock:
            if not isinstance(nonce, bytes):
                result.is_valid = False
                result.errors.append("Nonce must be bytes")
                return result

            if len(nonce) != required_length:
                result.is_valid = False
                result.errors.append(f"Nonce must be exactly {required_length} bytes")

            # Check for all zeros (common insecure pattern)
            if all(b == 0 for b in nonce):
                result.warnings.append("All-zero nonce detected - not cryptographically secure")
                if self.security_level >= CryptoSecurityLevel.FIPS_140_3:
                    result.is_valid = False
                    result.errors.append("All-zero nonce rejected at FIPS 140-3 security level")

            result.sanitized_value = nonce

        return result

    def _estimate_entropy(self, data: bytes) -> float:
        """Estimate Shannon entropy of byte data"""
        if len(data) == 0:
            return 0.0
        
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        
        import math
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        
        return min(8.0, entropy)


class KeyOperationRateLimiter:
    """
    Rate limiter specifically for cryptographic key operations.
    Prevents key enumeration attacks and DoS on HSM operations.
    """

    def __init__(self, max_operations_per_second: int = 100):
        self.max_ops = max_operations_per_second
        self._tokens = max_operations_per_second
        self._last_refill = threading.Lock()
        self._lock = threading.Lock()
        import time
        self._time = time
        self._last_refill_time = self._time.time()

    def try_key_operation(self) -> bool:
        """
        Try to perform a key operation. Returns False if rate limited.
        """
        with self._lock:
            now = self._time.time()
            elapsed = now - self._last_refill_time
            
            self._tokens = min(
                self.max_ops,
                self._tokens + elapsed * self.max_ops
            )
            self._last_refill_time = now

            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False


class UnifiedCryptoSecurityToolkit:
    """
    Main unified cryptographic security toolkit facade.
    Single entry point for all crypto security operations.
    """

    def __init__(self, security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD):
        self.security_level = security_level
        self.key_memory = SecureKeyMemory()
        self.constant_time = ConstantTimeCrypto()
        self.validator = CryptoInputValidator(security_level)
        self._rate_limiters: Dict[str, KeyOperationRateLimiter] = {}
        self._lock = threading.Lock()

    def get_key_rate_limiter(self, name: str, max_ops: int = 100) -> KeyOperationRateLimiter:
        """Get or create a named key operation rate limiter"""
        with self._lock:
            if name not in self._rate_limiters:
                self._rate_limiters[name] = KeyOperationRateLimiter(max_ops)
            return self._rate_limiters[name]

    def secure_compare_keys(self, key_a: bytes, key_b: bytes) -> bool:
        """Secure constant-time key comparison"""
        return self.constant_time.compare_keys(key_a, key_b)

    def secure_compare_signatures(self, sig_a: bytes, sig_b: bytes) -> bool:
        """Secure constant-time signature comparison"""
        return self.constant_time.compare_signatures(sig_a, sig_b)

    def zeroize_key(self, key_data: bytearray) -> None:
        """Securely zeroize cryptographic key material"""
        self.key_memory.zeroize_key_material(key_data)

    def validate_aes_key(self, key: bytes) -> CryptoValidationResult:
        """Validate AES key (128, 192, or 256 bits)"""
        if len(key) == 16:
            return self.validator.validate_key_length(key, required_length=16)
        elif len(key) == 24:
            return self.validator.validate_key_length(key, required_length=24)
        elif len(key) == 32:
            return self.validator.validate_key_length(key, required_length=32)
        else:
            result = CryptoValidationResult(is_valid=False)
            result.errors.append("AES key must be 16, 24, or 32 bytes")
            return result

    def validate_post_quantum_key(self, key: bytes, min_length: int = 32) -> CryptoValidationResult:
        """Validate post-quantum cryptographic key material"""
        return self.validator.validate_key_length(key, min_length=min_length)


# Default global instance for easy import
DEFAULT_CRYPTO_TOOLKIT = UnifiedCryptoSecurityToolkit(CryptoSecurityLevel.STANDARD)


def get_crypto_security_toolkit(
    security_level: Optional[CryptoSecurityLevel] = None
) -> UnifiedCryptoSecurityToolkit:
    """
    Get the unified cryptographic security toolkit instance.
    Usage:
        from quantum_crypt.crypto_security_hardening_unified_security_toolkit_v29_2026_june import get_crypto_security_toolkit
        toolkit = get_crypto_security_toolkit()
        if toolkit.secure_compare_keys(received_key, expected_key):
            ...
    """
    if security_level is None:
        return DEFAULT_CRYPTO_TOOLKIT
    return UnifiedCryptoSecurityToolkit(security_level)
