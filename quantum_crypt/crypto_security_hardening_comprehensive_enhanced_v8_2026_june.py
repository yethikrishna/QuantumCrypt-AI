"""
QuantumCrypt Security Hardening Module v8 - Comprehensive Enhanced
DIMENSION B - Security Hardening

ADD-ONLY implementation - wraps existing code, no core modifications
Cryptography-specific security hardening: key material protection,
constant-time crypto operations, side-channel resistance, entropy validation

This module provides security wrappers that can be OPTIONALLY applied
to existing cryptographic functions without modifying their core implementation.

Philosophy: Defense in depth for post-quantum cryptography
"""

import os
import sys
import time
import hmac
import hashlib
import secrets
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, TypeVar
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
import math

# Type variable for decorator
F = TypeVar('F', bound=Callable[..., Any])


class CryptoSecurityLevel(Enum):
    """Cryptographic security levels"""
    NIST_LEVEL_1 = "nist_level_1"      # 128-bit security
    NIST_LEVEL_3 = "nist_level_3"      # 192-bit security
    NIST_LEVEL_5 = "nist_level_5"      # 256-bit security
    QUANTUM_RESISTANT = "quantum_resistant"
    MAXIMUM_HARDENING = "maximum_hardening"


class KeyType(Enum):
    """Types of cryptographic keys"""
    SYMMETRIC = "symmetric"
    ASYMMETRIC_PRIVATE = "asymmetric_private"
    ASYMMETRIC_PUBLIC = "asymmetric_public"
    KEM_SECRET = "kem_secret"
    SIGNING_PRIVATE = "signing_private"
    SIGNING_PUBLIC = "signing_public"
    SESSION = "session"
    EPHEMERAL = "ephemeral"


class ValidationSeverity(Enum):
    """Severity levels for validation failures"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class CryptoSecurityContext:
    """Context for cryptographic security operations"""
    security_level: CryptoSecurityLevel = CryptoSecurityLevel.NIST_LEVEL_5
    enable_audit_logging: bool = False
    operation_id: str = field(default_factory=lambda: secrets.token_hex(16))
    caller_identity: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    allow_fallback: bool = False


@dataclass
class KeyValidationResult:
    """Result of key material validation"""
    valid: bool
    severity: ValidationSeverity
    message: str
    key_type: Optional[KeyType] = None
    estimated_entropy: float = 0.0
    recommendations: List[str] = field(default_factory=list)


class SecureKeyMaterialProtector:
    """
    Secure protection for cryptographic key material.
    
    Provides best-effort memory protection for sensitive key material.
    Note: In Python, true memory protection is limited due to GC and
    immutable string behavior. This is defense-in-depth.
    """
    
    @staticmethod
    def estimate_entropy(data: bytes) -> float:
        """
        Estimate Shannon entropy of key material.
        
        Returns:
            Estimated entropy in bits per byte (0.0 to 8.0)
        """
        if len(data) == 0:
            return 0.0
            
        # Count byte frequencies
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def zeroize_key_material(key_data: bytearray, passes: int = 5) -> None:
        """
        Securely zeroize key material.
        
        Uses multiple overwrite patterns to resist forensic recovery.
        Only works on mutable bytearrays.
        """
        if not isinstance(key_data, bytearray):
            return
            
        length = len(key_data)
        if length == 0:
            return
        
        # Cryptographic overwrite patterns - always end with zero
        patterns = [
            b'\x00' * length,      # Zero
            b'\xFF' * length,      # All ones
            b'\x55' * length,      # 01010101
            b'\xAA' * length,      # 10101010
            secrets.token_bytes(length),  # Random
        ]
        
        for i in range(min(passes, len(patterns))):
            key_data[:] = patterns[i]
        
        # Always end with zero
        key_data[:] = b'\x00' * length
    
    @staticmethod
    def validate_key_strength(
        key_data: bytes,
        key_type: KeyType,
        min_entropy: float = 4.0
    ) -> KeyValidationResult:
        """
        Validate cryptographic key strength.
        
        Checks:
        - Minimum length requirements
        - Common weak patterns (all bytes identical, etc.)
        - Entropy estimation
        """
        min_lengths = {
            KeyType.SYMMETRIC: 16,
            KeyType.ASYMMETRIC_PRIVATE: 32,
            KeyType.KEM_SECRET: 32,
            KeyType.SESSION: 16,
            KeyType.EPHEMERAL: 16,
        }
        
        min_len = min_lengths.get(key_type, 16)
        
        if len(key_data) < min_len:
            return KeyValidationResult(
                valid=False,
                severity=ValidationSeverity.CRITICAL,
                message=f"Key too short: {len(key_data)} bytes (min: {min_len})",
                key_type=key_type,
                estimated_entropy=0.0,
                recommendations=["Generate longer key material"]
            )
        
        # Check for common weak patterns FIRST (all bytes identical)
        if len(set(key_data)) == 1:
            return KeyValidationResult(
                valid=False,
                severity=ValidationSeverity.CRITICAL,
                message="All bytes identical - extremely weak key",
                key_type=key_type,
                estimated_entropy=0.0,
                recommendations=["Regenerate key immediately"]
            )
        
        entropy_per_byte = SecureKeyMaterialProtector.estimate_entropy(key_data)
        total_entropy = entropy_per_byte * len(key_data)
        
        # Check for low entropy
        if entropy_per_byte < min_entropy:
            return KeyValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Low entropy detected: {entropy_per_byte:.2f} bits/byte",
                key_type=key_type,
                estimated_entropy=total_entropy,
                recommendations=[
                    "Use cryptographically secure RNG",
                    "Avoid deterministic key generation"
                ]
            )
        
        return KeyValidationResult(
            valid=True,
            severity=ValidationSeverity.INFO,
            message="Key validation passed",
            key_type=key_type,
            estimated_entropy=total_entropy,
            recommendations=[]
        )


class ConstantTimeCryptoOperations:
    """
    Constant-time implementations for cryptographic operations.
    
    Prevents timing side-channel attacks by ensuring all code paths
    take approximately the same amount of time regardless of input.
    """
    
    @staticmethod
    def compare_bytes_ct(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte comparison.
        
        Uses hmac.compare_digest - specifically designed to resist
        timing attacks.
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def select_ct(condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Constant-time selection: returns a if condition else b.
        
        Prevents timing leaks from branch prediction.
        Both a and b must be same length.
        """
        if len(a) != len(b):
            raise ValueError("Inputs must be same length")
        
        # Create mask: all 0xFF if True, all 0x00 if False
        mask = (0 - int(condition)) & 0xFF
        
        result = bytearray(len(a))
        for i in range(len(a)):
            # result[i] = (a[i] & mask) | (b[i] & ~mask)
            result[i] = (a[i] & mask) | (b[i] & (0xFF ^ mask))
        
        return bytes(result)
    
    @staticmethod
    def verify_mac_ct(
        received_mac: bytes,
        computed_mac: bytes,
        key: bytes,
        data: bytes
    ) -> bool:
        """
        Constant-time MAC verification.
        
        Recomputes and compares in constant time to prevent
        timing oracle attacks.
        """
        # Always recompute to ensure timing consistency
        verified = hmac.new(key, data, hashlib.sha256).digest()
        return ConstantTimeCryptoOperations.compare_bytes_ct(verified, received_mac)
    
    @staticmethod
    def array_equals_ct(a: List[int], b: List[int]) -> bool:
        """Constant-time integer array comparison"""
        if len(a) != len(b):
            return False
            
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
            
        return result == 0


class EntropyHealthValidator:
    """
    Validates health and quality of randomness sources.
    
    Ensures cryptographic operations have sufficient entropy.
    """
    
    MIN_ENTROPY_THRESHOLD = 5.0  # bits per byte
    
    @staticmethod
    def run_entropy_health_check(
        random_bytes: bytes,
        min_bytes: int = 32
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Run comprehensive entropy health check.
        
        Returns:
            (is_healthy, metrics_dict)
        """
        if len(random_bytes) < min_bytes:
            return False, {
                "error": "Insufficient sample size",
                "sample_size": len(random_bytes),
                "required": min_bytes
            }
        
        entropy = SecureKeyMaterialProtector.estimate_entropy(random_bytes)
        
        # Monobit test (approximate)
        bit_count = bin(int.from_bytes(random_bytes, 'big')).count('1')
        total_bits = len(random_bytes) * 8
        monobit_ratio = bit_count / total_bits
        
        # Check for runs of same byte
        max_run = 1
        current_run = 1
        for i in range(1, len(random_bytes)):
            if random_bytes[i] == random_bytes[i-1]:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 1
        
        unique_bytes = len(set(random_bytes))
        
        metrics = {
            "entropy_bits_per_byte": entropy,
            "monobit_ratio": monobit_ratio,
            "max_consecutive_same_byte": max_run,
            "unique_byte_count": unique_bytes,
            "sample_size_bytes": len(random_bytes),
        }
        
        is_healthy = (
            entropy >= EntropyHealthValidator.MIN_ENTROPY_THRESHOLD and
            0.4 <= monobit_ratio <= 0.6 and
            max_run <= 8 and
            unique_bytes >= 128
        )
        
        return is_healthy, metrics


class CryptoRateLimiter:
    """
    Rate limiter specifically for cryptographic operations.
    
    Prevents key exposure through DoS attacks and timing analysis.
    Slows down attackers without impacting legitimate usage.
    """
    
    def __init__(
        self,
        operations_per_second: float = 100.0,
        max_burst: int = 50,
        key_operations_per_second: float = 10.0
    ):
        self.general_rate = operations_per_second
        self.general_capacity = max_burst
        self.key_rate = key_operations_per_second
        self.key_capacity = 20
        
        self._general_buckets: Dict[str, Tuple[float, float]] = {}
        self._key_buckets: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()
    
    def _refill(
        self,
        bucket: Tuple[float, float],
        rate: float,
        capacity: int
    ) -> Tuple[float, float]:
        tokens, last_update = bucket
        now = time.time()
        elapsed = now - last_update
        new_tokens = min(capacity, tokens + elapsed * rate)
        return new_tokens, now
    
    def consume_general(self, caller_id: str, cost: int = 1) -> bool:
        """Consume tokens for general crypto operations"""
        with self._lock:
            if caller_id not in self._general_buckets:
                self._general_buckets[caller_id] = (self.general_capacity, time.time())
            
            tokens, last = self._general_buckets[caller_id]
            tokens, last = self._refill((tokens, last), self.general_rate, self.general_capacity)
            
            if tokens >= cost:
                tokens -= cost
                self._general_buckets[caller_id] = (tokens, last)
                return True
            
            self._general_buckets[caller_id] = (tokens, last)
            return False
    
    def consume_key_operation(self, caller_id: str, cost: int = 1) -> bool:
        """Consume tokens for sensitive key operations (slower rate)"""
        with self._lock:
            if caller_id not in self._key_buckets:
                self._key_buckets[caller_id] = (self.key_capacity, time.time())
            
            tokens, last = self._key_buckets[caller_id]
            tokens, last = self._refill((tokens, last), self.key_rate, self.key_capacity)
            
            if tokens >= cost:
                tokens -= cost
                self._key_buckets[caller_id] = (tokens, last)
                return True
            
            self._key_buckets[caller_id] = (tokens, last)
            return False


class CryptoInputValidator:
    """
    Cryptographic-specific input validation.
    
    Validates inputs to cryptographic functions to prevent
    algorithmic attacks and misuse.
    """
    
    @staticmethod
    def validate_plaintext(plaintext: bytes, context: CryptoSecurityContext) -> KeyValidationResult:
        """Validate plaintext before encryption"""
        if not isinstance(plaintext, bytes):
            return KeyValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Plaintext must be bytes",
                key_type=None
            )
        
        if len(plaintext) == 0:
            return KeyValidationResult(
                valid=True,
                severity=ValidationSeverity.WARNING,
                message="Empty plaintext",
                key_type=None
            )
        
        return KeyValidationResult(
            valid=True,
            severity=ValidationSeverity.INFO,
            message="Plaintext validation passed",
            key_type=None
        )
    
    @staticmethod
    def validate_ciphertext(ciphertext: bytes, min_length: int = 16) -> KeyValidationResult:
        """Validate ciphertext before decryption"""
        if not isinstance(ciphertext, bytes):
            return KeyValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Ciphertext must be bytes",
                key_type=None
            )
        
        if len(ciphertext) < min_length:
            return KeyValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Ciphertext too short: {len(ciphertext)} bytes",
                key_type=None
            )
        
        return KeyValidationResult(
            valid=True,
            severity=ValidationSeverity.INFO,
            message="Ciphertext validation passed",
            key_type=None
        )
    
    @staticmethod
    def validate_nonce(nonce: bytes, expected_length: int) -> KeyValidationResult:
        """Validate nonce/IV for correct length"""
        if not isinstance(nonce, bytes):
            return KeyValidationResult(
                valid=False,
                severity=ValidationSeverity.CRITICAL,
                message="Nonce must be bytes",
                key_type=None
            )
        
        if len(nonce) != expected_length:
            return KeyValidationResult(
                valid=False,
                severity=ValidationSeverity.CRITICAL,
                message=f"Nonce incorrect length: {len(nonce)} != {expected_length}",
                key_type=None
            )
        
        return KeyValidationResult(
            valid=True,
            severity=ValidationSeverity.INFO,
            message="Nonce validation passed",
            key_type=None
        )


class CryptoSecurityWrapper:
    """
    Main wrapper for applying crypto security hardening.
    
    Provides decorators that wrap existing crypto functions
    without modifying their core implementation.
    """
    
    def __init__(self, context: Optional[CryptoSecurityContext] = None):
        self.context = context or CryptoSecurityContext()
        self.rate_limiter = CryptoRateLimiter()
        self._validation_failures: List[KeyValidationResult] = []
    
    def with_key_validation(
        self,
        key_param: str,
        key_type: KeyType = KeyType.SYMMETRIC
    ) -> Callable[[F], F]:
        """
        Decorator: Validate key material before function execution.
        
        Usage:
            @wrapper.with_key_validation('key', KeyType.SYMMETRIC)
            def encrypt(key, plaintext):
                ...
        """
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapped(*args, **kwargs):
                import inspect
                sig = inspect.signature(func)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                
                if key_param in bound.arguments:
                    key = bound.arguments[key_param]
                    if isinstance(key, bytes):
                        result = SecureKeyMaterialProtector.validate_key_strength(key, key_type)
                        if not result.valid:
                            self._validation_failures.append(result)
                            if result.severity in (ValidationSeverity.ERROR, ValidationSeverity.CRITICAL):
                                raise ValueError(f"Key validation failed: {result.message}")
                
                return func(*args, **kwargs)
            return wrapped  # type: ignore
        return decorator
    
    def with_rate_limiting(
        self,
        is_key_operation: bool = False,
        cost: int = 1
    ) -> Callable[[F], F]:
        """
        Decorator: Apply rate limiting to crypto operations.
        """
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapped(*args, **kwargs):
                caller_id = self.context.caller_identity or f"thread_{threading.get_ident()}"
                
                if is_key_operation:
                    if not self.rate_limiter.consume_key_operation(caller_id, cost):
                        raise RuntimeError("Key operation rate limit exceeded")
                else:
                    if not self.rate_limiter.consume_general(caller_id, cost):
                        raise RuntimeError("Crypto operation rate limit exceeded")
                
                return func(*args, **kwargs)
            return wrapped  # type: ignore
        return decorator
    
    def with_secure_key_cleanup(
        self,
        key_params: List[str],
        zeroize: bool = True
    ) -> Callable[[F], F]:
        """
        Decorator: Best-effort key cleanup after operation.
        """
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapped(*args, **kwargs):
                try:
                    return func(*args, **kwargs)
                finally:
                    if zeroize:
                        for param in key_params:
                            if param in kwargs:
                                if isinstance(kwargs[param], bytearray):
                                    SecureKeyMaterialProtector.zeroize_key_material(kwargs[param])
            return wrapped  # type: ignore
        return decorator
    
    def get_validation_failures(self) -> List[KeyValidationResult]:
        """Get all validation failures"""
        return self._validation_failures.copy()


# Global default instances
_default_context = CryptoSecurityContext(
    security_level=CryptoSecurityLevel.NIST_LEVEL_5
)
default_crypto_wrapper = CryptoSecurityWrapper(_default_context)
key_protector = SecureKeyMaterialProtector()
constant_time_crypto = ConstantTimeCryptoOperations()
entropy_validator = EntropyHealthValidator()
crypto_validator = CryptoInputValidator()


def create_crypto_secure_wrapper(
    security_level: CryptoSecurityLevel = CryptoSecurityLevel.NIST_LEVEL_5,
    enable_audit: bool = False
) -> CryptoSecurityWrapper:
    """
    Factory function to create a configured crypto security wrapper.
    
    This is the main entry point for using this module.
    """
    context = CryptoSecurityContext(
        security_level=security_level,
        enable_audit_logging=enable_audit
    )
    return CryptoSecurityWrapper(context)


# Export public interface
__all__ = [
    'CryptoSecurityLevel',
    'KeyType',
    'ValidationSeverity',
    'CryptoSecurityContext',
    'KeyValidationResult',
    'SecureKeyMaterialProtector',
    'ConstantTimeCryptoOperations',
    'EntropyHealthValidator',
    'CryptoRateLimiter',
    'CryptoInputValidator',
    'CryptoSecurityWrapper',
    'create_crypto_secure_wrapper',
    'default_crypto_wrapper',
    'key_protector',
    'constant_time_crypto',
    'entropy_validator',
    'crypto_validator',
]
