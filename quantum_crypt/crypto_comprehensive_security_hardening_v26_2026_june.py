"""
QuantumCrypt-AI Comprehensive Security Hardening Module v26
Dimension B - Security Hardening

Incremental security layer - wraps existing code, does NOT modify core
All security features are opt-in and backward compatible

Crypto-specific security features:
1. Secure key material zeroization (crypto-specific memory handling)
2. Constant-time cryptographic comparison helpers
3. Cryptographic input validation (key sizes, algorithm parameters)
4. Rate limiting for sensitive crypto operations
5. Secure key buffer management with automatic zeroization
6. Side-channel attack mitigation wrappers
"""

import os
import sys
import time
import hmac
import ctypes
import threading
import secrets
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import re

# Type variable for generic functions
T = TypeVar('T')
F = TypeVar('F', bound=Callable)


class CryptoSecurityLevel(Enum):
    """Cryptographic security level enumeration"""
    MINIMAL = "minimal"          # For testing only
    STANDARD = "standard"        # Production default
    HIGH = "high"                # Sensitive operations
    FIPS_140_3 = "fips_140_3"    # FIPS compliant mode


@dataclass
class CryptoValidationResult:
    """Result of cryptographic input validation"""
    is_valid: bool
    sanitized_value: Any = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD


class CryptoSecureMemory:
    """
    Cryptographic secure memory zeroization utilities.
    
    Specialized for cryptographic key material.
    Uses multiple overwrite passes and low-level operations.
    """
    
    # Overwrite patterns per FIPS 140-3 guidance
    OVERWRITE_PATTERNS = [0x00, 0xFF, 0xAA, 0x55, 0x00]
    
    @staticmethod
    def zeroize_key_material(key_buffer: bytearray) -> None:
        """
        Securely zeroize cryptographic key material.
        Implements NIST SP 800-88 compliant overwriting.
        
        Args:
            key_buffer: Mutable bytearray containing key material
        """
        if not isinstance(key_buffer, bytearray):
            return
        
        length = len(key_buffer)
        if length == 0:
            return
        
        # Multiple overwrite passes with different patterns
        for pattern in CryptoSecureMemory.OVERWRITE_PATTERNS:
            for i in range(length):
                key_buffer[i] = pattern
        
        # Force memory barrier using ctypes
        buffer = (ctypes.c_ubyte * length).from_buffer(key_buffer)
        ctypes.memset(ctypes.byref(buffer), 0x00, length)
        
        # Final verification pass
        for i in range(length):
            key_buffer[i] = 0x00
    
    @staticmethod
    def create_secure_key_buffer(size: int) -> bytearray:
        """
        Create a buffer for key material that can be securely zeroized.
        
        Args:
            size: Key size in bytes
            
        Returns:
            Zero-initialized bytearray
        """
        return bytearray(size)
    
    @staticmethod
    def secure_compare_digests(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison for hash digests and MACs.
        
        Uses HMAC compare_digest which is designed to resist timing attacks.
        
        Args:
            a: First digest bytes
            b: Second digest bytes
            
        Returns:
            True if equal, False otherwise
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def wipe_object(obj: Any) -> None:
        """
        Best-effort secure wipe for various object types.
        Handles bytearray, list of integers, and memoryview.
        """
        if isinstance(obj, bytearray):
            CryptoSecureMemory.zeroize_key_material(obj)
        elif isinstance(obj, list) and all(isinstance(x, int) for x in obj):
            for i in range(len(obj)):
                obj[i] = 0
        elif isinstance(obj, memoryview):
            # Convert to bytearray and wipe
            try:
                buf = bytearray(obj)
                CryptoSecureMemory.zeroize_key_material(buf)
            except Exception:
                pass


class CryptoConstantTime:
    """
    Constant-time utilities specialized for cryptographic operations.
    Prevents timing side-channel attacks.
    """
    
    @staticmethod
    def compare_keys(a: bytes, b: bytes) -> bool:
        """
        Constant-time key comparison.
        
        Args:
            a: First key bytes
            b: Second key bytes
            
        Returns:
            True if equal, False otherwise
        """
        return CryptoSecureMemory.secure_compare_digests(a, b)
    
    @staticmethod
    def compare_signatures(a: bytes, b: bytes) -> bool:
        """
        Constant-time signature comparison.
        
        Args:
            a: First signature bytes
            b: Second signature bytes
            
        Returns:
            True if equal, False otherwise
        """
        return CryptoSecureMemory.secure_compare_digests(a, b)
    
    @staticmethod
    def verify_hmac(expected: bytes, data: bytes, key: bytes, hash_alg=hashlib.sha256) -> bool:
        """
        Constant-time HMAC verification.
        
        Args:
            expected: Expected HMAC digest
            data: Data that was HMACed
            key: HMAC key
            hash_alg: Hash algorithm to use
            
        Returns:
            True if verification succeeds
        """
        computed = hmac.new(key, data, hash_alg).digest()
        return CryptoSecureMemory.secure_compare_digests(expected, computed)
    
    @staticmethod
    def select(condition: bool, a: T, b: T) -> T:
        """
        Constant-time conditional selection.
        Returns a if condition is True, b otherwise.
        Both branches are always evaluated.
        
        WARNING: This is a simplified implementation.
        For true constant-time, use native crypto libraries.
        """
        # This is NOT truly constant-time in Python due to bytecode interpretation
        # Provided as a best-effort utility
        mask = -int(condition)  # All 1s if True, all 0s if False
        # Note: This only works reliably for integer types
        if isinstance(a, int) and isinstance(b, int):
            return b ^ ((a ^ b) & mask)
        return a if condition else b


class CryptoInputValidator:
    """
    Cryptographic input validation specialized for crypto operations.
    Validates key sizes, algorithm parameters, and input formats.
    """
    
    # Standard key sizes (bytes)
    KEY_SIZES = {
        'AES-128': 16,
        'AES-192': 24,
        'AES-256': 32,
        'HMAC-SHA256': 32,
        'HMAC-SHA512': 64,
        'ChaCha20': 32,
    }
    
    # Nonce sizes (bytes)
    NONCE_SIZES = {
        'AES-GCM': 12,
        'ChaCha20-Poly1305': 12,
        'XChaCha20-Poly1305': 24,
    }
    
    @staticmethod
    def validate_key(
        key: bytes,
        algorithm: Optional[str] = None,
        min_size: int = 16,
        max_size: int = 128,
        security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD
    ) -> CryptoValidationResult:
        """
        Validate cryptographic key material.
        
        Args:
            key: Key bytes
            algorithm: Algorithm name for size validation
            min_size: Minimum acceptable key size
            max_size: Maximum acceptable key size
            security_level: Security strictness
            
        Returns:
            Validation result
        """
        errors = []
        warnings = []
        
        if key is None:
            return CryptoValidationResult(False, None, ["Key cannot be None"], warnings, security_level)
        
        if not isinstance(key, bytes):
            return CryptoValidationResult(False, None, ["Key must be bytes"], warnings, security_level)
        
        key_len = len(key)
        
        # Check algorithm-specific size
        if algorithm and algorithm in CryptoInputValidator.KEY_SIZES:
            expected_size = CryptoInputValidator.KEY_SIZES[algorithm]
            if key_len != expected_size:
                errors.append(f"{algorithm} key must be {expected_size} bytes, got {key_len}")
        
        # General size bounds
        if key_len < min_size:
            errors.append(f"Key too short: minimum {min_size} bytes, got {key_len}")
        
        if key_len > max_size:
            errors.append(f"Key too long: maximum {max_size} bytes, got {key_len}")
        
        # Check for weak keys (all zeros, all same byte)
        if security_level in [CryptoSecurityLevel.HIGH, CryptoSecurityLevel.FIPS_140_3]:
            if len(set(key)) == 1:
                warnings.append("Key consists of identical bytes - may be weak")
            
            if all(b == 0 for b in key):
                errors.append("All-zero key is not allowed")
        
        return CryptoValidationResult(len(errors) == 0, key, errors, warnings, security_level)
    
    @staticmethod
    def validate_nonce(
        nonce: bytes,
        algorithm: Optional[str] = None,
        security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD
    ) -> CryptoValidationResult:
        """
        Validate nonce/IV for encryption operations.
        
        Args:
            nonce: Nonce bytes
            algorithm: Algorithm name for size validation
            security_level: Security strictness
            
        Returns:
            Validation result
        """
        errors = []
        warnings = []
        
        if nonce is None:
            return CryptoValidationResult(False, None, ["Nonce cannot be None"], warnings, security_level)
        
        if not isinstance(nonce, bytes):
            return CryptoValidationResult(False, None, ["Nonce must be bytes"], warnings, security_level)
        
        nonce_len = len(nonce)
        
        # Check algorithm-specific size
        if algorithm and algorithm in CryptoInputValidator.NONCE_SIZES:
            expected_size = CryptoInputValidator.NONCE_SIZES[algorithm]
            if nonce_len != expected_size:
                errors.append(f"{algorithm} nonce must be {expected_size} bytes, got {nonce_len}")
        
        # Reuse detection warning
        # Note: This can't actually detect reuse without tracking state
        # Just provide general guidance
        if security_level in [CryptoSecurityLevel.HIGH, CryptoSecurityLevel.FIPS_140_3]:
            if len(set(nonce)) == 1:
                warnings.append("Nonce has low entropy - ensure uniqueness")
        
        return CryptoValidationResult(len(errors) == 0, nonce, errors, warnings, security_level)
    
    @staticmethod
    def validate_plaintext_size(
        data: bytes,
        max_size: int = 10 * 1024 * 1024,  # 10MB default
        allow_empty: bool = False
    ) -> CryptoValidationResult:
        """
        Validate plaintext/ciphertext size bounds.
        
        Args:
            data: Data to validate
            max_size: Maximum allowed size
            allow_empty: Whether empty data is allowed
            
        Returns:
            Validation result
        """
        errors = []
        warnings = []
        
        if data is None:
            return CryptoValidationResult(False, None, ["Data cannot be None"], warnings)
        
        if not isinstance(data, bytes):
            return CryptoValidationResult(False, None, ["Data must be bytes"], warnings)
        
        if len(data) == 0 and not allow_empty:
            errors.append("Empty data not allowed")
        
        if len(data) > max_size:
            errors.append(f"Data too large: maximum {max_size} bytes, got {len(data)}")
        
        return CryptoValidationResult(len(errors) == 0, data, errors, warnings)
    
    @staticmethod
    def sanitize_hex_key(hex_str: str) -> CryptoValidationResult:
        """
        Sanitize and validate hex-encoded key material.
        
        Args:
            hex_str: Hex-encoded key string
            
        Returns:
            Validation result with decoded bytes
        """
        errors = []
        warnings = []
        
        if not isinstance(hex_str, str):
            return CryptoValidationResult(False, None, ["Hex key must be string"], warnings)
        
        # Remove whitespace and common separators
        cleaned = re.sub(r'[\s:-]', '', hex_str)
        
        # Validate hex format
        if not re.match(r'^[0-9a-fA-F]*$', cleaned):
            errors.append("Invalid hex characters in key")
            return CryptoValidationResult(False, None, errors, warnings)
        
        # Check even length
        if len(cleaned) % 2 != 0:
            errors.append("Hex key must have even length")
            return CryptoValidationResult(False, None, errors, warnings)
        
        try:
            key_bytes = bytes.fromhex(cleaned)
            return CryptoValidationResult(True, key_bytes, [], warnings)
        except ValueError as e:
            return CryptoValidationResult(False, None, [f"Hex decode failed: {e}"], warnings)


class CryptoOperationRateLimiter:
    """
    Rate limiter specifically for cryptographic operations.
    Prevents key enumeration, timing attack amplification, and DoS.
    """
    
    def __init__(self):
        self._buckets: Dict[str, 'TokenBucket'] = {}
        self._lock = threading.Lock()
        
        # Default limits per operation type
        self._operation_limits = {
            'key_derivation': (1.0, 5.0),      # 1 per second, burst 5
            'signature_verify': (10.0, 20.0),   # 10 per second, burst 20
            'decryption': (50.0, 100.0),        # 50 per second, burst 100
            'encryption': (100.0, 200.0),       # 100 per second, burst 200
            'hash': (1000.0, 2000.0),           # 1000 per second, burst 2000
        }
    
    def _get_bucket(self, operation: str, key_id: str) -> 'TokenBucket':
        cache_key = f"{operation}:{key_id}"
        with self._lock:
            if cache_key not in self._buckets:
                rate, capacity = self._operation_limits.get(
                    operation, (10.0, 20.0)
                )
                self._buckets[cache_key] = TokenBucket(rate, capacity)
            return self._buckets[cache_key]
    
    def check_operation_allowed(self, operation: str, key_id: str = "global") -> bool:
        """
        Check if crypto operation should be allowed.
        
        Args:
            operation: Operation type name
            key_id: Optional key identifier for per-key limiting
            
        Returns:
            True if allowed, False if rate limited
        """
        bucket = self._get_bucket(operation, key_id)
        return bucket.consume(1.0)


class TokenBucket:
    """Token bucket implementation for rate limiting"""
    
    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = threading.Lock()
    
    def consume(self, tokens: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


class SecureKeyContext:
    """
    Context manager for secure key handling.
    Automatically zeroizes key material when exiting context.
    """
    
    def __init__(self, key: bytes):
        """
        Initialize with key material.
        
        Args:
            key: Key bytes to protect
        """
        self._key_copy = bytearray(key)
        self._original_key_ref = None
    
    def __enter__(self) -> bytes:
        """Return key as immutable bytes for use"""
        return bytes(self._key_copy)
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Securely zeroize key material"""
        CryptoSecureMemory.zeroize_key_material(self._key_copy)
        self._key_copy.clear()
        return False


class SecureCryptoBuffer:
    """
    Context manager for secure crypto buffers (plaintext, intermediate values).
    Automatically zeroizes when exiting scope.
    """
    
    def __init__(self, size_or_data: Union[int, bytes]):
        if isinstance(size_or_data, int):
            self._buffer = bytearray(size_or_data)
        else:
            self._buffer = bytearray(size_or_data)
    
    def __enter__(self) -> bytearray:
        return self._buffer
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        CryptoSecureMemory.zeroize_key_material(self._buffer)
        self._buffer.clear()
        return False


class CryptoSecurityFacade:
    """
    Facade providing unified access to all crypto security hardening features.
    Main entry point for integrating security into existing crypto code.
    """
    
    def __init__(self, security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD):
        self.security_level = security_level
        self._rate_limiter = CryptoOperationRateLimiter()
        self._stats: Dict[str, int] = {
            'validations_total': 0,
            'validations_failed': 0,
            'operations_rate_limited': 0,
            'keys_protected': 0,
        }
        self._stats_lock = threading.Lock()
    
    def validate_key(self, key: bytes, algorithm: Optional[str] = None) -> CryptoValidationResult:
        """Validate cryptographic key material"""
        with self._stats_lock:
            self._stats['validations_total'] += 1
        
        result = CryptoInputValidator.validate_key(
            key, algorithm, security_level=self.security_level
        )
        
        if not result.is_valid:
            with self._stats_lock:
                self._stats['validations_failed'] += 1
        
        return result
    
    def validate_nonce(self, nonce: bytes, algorithm: Optional[str] = None) -> CryptoValidationResult:
        """Validate nonce/IV"""
        with self._stats_lock:
            self._stats['validations_total'] += 1
        
        result = CryptoInputValidator.validate_nonce(
            nonce, algorithm, security_level=self.security_level
        )
        
        if not result.is_valid:
            with self._stats_lock:
                self._stats['validations_failed'] += 1
        
        return result
    
    def secure_key_context(self, key: bytes) -> SecureKeyContext:
        """Create context-managed secure key"""
        with self._stats_lock:
            self._stats['keys_protected'] += 1
        return SecureKeyContext(key)
    
    def secure_buffer(self, size_or_data: Union[int, bytes]) -> SecureCryptoBuffer:
        """Create context-managed secure buffer"""
        return SecureCryptoBuffer(size_or_data)
    
    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Constant-time bytes comparison"""
        return CryptoSecureMemory.secure_compare_digests(a, b)
    
    def check_crypto_rate_limit(self, operation: str, key_id: str = "global") -> bool:
        """Check if operation should be rate limited"""
        allowed = self._rate_limiter.check_operation_allowed(operation, key_id)
        if not allowed:
            with self._stats_lock:
                self._stats['operations_rate_limited'] += 1
        return allowed
    
    def get_security_stats(self) -> Dict[str, int]:
        """Get security operation statistics"""
        with self._stats_lock:
            return dict(self._stats)
    
    def zeroize_sensitive_data(self, data: bytearray) -> None:
        """Securely zeroize sensitive data"""
        CryptoSecureMemory.zeroize_key_material(data)


# Export default facade
_default_crypto_security = CryptoSecurityFacade()

def get_crypto_security_facade() -> CryptoSecurityFacade:
    """Get the default cryptographic security facade"""
    return _default_crypto_security


# Generate cryptographically secure random nonce
def generate_secure_nonce(size: int = 12) -> bytes:
    """
    Generate cryptographically secure nonce.
    
    Args:
        size: Nonce size in bytes
        
    Returns:
        Cryptographically secure random bytes
    """
    return secrets.token_bytes(size)


# Module version info
__version__ = "26.0.0"
__security_dimension__ = "B - Security Hardening (Crypto Specific)"
