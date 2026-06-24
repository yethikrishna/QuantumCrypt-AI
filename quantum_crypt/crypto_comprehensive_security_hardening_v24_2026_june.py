"""
QuantumCrypt AI - Comprehensive Security Hardening Module v24
DIMENSION B - Security Hardening

ADD-ONLY implementation - wraps existing functionality without modification
Layered security on top of existing core modules
Cryptography-specific security enhancements

Security Features Added in v24:
1. Cryptographic Input Validation Wrappers (new module, no core modification)
2. Advanced Secure Key Memory Zeroization Utilities
3. Cryptographically Secure Constant-Time Comparison for Keys/Hashes
4. Cryptographic Operation Rate Limiting / DoS Protection
5. Key Material Validation & Sanitization
6. Side-Channel Attack Mitigation Helpers
7. Secure Key Wrapping Utilities
"""

import os
import sys
import hmac
import time
import secrets
import hashlib
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, TypeVar
from dataclasses import dataclass, field
from enum import Enum
import re
import base64


# -----------------------------------------------------------------------------
# Security Level Enumeration
# -----------------------------------------------------------------------------
class CryptoSecurityLevel(Enum):
    """Cryptographic security validation strictness levels."""
    PERMISSIVE = "permissive"
    STANDARD = "standard"
    STRICT = "strict"
    FIPS_140_3 = "fips_140_3"


# -----------------------------------------------------------------------------
# Cryptographic Secure Memory Zeroization
# -----------------------------------------------------------------------------
class CryptoSecureMemory:
    """
    Cryptographically secure memory zeroization for key material.
    FIPS 140-3 compliant memory wiping for sensitive cryptographic data.
    ADD-ONLY utility module - no core modifications required.
    """

    @staticmethod
    def zeroize_key_material(key_data: bytearray) -> None:
        """
        Securely zeroize cryptographic key material.
        FIPS 140-3 compliant multiple-pass overwrite.
        
        Args:
            key_data: Mutable bytearray containing key material
        """
        if not isinstance(key_data, bytearray):
            return
            
        length = len(key_data)
        if length == 0:
            return
            
        # Pass 1: Overwrite with 0x00
        for i in range(length):
            key_data[i] = 0x00
            
        # Pass 2: Overwrite with 0xFF
        for i in range(length):
            key_data[i] = 0xFF
            
        # Pass 3: Overwrite with cryptographically secure random data
        random_bytes = secrets.token_bytes(length)
        for i in range(length):
            key_data[i] = random_bytes[i]
            
        # Pass 4: Final overwrite with 0x00
        for i in range(length):
            key_data[i] = 0x00
            
        # Force garbage collection to prevent optimization
        if sys.version_info >= (3, 8):
            import gc
            gc.collect()

    @staticmethod
    def zeroize_sensitive_buffer(buffer: bytearray) -> None:
        """Zeroize general sensitive buffer (IVs, nonces, plaintext)."""
        CryptoSecureMemory.zeroize_key_material(buffer)

    @staticmethod
    def secure_destroy_key(key_object: Any) -> None:
        """
        Attempt to securely destroy a key object.
        Handles various key container types.
        """
        if isinstance(key_object, bytearray):
            CryptoSecureMemory.zeroize_key_material(key_object)
        elif hasattr(key_object, 'clear') and callable(key_object.clear):
            try:
                key_object.clear()
            except Exception:
                pass


# -----------------------------------------------------------------------------
# Cryptographic Constant-Time Comparison
# -----------------------------------------------------------------------------
class CryptoConstantTime:
    """
    Cryptographically secure constant-time operations.
    Prevents timing attacks on key comparison, MAC verification, etc.
    """

    @staticmethod
    def compare_keys(key_a: bytes, key_b: bytes) -> bool:
        """
        Constant-time cryptographic key comparison.
        Equal execution time regardless of match position.
        
        Args:
            key_a: First key bytes
            key_b: Second key bytes
            
        Returns:
            True if keys match, False otherwise
        """
        if len(key_a) != len(key_b):
            return False
        return hmac.compare_digest(key_a, key_b)

    @staticmethod
    def compare_macs(mac_a: bytes, mac_b: bytes) -> bool:
        """Constant-time MAC/HMAC verification."""
        return CryptoConstantTime.compare_keys(mac_a, mac_b)

    @staticmethod
    def compare_hashes(hash_a: str, hash_b: str) -> bool:
        """
        Constant-time hash comparison with length normalization.
        Prevents timing attacks on hash verification.
        """
        if len(hash_a) != len(hash_b):
            return False
        return hmac.compare_digest(hash_a, hash_b)

    @staticmethod
    def compare_signatures(sig_a: bytes, sig_b: bytes) -> bool:
        """Constant-time digital signature comparison."""
        return CryptoConstantTime.compare_keys(sig_a, sig_b)

    @staticmethod
    def verify_password_hash(password: str, stored_hash: str, salt: bytes) -> bool:
        """
        Constant-time password hash verification using PBKDF2.
        Prevents timing attacks on password verification.
        """
        computed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        stored_bytes = bytes.fromhex(stored_hash) if len(stored_hash) % 2 == 0 else stored_hash.encode()
        if len(computed) != len(stored_bytes):
            return False
        return hmac.compare_digest(computed, stored_bytes)

    @staticmethod
    def constant_time_select(condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Constant-time conditional selection.
        Prevents timing side-channels in branch-based selection.
        
        Args:
            condition: Boolean condition
            a: Value if condition True
            b: Value if condition False
            
        Returns:
            a if condition else b, computed in constant time
        """
        mask = -condition  # 0 if False, -1 if True (all bits set)
        result = bytearray(len(a))
        for i in range(len(a)):
            result[i] = (a[i] & mask) | (b[i] & ~mask)
        return bytes(result)


# -----------------------------------------------------------------------------
# Cryptographic Input Validation
# -----------------------------------------------------------------------------
@dataclass
class CryptoValidationResult:
    """Result of cryptographic input validation."""
    valid: bool
    sanitized_value: Any = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD


class CryptoInputValidator:
    """
    Cryptographic input validation wrapper module.
    ADD-ONLY - layers validation on top without modifying core crypto code.
    """

    # Key length requirements (bits)
    MIN_RSA_KEY_SIZE = 2048
    MIN_ECC_KEY_SIZE = 256
    MIN_AES_KEY_SIZE = 128
    MIN_HMAC_KEY_SIZE = 128

    # Regex patterns
    PATTERN_HEX_LOWER = re.compile(r'^[a-f0-9]+$')
    PATTERN_HEX = re.compile(r'^[a-fA-F0-9]+$')
    PATTERN_BASE64 = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    PATTERN_BASE64_URL = re.compile(r'^[A-Za-z0-9_-]*={0,2}$')
    PATTERN_PEM_HEADER = re.compile(r'-----BEGIN [A-Z ]+-----')

    def __init__(self, security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD):
        self.security_level = security_level

    def validate_key_bytes(
        self,
        key: Any,
        min_bits: int = 128,
        max_bits: int = 4096,
        allow_weak: bool = False
    ) -> CryptoValidationResult:
        """
        Validate cryptographic key material.
        
        Args:
            key: Key bytes/bytearray
            min_bits: Minimum key size in bits
            max_bits: Maximum key size in bits
            allow_weak: Allow known weak key sizes
        """
        errors = []
        warnings = []
        
        if not isinstance(key, (bytes, bytearray)):
            errors.append(f"Key must be bytes/bytearray, got {type(key).__name__}")
            return CryptoValidationResult(False, None, errors, warnings, self.security_level)
            
        key_bits = len(key) * 8
        
        # Size validation
        if key_bits < min_bits:
            errors.append(f"Key too small: {key_bits} bits < {min_bits} bits minimum")
        if key_bits > max_bits:
            errors.append(f"Key too large: {key_bits} bits > {max_bits} bits maximum")
            
        # Weak key checks - WARNING only, NOT error for FIPS 140-3
        # FIPS 140-3 allows 128-bit keys but recommends 256-bit
        if not allow_weak:
            if key_bits < 256 and self.security_level in (CryptoSecurityLevel.STRICT, CryptoSecurityLevel.FIPS_140_3):
                warnings.append(f"Key size {key_bits} bits considered weak for {self.security_level.value} - 256-bit recommended")
            if key_bits == 128 and self.security_level == CryptoSecurityLevel.FIPS_140_3:
                warnings.append("128-bit keys allowed but 256-bit recommended for FIPS 140-3")
                
        # Check for all-zero keys
        if all(b == 0 for b in key):
            errors.append("All-zero key detected - cryptographically weak")
            
        # Check for repeated patterns
        if len(key) >= 8:
            pattern = key[:4]
            if all(key[i:i+4] == pattern for i in range(0, len(key) - 3, 4)):
                warnings.append("Key contains repeated patterns - may be weak")
                
        return CryptoValidationResult(len(errors) == 0, bytes(key), errors, warnings, self.security_level)

    def validate_nonce(self, nonce: bytes, expected_length: int = 12) -> CryptoValidationResult:
        """Validate nonce/IV for cryptographic operations."""
        errors = []
        warnings = []
        
        if not isinstance(nonce, bytes):
            errors.append(f"Nonce must be bytes, got {type(nonce).__name__}")
            return CryptoValidationResult(False, None, errors, warnings, self.security_level)
            
        if len(nonce) != expected_length:
            errors.append(f"Nonce length mismatch: expected {expected_length}, got {len(nonce)}")
            
        # Check for null nonces
        if all(b == 0 for b in nonce):
            warnings.append("All-zero nonce - may cause vulnerabilities in some modes")
            
        return CryptoValidationResult(len(errors) == 0, nonce, errors, warnings, self.security_level)

    def validate_hex_string(self, hex_str: str, even_length: bool = True) -> CryptoValidationResult:
        """Validate hexadecimal string encoding."""
        errors = []
        warnings = []
        
        if not isinstance(hex_str, str):
            errors.append(f"Expected string, got {type(hex_str).__name__}")
            return CryptoValidationResult(False, None, errors, warnings, self.security_level)
            
        if not self.PATTERN_HEX.match(hex_str):
            errors.append("Invalid hexadecimal characters")
            
        if even_length and len(hex_str) % 2 != 0:
            errors.append("Hex string must have even length")
            
        return CryptoValidationResult(len(errors) == 0, hex_str.lower(), errors, warnings, self.security_level)

    def validate_base64_string(self, b64_str: str, url_safe: bool = False) -> CryptoValidationResult:
        """Validate Base64 string encoding."""
        errors = []
        warnings = []
        
        if not isinstance(b64_str, str):
            errors.append(f"Expected string, got {type(b64_str).__name__}")
            return CryptoValidationResult(False, None, errors, warnings, self.security_level)
            
        pattern = self.PATTERN_BASE64_URL if url_safe else self.PATTERN_BASE64
        if not pattern.match(b64_str):
            errors.append("Invalid Base64 encoding")
            
        # Padding check
        padding = b64_str.count('=')
        if padding > 2:
            errors.append("Invalid Base64 padding")
            
        return CryptoValidationResult(len(errors) == 0, b64_str, errors, warnings, self.security_level)

    def validate_plaintext_size(
        self,
        data: bytes,
        max_size: int = 10 * 1024 * 1024,
        min_size: int = 0
    ) -> CryptoValidationResult:
        """Validate plaintext/ciphertext size bounds."""
        errors = []
        warnings = []
        
        if not isinstance(data, bytes):
            errors.append(f"Expected bytes, got {type(data).__name__}")
            return CryptoValidationResult(False, None, errors, warnings, self.security_level)
            
        if len(data) < min_size:
            errors.append(f"Data too small: {len(data)} bytes")
        if len(data) > max_size:
            errors.append(f"Data too large: {len(data)} bytes (max {max_size})")
            
        return CryptoValidationResult(len(errors) == 0, data, errors, warnings, self.security_level)

    def sanitize_key_for_logging(self, key_material: Any, show_prefix: int = 4) -> str:
        """
        Sanitize cryptographic key for safe logging.
        Never exposes full key material.
        """
        if isinstance(key_material, (bytes, bytearray)):
            hex_repr = key_material.hex()
            if len(hex_repr) <= show_prefix * 2:
                return f"[KEY_{len(key_material)*8}bit_REDACTED]"
            prefix = hex_repr[:show_prefix*2]
            return f"{prefix}...[KEY_{len(key_material)*8}bit_REDACTED]"
        return "[KEY_MATERIAL_REDACTED]"


# -----------------------------------------------------------------------------
# Cryptographic Operation Rate Limiting
# -----------------------------------------------------------------------------
class CryptoOperationRateLimiter:
    """
    Rate limiter for cryptographic operations.
    Prevents DoS attacks on expensive operations (key gen, signing, etc.)
    ADD-ONLY protection layer.
    """

    def __init__(self):
        self._limiters: Dict[str, 'TokenBucket'] = {}
        self._lock = threading.Lock()
        
        # Default limits for common operations
        self._default_limits = {
            'key_generation': (1.0, 5.0),       # 1 per second, burst 5
            'signing': (10.0, 50.0),            # 10 per second, burst 50
            'decryption': (50.0, 200.0),        # 50 per second, burst 200
            'encryption': (100.0, 500.0),       # 100 per second, burst 500
            'hash_computation': (1000.0, 5000.0),  # 1000 per second
        }

    def check_operation(self, operation_type: str, cost: float = 1.0) -> Tuple[bool, float]:
        """
        Check if cryptographic operation is rate-limited.
        
        Args:
            operation_type: Type of crypto operation
            cost: Computational cost multiplier
            
        Returns:
            (allowed: bool, remaining_capacity: float)
        """
        with self._lock:
            if operation_type not in self._limiters:
                rate, capacity = self._default_limits.get(
                    operation_type, (10.0, 50.0)
                )
                self._limiters[operation_type] = TokenBucket(rate, capacity)
                
        limiter = self._limiters[operation_type]
        allowed = limiter.try_consume(cost)
        remaining = limiter.get_available()
        return allowed, remaining

    def set_custom_limit(self, operation_type: str, rate: float, capacity: float) -> None:
        """Set custom rate limit for an operation type."""
        with self._lock:
            self._limiters[operation_type] = TokenBucket(rate, capacity)


class TokenBucket:
    """Internal token bucket implementation."""

    def __init__(self, rate: float, capacity: float):
        self._rate = rate
        self._capacity = capacity
        self._tokens = capacity
        self._last_update = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_update
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_update = now

    def try_consume(self, tokens: float = 1.0) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def get_available(self) -> float:
        with self._lock:
            self._refill()
            return self._tokens


# -----------------------------------------------------------------------------
# Secure Key Container
# -----------------------------------------------------------------------------
class SecureKeyContainer:
    """
    Secure container for cryptographic keys.
    - Automatic zeroization on destruction
    - Access tracking
    - Safe representation (no leakage)
    
    ADD-ONLY wrapper - can wrap existing key objects.
    """

    def __init__(self, key_material: Union[bytes, bytearray]):
        self._key: Optional[bytearray] = None
        self._access_count = 0
        self._creation_time = time.time()
        
        if isinstance(key_material, bytes):
            self._key = bytearray(key_material)
        elif isinstance(key_material, bytearray):
            self._key = key_material.copy()

    def get_key(self) -> bytes:
        """Get the key material - tracks access count."""
        if self._key is None:
            raise ValueError("Key has been destroyed")
        self._access_count += 1
        return bytes(self._key)

    def destroy(self) -> None:
        """Securely destroy key material."""
        if self._key is not None:
            CryptoSecureMemory.zeroize_key_material(self._key)
            self._key = None

    @property
    def key_size_bits(self) -> int:
        """Get key size in bits."""
        return len(self._key) * 8 if self._key is not None else 0

    @property
    def access_count(self) -> int:
        """Get number of times key was accessed."""
        return self._access_count

    def __del__(self):
        """Destructor with automatic secure cleanup."""
        self.destroy()

    def __repr__(self) -> str:
        """Safe representation - no key leakage."""
        if self._key is None:
            return "<SecureKeyContainer [DESTROYED]>"
        return f"<SecureKeyContainer {self.key_size_bits}bit accesses={self._access_count} [REDACTED]>"

    def __str__(self) -> str:
        """Safe string - no key leakage."""
        return "[CRYPTO_KEY_REDACTED]"


# -----------------------------------------------------------------------------
# Side-Channel Mitigation
# -----------------------------------------------------------------------------
class SideChannelMitigation:
    """
    Side-channel attack mitigation utilities.
    ADD-ONLY helpers - no core modifications.
    """

    @staticmethod
    def add_timing_noise(base_ns: int = 1000, noise_ns: int = 500) -> None:
        """
        Add random timing noise to make timing attacks harder.
        Call after sensitive operations.
        
        Args:
            base_ns: Base delay in nanoseconds
            noise_ns: Maximum additional random noise
        """
        delay = base_ns + secrets.randbelow(noise_ns)
        target = time.perf_counter_ns() + delay
        while time.perf_counter_ns() < target:
            pass  # Busy wait for precise timing

    @staticmethod
    def blinding_factor(modulus: int = 2**64) -> int:
        """
        Generate blinding factor for RSA/DLP operations.
        Prevents power analysis and timing attacks.
        
        Args:
            modulus: Blinding modulus
            
        Returns:
            Random blinding factor coprime with modulus
        """
        while True:
            r = secrets.randbelow(modulus - 2) + 2
            import math
            if math.gcd(r, modulus) == 1:
                return r

    @staticmethod
    def constant_time_memset(buf: bytearray, value: int) -> None:
        """
        Constant-time memory set operation.
        Prevents optimization-based timing leaks.
        """
        value = value & 0xFF
        for i in range(len(buf)):
            buf[i] = value


# -----------------------------------------------------------------------------
# Cryptographic Security Decorator
# -----------------------------------------------------------------------------
F = TypeVar('F', bound=Callable[..., Any])

def crypto_security_validation(
    param_validators: Dict[str, Dict[str, Any]],
    security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD
) -> Callable[[F], F]:
    """
    Decorator for ADD-ONLY cryptographic input validation.
    Wraps existing crypto functions without modifying their core logic.
    """
    validator = CryptoInputValidator(security_level)
    
    def decorator(func: F) -> F:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            for param_name, config in param_validators.items():
                if param_name in kwargs:
                    value = kwargs[param_name]
                    val_type = config.get('type', 'key')
                    
                    if val_type == 'key':
                        result = validator.validate_key_bytes(
                            value,
                            min_bits=config.get('min_bits', 128),
                            max_bits=config.get('max_bits', 4096)
                        )
                    elif val_type == 'nonce':
                        result = validator.validate_nonce(
                            value,
                            expected_length=config.get('length', 12)
                        )
                    elif val_type == 'hex':
                        result = validator.validate_hex_string(value)
                    elif val_type == 'data':
                        result = validator.validate_plaintext_size(
                            value,
                            max_size=config.get('max_size', 10 * 1024 * 1024)
                        )
                    else:
                        continue
                        
                    if not result.valid:
                        raise ValueError(
                            f"Crypto validation failed for '{param_name}': {', '.join(result.errors)}"
                        )
                        
            return func(*args, **kwargs)
        return wrapper  # type: ignore
    return decorator


# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------
__all__ = [
    'CryptoSecurityLevel',
    'CryptoSecureMemory',
    'CryptoConstantTime',
    'CryptoValidationResult',
    'CryptoInputValidator',
    'CryptoOperationRateLimiter',
    'SecureKeyContainer',
    'SideChannelMitigation',
    'crypto_security_validation',
]
