"""
QuantumCrypt Security Hardening - Comprehensive Protection v19
Dimension B: Security Hardening

This module provides production-grade security hardening for cryptographic operations:
- Enhanced key material validation wrappers (additive, no core modification)
- Secure key memory zeroization with side-channel resistance
- Advanced constant-time comparison for cryptographic operations
- Adaptive rate limiting for key operations (DoS protection)
- Side-channel timing attack resistance for crypto primitives
- Key material sensitivity wrappers

All features are OPT-IN and layered on top of existing code.
No existing production code is modified - 100% backward compatible.

API Stability: STABLE
"""

import hashlib
import hmac
import secrets
import threading
import time
import weakref
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, cast
from functools import wraps
import re
import math
import math
import base64

T = TypeVar('T')

# -----------------------------------------------------------------------------
# Cryptographic Secure Memory Zeroization
# -----------------------------------------------------------------------------

class CryptoSecureMemory:
    """
    Cryptographic secure memory management with side-channel resistant zeroization.
    
    Specifically designed for sensitive key material. Uses multiple passes
    with different patterns to prevent compiler optimization and ensure
    memory is actually cleared.
    """
    
    @staticmethod
    def zeroize_key_material(key_data: bytearray) -> None:
        """
        Securely zeroize cryptographic key material.
        
        Uses cryptographic-strength zeroization with multiple passes.
        Designed for private keys, secret keys, and other sensitive material.
        
        Args:
            key_data: Mutable bytearray containing key material
        """
        length = len(key_data)
        if length == 0:
            return
        
        # Pass 1: All zeros
        for i in range(length):
            key_data[i] = 0
        
        # Pass 2: All ones
        for i in range(length):
            key_data[i] = 0xFF
        
        # Pass 3: Alternating pattern
        for i in range(length):
            key_data[i] = 0xAA if i % 2 == 0 else 0x55
        
        # Pass 4: Cryptographically secure random pattern
        rng = secrets.SystemRandom()
        for i in range(length):
            key_data[i] = rng.randint(0, 255)
        
        # Pass 5: Final zeroization
        for i in range(length):
            key_data[i] = 0
    
    @staticmethod
    def secure_compare_constant(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison for cryptographic material.
        
        Prevents timing attacks by ensuring comparison time
        does not depend on how many bytes match.
        
        Args:
            a: First cryptographic value (hash, MAC, key)
            b: Second cryptographic value
            
        Returns:
            True if equal, False otherwise
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def verify_hmac(
        received_mac: bytes,
        key: bytes,
        data: bytes,
        digest: str = 'sha256'
    ) -> bool:
        """
        Constant-time HMAC verification.
        
        Args:
            received_mac: Received MAC to verify
            key: HMAC verification key
            data: Data that was MACed
            digest: Hash algorithm to use
            
        Returns:
            True if MAC is valid, False otherwise
        """
        computed = hmac.new(key, data, digestmod=digest).digest()
        return hmac.compare_digest(received_mac, computed)


class SensitiveKeyMaterial:
    """
    Auto-zeroizing container for cryptographic key material.
    
    Automatically zeroizes memory when the container is garbage collected
    or explicitly closed. Uses weakref finalizer for guaranteed cleanup.
    Implements context manager protocol for safe usage.
    """
    
    def __init__(self, key_bytes: Optional[bytes] = None):
        self._key: bytearray = bytearray()
        self._is_destroyed = False
        
        if key_bytes is not None:
            self._key.extend(key_bytes)
        
        # Register finalizer to ensure zeroization on GC
        self._finalizer = weakref.finalize(
            self, self._finalize_key, self._key
        )
    
    @staticmethod
    def _finalize_key(key: bytearray) -> None:
        """Finalizer called during GC to zeroize key material."""
        CryptoSecureMemory.zeroize_key_material(key)
    
    def get_key_bytes(self) -> bytes:
        """Get copy of key material as bytes."""
        if self._is_destroyed:
            raise ValueError("Key material has been destroyed")
        return bytes(self._key)
    
    def destroy(self) -> None:
        """Explicitly destroy and zeroize key material."""
        if not self._is_destroyed:
            CryptoSecureMemory.zeroize_key_material(self._key)
            self._is_destroyed = True
    
    def __enter__(self) -> 'SensitiveKeyMaterial':
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.destroy()
    
    def __del__(self) -> None:
        self.destroy()


# -----------------------------------------------------------------------------
# Constant-Time Cryptographic Operations
# -----------------------------------------------------------------------------

class CryptoConstantTime:
    """
    Constant-time cryptographic operations library.
    
    Provides comparison and selection operations that execute in
    constant time regardless of input values, preventing timing attacks
    on cryptographic operations.
    """
    
    @staticmethod
    def bytes_eq(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte equality check.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            True if equal, False otherwise (constant time)
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def select_byte(condition: bool, val_true: int, val_false: int) -> int:
        """
        Constant-time byte selection.
        
        Args:
            condition: Selection condition
            val_true: Byte value if True (0-255)
            val_false: Byte value if False (0-255)
            
        Returns:
            Selected byte value (constant time)
        """
        mask = -int(condition) & 0xFF
        return (val_true & mask) | (val_false & ~mask)
    
    @staticmethod
    def verify_signature_constant(sig_a: bytes, sig_b: bytes) -> bool:
        """
        Constant-time signature verification.
        
        Args:
            sig_a: First signature
            sig_b: Second signature
            
        Returns:
            True if signatures match, False otherwise
        """
        return hmac.compare_digest(sig_a, sig_b)
    
    @staticmethod
    def public_key_fingerprint_eq(fp1: str, fp2: str) -> bool:
        """
        Constant-time public key fingerprint comparison.
        
        Args:
            fp1: First fingerprint (hex or base64)
            fp2: Second fingerprint
            
        Returns:
            True if fingerprints match
        """
        if len(fp1) != len(fp2):
            return False
        return hmac.compare_digest(fp1.encode('utf-8'), fp2.encode('utf-8'))


# -----------------------------------------------------------------------------
# Key Material Input Validation
# -----------------------------------------------------------------------------

@dataclass
class KeyValidationResult:
    """Result of key material validation."""
    is_valid: bool
    sanitized: Optional[bytes] = None
    error_message: Optional[str] = None
    key_strength: int = 0


class CryptoInputValidator:
    """
    Cryptographic input validation wrapper.
    
    Layered security - wraps existing functions without modifying them.
    Provides validation and sanitization for keys, nonces, and crypto inputs.
    """
    
    # Common weak keys and patterns to reject
    WEAK_KEY_PATTERNS = [
        b'\x00' * 8,      # All zeros
        b'\xFF' * 8,      # All ones
        b'\xAA' * 8,      # Repeating pattern
        b'12345678',      # Numeric sequence
        b'password',      # Common password
    ]
    
    def __init__(self):
        self._min_key_entropy = 64  # bits
    
    def validate_key_bytes(
        self,
        key_data: bytes,
        min_length: int = 16,
        max_length: int = 1024,
        check_weak_keys: bool = True
    ) -> KeyValidationResult:
        """
        Validate cryptographic key material.
        
        Args:
            key_data: Raw key bytes
            min_length: Minimum allowed key length
            max_length: Maximum allowed key length
            check_weak_keys: Check for common weak key patterns
            
        Returns:
            KeyValidationResult with validation status
        """
        if not isinstance(key_data, bytes):
            return KeyValidationResult(
                is_valid=False,
                error_message="Key must be bytes"
            )
        
        if len(key_data) < min_length:
            return KeyValidationResult(
                is_valid=False,
                error_message=f"Key too short: {len(key_data)} < {min_length}"
            )
        
        if len(key_data) > max_length:
            return KeyValidationResult(
                is_valid=False,
                error_message=f"Key too long: {len(key_data)} > {max_length}"
            )
        
        # Check for weak key patterns
        if check_weak_keys:
            for pattern in self.WEAK_KEY_PATTERNS:
                if pattern in key_data:
                    return KeyValidationResult(
                        is_valid=False,
                        error_message="Weak key pattern detected"
                    )
        
        # Calculate approximate entropy
        entropy = self._estimate_entropy(key_data)
        
        return KeyValidationResult(
            is_valid=True,
            sanitized=key_data,
            key_strength=entropy
        )
    
    def validate_nonce(
        self,
        nonce: bytes,
        expected_length: int = 12
    ) -> KeyValidationResult:
        """
        Validate cryptographic nonce/IV.
        
        Args:
            nonce: Nonce bytes
            expected_length: Expected nonce length
            
        Returns:
            Validation result
        """
        if len(nonce) != expected_length:
            return KeyValidationResult(
                is_valid=False,
                error_message=f"Nonce length mismatch: {len(nonce)} != {expected_length}"
            )
        
        # Check for all zeros (common mistake)
        if all(b == 0 for b in nonce):
            return KeyValidationResult(
                is_valid=False,
                error_message="All-zero nonce is insecure"
            )
        
        return KeyValidationResult(is_valid=True, sanitized=nonce)
    
    def validate_base64_key(
        self,
        key_str: str,
        min_length: int = 16
    ) -> KeyValidationResult:
        """
        Validate and decode base64-encoded key.
        
        Args:
            key_str: Base64 encoded key string
            min_length: Minimum decoded key length
            
        Returns:
            Validation result with decoded bytes
        """
        try:
            decoded = base64.b64decode(key_str)
        except Exception as e:
            return KeyValidationResult(
                is_valid=False,
                error_message=f"Invalid base64: {e}"
            )
        
        return self.validate_key_bytes(decoded, min_length=min_length)
    
    def _estimate_entropy(self, data: bytes) -> int:
        """Estimate Shannon entropy of key material."""
        if len(data) == 0:
            return 0
        
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)  # Shannon entropy calculation
        
        return int(entropy * len(data))


def validate_crypto_inputs(**validation_spec):
    """
    Decorator for cryptographic input validation.
    
    Usage:
        @validate_crypto_inputs(
            key={'type': 'key_bytes', 'min_length': 32},
            nonce={'type': 'nonce', 'length': 12}
        )
        def encrypt(key, nonce, plaintext):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            validator = CryptoInputValidator()
            
            for param_name, spec in validation_spec.items():
                if param_name in kwargs:
                    value = kwargs[param_name]
                    param_type = spec.get('type', 'key_bytes')
                    
                    if param_type == 'key_bytes':
                        result = validator.validate_key_bytes(
                            value,
                            min_length=spec.get('min_length', 16)
                        )
                        if not result.is_valid:
                            raise ValueError(
                                f"Invalid {param_name}: {result.error_message}"
                            )
                        kwargs[param_name] = result.sanitized
                    
                    elif param_type == 'nonce':
                        result = validator.validate_nonce(
                            value,
                            expected_length=spec.get('length', 12)
                        )
                        if not result.is_valid:
                            raise ValueError(
                                f"Invalid {param_name}: {result.error_message}"
                            )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# Key Operation Rate Limiting (DoS Protection)
# -----------------------------------------------------------------------------

@dataclass
class KeyOperationRateLimit:
    """Rate limit configuration for key operations."""
    max_key_generations: int = 10
    max_signatures: int = 100
    max_verifications: int = 500
    window_seconds: float = 60.0
    burst_multiplier: float = 1.5


@dataclass
class KeyOpBucket:
    """Token bucket state for key operation rate limiting."""
    gen_tokens: float
    sign_tokens: float
    verify_tokens: float
    last_update: float
    lock: threading.Lock = field(default_factory=threading.Lock)


class KeyOperationRateLimiter:
    """
    Rate limiter specifically for cryptographic key operations.
    
    Prevents DoS attacks against expensive crypto operations:
    - Key generation (most expensive)
    - Digital signatures
    - Signature verification
    
    Layered security - can wrap any existing crypto function.
    """
    
    def __init__(self, config: Optional[KeyOperationRateLimit] = None):
        self._config = config or KeyOperationRateLimit()
        self._buckets: Dict[str, KeyOpBucket] = {}
        self._global_lock = threading.Lock()
        self._cleanup_interval = 300.0
        self._last_cleanup = time.time()
    
    def _cleanup(self) -> None:
        """Remove stale buckets."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        with self._global_lock:
            stale = [
                k for k, b in self._buckets.items()
                if now - b.last_update > self._cleanup_interval * 2
            ]
            for k in stale:
                del self._buckets[k]
            self._last_cleanup = now
    
    def _get_or_create_bucket(self, client_id: str) -> KeyOpBucket:
        with self._global_lock:
            if client_id not in self._buckets:
                cfg = self._config
                self._buckets[client_id] = KeyOpBucket(
                    gen_tokens=cfg.max_key_generations,
                    sign_tokens=cfg.max_signatures,
                    verify_tokens=cfg.max_verifications,
                    last_update=time.time()
                )
            return self._buckets[client_id]
    
    def check_key_generation(self, client_id: str) -> bool:
        """Check if key generation is allowed."""
        return self._check_op(client_id, 'gen', 1)
    
    def check_signature(self, client_id: str) -> bool:
        """Check if signature operation is allowed."""
        return self._check_op(client_id, 'sign', 1)
    
    def check_verification(self, client_id: str) -> bool:
        """Check if verification operation is allowed."""
        return self._check_op(client_id, 'verify', 1)
    
    def _check_op(self, client_id: str, op_type: str, cost: int) -> bool:
        self._cleanup()
        bucket = self._get_or_create_bucket(client_id)
        cfg = self._config
        
        with bucket.lock:
            now = time.time()
            elapsed = now - bucket.last_update
            
            # Refill tokens
            bucket.gen_tokens = min(
                bucket.gen_tokens + elapsed * (cfg.max_key_generations / cfg.window_seconds),
                cfg.max_key_generations * cfg.burst_multiplier
            )
            bucket.sign_tokens = min(
                bucket.sign_tokens + elapsed * (cfg.max_signatures / cfg.window_seconds),
                cfg.max_signatures * cfg.burst_multiplier
            )
            bucket.verify_tokens = min(
                bucket.verify_tokens + elapsed * (cfg.max_verifications / cfg.window_seconds),
                cfg.max_verifications * cfg.burst_multiplier
            )
            bucket.last_update = now
            
            # Check and consume tokens
            if op_type == 'gen' and bucket.gen_tokens >= cost:
                bucket.gen_tokens -= cost
                return True
            elif op_type == 'sign' and bucket.sign_tokens >= cost:
                bucket.sign_tokens -= cost
                return True
            elif op_type == 'verify' and bucket.verify_tokens >= cost:
                bucket.verify_tokens -= cost
                return True
            
            return False


# -----------------------------------------------------------------------------
# Side-Channel Timing Resistance for Crypto
# -----------------------------------------------------------------------------

class CryptoTimingResistance:
    """
    Side-channel timing attack resistance for cryptographic operations.
    
    Provides methods to make key operations resistant to timing analysis.
    Critical for preventing key recovery via timing side channels.
    """
    
    @staticmethod
    def key_op_timing_mask(
        min_duration: float = 0.005,
        jitter: float = 0.005
    ) -> None:
        """
        Add timing masking to obscure key operation execution time.
        
        Args:
            min_duration: Minimum operation duration
            jitter: Additional random jitter range
        """
        delay = min_duration + secrets.SystemRandom().random() * jitter
        time.sleep(delay)
    
    @staticmethod
    def normalize_key_operation(
        target_ms: float,
        start_time: float
    ) -> None:
        """
        Ensure key operation takes at least target duration.
        
        Args:
            target_ms: Target duration in milliseconds
            start_time: Operation start timestamp
        """
        target_sec = target_ms / 1000.0
        elapsed = time.time() - start_time
        remaining = target_sec - elapsed
        if remaining > 0:
            time.sleep(remaining)
    
    @staticmethod
    def dummy_key_operations(count: int = 10) -> None:
        """
        Perform dummy key operations to confuse timing analysis.
        
        Args:
            count: Number of dummy hash operations
        """
        dummy_data = secrets.token_bytes(32)
        for _ in range(count):
            hashlib.sha256(dummy_data).digest()
            dummy_data = hashlib.sha256(dummy_data).digest()


# -----------------------------------------------------------------------------
# Crypto Security Hardening Facade
# -----------------------------------------------------------------------------

class CryptoSecurityHardening:
    """
    Unified facade for all cryptographic security hardening features.
    
    Single entry point for all crypto security features.
    Can be instantiated and added to existing code without modification.
    """
    
    def __init__(self):
        self.memory = CryptoSecureMemory()
        self.constant_time = CryptoConstantTime()
        self.validator = CryptoInputValidator()
        self.rate_limiter = KeyOperationRateLimiter()
        self.timing = CryptoTimingResistance()
    
    def create_sensitive_key(self, key_data: bytes) -> SensitiveKeyMaterial:
        """Create auto-zeroizing container for key material."""
        return SensitiveKeyMaterial(key_data)
    
    def secure_key_compare(self, key_a: bytes, key_b: bytes) -> bool:
        """Constant-time key comparison."""
        return CryptoSecureMemory.secure_compare_constant(key_a, key_b)
    
    def validate_private_key(self, key_bytes: bytes) -> bytes:
        """Validate private key material."""
        result = self.validator.validate_key_bytes(
            key_bytes,
            min_length=32,
            check_weak_keys=True
        )
        if not result.is_valid:
            raise ValueError(f"Invalid key material: {result.error_message}")
        return result.sanitized
    
    def check_key_gen_rate_limit(self, client_id: str) -> bool:
        """Check rate limit for key generation."""
        return self.rate_limiter.check_key_generation(client_id)
    
    def check_signature_rate_limit(self, client_id: str) -> bool:
        """Check rate limit for signature operations."""
        return self.rate_limiter.check_signature(client_id)


# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------

__all__ = [
    'CryptoSecureMemory',
    'SensitiveKeyMaterial',
    'CryptoConstantTime',
    'CryptoInputValidator',
    'KeyValidationResult',
    'validate_crypto_inputs',
    'KeyOperationRateLimit',
    'KeyOperationRateLimiter',
    'CryptoTimingResistance',
    'CryptoSecurityHardening',
]
