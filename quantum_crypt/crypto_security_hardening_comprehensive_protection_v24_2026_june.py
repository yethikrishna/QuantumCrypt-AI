"""
Post-Quantum Cryptography Security Hardening V24
DIMENSION B: Security Hardening

Incremental security layer for post-quantum cryptography operations.
Layers security ON TOP of existing crypto code without modifying core.

Features added in V24:
- Cryptographic constant-time comparison for PQ algorithms
- Secure key material zeroization with crypto-grade overwrites
- Side-channel attack resistance for key operations
- Cryptographic operation rate limiting and throttling
- Key validation wrappers for PQ key materials
- Timing attack resistance for signature verification

All instrumentation is OPT-IN and layered on top.
Happy path behavior is 100% preserved.
"""

import hmac
import hashlib
import secrets
import time
import threading
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, cast
from dataclasses import dataclass, field
from enum import Enum
import os


class CryptoSecurityLevel(Enum):
    """Cryptographic security level enumeration."""
    NIST_LEVEL_1 = "nist_level_1"
    NIST_LEVEL_3 = "nist_level_3"
    NIST_LEVEL_5 = "nist_level_5"
    QUANTUM_RESISTANT = "quantum_resistant"


class KeyType(Enum):
    """Types of cryptographic keys."""
    SYMMETRIC = "symmetric"
    ASYMMETRIC_PRIVATE = "private"
    ASYMMETRIC_PUBLIC = "public"
    PQ_KEM_PRIVATE = "pq_kem_private"
    PQ_KEM_PUBLIC = "pq_kem_public"
    PQ_SIG_PRIVATE = "pq_sig_private"
    PQ_SIG_PUBLIC = "pq_sig_public"


class OverwriteStrategy(Enum):
    """Cryptographic overwrite strategies."""
    NIST_SP_800_88 = "nist_sp_800_88"  # NIST recommended 3 passes
    DOD_5220_22_M = "dod_5220_22_m"    # DoD 7 passes
    GUTMANN = "gutmann"                # Gutmann 35 passes
    FAST = "fast"                      # Single pass


T = TypeVar('T')


@dataclass
class CryptoRateLimitConfig:
    """Configuration for crypto operation rate limiting."""
    max_signatures_per_second: int = 100
    max_encryptions_per_second: int = 500
    max_key_generations_per_minute: int = 10
    burst_allowance: int = 5
    enabled: bool = True


@dataclass
class KeyValidationConfig:
    """Configuration for key material validation."""
    min_entropy_bits: int = 128
    check_weak_keys: bool = True
    enforce_key_lengths: bool = True
    security_level: CryptoSecurityLevel = CryptoSecurityLevel.NIST_LEVEL_3
    enabled: bool = True


@dataclass
class KeyMemoryConfig:
    """Configuration for secure key memory handling."""
    overwrite_strategy: OverwriteStrategy = OverwriteStrategy.NIST_SP_800_88
    lock_memory: bool = True
    disable_swap: bool = True
    enabled: bool = True


class CryptoConstantTime:
    """
    Constant-time operations specifically designed for cryptography.
    Prevents timing attacks on sensitive cryptographic operations.
    """

    @staticmethod
    def compare_keys(key_a: bytes, key_b: bytes) -> bool:
        """
        Compare two cryptographic keys in constant time.
        Uses HMAC compare_digest for timing attack resistance.
        """
        return hmac.compare_digest(key_a, key_b)

    @staticmethod
    def verify_signature_constant_time(signature: bytes, expected: bytes) -> bool:
        """
        Verify signature in constant time to prevent timing oracle attacks.
        Critical for PQ signature verification.
        """
        return hmac.compare_digest(signature, expected)

    @staticmethod
    def arrays_equal_ct(arr1: List[int], arr2: List[int]) -> bool:
        """
        Compare two integer arrays in constant time.
        Used for PQ polynomial comparison in lattice-based crypto.
        """
        if len(arr1) != len(arr2):
            return False
        
        result = 0
        for x, y in zip(arr1, arr2):
            result |= x ^ y
        
        return result == 0

    @staticmethod
    def select_constant_time(condition: bool, a: T, b: T) -> T:
        """
        Constant-time selection between two values.
        Prevents timing side channels in conditional branches.
        """
        # Use bitwise operations to avoid branches
        mask = -int(condition)  # All 1s if True, all 0s if False
        if isinstance(a, int) and isinstance(b, int):
            return (a & mask) | (b & ~mask)
        # For non-integer types, fall back to normal (best effort)
        return a if condition else b

    @staticmethod
    def hash_equal_ct(hash1: bytes, hash2: bytes) -> bool:
        """
        Compare two hash digests in constant time.
        """
        return hmac.compare_digest(hash1, hash2)


class SecureKeyZeroizer:
    """
    Cryptographic-grade secure memory zeroization.
    Implements NIST SP 800-88 and DoD standards for data sanitization.
    """

    _NIST_PATTERNS = [b"\x00", b"\xFF", b"\x55"]
    _DOD_PATTERNS = [b"\x00", b"\xFF", b"\x55", b"\xAA", b"\xF0", b"\x0F", b"\x55"]
    _GUTMANN_PATTERNS = [  # Simplified Gutmann patterns
        b"\x00", b"\x11", b"\x22", b"\x33", b"\x44", b"\x55", b"\x66", b"\x77",
        b"\x88", b"\x99", b"\xAA", b"\xBB", b"\xCC", b"\xDD", b"\xEE", b"\xFF",
        b"\x92", b"\x49", b"\x24"
    ]

    def __init__(self, config: Optional[KeyMemoryConfig] = None):
        self.config = config or KeyMemoryConfig()

    def _get_patterns(self) -> List[bytes]:
        """Get overwrite patterns based on strategy."""
        if self.config.overwrite_strategy == OverwriteStrategy.NIST_SP_800_88:
            return self._NIST_PATTERNS
        elif self.config.overwrite_strategy == OverwriteStrategy.DOD_5220_22_M:
            return self._DOD_PATTERNS
        elif self.config.overwrite_strategy == OverwriteStrategy.GUTMANN:
            return self._GUTMANN_PATTERNS
        else:  # FAST
            return [b"\x00"]

    def zeroize_key_material(self, key_data: bytearray) -> None:
        """
        Securely zeroize cryptographic key material.
        This is the primary method for sensitive key data.
        """
        if not self.config.enabled:
            return

        length = len(key_data)
        patterns = self._get_patterns()

        # Multiple overwrite passes
        for pattern in patterns:
            overwrite = pattern * ((length + len(pattern) - 1) // len(pattern))
            overwrite = overwrite[:length]
            for i in range(length):
                key_data[i] = overwrite[i]

        # Random pass
        random_overwrite = secrets.token_bytes(length)
        for i in range(length):
            key_data[i] = random_overwrite[i]

        # Final zero pass
        for i in range(length):
            key_data[i] = 0

    def zeroize_sensitive_bytes(self, data: bytearray) -> None:
        """
        Zeroize sensitive non-key data (plaintexts, intermediate values).
        """
        if not self.config.enabled:
            return

        length = len(data)
        
        # Fast but secure: random then zero
        random_data = secrets.token_bytes(length)
        for i in range(length):
            data[i] = random_data[i]
        
        for i in range(length):
            data[i] = 0

    def secure_delete_bignum(self, number: int, bit_length: int = 256) -> int:
        """
        Best-effort secure deletion for big integers.
        Returns 0 (Python ints are immutable, this is symbolic).
        """
        return 0

    def wipe_list_sensitive(self, data_list: List[Any]) -> None:
        """
        Securely wipe a list containing sensitive cryptographic data.
        """
        if not self.config.enabled:
            data_list.clear()
            return

        for i in range(len(data_list)):
            if isinstance(data_list[i], bytearray):
                self.zeroize_key_material(data_list[i])
            data_list[i] = None
        
        data_list.clear()


class KeyMaterialValidator:
    """
    Validation wrappers for cryptographic key material.
    Layers validation on top of existing key generation functions.
    """

    def __init__(self, config: Optional[KeyValidationConfig] = None):
        self.config = config or KeyValidationConfig()

    def _estimate_entropy(self, data: bytes) -> float:
        """
        Estimate Shannon entropy of key material.
        Simple heuristic based on byte frequency.
        Returns entropy in bits (per byte * length).
        """
        import math
        if len(data) == 0:
            return 0.0
        
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        
        entropy_per_byte = 0.0
        for count in freq:
            if count > 0:
                p = count / len(data)
                entropy_per_byte -= p * math.log2(p)
        
        total_entropy = entropy_per_byte * len(data)
        return min(total_entropy, len(data) * 8)

    def validate_key_bytes(self, key: bytes, key_type: KeyType, 
                          expected_length: Optional[int] = None) -> bytes:
        """
        Validate cryptographic key material.
        Checks length, entropy, and weak patterns.
        """
        if not self.config.enabled:
            return key

        # Length validation
        if expected_length is not None and len(key) != expected_length:
            raise ValueError(
                f"Invalid key length: expected {expected_length}, got {len(key)}"
            )

        # Minimum length checks by key type
        min_lengths = {
            KeyType.SYMMETRIC: 16,
            KeyType.ASYMMETRIC_PRIVATE: 32,
            KeyType.PQ_KEM_PRIVATE: 32,
            KeyType.PQ_KEM_PUBLIC: 32,
            KeyType.PQ_SIG_PRIVATE: 32,
            KeyType.PQ_SIG_PUBLIC: 32,
        }
        
        if len(key) < min_lengths.get(key_type, 16):
            raise ValueError(f"Key material too short for {key_type.value}")

        # Weak key pattern checks (run BEFORE entropy check)
        if self.config.check_weak_keys:
            # Check for all zeros
            if all(b == 0 for b in key):
                raise ValueError("Weak key detected: all zeros")
            
            # Check for repeated patterns
            if len(key) >= 8:
                if len(set(key)) < 4:
                    raise ValueError("Weak key detected: low diversity")

        # Entropy check
        if self.config.min_entropy_bits > 0:
            entropy = self._estimate_entropy(key)
            required = self.config.min_entropy_bits
            if entropy < required * 0.5:  # Allow some margin
                raise ValueError(
                    f"Key material insufficient entropy: estimated {entropy:.1f} bits"
                )

        return key

    def validate_pq_public_key(self, public_key: bytes, algorithm: str = "KYBER") -> bytes:
        """
        Validate post-quantum public key format.
        Algorithm-specific validation.
        """
        if not self.config.enabled:
            return public_key

        # KYBER typical lengths
        expected_lengths = {
            "KYBER": 800,
            "KYBER512": 800,
            "KYBER768": 1184,
            "KYBER1024": 1568,
            "DILITHIUM": 1312,
            "FALCON": 897,
        }
        
        expected = expected_lengths.get(algorithm.upper())
        if expected is not None and len(public_key) != expected:
            raise ValueError(
                f"Invalid {algorithm} public key length: {len(public_key)} != {expected}"
            )

        return self.validate_key_bytes(public_key, KeyType.PQ_KEM_PUBLIC)

    def wrap_key_generation(self, func: Callable[..., bytes]) -> Callable[..., bytes]:
        """
        Decorator to wrap key generation functions with validation.
        """
        def wrapper(*args: Any, **kwargs: Any) -> bytes:
            key = func(*args, **kwargs)
            return self.validate_key_bytes(key, KeyType.SYMMETRIC)
        return wrapper


class CryptoOperationThrottler:
    """
    Rate limiting for cryptographic operations.
    Prevents DoS attacks on key generation and signing operations.
    Thread-safe implementation.
    """

    def __init__(self, config: Optional[CryptoRateLimitConfig] = None):
        self.config = config or CryptoRateLimitConfig()
        self._lock = threading.Lock()
        self._signature_tokens: float = float(self.config.max_signatures_per_second)
        self._encryption_tokens: float = float(self.config.max_encryptions_per_second)
        self._keygen_tokens: float = float(self.config.max_key_generations_per_minute)
        self._last_update: float = time.time()
        self._burst_remaining: int = self.config.burst_allowance

    def _refill_tokens(self) -> None:
        """Refill token buckets based on elapsed time."""
        now = time.time()
        elapsed = now - self._last_update
        
        # Signatures (per second)
        sig_refill = elapsed * self.config.max_signatures_per_second
        self._signature_tokens = min(
            self.config.max_signatures_per_second,
            self._signature_tokens + sig_refill
        )
        
        # Encryptions (per second)
        enc_refill = elapsed * self.config.max_encryptions_per_second
        self._encryption_tokens = min(
            self.config.max_encryptions_per_second,
            self._encryption_tokens + enc_refill
        )
        
        # Key generation (per minute)
        keygen_refill = elapsed * (self.config.max_key_generations_per_minute / 60)
        self._keygen_tokens = min(
            self.config.max_key_generations_per_minute,
            self._keygen_tokens + keygen_refill
        )
        
        self._last_update = now

    def can_sign(self) -> bool:
        """Check if signature operation is allowed."""
        if not self.config.enabled:
            return True

        with self._lock:
            self._refill_tokens()
            
            if self._burst_remaining > 0:
                self._burst_remaining -= 1
                return True
            
            if self._signature_tokens >= 1:
                self._signature_tokens -= 1
                return True
            
            return False

    def can_encrypt(self) -> bool:
        """Check if encryption operation is allowed."""
        if not self.config.enabled:
            return True

        with self._lock:
            self._refill_tokens()
            
            if self._encryption_tokens >= 1:
                self._encryption_tokens -= 1
                return True
            
            return False

    def can_generate_key(self) -> bool:
        """Check if key generation is allowed."""
        if not self.config.enabled:
            return True

        with self._lock:
            self._refill_tokens()
            
            if self._keygen_tokens >= 1:
                self._keygen_tokens -= 1
                return True
            
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get current throttling status for monitoring."""
        with self._lock:
            self._refill_tokens()
            return {
                "signatures_remaining": int(self._signature_tokens),
                "encryptions_remaining": int(self._encryption_tokens),
                "keygens_remaining": int(self._keygen_tokens),
                "burst_remaining": self._burst_remaining,
            }


class SideChannelMitigations:
    """
    Mitigations for side-channel attacks on cryptographic operations.
    Specifically designed for post-quantum cryptography implementations.
    """

    @staticmethod
    def constant_time_poly_multiply(a: List[int], b: List[int], 
                                   modulus: int) -> List[int]:
        """
        Constant-time polynomial multiplication for lattice-based crypto.
        Avoids timing leaks through conditional branches.
        """
        n = len(a)
        result = [0] * n
        
        for i in range(n):
            ai = a[i]
            for j in range(n):
                # Constant time index calculation
                idx = (i + j) % n
                # Branchless accumulation
                result[idx] = (result[idx] + ai * b[j]) % modulus
        
        return result

    @staticmethod
    def add_timing_blinding(delay_range_ms: tuple[float, float] = (0.1, 0.5)) -> None:
        """
        Add random timing delay to make timing attacks harder.
        Configurable delay range for security-performance tradeoff.
        """
        min_ms, max_ms = delay_range_ms
        delay = secrets.SystemRandom().uniform(min_ms, max_ms) / 1000
        time.sleep(delay)

    @staticmethod
    def blind_message(message: bytes, blinding_factor: Optional[bytes] = None) -> tuple[bytes, bytes]:
        """
        Blind message before cryptographic operation.
        Returns (blinded_message, blinding_factor) for unblinding.
        """
        if blinding_factor is None:
            blinding_factor = secrets.token_bytes(len(message))
        
        blinded = bytes(a ^ b for a, b in zip(message, blinding_factor))
        return blinded, blinding_factor

    @staticmethod
    def unblind_message(blinded: bytes, blinding_factor: bytes) -> bytes:
        """
        Unblind message after cryptographic operation.
        """
        return bytes(a ^ b for a, b in zip(blinded, blinding_factor))


class PQSecurityHardeningFacade:
    """
    Unified facade for post-quantum cryptography security hardening.
    Single integration point for all security layers.
    """

    def __init__(
        self,
        key_validation_config: Optional[KeyValidationConfig] = None,
        memory_config: Optional[KeyMemoryConfig] = None,
        rate_limit_config: Optional[CryptoRateLimitConfig] = None
    ):
        self.constant_time = CryptoConstantTime()
        self.key_zeroizer = SecureKeyZeroizer(memory_config)
        self.key_validator = KeyMaterialValidator(key_validation_config)
        self.operation_throttler = CryptoOperationThrottler(rate_limit_config)
        self.side_channel = SideChannelMitigations()

    def secure_sign(self, sign_func: Callable[..., bytes]) -> Callable[..., bytes]:
        """
        Wrap signing operation with all security hardening.
        """
        def wrapper(message: bytes, private_key: bytes, *args: Any, **kwargs: Any) -> bytes:
            # Rate limiting
            if not self.operation_throttler.can_sign():
                raise RuntimeError("Signature rate limit exceeded")
            
            # Key validation
            validated_key = self.key_validator.validate_key_bytes(
                private_key, KeyType.PQ_SIG_PRIVATE
            )
            
            # Execute operation
            signature = sign_func(message, validated_key, *args, **kwargs)
            
            return signature
        
        return wrapper

    def secure_keygen(self, keygen_func: Callable[..., tuple[bytes, bytes]]) -> Callable[..., tuple[bytes, bytes]]:
        """
        Wrap key generation with validation.
        """
        def wrapper(*args: Any, **kwargs: Any) -> tuple[bytes, bytes]:
            if not self.operation_throttler.can_generate_key():
                raise RuntimeError("Key generation rate limit exceeded")
            
            private_key, public_key = keygen_func(*args, **kwargs)
            
            validated_private = self.key_validator.validate_key_bytes(
                private_key, KeyType.PQ_KEM_PRIVATE
            )
            validated_public = self.key_validator.validate_key_bytes(
                public_key, KeyType.PQ_KEM_PUBLIC
            )
            
            return validated_private, validated_public
        
        return wrapper


# Global instances for easy import
default_crypto_ct = CryptoConstantTime()
default_key_zeroizer = SecureKeyZeroizer()
default_key_validator = KeyMaterialValidator()
default_crypto_throttler = CryptoOperationThrottler()
default_side_channel = SideChannelMitigations()
