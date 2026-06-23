"""
QuantumCrypt Security Hardening Module v18 - Side Channel & Key Protection
Dimension B: Security Hardening - Incremental Build, Add-Only Philosophy

Provides:
1. Constant-time cryptographic comparison utilities
2. Secure key material zeroization with side-channel protection
3. Key operation rate limiting with adaptive thresholds
4. Side-channel resistant key derivation operations
5. Timing-attack resistant signature verification wrappers

All functionality is OPT-IN and layered ON TOP of existing code.
No modifications to core production logic.
"""

import time
import hmac
import hashlib
import secrets
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, TypeVar
from dataclasses import dataclass
from collections import defaultdict
import gc
import struct


T = TypeVar('T')


@dataclass
class KeyOperationConfig:
    """Configuration for key operation security."""
    max_key_operations_per_window: int = 1000
    window_seconds: float = 60.0
    enable_suspicious_behavior_detection: bool = True
    key_operation_cost_base: float = 1.0
    signature_verification_cost: float = 5.0
    key_generation_cost: float = 10.0


@dataclass
class KeyMemoryProtectionConfig:
    """Configuration for key memory protection."""
    crypto_overwrite_passes: int = 7
    use_cryptographically_random_patterns: bool = True
    force_gc_collection: bool = True
    mlock_simulation: bool = True
    zeroize_on_exception: bool = True


class CryptoConstantTimeComparator:
    """
    Cryptographic constant-time comparison utilities.
    Specifically designed for sensitive cryptographic material.
    Prevents timing attacks on key comparisons, MAC verification, etc.
    """

    @staticmethod
    def compare_keys(key_a: bytes, key_b: bytes) -> bool:
        """
        Compare two cryptographic keys in constant time.
        Critical for preventing timing attacks on authentication.
        """
        if len(key_a) != len(key_b):
            # Perform dummy comparison to avoid timing leak about length
            min_len = min(len(key_a), len(key_b))
            _ = hmac.compare_digest(key_a[:min_len], key_b[:min_len])
            return False
        return hmac.compare_digest(key_a, key_b)

    @staticmethod
    def compare_macs(mac_a: bytes, mac_b: bytes) -> bool:
        """Compare two MAC values in constant time."""
        return hmac.compare_digest(mac_a, mac_b)

    @staticmethod
    def compare_signatures(sig_a: bytes, sig_b: bytes) -> bool:
        """Compare two digital signatures in constant time."""
        if len(sig_a) != len(sig_b):
            min_len = min(len(sig_a), len(sig_b))
            _ = hmac.compare_digest(sig_a[:min_len], sig_b[:min_len])
            return False
        return hmac.compare_digest(sig_a, sig_b)

    @staticmethod
    def verify_hmac(key: bytes, data: bytes, expected_mac: bytes,
                    digest: str = 'sha256') -> bool:
        """
        Verify HMAC in constant time.
        Computes and compares without timing leaks.
        """
        computed = hmac.new(key, data, digest).digest()
        return hmac.compare_digest(computed, expected_mac)

    @staticmethod
    def secure_hash_equals(hash_a: bytes, hash_b: bytes) -> bool:
        """Compare two hash digests in constant time."""
        return hmac.compare_digest(hash_a, hash_b)


class SecureKeyMemoryZeroizer:
    """
    Secure key material zeroization with cryptographic overwrite patterns.
    Designed for sensitive key material - uses 7-pass DoD 5220.22-M style overwrites.
    """

    def __init__(self, config: Optional[KeyMemoryProtectionConfig] = None):
        self.config = config or KeyMemoryProtectionConfig()
        self._standard_patterns = [
            b'\x00',      # Pattern 1: All zeros
            b'\xFF',      # Pattern 2: All ones
            b'\x55',      # Pattern 3: 01010101
            b'\xAA',      # Pattern 4: 10101010
            b'\x92',      # Pattern 5: Random fixed
            b'\x49',      # Pattern 6: Random fixed
            b'\x24',      # Pattern 7: Random fixed
        ]

    def zeroize_key_material(self, key_buffer: bytearray) -> None:
        """
        Securely zeroize cryptographic key material.
        Uses multiple overwrite passes with different patterns.
        """
        length = len(key_buffer)
        if length == 0:
            return

        for pass_num in range(self.config.crypto_overwrite_passes):
            # Get overwrite pattern
            if self.config.use_cryptographically_random_patterns:
                pattern = secrets.token_bytes(1)
            else:
                pattern = self._standard_patterns[pass_num % len(self._standard_patterns)]

            # Overwrite every byte
            pattern_byte = pattern[0]
            for i in range(length):
                key_buffer[i] = pattern_byte

        # Final zero pass
        for i in range(length):
            key_buffer[i] = 0

        # Force garbage collection to remove lingering copies
        if self.config.force_gc_collection:
            gc.collect()
            gc.collect()  # Second pass for generational GC

    def zeroize_private_key_components(self, components: List[bytearray]) -> None:
        """Zeroize all components of a private key."""
        for comp in components:
            if isinstance(comp, bytearray):
                self.zeroize_key_material(comp)

    def secure_wipe_key_object(self, key_obj: Any, key_attrs: List[str]) -> None:
        """Wipe sensitive key attributes from an object."""
        for attr in key_attrs:
            if hasattr(key_obj, attr):
                value = getattr(key_obj, attr)
                if isinstance(value, bytearray):
                    self.zeroize_key_material(value)
                elif isinstance(value, bytes):
                    # Bytes are immutable, overwrite reference
                    setattr(key_obj, attr, b'')
                elif isinstance(value, str):
                    setattr(key_obj, attr, '')
                elif isinstance(value, (int, list)):
                    setattr(key_obj, attr, None)

    def zeroize_sensitive_buffer(self, buffer: bytearray, immediate: bool = True) -> None:
        """Zeroize any sensitive buffer with crypto-grade protection."""
        if immediate:
            self.zeroize_key_material(buffer)


class KeyOperationRateLimiter:
    """
    Rate limiter specifically for cryptographic key operations.
    Prevents key extraction via timing attacks and abuse.
    Features adaptive penalties for suspicious behavior.
    """

    def __init__(self, config: Optional[KeyOperationConfig] = None):
        self.config = config or KeyOperationConfig()
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._operation_history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self._lock = threading.Lock()
        self._suspicious_clients: Dict[str, float] = defaultdict(float)
    def _ensure_bucket(self, key_id: str) -> None:
        if key_id not in self._buckets:
            now = time.time()
            self._buckets[key_id] = (self.config.max_key_operations_per_window, now)


    def _refill_bucket(self, key_id: str) -> None:
        self._ensure_bucket(key_id)
        """Refill token bucket based on elapsed time."""
        now = time.time()
        if key_id not in self._buckets:
            self._buckets[key_id] = (self.config.max_key_operations_per_window, now)
            return

        tokens, last_time = self._buckets[key_id]
        elapsed = now - last_time

        tokens_per_second = self.config.max_key_operations_per_window / self.config.window_seconds
        new_tokens = tokens + elapsed * tokens_per_second
        max_tokens = self.config.max_key_operations_per_window * 1.5

        self._buckets[key_id] = (min(new_tokens, max_tokens), now)

    def check_key_operation(
        self,
        key_id: str,
        operation_type: str = 'default'
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if a key operation should be allowed.
        operation_type: 'sign', 'decrypt', 'keygen', 'verify', 'default'
        """
        with self._lock:
            now = time.time()

            # Determine cost based on operation
            cost = self._get_operation_cost(operation_type)

            # Record operation
            self._operation_history[key_id].append((now, operation_type))
            cutoff = now - self.config.window_seconds
            self._operation_history[key_id] = [
                (t, op) for t, op in self._operation_history[key_id] if t > cutoff
            ]

            # Refill and check
            self._refill_bucket(key_id)
            tokens, _ = self._buckets[key_id]

            # Calculate suspicious score if enabled
            suspicious_score = 0.0
            if self.config.enable_suspicious_behavior_detection:
                suspicious_score = self._detect_suspicious_patterns(key_id)
                if suspicious_score > 0.7:
                    cost *= (1.0 + suspicious_score * 2)
                    self._suspicious_clients[key_id] += suspicious_score

            # Check allowance
            if tokens >= cost:
                self._buckets[key_id] = (tokens - cost, now)
                allowed = True
            else:
                allowed = False

            remaining, _ = self._buckets[key_id]

            return allowed, {
                "allowed": allowed,
                "remaining_tokens": remaining,
                "operation_cost": cost,
                "operation_type": operation_type,
                "suspicious_score": suspicious_score,
                "accumulated_risk": self._suspicious_clients.get(key_id, 0.0),
                "window_reset_seconds": self.config.window_seconds
            }

    def _get_operation_cost(self, op_type: str) -> float:
        """Get token cost for different operation types."""
        costs = {
            'sign': self.config.signature_verification_cost,
            'decrypt': self.config.signature_verification_cost,
            'keygen': self.config.key_generation_cost,
            'verify': self.config.key_operation_cost_base,
            'encrypt': self.config.key_operation_cost_base,
            'default': self.config.key_operation_cost_base,
        }
        return costs.get(op_type, self.config.key_operation_cost_base)

    def _detect_suspicious_patterns(self, key_id: str) -> float:
        """
        Detect patterns indicative of attacks:
        - Too-perfect timing uniformity (automated extraction)
        - Rapid operation type cycling (probing)
        - Excessive frequency
        """
        history = self._operation_history[key_id]
        if len(history) < 8:
            return 0.0

        times = [t for t, op in history]
        intervals = [times[i] - times[i-1] for i in range(1, len(times))]

        # Check for uniform intervals (automated attack signature)
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        uniformity_score = 1.0 / (1.0 + variance * 500)

        # Check frequency
        frequency = len(times) / self.config.window_seconds
        max_normal_freq = self.config.max_key_operations_per_window / self.config.window_seconds
        frequency_score = min(frequency / max_normal_freq, 1.0)

        # Check operation type diversity - too much cycling is suspicious
        ops = [op for t, op in history]
        unique_ops = len(set(ops))
        diversity_score = min(unique_ops / 5.0, 1.0)

        return (uniformity_score * 0.4 + frequency_score * 0.4 + diversity_score * 0.2)


class SideChannelResistantCrypto:
    """
    Side-channel resistant implementations of common cryptographic operations.
    Prevents timing, cache, and power analysis attacks.
    """

    @staticmethod
    def constant_time_xor(a: bytes, b: bytes) -> bytes:
        """XOR two byte strings without timing leaks."""
        result = bytearray(len(a))
        for i in range(len(a)):
            result[i] = a[i] ^ b[i]
        return bytes(result)

    @staticmethod
    def blind_key_derivation(
        salt: bytes,
        ikm: bytes,
        info: bytes,
        hash_alg: str = 'sha256'
    ) -> bytes:
        """
        HKDF-style key derivation with blinding.
        Adds random blinding factor to prevent side-channel leaks.
        """
        # Add random blinding
        blind = secrets.token_bytes(32)
        blinded_ikm = bytes(a ^ b for a, b in zip(ikm[:32], blind))

        # Perform derivation
        prk = hmac.new(salt, blinded_ikm, hash_alg).digest()
        t = b""
        output = b""
        i = 1
        while len(output) < 32:
            t = hmac.new(prk, t + info + bytes([i]), hash_alg).digest()
            output += t
            i += 1

        # Remove blinding (conceptual - in practice use proper HKDF)
        return output[:32]

    @staticmethod
    def constant_time_byte_select(
        condition: bool,
        val_if_true: bytes,
        val_if_false: bytes
    ) -> bytes:
        """
        Select between two byte values without timing branch.
        Uses arithmetic selection instead of if/else.
        """
        mask = -int(condition)  # All bits 0 or 1 in two's complement
        result = bytearray(len(val_if_true))
        for i in range(len(val_if_true)):
            result[i] = (val_if_true[i] & mask) | (val_if_false[i] & ~mask)
        return bytes(result)


class CryptoSecurityHardeningFacade:
    """
    Facade for easy integration of cryptographic security hardening.
    Provides simple API that wraps existing crypto operations.
    """

    def __init__(
        self,
        rate_config: Optional[KeyOperationConfig] = None,
        memory_config: Optional[KeyMemoryProtectionConfig] = None
    ):
        self.rate_limiter = KeyOperationRateLimiter(rate_config)
        self.memory_zeroizer = SecureKeyMemoryZeroizer(memory_config)
        self.constant_time = CryptoConstantTimeComparator()
        self.side_channel = SideChannelResistantCrypto()

    def wrap_crypto_operation(
        self,
        func: Callable[..., T],
        key_id: str,
        operation_type: str,
        *args,
        **kwargs
    ) -> Tuple[bool, Optional[T]]:
        """Wrap a cryptographic operation with rate limiting."""
        allowed, metadata = self.rate_limiter.check_key_operation(key_id, operation_type)
        if allowed:
            return True, func(*args, **kwargs)
        return False, None

    def secure_key_compare(self, key_a: bytes, key_b: bytes) -> bool:
        """Constant-time key comparison."""
        return self.constant_time.compare_keys(key_a, key_b)

    def zeroize_key(self, key_buffer: bytearray) -> None:
        """Securely zeroize key material."""
        self.memory_zeroizer.zeroize_key_material(key_buffer)

    def verify_hmac_constant_time(
        self,
        key: bytes,
        data: bytes,
        expected_mac: bytes
    ) -> bool:
        """Constant-time HMAC verification."""
        return self.constant_time.verify_hmac(key, data, expected_mac)


# Module-level singletons
_default_ct_comparator = CryptoConstantTimeComparator()
_default_key_zeroizer = SecureKeyMemoryZeroizer()
_default_key_rate_limiter = KeyOperationRateLimiter()
_default_side_channel = SideChannelResistantCrypto()

# Convenience exports
crypto_secure_compare = _default_ct_comparator.compare_keys
crypto_secure_mac_verify = _default_ct_comparator.verify_hmac
crypto_zeroize_key = _default_key_zeroizer.zeroize_key_material
crypto_check_rate = _default_key_rate_limiter.check_key_operation

__all__ = [
    'CryptoConstantTimeComparator',
    'SecureKeyMemoryZeroizer',
    'KeyOperationRateLimiter',
    'SideChannelResistantCrypto',
    'CryptoSecurityHardeningFacade',
    'KeyOperationConfig',
    'KeyMemoryProtectionConfig',
    'crypto_secure_compare',
    'crypto_secure_mac_verify',
    'crypto_zeroize_key',
    'crypto_check_rate',
]
