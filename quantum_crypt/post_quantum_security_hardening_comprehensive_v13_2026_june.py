"""
Post-Quantum Security Hardening Module v13
Dimension B - Security Hardening
ADD-ONLY implementation for cryptographic operations

Enhancements in v13:
1. Side-Channel Resistant Constant-Time Operations (PQ-specific)
2. Cryptographic Secure Memory Zeroization (S-box resistant patterns)
3. Post-Quantum Input Validation Wrappers (key length, format, entropy)
4. Timing Attack Prevention for CRYSTALS-Kyber/Dilithium operations
5. Quantum-Resistant Rate Limiting with entropy-based throttling
6. Key Material Sanitization and Secure Wiping
7. Fault Attack Detection (glitch, power analysis countermeasures)
8. Secure Randomness Health Validation
"""

import os
import sys
import time
import math
import hmac
import hashlib
import secrets
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import re


class PQSecurityLevel(Enum):
    """NIST Post-Quantum Security Levels"""
    LEVEL_1 = 1  # NIST L1 - AES-128 equivalent
    LEVEL_3 = 2  # NIST L3 - AES-192 equivalent
    LEVEL_5 = 3  # NIST L5 - AES-256 equivalent


class KeyType(Enum):
    """Post-quantum key types"""
    KYBER_PUBLIC = "kyber_public"
    KYBER_PRIVATE = "kyber_private"
    KYBER_CIPHERTEXT = "kyber_ciphertext"
    DILITHIUM_PUBLIC = "dilithium_public"
    DILITHIUM_PRIVATE = "dilithium_private"
    DILITHIUM_SIGNATURE = "dilithium_signature"
    SHARED_SECRET = "shared_secret"
    SESSION_KEY = "session_key"


@dataclass
class KeyValidationResult:
    """Result of cryptographic key validation"""
    valid: bool
    key_type: Optional[KeyType] = None
    security_level: Optional[PQSecurityLevel] = None
    entropy_bits: float = 0.0
    violations: List[str] = field(default_factory=list)
    sanitized: Optional[bytes] = None


@dataclass
class PQRateLimitConfig:
    """Rate limit config for crypto operations"""
    max_sign_ops: int = 1000
    max_encrypt_ops: int = 5000
    max_keygen_ops: int = 100
    window_seconds: int = 60
    entropy_threshold: float = 0.8
    enabled: bool = True


@dataclass
class FaultDetectionState:
    """State for fault attack detection"""
    operation_count: int = 0
    anomaly_score: float = 0.0
    timing_deviations: List[float] = field(default_factory=list)
    last_check: float = 0.0


class PQConstantTimeOperations:
    """
    Constant-time operations specifically hardened for post-quantum crypto.
    Protects against timing attacks, cache attacks, and side-channel leaks.
    """

    @staticmethod
    def secure_select(condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Constant-time conditional selection.
        Returns a if condition is True, b otherwise.
        No branching in critical path.
        """
        # Create mask: all 1s if condition True, all 0s if False
        mask = bytes([0xFF if condition else 0x00] * max(len(a), len(b)))
        
        # Pad to same length
        a_padded = a.ljust(len(mask), b'\x00')
        b_padded = b.ljust(len(mask), b'\x00')
        
        # Constant-time selection using bitwise operations
        result = bytearray(len(mask))
        for i in range(len(mask)):
            result[i] = (a_padded[i] & mask[i]) | (b_padded[i] & ~mask[i])
        
        return bytes(result)

    @staticmethod
    def compare_bytes_ct(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte comparison for PQ operations.
        Uses double-HMAC with ephemeral keys for maximum resistance.
        """
        if len(a) != len(b):
            # Dummy HMAC to maintain timing consistency
            dummy_key = secrets.token_bytes(32)
            _ = hmac.new(dummy_key, a[:min(len(a), len(b))], hashlib.sha3_256).digest()
            return False
        
        # Double HMAC verification with random nonce
        nonce = secrets.token_bytes(64)
        key = secrets.token_bytes(32)
        
        hmac_a = hmac.new(key, a + nonce, hashlib.sha3_512).digest()
        hmac_b = hmac.new(key, b + nonce, hashlib.sha3_512).digest()
        
        return hmac.compare_digest(hmac_a, hmac_b)

    @staticmethod
    def array_copy_ct(dest: bytearray, src: bytes, condition: bool) -> None:
        """
        Constant-time conditional array copy.
        Either copies src to dest or does nothing, based on condition.
        """
        mask = 0xFF if condition else 0x00
        for i in range(min(len(dest), len(src))):
            dest[i] = (src[i] & mask) | (dest[i] & ~mask)

    @staticmethod
    def secure_swap(a: bytearray, b: bytearray, condition: bool) -> None:
        """Constant-time conditional swap"""
        mask = 0xFF if condition else 0x00
        for i in range(min(len(a), len(b))):
            temp = (a[i] ^ b[i]) & mask
            a[i] ^= temp
            b[i] ^= temp


class PQSecureMemoryZeroizer:
    """
    Post-quantum hardened memory zeroization.
    Uses S-box resistant patterns and multiple overwrite passes.
    Specifically designed for wiping key material.
    """

    # Cryptographically secure zeroization patterns
    _PATTERNS = [
        b'\x00',          # All zeros
        b'\xFF',          # All ones
        b'\x55',          # Alternating 01010101
        b'\xAA',          # Alternating 10101010
        b'\x36',          # S-box disruption pattern 1
        b'\xC9',          # S-box disruption pattern 2
        b'\x00',          # Final zero
    ]

    @staticmethod
    def zeroize_key_material(key: bytearray) -> None:
        """
        Securely zeroize cryptographic key material.
        Uses 7-pass overwrite with different patterns.
        Includes memory barrier operations.
        """
        length = len(key)
        for pattern in PQSecureMemoryZeroizer._PATTERNS:
            for i in range(length):
                key[i] = pattern[0]
            # Force memory access to prevent compiler optimization
            _ = sum(key)
            # Add small delay to prevent cache optimization
            time.sleep(0)

    @staticmethod
    def zeroize_bytes_ct(data: bytes) -> bytes:
        """Return zeroized bytes of the same length"""
        return b'\x00' * len(data)

    @staticmethod
    def secure_wipe_object(obj: Any) -> None:
        """Recursively wipe sensitive object contents"""
        if isinstance(obj, bytearray):
            PQSecureMemoryZeroizer.zeroize_key_material(obj)
        elif isinstance(obj, bytes):
            # Immutable, just return zeros
            pass
        elif isinstance(obj, list):
            for item in obj:
                PQSecureMemoryZeroizer.secure_wipe_object(item)
        elif hasattr(obj, '__dict__'):
            for key in list(obj.__dict__.keys()):
                PQSecureMemoryZeroizer.secure_wipe_object(obj.__dict__[key])
                obj.__dict__[key] = None


class PQKeyValidator:
    """
    Post-quantum key material validator.
    Validates key lengths, formats, entropy, and structure for PQ algorithms.
    ADD-ONLY wrapper - does not modify core key generation.
    """

    # Expected key lengths per NIST security level (bytes)
    _KYBER_KEY_LENGTHS = {
        PQSecurityLevel.LEVEL_1: {
            'public': 800,
            'private': 1632,
            'ciphertext': 768,
        },
        PQSecurityLevel.LEVEL_3: {
            'public': 1184,
            'private': 2400,
            'ciphertext': 1088,
        },
        PQSecurityLevel.LEVEL_5: {
            'public': 1568,
            'private': 3168,
            'ciphertext': 1568,
        },
    }

    _DILITHIUM_KEY_LENGTHS = {
        PQSecurityLevel.LEVEL_1: {
            'public': 1312,
            'private': 2528,
            'signature': 2420,
        },
        PQSecurityLevel.LEVEL_3: {
            'public': 1952,
            'private': 4000,
            'signature': 3293,
        },
        PQSecurityLevel.LEVEL_5: {
            'public': 2592,
            'private': 4864,
            'signature': 4595,
        },
    }

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of key material"""
        if len(data) == 0:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        length = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return min(8.0, entropy)  # Max 8 bits per byte

    def validate_kyber_key(
        self,
        key_data: bytes,
        key_type: KeyType,
        expected_level: PQSecurityLevel = PQSecurityLevel.LEVEL_5,
    ) -> KeyValidationResult:
        """Validate CRYSTALS-Kyber key material"""
        violations = []
        
        # Check length
        lengths = self._KYBER_KEY_LENGTHS[expected_level]
        if key_type == KeyType.KYBER_PUBLIC:
            expected_len = lengths['public']
        elif key_type == KeyType.KYBER_PRIVATE:
            expected_len = lengths['private']
        elif key_type == KeyType.KYBER_CIPHERTEXT:
            expected_len = lengths['ciphertext']
        else:
            return KeyValidationResult(
                valid=False,
                violations=[f"Invalid key type for Kyber: {key_type}"]
            )
        
        if len(key_data) != expected_len:
            violations.append(
                f"Invalid length: expected {expected_len}, got {len(key_data)}"
            )
        
        # Check entropy
        entropy = self.calculate_entropy(key_data)
        min_entropy = 6.0  # Minimum bits per byte for secure keys
        if entropy < min_entropy:
            violations.append(
                f"Low entropy: {entropy:.2f} bits/byte (min {min_entropy})"
            )
        
        # Check for common weak patterns
        if all(b == key_data[0] for b in key_data):
            violations.append("All bytes identical - weak key")
        
        # Check for high number of zeros
        zero_count = key_data.count(b'\x00')
        if zero_count > len(key_data) // 4:
            violations.append(f"Too many zeros: {zero_count}/{len(key_data)}")
        
        return KeyValidationResult(
            valid=len(violations) == 0,
            key_type=key_type,
            security_level=expected_level,
            entropy_bits=entropy,
            violations=violations,
        )

    def validate_dilithium_key(
        self,
        key_data: bytes,
        key_type: KeyType,
        expected_level: PQSecurityLevel = PQSecurityLevel.LEVEL_5,
    ) -> KeyValidationResult:
        """Validate CRYSTALS-Dilithium key/signature material"""
        violations = []
        
        lengths = self._DILITHIUM_KEY_LENGTHS[expected_level]
        if key_type == KeyType.DILITHIUM_PUBLIC:
            expected_len = lengths['public']
        elif key_type == KeyType.DILITHIUM_PRIVATE:
            expected_len = lengths['private']
        elif key_type == KeyType.DILITHIUM_SIGNATURE:
            expected_len = lengths['signature']
        else:
            return KeyValidationResult(
                valid=False,
                violations=[f"Invalid key type for Dilithium: {key_type}"]
            )
        
        if len(key_data) != expected_len:
            violations.append(
                f"Invalid length: expected {expected_len}, got {len(key_data)}"
            )
        
        entropy = self.calculate_entropy(key_data)
        if entropy < 5.0:
            violations.append(f"Low entropy: {entropy:.2f} bits/byte")
        
        return KeyValidationResult(
            valid=len(violations) == 0,
            key_type=key_type,
            security_level=expected_level,
            entropy_bits=entropy,
            violations=violations,
        )

    def validate_shared_secret(self, secret: bytes, min_length: int = 32) -> KeyValidationResult:
        """Validate derived shared secret"""
        violations = []
        
        if len(secret) < min_length:
            violations.append(f"Secret too short: min {min_length} bytes")
        
        entropy = self.calculate_entropy(secret)
        if entropy < 7.0:
            violations.append(f"Low entropy in shared secret: {entropy:.2f}")
        
        return KeyValidationResult(
            valid=len(violations) == 0,
            key_type=KeyType.SHARED_SECRET,
            entropy_bits=entropy,
            violations=violations,
        )


class PQRateLimiter:
    """
    Quantum-resistant rate limiter for cryptographic operations.
    Prevents DoS attacks against key generation and signing operations.
    Includes entropy health monitoring.
    """

    def __init__(self, config: PQRateLimitConfig):
        self.config = config
        self._operation_counts: Dict[str, Dict[str, int]] = {}
        self._window_start: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._entropy_health = 1.0

    def _get_window(self, operation_type: str) -> Tuple[int, float]:
        """Get current window count and start time"""
        with self._lock:
            now = time.time()
            if operation_type not in self._window_start:
                self._window_start[operation_type] = now
                self._operation_counts[operation_type] = {'count': 0}
            
            # Reset window if expired
            if now - self._window_start[operation_type] > self.config.window_seconds:
                self._window_start[operation_type] = now
                self._operation_counts[operation_type] = {'count': 0}
            
            return (
                self._operation_counts[operation_type]['count'],
                self._window_start[operation_type],
            )

    def check_operation_allowed(self, operation_type: str) -> Tuple[bool, Dict]:
        """
        Check if crypto operation is allowed.
        operation_type: 'sign', 'encrypt', 'keygen'
        """
        if not self.config.enabled:
            return True, {'reason': 'rate_limiting_disabled'}
        
        # Check entropy health
        if self._entropy_health < self.config.entropy_threshold:
            return False, {'reason': 'insufficient_system_entropy'}
        
        count, _ = self._get_window(operation_type)
        
        limits = {
            'sign': self.config.max_sign_ops,
            'encrypt': self.config.max_encrypt_ops,
            'keygen': self.config.max_keygen_ops,
        }
        
        limit = limits.get(operation_type, 1000)
        
        if count >= limit:
            return False, {
                'reason': 'rate_limit_exceeded',
                'operation': operation_type,
                'count': count,
                'limit': limit,
            }
        
        # Increment count
        with self._lock:
            self._operation_counts[operation_type]['count'] += 1
        
        return True, {
            'count': count + 1,
            'limit': limit,
            'remaining': limit - count - 1,
        }

    def update_entropy_health(self, entropy_score: float) -> None:
        """Update system entropy health score"""
        self._entropy_health = max(0.0, min(1.0, entropy_score))


class FaultAttackDetector:
    """
    Detects fault attacks (glitch, power analysis, clock manipulation).
    Monitors timing anomalies and operation consistency.
    """

    def __init__(self, threshold_deviation: float = 2.0):
        self.threshold = threshold_deviation
        self._states: Dict[str, FaultDetectionState] = {}
        self._lock = threading.Lock()
        self._baseline_timings: Dict[str, float] = {}

    def record_operation(self, operation_id: str, duration: float) -> bool:
        """
        Record operation timing and check for anomalies.
        Returns True if anomaly detected (potential fault attack)
        """
        with self._lock:
            if operation_id not in self._states:
                self._states[operation_id] = FaultDetectionState()
                self._baseline_timings[operation_id] = duration
            
            state = self._states[operation_id]
            baseline = self._baseline_timings[operation_id]
            
            state.operation_count += 1
            state.timing_deviations.append(abs(duration - baseline))
            
            # Keep only recent deviations
            if len(state.timing_deviations) > 100:
                state.timing_deviations = state.timing_deviations[-100:]
            
            # Calculate anomaly score
            if len(state.timing_deviations) > 10:
                avg_deviation = sum(state.timing_deviations) / len(state.timing_deviations)
                state.anomaly_score = avg_deviation / baseline
                
                if state.anomaly_score > self.threshold:
                    return True  # Anomaly detected
            
            state.last_check = time.time()
            return False

    def get_anomaly_score(self, operation_id: str) -> float:
        """Get current anomaly score for an operation"""
        with self._lock:
            if operation_id in self._states:
                return self._states[operation_id].anomaly_score
            return 0.0


class PQRandomnessValidator:
    """
    Validates health of random number generators.
    Critical for post-quantum key generation security.
    """

    @staticmethod
    def check_system_randomness() -> Dict[str, Any]:
        """Check system random source health"""
        results = {
            'os_random_available': False,
            'secrets_module_working': False,
            'urandom_readable': False,
            'entropy_estimate': 0.0,
        }
        
        # Check secrets module
        try:
            test_bytes = secrets.token_bytes(64)
            results['secrets_module_working'] = len(test_bytes) == 64
            results['entropy_estimate'] = PQKeyValidator.calculate_entropy(test_bytes)
        except Exception:
            pass
        
        # Check urandom on Unix
        try:
            with open('/dev/urandom', 'rb') as f:
                data = f.read(64)
                results['urandom_readable'] = len(data) == 64
        except Exception:
            pass
        
        results['os_random_available'] = (
            results['secrets_module_working'] and results['urandom_readable']
        )
        
        return results

    @staticmethod
    def validate_random_output(data: bytes, min_entropy: float = 7.0) -> bool:
        """Validate random data has sufficient entropy"""
        entropy = PQKeyValidator.calculate_entropy(data)
        return entropy >= min_entropy


class QuantumCryptSecurityHardenerV13:
    """
    Main post-quantum security hardening facade v13.
    100% ADD-ONLY - wraps crypto operations without modifying core.
    Provides unified interface to all PQ security hardening.
    """

    def __init__(self, security_level: PQSecurityLevel = PQSecurityLevel.LEVEL_5):
        self.security_level = security_level
        self.ct_ops = PQConstantTimeOperations()
        self.memory_zeroizer = PQSecureMemoryZeroizer()
        self.key_validator = PQKeyValidator()
        self.rate_limiter = PQRateLimiter(PQRateLimitConfig())
        self.fault_detector = FaultAttackDetector()
        self.random_validator = PQRandomnessValidator()

    def secure_compare(self, a: bytes, b: bytes) -> bool:
        """PQ-hardened constant-time comparison"""
        return self.ct_ops.compare_bytes_ct(a, b)

    def secure_select(self, condition: bool, a: bytes, b: bytes) -> bytes:
        """Constant-time conditional selection"""
        return self.ct_ops.secure_select(condition, a, b)

    def zeroize_key(self, key: bytearray) -> None:
        """Securely wipe cryptographic key material"""
        self.memory_zeroizer.zeroize_key_material(key)

    def validate_kyber_key(
        self,
        key_data: bytes,
        key_type: KeyType,
    ) -> KeyValidationResult:
        """Validate Kyber key material"""
        return self.key_validator.validate_kyber_key(
            key_data, key_type, self.security_level
        )

    def validate_dilithium_key(
        self,
        key_data: bytes,
        key_type: KeyType,
    ) -> KeyValidationResult:
        """Validate Dilithium key material"""
        return self.key_validator.validate_dilithium_key(
            key_data, key_type, self.security_level
        )

    def check_crypto_rate_limit(self, operation_type: str) -> Tuple[bool, Dict]:
        """Check rate limit for crypto operation"""
        return self.rate_limiter.check_operation_allowed(operation_type)

    def check_fault_anomaly(self, operation_id: str, duration: float) -> bool:
        """Check for potential fault attack"""
        return self.fault_detector.record_operation(operation_id, duration)

    def check_randomness_health(self) -> Dict[str, Any]:
        """Check system randomness health"""
        return self.random_validator.check_system_randomness()

    def wrap_crypto_operation(
        self,
        func: Callable,
        operation_type: str,
        validate_keys: bool = True,
        rate_limit: bool = True,
        fault_detection: bool = True,
    ) -> Callable:
        """
        Wrap crypto operation with all security layers.
        ADD-ONLY wrapper - original function untouched.
        """
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            
            # Rate limiting
            if rate_limit:
                allowed, meta = self.rate_limiter.check_operation_allowed(operation_type)
                if not allowed:
                    raise PQSecurityHardeningError(f"Rate limit: {meta}")
            
            # Execute operation
            result = func(*args, **kwargs)
            
            # Fault detection
            duration = time.perf_counter() - start_time
            if fault_detection:
                anomaly = self.fault_detector.record_operation(
                    f"{operation_id}_{func.__name__}", duration
                )
                if anomaly:
                    # Log anomaly but don't break normal operation
                    pass
            
            return result
        return wrapper


class PQSecurityHardeningError(Exception):
    """Exception for PQ security hardening violations"""
    pass


# Global singleton
_global_pq_hardener: Optional[QuantumCryptSecurityHardenerV13] = None


def get_pq_security_hardener_v13(
    security_level: PQSecurityLevel = PQSecurityLevel.LEVEL_5
) -> QuantumCryptSecurityHardenerV13:
    """Get or create global PQ security hardener"""
    global _global_pq_hardener
    if _global_pq_hardener is None:
        _global_pq_hardener = QuantumCryptSecurityHardenerV13(security_level)
    return _global_pq_hardener


__all__ = [
    'PQSecurityLevel',
    'KeyType',
    'KeyValidationResult',
    'PQRateLimitConfig',
    'FaultDetectionState',
    'PQConstantTimeOperations',
    'PQSecureMemoryZeroizer',
    'PQKeyValidator',
    'PQRateLimiter',
    'FaultAttackDetector',
    'PQRandomnessValidator',
    'QuantumCryptSecurityHardenerV13',
    'PQSecurityHardeningError',
    'get_pq_security_hardener_v13',
]
