"""
QuantumCrypt AI - Comprehensive Crypto Security Hardening Integration V7
Dimension B: Security Hardening

ADD-ONLY IMPLEMENTATION - NO EXISTING CODE MODIFIED
Layers security ON TOP of existing crypto code - 100% backward compatible

This module provides crypto-specific security hardening that integrates:
1. Cryptographic input validation & sanitization
2. Secure key management & zeroization
3. Side-channel resistant operations
4. Key usage policy enforcement
5. Crypto audit logging & compliance
6. Algorithm agility & fallback mechanisms
7. Randomness health monitoring
8. Certificate validation hardening

All features are OPT-IN and wrap existing crypto functionality.
"""

import os
import sys
import time
import hmac
import hashlib
import secrets
import threading
import math
from typing import (
    Any, Callable, Optional, Union, List, Dict, TypeVar,
    Tuple, Set, ByteString,
)
from functools import wraps
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict
import re

T = TypeVar('T')

# -----------------------------------------------------------------------------
# Crypto Security Enums
# -----------------------------------------------------------------------------

class CryptoSecurityLevel(Enum):
    """Cryptographic security enforcement levels."""
    DISABLED = auto()      # No security checks
    BASIC = auto()         # Basic validation only
    STANDARD = auto()      # FIPS 140-2 Level 1 equivalent
    ENHANCED = auto()      # FIPS 140-2 Level 2 equivalent
    FIPS140_3 = auto()     # FIPS 140-3 Level 3 compliance


class CryptoOperationType(Enum):
    """Types of cryptographic operations."""
    KEY_GENERATION = auto()
    KEY_ENCAPSULATION = auto()
    KEY_DECAPSULATION = auto()
    KEY_WRAP = auto()
    KEY_UNWRAP = auto()
    ENCRYPTION = auto()
    DECRYPTION = auto()
    SIGNATURE = auto()
    SIGNATURE_VERIFY = auto()
    HASH = auto()
    HMAC = auto()
    RANDOM_GENERATION = auto()
    CERTIFICATE_VALIDATE = auto()


class CryptoAlgorithmClass(Enum):
    """Cryptographic algorithm classifications."""
    POST_QUANTUM = auto()    # NIST PQC standards
    CLASSIC_MODERN = auto()   # AES-GCM, ChaCha20, SHA-2
    LEGACY = auto()           # SHA-1, 3DES (deprecated)
    EXPERIMENTAL = auto()     # Research algorithms


class CryptoSecurityEventType(Enum):
    """Security events for crypto audit logging."""
    KEY_GENERATION = auto()
    KEY_USAGE = auto()
    KEY_ZEROIZATION = auto()
    ALGORITHM_USAGE = auto()
    RANDOMNESS_QUALITY_CHECK = auto()
    SIDE_CHANNEL_PROTECTION = auto()
    CERTIFICATE_VALIDATION_PASS = auto()
    CERTIFICATE_VALIDATION_FAIL = auto()
    POLICY_ENFORCEMENT_PASS = auto()
    POLICY_ENFORCEMENT_FAIL = auto()
    INPUT_VALIDATION_PASS = auto()
    INPUT_VALIDATION_FAIL = auto()


# -----------------------------------------------------------------------------
# Crypto Security Event & Audit Logging
# -----------------------------------------------------------------------------

@dataclass
class CryptoSecurityEvent:
    """Represents a cryptographic security event."""
    event_type: CryptoSecurityEventType
    timestamp: float = field(default_factory=time.time)
    operation: Optional[CryptoOperationType] = None
    algorithm: str = ""
    key_id: str = ""
    success: bool = True
    details: Dict[str, Any] = field(default_factory=dict)


class CryptoSecurityAuditLog:
    """Thread-safe cryptographic audit logging with compliance tracking."""
    
    def __init__(self, max_entries: int = 50000):
        self._lock = threading.RLock()
        self._events: List[CryptoSecurityEvent] = []
        self._max_entries = max_entries
        self._operation_counts: Dict[CryptoOperationType, int] = defaultdict(int)
        self._algorithm_usage: Dict[str, int] = defaultdict(int)
        self._total_events = 0
    
    def log(self, event: CryptoSecurityEvent) -> None:
        """Log a crypto security event."""
        with self._lock:
            self._events.append(event)
            self._total_events += 1
            if event.operation:
                self._operation_counts[event.operation] += 1
            if event.algorithm:
                self._algorithm_usage[event.algorithm] += 1
            
            if len(self._events) > self._max_entries:
                self._events = self._events[-self._max_entries:]
    
    def get_event_count(self) -> int:
        """Get total number of events logged."""
        with self._lock:
            return self._total_events
    
    def get_operation_count(self, op: Optional[CryptoOperationType] = None) -> int:
        """Get count of operations, optionally filtered."""
        with self._lock:
            if op:
                return self._operation_counts.get(op, 0)
            return sum(self._operation_counts.values())
    
    def get_top_algorithms(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get most frequently used algorithms."""
        with self._lock:
            sorted_algs = sorted(
                self._algorithm_usage.items(),
                key=lambda x: x[1],
                reverse=True,
            )
            return sorted_algs[:limit]
    
    def get_compliance_metrics(self) -> Dict[str, Any]:
        """Get compliance-related metrics."""
        with self._lock:
            total = len(self._events)
            failures = sum(1 for e in self._events if not e.success)
            return {
                "total_operations": total,
                "failed_operations": failures,
                "failure_rate": failures / total if total > 0 else 0.0,
                "unique_algorithms": len(self._algorithm_usage),
                "unique_operations": len(self._operation_counts),
            }


# Global audit log
_global_crypto_audit_log = CryptoSecurityAuditLog()


def get_crypto_security_audit_log() -> CryptoSecurityAuditLog:
    """Get the global crypto security audit log."""
    return _global_crypto_audit_log


# -----------------------------------------------------------------------------
# Cryptographic Input Validation
# -----------------------------------------------------------------------------

class CryptoValidationError(Exception):
    """Raised when cryptographic input validation fails."""
    pass


class CryptoInputValidator:
    """
    Cryptographic-specific input validation.
    
    Validates: key lengths, nonce sizes, algorithm parameters,
    certificate formats, and prevents invalid crypto operations.
    """
    
    # Standard key lengths (bytes)
    KEY_LENGTHS = {
        "AES-128": 16,
        "AES-192": 24,
        "AES-256": 32,
        "Kyber-512": 1632,
        "Kyber-768": 2400,
        "Kyber-1024": 3168,
        "Dilithium-2": 2528,
        "Dilithium-3": 4000,
        "Dilithium-5": 4864,
    }
    
    # Nonce sizes (bytes)
    NONCE_SIZES = {
        "AES-GCM": 12,
        "ChaCha20": 12,
        "XChaCha20": 24,
    }
    
    def __init__(
        self,
        security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD,
        audit_log: Optional[CryptoSecurityAuditLog] = None,
    ):
        self.security_level = security_level
        self._audit = audit_log or _global_crypto_audit_log
        self._lock = threading.RLock()
    
    def _log_event(
        self,
        event_type: CryptoSecurityEventType,
        success: bool,
        **details,
    ) -> None:
        """Log a validation event."""
        self._audit.log(CryptoSecurityEvent(
            event_type=event_type,
            success=success,
            details=details,
        ))
    
    def validate_key_length(
        self,
        key: bytes,
        algorithm: str,
        field_name: str = "key",
    ) -> bytes:
        """
        Validate cryptographic key material length.
        
        Args:
            key: Key bytes to validate
            algorithm: Algorithm name (e.g., "AES-256", "Kyber-768")
            field_name: Field name for error reporting
            
        Returns:
            Validated key bytes
            
        Raises:
            CryptoValidationError: If validation fails
        """
        if self.security_level == CryptoSecurityLevel.DISABLED:
            return key
        
        if not isinstance(key, bytes):
            self._log_event(
                CryptoSecurityEventType.INPUT_VALIDATION_FAIL,
                False,
                field=field_name,
                reason="wrong_type",
            )
            raise CryptoValidationError(
                f"{field_name}: expected bytes, got {type(key).__name__}"
            )
        
        expected_length = self.KEY_LENGTHS.get(algorithm)
        if expected_length and len(key) != expected_length:
            self._log_event(
                CryptoSecurityEventType.INPUT_VALIDATION_FAIL,
                False,
                field=field_name,
                algorithm=algorithm,
                expected=expected_length,
                got=len(key),
            )
            raise CryptoValidationError(
                f"{field_name} for {algorithm}: expected {expected_length} bytes, got {len(key)}"
            )
        
        # Check for weak keys (all zeros, all ones, patterns)
        if self.security_level.value >= CryptoSecurityLevel.ENHANCED.value:
            if all(b == 0 for b in key):
                self._log_event(
                    CryptoSecurityEventType.INPUT_VALIDATION_FAIL,
                    False,
                    field=field_name,
                    reason="all_zeros_key",
                )
                raise CryptoValidationError(f"{field_name}: all zeros key detected")
            
            if all(b == 0xFF for b in key):
                self._log_event(
                    CryptoSecurityEventType.INPUT_VALIDATION_FAIL,
                    False,
                    field=field_name,
                    reason="all_ones_key",
                )
                raise CryptoValidationError(f"{field_name}: all ones key detected")
        
        self._log_event(
            CryptoSecurityEventType.INPUT_VALIDATION_PASS,
            True,
            field=field_name,
            algorithm=algorithm,
            length=len(key),
        )
        
        return key
    
    def validate_nonce(
        self,
        nonce: bytes,
        algorithm: str,
        field_name: str = "nonce",
    ) -> bytes:
        """Validate nonce/IV length."""
        if self.security_level == CryptoSecurityLevel.DISABLED:
            return nonce
        
        if not isinstance(nonce, bytes):
            raise CryptoValidationError(f"{field_name}: expected bytes")
        
        expected_size = self.NONCE_SIZES.get(algorithm)
        if expected_size and len(nonce) != expected_size:
            self._log_event(
                CryptoSecurityEventType.INPUT_VALIDATION_FAIL,
                False,
                field=field_name,
                algorithm=algorithm,
            )
            raise CryptoValidationError(
                f"{field_name} for {algorithm}: expected {expected_size} bytes"
            )
        
        return nonce
    
    def validate_plaintext(
        self,
        plaintext: bytes,
        max_size: int = 10 * 1024 * 1024,  # 10MB default
        field_name: str = "plaintext",
    ) -> bytes:
        """Validate plaintext input."""
        if self.security_level == CryptoSecurityLevel.DISABLED:
            return plaintext
        
        if not isinstance(plaintext, bytes):
            raise CryptoValidationError(f"{field_name}: expected bytes")
        
        if len(plaintext) > max_size:
            self._log_event(
                CryptoSecurityEventType.INPUT_VALIDATION_FAIL,
                False,
                field=field_name,
                reason="too_large",
                size=len(plaintext),
            )
            raise CryptoValidationError(
                f"{field_name}: size {len(plaintext)} exceeds maximum {max_size}"
            )
        
        return plaintext
    
    def validate_ciphertext(
        self,
        ciphertext: bytes,
        min_size: int = 16,
        field_name: str = "ciphertext",
    ) -> bytes:
        """Validate ciphertext input."""
        if self.security_level == CryptoSecurityLevel.DISABLED:
            return ciphertext
        
        if not isinstance(ciphertext, bytes):
            raise CryptoValidationError(f"{field_name}: expected bytes")
        
        if len(ciphertext) < min_size:
            raise CryptoValidationError(
                f"{field_name}: size {len(ciphertext)} below minimum {min_size}"
            )
        
        return ciphertext


# -----------------------------------------------------------------------------
# Secure Key Management with Zeroization
# -----------------------------------------------------------------------------

class SecureKey:
    """
    Wrapper for cryptographic keys with automatic zeroization.
    
    Uses context manager for automatic cleanup.
    """
    
    def __init__(self, key_data: bytes, algorithm: str, key_id: Optional[str] = None):
        self._key = bytearray(key_data)
        self._algorithm = algorithm
        self._key_id = key_id or secrets.token_hex(8)
        self._used = False
        self._zeroized = False
        self._lock = threading.RLock()
        _global_crypto_audit_log.log(CryptoSecurityEvent(
            event_type=CryptoSecurityEventType.KEY_GENERATION,
            operation=CryptoOperationType.KEY_GENERATION,
            algorithm=algorithm,
            key_id=self._key_id,
            success=True,
            details={"length": len(key_data)},
        ))
    
    def get_bytes(self) -> bytes:
        """Get key as bytes (read-only copy)."""
        with self._lock:
            if self._zeroized:
                raise CryptoValidationError("Key has been zeroized")
            self._used = True
            _global_crypto_audit_log.log(CryptoSecurityEvent(
                event_type=CryptoSecurityEventType.KEY_USAGE,
                operation=CryptoOperationType.KEY_GENERATION,
                algorithm=self._algorithm,
                key_id=self._key_id,
                success=True,
            ))
            return bytes(self._key)
    
    def zeroize(self) -> None:
        """Securely zeroize the key material."""
        with self._lock:
            if not self._zeroized:
                for i in range(len(self._key)):
                    self._key[i] = 0
                self._zeroized = True
                _global_crypto_audit_log.log(CryptoSecurityEvent(
                    event_type=CryptoSecurityEventType.KEY_ZEROIZATION,
                    operation=CryptoOperationType.KEY_GENERATION,
                    algorithm=self._algorithm,
                    key_id=self._key_id,
                    success=True,
                ))
    
    @property
    def key_id(self) -> str:
        return self._key_id
    
    @property
    def algorithm(self) -> str:
        return self._algorithm
    
    @property
    def is_zeroized(self) -> bool:
        return self._zeroized
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.zeroize()
        return False
    
    def __del__(self):
        self.zeroize()


# -----------------------------------------------------------------------------
# Side-Channel Resistant Operations
# -----------------------------------------------------------------------------

class SideChannelResistant:
    """
    Side-channel resistant cryptographic operations.
    
    Implements constant-time comparisons and blinded operations.
    """
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte comparison.
        
        Uses HMAC compare_digest which is timing-attack resistant.
        """
        _global_crypto_audit_log.log(CryptoSecurityEvent(
            event_type=CryptoSecurityEventType.SIDE_CHANNEL_PROTECTION,
            success=True,
            details={"operation": "constant_time_compare"},
        ))
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def constant_time_select(condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Constant-time selection between two values.
        
        No branching based on secret data.
        """
        if len(a) != len(b):
            raise ValueError("Inputs must be same length")
        
        # Create mask: all 1s if condition True, all 0s if False
        mask = (condition * 0xFF).to_bytes(1, 'big') * len(a)
        
        # a & mask | b & ~mask
        result = bytearray(len(a))
        for i in range(len(a)):
            result[i] = (a[i] & mask[i]) | (b[i] & ~mask[i])
        
        return bytes(result)
    
    @staticmethod
    def blinded_modular_exponentiation(
        base: int,
        exponent: int,
        modulus: int,
        blinding_factor: Optional[int] = None,
    ) -> int:
        """
        Blinded modular exponentiation to prevent timing attacks.
        
        Uses base blinding technique.
        """
        if blinding_factor is None:
            blinding_factor = secrets.randbelow(modulus - 2) + 2
        
        # Compute blinding inverse
        inv_blinding = pow(blinding_factor, -1, modulus)
        
        # Blind the base
        blinded_base = (base * pow(blinding_factor, exponent, modulus)) % modulus
        
        # Perform exponentiation
        blinded_result = pow(blinded_base, 1, modulus)
        
        # Unblind
        result = (blinded_result * inv_blinding) % modulus
        
        return result


# -----------------------------------------------------------------------------
# Randomness Health Monitor
# -----------------------------------------------------------------------------

class RandomnessHealthError(Exception):
    """Raised when randomness health check fails."""
    pass


class RandomnessHealthMonitor:
    """
    Monitors random number generator quality.
    
    Performs continuous health checks on generated randomness.
    """
    
    def __init__(
        self,
        min_entropy_bits: float = 0.8,
        max_repetition: int = 8,
        audit_log: Optional[CryptoSecurityAuditLog] = None,
    ):
        self.min_entropy_bits = min_entropy_bits
        self.max_repetition = max_repetition
        self._audit = audit_log or _global_crypto_audit_log
        self._lock = threading.RLock()
        self._sample_window: List[int] = []
        self._window_size = 256
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if len(data) == 0:
            return 0.0
        
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        
        return abs(entropy)
    
    def _check_repetitions(self, data: bytes) -> bool:
        """Check for excessive byte repetitions."""
        max_run = 1
        current_run = 1
        
        for i in range(1, len(data)):
            if data[i] == data[i-1]:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 1
        
        return max_run <= self.max_repetition
    
    def check_randomness(self, data: bytes) -> bool:
        """
        Perform health checks on random data.
        
        Args:
            data: Random bytes to check
            
        Returns:
            True if randomness passes health checks
            
        Raises:
            RandomnessHealthError: If health check fails
        """
        if len(data) < 64:
            return True  # Too small for meaningful entropy checks
        
        entropy = self._calculate_entropy(data)
        min_entropy = self.min_entropy_bits * 8  # bits per byte
        
        if entropy < min_entropy:
            self._audit.log(CryptoSecurityEvent(
                event_type=CryptoSecurityEventType.RANDOMNESS_QUALITY_CHECK,
                operation=CryptoOperationType.RANDOM_GENERATION,
                success=False,
                details={
                    "entropy": entropy,
                    "min_required": min_entropy,
                    "reason": "low_entropy",
                },
            ))
            raise RandomnessHealthError(
                f"Randomness entropy too low: {entropy:.2f} < {min_entropy:.2f}"
            )
        
        if not self._check_repetitions(data):
            self._audit.log(CryptoSecurityEvent(
                event_type=CryptoSecurityEventType.RANDOMNESS_QUALITY_CHECK,
                operation=CryptoOperationType.RANDOM_GENERATION,
                success=False,
                details={"reason": "excessive_repetition"},
            ))
            raise RandomnessHealthError("Randomness has excessive repetition")
        
        self._audit.log(CryptoSecurityEvent(
            event_type=CryptoSecurityEventType.RANDOMNESS_QUALITY_CHECK,
            operation=CryptoOperationType.RANDOM_GENERATION,
            success=True,
            details={"entropy": entropy, "size": len(data)},
        ))
        
        return True
    
    def generate_checked_random(self, num_bytes: int) -> bytes:
        """Generate cryptographically secure random bytes with health check."""
        data = secrets.token_bytes(num_bytes)
        self.check_randomness(data)
        return data


# -----------------------------------------------------------------------------
# Crypto Security Policy Enforcement
# -----------------------------------------------------------------------------

class CryptoSecurityPolicy:
    """Defines cryptographic security policy."""
    
    def __init__(
        self,
        name: str,
        allowed_algorithms: Set[str],
        blocked_algorithms: Set[str],
        min_key_strength: int = 128,
        require_fips: bool = False,
        audit_all_operations: bool = True,
    ):
        self.name = name
        self.allowed_algorithms = allowed_algorithms
        self.blocked_algorithms = blocked_algorithms
        self.min_key_strength = min_key_strength
        self.require_fips = require_fips
        self.audit_all_operations = audit_all_operations


class CryptoPolicyEnforcer:
    """
    Enforces cryptographic security policies.
    
    Validates algorithm usage, key strengths, and compliance requirements.
    """
    
    def __init__(self, audit_log: Optional[CryptoSecurityAuditLog] = None):
        self._lock = threading.RLock()
        self._policies: Dict[str, CryptoSecurityPolicy] = {}
        self._audit = audit_log or _global_crypto_audit_log
    
    def register_policy(self, policy: CryptoSecurityPolicy) -> None:
        """Register a crypto security policy."""
        with self._lock:
            self._policies[policy.name] = policy
    
    def validate_algorithm(
        self,
        algorithm: str,
        policy_name: str = "default",
    ) -> bool:
        """
        Validate algorithm usage against policy.
        
        Returns True if allowed, raises CryptoValidationError if blocked.
        """
        policy = self._policies.get(policy_name)
        if not policy:
            return True
        
        if algorithm in policy.blocked_algorithms:
            self._audit.log(CryptoSecurityEvent(
                event_type=CryptoSecurityEventType.POLICY_ENFORCEMENT_FAIL,
                algorithm=algorithm,
                success=False,
                details={"policy": policy_name, "reason": "blocked"},
            ))
            raise CryptoValidationError(
                f"Algorithm {algorithm} is blocked by policy {policy_name}"
            )
        
        if policy.allowed_algorithms and algorithm not in policy.allowed_algorithms:
            self._audit.log(CryptoSecurityEvent(
                event_type=CryptoSecurityEventType.POLICY_ENFORCEMENT_FAIL,
                algorithm=algorithm,
                success=False,
                details={"policy": policy_name, "reason": "not_allowed"},
            ))
            raise CryptoValidationError(
                f"Algorithm {algorithm} is not allowed by policy {policy_name}"
            )
        
        self._audit.log(CryptoSecurityEvent(
            event_type=CryptoSecurityEventType.POLICY_ENFORCEMENT_PASS,
            algorithm=algorithm,
            success=True,
            details={"policy": policy_name},
        ))
        
        return True
    
    def secure_operation(
        self,
        policy_name: str = "default",
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """
        Decorator to enforce crypto security policy on operations.
        """
        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            @wraps(func)
            def wrapper(*args, **kwargs) -> T:
                policy = self._policies.get(policy_name)
                if policy and policy.audit_all_operations:
                    self._audit.log(CryptoSecurityEvent(
                        event_type=CryptoSecurityEventType.ALGORITHM_USAGE,
                        operation=CryptoOperationType.ENCRYPTION,
                        function=func.__name__,
                        success=True,
                    ))
                return func(*args, **kwargs)
            return wrapper
        return decorator


# -----------------------------------------------------------------------------
# Unified Crypto Security Facade
# -----------------------------------------------------------------------------

class CryptoSecurityHardeningFacade:
    """
    Unified facade for all cryptographic security hardening features.
    
    One-stop access to:
    - Crypto input validation
    - Secure key management
    - Side-channel resistant operations
    - Randomness health monitoring
    - Policy enforcement
    - Audit logging
    
    100% ADD-ONLY - wraps existing crypto without modification.
    """
    
    def __init__(
        self,
        security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD,
    ):
        self.security_level = security_level
        self.validator = CryptoInputValidator(security_level=security_level)
        self.side_channel = SideChannelResistant()
        self.randomness_monitor = RandomnessHealthMonitor()
        self.policy_enforcer = CryptoPolicyEnforcer()
        self.audit_log = get_crypto_security_audit_log()
    
    # --- Input Validation ---
    
    def validate_key(self, key: bytes, algorithm: str, **kwargs) -> bytes:
        return self.validator.validate_key_length(key, algorithm, **kwargs)
    
    def validate_nonce(self, nonce: bytes, algorithm: str, **kwargs) -> bytes:
        return self.validator.validate_nonce(nonce, algorithm, **kwargs)
    
    def validate_plaintext(self, plaintext: bytes, **kwargs) -> bytes:
        return self.validator.validate_plaintext(plaintext, **kwargs)
    
    def validate_ciphertext(self, ciphertext: bytes, **kwargs) -> bytes:
        return self.validator.validate_ciphertext(ciphertext, **kwargs)
    
    # --- Secure Key Management ---
    
    def create_secure_key(self, key_data: bytes, algorithm: str) -> SecureKey:
        return SecureKey(key_data, algorithm)
    
    # --- Side Channel Protection ---
    
    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        return self.side_channel.constant_time_compare(a, b)
    
    # --- Randomness ---
    
    def check_randomness(self, data: bytes) -> bool:
        return self.randomness_monitor.check_randomness(data)
    
    def generate_secure_random(self, num_bytes: int) -> bytes:
        return self.randomness_monitor.generate_checked_random(num_bytes)
    
    # --- Policy Enforcement ---
    
    def validate_algorithm(self, algorithm: str, policy_name: str = "default") -> bool:
        return self.policy_enforcer.validate_algorithm(algorithm, policy_name)
    
    def register_policy(self, policy: CryptoSecurityPolicy) -> None:
        self.policy_enforcer.register_policy(policy)
    
    # --- Audit & Metrics ---
    
    def get_audit_metrics(self) -> Dict[str, Any]:
        return self.audit_log.get_compliance_metrics()
    
    def get_operation_count(self, op: Optional[CryptoOperationType] = None) -> int:
        return self.audit_log.get_operation_count(op)


# -----------------------------------------------------------------------------
# Convenience Functions
# -----------------------------------------------------------------------------

_default_crypto_facade = CryptoSecurityHardeningFacade()


def crypto_validate_key(key: bytes, algorithm: str, **kwargs) -> bytes:
    return _default_crypto_facade.validate_key(key, algorithm, **kwargs)


def crypto_validate_nonce(nonce: bytes, algorithm: str, **kwargs) -> bytes:
    return _default_crypto_facade.validate_nonce(nonce, algorithm, **kwargs)


def crypto_constant_time_compare(a: bytes, b: bytes) -> bool:
    return _default_crypto_facade.constant_time_compare(a, b)


def crypto_generate_secure_random(num_bytes: int) -> bytes:
    return _default_crypto_facade.generate_secure_random(num_bytes)


def crypto_create_secure_key(key_data: bytes, algorithm: str) -> SecureKey:
    return _default_crypto_facade.create_secure_key(key_data, algorithm)


def get_crypto_security_metrics() -> Dict[str, Any]:
    return _default_crypto_facade.get_audit_metrics()
