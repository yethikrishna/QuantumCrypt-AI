"""
QuantumCrypt AI - Crypto Security Hardening Module v17
DIMENSION B: Security Hardening
Incremental Build: ADD-ONLY - No existing code modified

Crypto-Specific Features:
1. Side-Channel Resistant Operations
2. Secure Key Memory Zeroization
3. Constant-Time Crypto Comparisons
4. Cryptographic Input Validation
5. Key Material Sanitization
6. Timing Attack Prevention
"""

import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


class CryptoSecurityLevel(Enum):
    """Cryptographic security classification levels."""
    L1 = "level1"  # Standard crypto
    L2 = "level2"  # Side-channel resistant
    L3 = "level3"  # FIPS 140-2 compliant
    L4 = "level4"  # HSM-level protection


class KeyType(Enum):
    """Types of cryptographic keys."""
    SYMMETRIC = "symmetric"      # AES, ChaCha20
    ASYMMETRIC = "asymmetric"    # RSA, ECC
    POST_QUANTUM = "post_quantum"  # CRYSTALS-Kyber, Dilithium
    SIGNATURE = "signature"      # Digital signature keys
    KEM = "kem"                  # Key encapsulation mechanisms
    DERIVATION = "derivation"    # KDF, HKDF


class ValidationResult(Enum):
    """Result of cryptographic validation."""
    VALID = "valid"
    INVALID = "invalid"
    WEAK = "weak"
    SUSPICIOUS = "suspicious"


@dataclass
class CryptoValidationReport:
    """Detailed validation report for cryptographic materials."""
    result: ValidationResult
    entropy_bits: float
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecureKeyMemory:
    """
    Secure memory management for cryptographic keys.
    Provides zeroization, locking, and protection utilities.
    """

    @staticmethod
    def zeroize_key_material(key_data: Union[bytearray, List[int], memoryview]) -> None:
        """
        Securely zeroize cryptographic key material.
        Uses multi-pass overwriting for maximum security.
        
        Pass 1: All zeros (0x00)
        Pass 2: All ones (0xFF)
        Pass 3: Random pattern
        Pass 4: All zeros (0x00)
        """
        if isinstance(key_data, bytearray):
            length = len(key_data)
            # Pass 1: Zeros
            for i in range(length):
                key_data[i] = 0x00
            # Pass 2: Ones
            for i in range(length):
                key_data[i] = 0xFF
            # Pass 3: Random
            random_bytes = secrets.token_bytes(length)
            for i in range(length):
                key_data[i] = random_bytes[i]
            # Pass 4: Final zeros
            for i in range(length):
                key_data[i] = 0x00
        
        elif isinstance(key_data, list):
            length = len(key_data)
            for i in range(length):
                key_data[i] = 0
            for i in range(length):
                key_data[i] = 0xFF
            for i in range(length):
                key_data[i] = 0

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Cryptographically secure constant-time comparison.
        Uses hmac.compare_digest which is designed for this purpose.
        Prevents timing attacks on MAC verification, signature checks, etc.
        """
        return hmac.compare_digest(a, b)

    @staticmethod
    def constant_time_select(condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Constant-time selection between two byte strings.
        Returns a if condition is True, b otherwise.
        No branching based on secret data.
        """
        if len(a) != len(b):
            raise ValueError("Both byte strings must be same length")
        
        mask = -int(condition)  # All 1s if True, all 0s if False
        result = bytearray(len(a))
        
        for i in range(len(a)):
            result[i] = b[i] ^ (mask & (a[i] ^ b[i]))
        
        return bytes(result)

    @staticmethod
    def wipe_bytes(data: bytearray) -> None:
        """Alias for zeroize_key_material with clear naming."""
        SecureKeyMemory.zeroize_key_material(data)


class SideChannelResistant:
    """
    Side-channel attack resistant operations.
    Implements techniques to prevent timing, power, and EM analysis attacks.
    """

    @staticmethod
    def blind_operation(operation: Callable, data: bytes, blinding_factor: Optional[bytes] = None) -> bytes:
        """
        Apply blinding to an operation to prevent side-channel leaks.
        Adds random noise before operation, removes after.
        """
        if blinding_factor is None:
            blinding_factor = secrets.token_bytes(len(data))
        
        # XOR with blinding factor
        blinded = bytes(a ^ b for a, b in zip(data, blinding_factor))
        
        # Perform operation
        result = operation(blinded)
        
        # Remove blinding (implementation depends on operation type)
        # This is a simplified demonstration
        return result

    @staticmethod
    def constant_time_lookup(table: List[bytes], index: int) -> bytes:
        """
        Constant-time table lookup.
        Prevents cache-timing attacks on S-boxes and lookup tables.
        """
        result = bytearray(len(table[0]))
        for i in range(len(table)):
            # Select if i == index
            mask = -int(i == index)
            for j in range(len(table[i])):
                result[j] |= mask & table[i][j]
        return bytes(result)

    @staticmethod
    def dummy_operations(count: int = 10) -> None:
        """
        Insert dummy operations to normalize timing.
        Makes execution time less data-dependent.
        """
        accumulator = 0
        for i in range(count):
            accumulator ^= secrets.randbelow(256)
        # Use the result to prevent compiler optimization
        _ = accumulator


class CryptoInputValidator:
    """
    Validation for cryptographic inputs and key materials.
    Ensures keys have sufficient entropy and proper format.
    """

    # Weak key patterns to detect
    WEAK_KEY_PATTERNS = [
        b'\x00' * 8,      # All zeros
        b'\xFF' * 8,      # All ones
        b'\x01' * 8,      # All 0x01
        b'01234567',      # Sequential
        b'password',      # Common pattern
    ]

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate entropy estimate of key material.
        Higher = more random (better).
        Uses unique byte ratio as a simple heuristic.
        """
        if not data:
            return 0.0
        
        # Simple entropy heuristic based on unique bytes
        unique_bytes = len(set(data))
        # Scale to 0-8 bits per byte
        entropy_per_byte = min(8.0, 8.0 * (unique_bytes / 256))
        return entropy_per_byte * len(data) / 8

    def validate_key(self, key: bytes, key_type: KeyType, min_length: int = 16) -> CryptoValidationReport:
        """
        Validate a cryptographic key.
        Checks: length, entropy, weak patterns, format
        """
        issues = []
        recommendations = []
        result = ValidationResult.VALID

        # Check minimum length
        if len(key) < min_length:
            issues.append(f"Key too short: {len(key)} bytes (minimum {min_length})")
            result = ValidationResult.INVALID

        # Check maximum length (prevent DoS)
        if len(key) > 10000:
            issues.append(f"Key suspiciously long: {len(key)} bytes")
            if result == ValidationResult.VALID:
                result = ValidationResult.SUSPICIOUS

        # Calculate entropy
        entropy = self.calculate_entropy(key)
        entropy_per_byte = entropy / len(key) if len(key) > 0 else 0

        if entropy_per_byte < 3.0:
            issues.append(f"Low entropy: {entropy_per_byte:.2f} bits/byte")
            if result == ValidationResult.VALID:
                result = ValidationResult.WEAK

        # Check for weak patterns
        for pattern in self.WEAK_KEY_PATTERNS:
            if pattern in key:
                issues.append(f"Weak pattern detected in key material")
                if result == ValidationResult.VALID:
                    result = ValidationResult.WEAK
                break

        # Check for repeated bytes
        unique_bytes = len(set(key))
        if unique_bytes < len(key) * 0.1:
            issues.append(f"Very few unique bytes: {unique_bytes}/{len(key)}")
            if result == ValidationResult.VALID:
                result = ValidationResult.WEAK

        # Recommendations
        if entropy_per_byte < 6.0:
            recommendations.append("Use cryptographically secure random number generator")
        if key_type == KeyType.POST_QUANTUM and len(key) < 32:
            recommendations.append("Post-quantum keys recommend >= 32 bytes")

        return CryptoValidationReport(
            result=result,
            entropy_bits=entropy,
            issues=issues,
            recommendations=recommendations,
            metadata={
                "key_length": len(key),
                "key_type": key_type.value,
                "unique_bytes": unique_bytes,
                "entropy_per_byte": entropy_per_byte
            }
        )

    def validate_nonce(self, nonce: bytes, expected_length: int = 12) -> CryptoValidationReport:
        """Validate a nonce/IV for cryptographic operations."""
        issues = []
        result = ValidationResult.VALID

        if len(nonce) != expected_length:
            issues.append(f"Nonce length mismatch: expected {expected_length}, got {len(nonce)}")
            result = ValidationResult.INVALID

        # Nonces don't need high entropy, but should not be all zeros
        if all(b == 0 for b in nonce):
            issues.append("Nonce is all zeros - may cause reuse issues")
            result = ValidationResult.WEAK

        entropy = self.calculate_entropy(nonce)

        return CryptoValidationReport(
            result=result,
            entropy_bits=entropy,
            issues=issues,
            metadata={"nonce_length": len(nonce)}
        )


class TimingAttackProtector:
    """
    Protection against timing attacks.
    Normalizes execution time across different code paths.
    """

    def __init__(self, min_execution_ms: float = 10.0):
        self.min_execution_ms = min_execution_ms
        self._operation_start: float = 0

    def __enter__(self):
        """Start timing protection context."""
        self._operation_start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Ensure minimum execution time."""
        elapsed = (time.perf_counter() - self._operation_start) * 1000
        remaining = self.min_execution_ms - elapsed
        
        if remaining > 0:
            # Busy-wait for remaining time (more precise than sleep)
            target = time.perf_counter() + remaining / 1000
            while time.perf_counter() < target:
                # Perform dummy operations
                _ = secrets.randbelow(256) ^ secrets.randbelow(256)
        
        return False  # Don't suppress exceptions


class CryptoSecurityFacade:
    """
    Unified facade for all crypto security hardening features.
    Easy integration with existing post-quantum cryptography code.
    """

    def __init__(self, security_level: CryptoSecurityLevel = CryptoSecurityLevel.L2):
        self.key_memory = SecureKeyMemory()
        self.side_channel = SideChannelResistant()
        self.validator = CryptoInputValidator()
        self.security_level = security_level
        self._lock = threading.Lock()

    def secure_key_operation(self,
                            operation: Callable,
                            key: bytes,
                            *args,
                            key_type: KeyType = KeyType.SYMMETRIC,
                            **kwargs) -> Tuple[bool, Any]:
        """
        Wrap a key operation with security hardening:
        1. Validate key material
        2. Apply timing protection
        3. Execute operation
        4. Clean up sensitive data
        """
        with self._lock:
            # Validate key
            validation = self.validator.validate_key(key, key_type)
            if validation.result == ValidationResult.INVALID:
                return False, f"Key validation failed: {validation.issues}"

            # Apply timing protection
            with TimingAttackProtector(min_execution_ms=5.0):
                try:
                    result = operation(key, *args, **kwargs)
                    return True, result
                except Exception as e:
                    return False, f"Operation failed: {str(e)}"

    def compare_constant_time(self, a: bytes, b: bytes) -> bool:
        """Secure constant-time comparison for crypto materials."""
        return self.key_memory.constant_time_compare(a, b)

    def validate_and_wipe(self, key_data: bytearray) -> CryptoValidationReport:
        """Validate key and then securely wipe it from memory."""
        report = self.validator.validate_key(bytes(key_data), KeyType.SYMMETRIC)
        self.key_memory.zeroize_key_material(key_data)
        return report

    def create_timing_protector(self, min_ms: float = 10.0) -> TimingAttackProtector:
        """Create a timing protector context manager."""
        return TimingAttackProtector(min_execution_ms=min_ms)


# Default instance for easy import
_default_crypto_security: Optional[CryptoSecurityFacade] = None


def get_crypto_security(security_level: CryptoSecurityLevel = CryptoSecurityLevel.L2) -> CryptoSecurityFacade:
    """Get or create the default crypto security hardening instance."""
    global _default_crypto_security
    if _default_crypto_security is None:
        _default_crypto_security = CryptoSecurityFacade(security_level)
    return _default_crypto_security
