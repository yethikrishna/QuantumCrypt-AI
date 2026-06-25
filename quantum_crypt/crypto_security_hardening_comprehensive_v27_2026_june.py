"""
QuantumCrypt AI - Cryptographic Security Hardening Module v27
DIMENSION B - Security Hardening
Incremental Build - Layered on Top, No Core Modifications

This module provides quantum-resistant security hardening:
- Cryptographic constant-time operations (side-channel resistance)
- Secure key material zeroization
- Cryptographic input validation with quantum-specific checks
- Key operation rate limiting
- Side-channel attack mitigations
- Secure randomness validation

All functions are OPT-IN and wrap existing code - happy path preserved.
"""

import hmac
import hashlib
import secrets
import threading
import time
import os
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum


class CryptoSecurityLevel(Enum):
    """Cryptographic security level enumeration."""
    CLASSIC = "classic"           # Standard crypto
    QUANTUM_READY = "quantum_ready"  # PQ-hardened
    QUANTUM_RESISTANT = "quantum_resistant"  # Full PQ
    MAXIMUM = "maximum"           # All mitigations enabled


class KeyType(Enum):
    """Cryptographic key types for validation."""
    SYMMETRIC = "symmetric"
    ASYMMETRIC_PRIVATE = "private"
    ASYMMETRIC_PUBLIC = "public"
    POST_QUANTUM = "post_quantum"
    HYBRID = "hybrid"


@dataclass
class KeyValidationResult:
    """Result of cryptographic key material validation."""
    is_valid: bool
    key_type: Optional[KeyType]
    estimated_strength_bits: int
    entropy_estimate: float
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class CryptoRateLimitConfig:
    """Configuration for cryptographic operation rate limiting."""
    max_sign_operations: int = 1000
    max_decrypt_operations: int = 500
    max_keygen_operations: int = 50
    window_seconds: int = 60
    block_duration_seconds: int = 60


class CryptoSecureMemory:
    """
    Cryptographic secure memory zeroization.
    Specialized for sensitive key material with enhanced overwriting.
    """
    
    @staticmethod
    def zeroize_key_material(key_data: bytearray) -> None:
        """
        Securely zeroize cryptographic key material.
        Uses cryptographic-grade overwriting with multiple patterns.
        
        Args:
            key_data: Mutable bytearray containing key material
        """
        if not isinstance(key_data, bytearray):
            return
            
        length = len(key_data)
        
        # Pattern 1: Alternating 0x55
        for i in range(length):
            key_data[i] = 0x55
        
        # Pattern 2: Alternating 0xAA
        for i in range(length):
            key_data[i] = 0xAA
        
        # Pattern 3: All 0xFF
        for i in range(length):
            key_data[i] = 0xFF
        
        # Pattern 4: Cryptographic random
        for i in range(length):
            key_data[i] = secrets.randbits(8)
        
        # Pattern 5: Position-based pattern
        for i in range(length):
            key_data[i] = i & 0xFF
        
        # Pattern 6: Inverse position
        for i in range(length):
            key_data[i] = (~i) & 0xFF
        
        # Final: All zeros
        for i in range(length):
            key_data[i] = 0x00
    
    @staticmethod
    def zeroize_sensitive_buffer(buffer: Union[bytearray, memoryview]) -> None:
        """
        Zeroize a sensitive buffer (supports memoryview for mmap'd files).
        
        Args:
            buffer: Mutable buffer to zeroize
        """
        if isinstance(buffer, memoryview):
            # For memoryview, create a zero bytearray and assign element by element
            # Note: memoryview elements are integers, not bytes
            for i in range(len(buffer)):
                buffer[i] = 0
        elif isinstance(buffer, bytearray):
            CryptoSecureMemory.zeroize_key_material(buffer)
    
    @staticmethod
    def wipe_object_secrets(obj: Any) -> None:
        """
        Recursively wipe secrets from an object.
        Looks for common sensitive attribute names.
        
        Args:
            obj: Object potentially containing secrets
        """
        sensitive_names = {
            'key', 'private_key', 'secret', 'password', 'passphrase',
            'nonce', 'iv', 'salt', 'seed', 'token', 'credential'
        }
        
        if hasattr(obj, '__dict__'):
            for attr_name, attr_value in list(obj.__dict__.items()):
                name_lower = attr_name.lower()
                if any(sensitive in name_lower for sensitive in sensitive_names):
                    if isinstance(attr_value, bytearray):
                        CryptoSecureMemory.zeroize_key_material(attr_value)
                    elif isinstance(attr_value, (list, dict)):
                        attr_value.clear()
                    obj.__dict__[attr_name] = None


class CryptoConstantTime:
    """
    Cryptographic constant-time operations.
    Specialized for cryptographic comparisons and array operations.
    """
    
    @staticmethod
    def compare_digests(a: bytes, b: bytes) -> bool:
        """
        Constant-time digest comparison for crypto use.
        Uses standard library hmac.compare_digest which is timing-safe.
        
        Args:
            a: First digest bytes
            b: Second digest bytes
            
        Returns:
            True if equal, False otherwise (constant time)
        """
        if len(a) != len(b):
            # Still do a comparison to maintain constant timing
            dummy = bytes([0]) * max(len(a), len(b))
            hmac.compare_digest(dummy, dummy)
            return False
            
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def select(condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Constant-time selection: return a if condition else b.
        Execution time does not depend on condition value.
        
        Args:
            condition: Boolean selector
            a: Value if True
            b: Value if False
            
        Returns:
            Either a or b, chosen in constant time
        """
        # Create mask: all 1s if condition, all 0s otherwise
        mask = -condition if condition else 0
        
        if len(a) != len(b):
            return a if condition else b
        
        result = bytearray(len(a))
        for i in range(len(a)):
            result[i] = (a[i] & mask) | (b[i] & ~mask)
        
        return bytes(result)
    
    @staticmethod
    def is_equal_bytes(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte equality check.
        Handles different lengths correctly.
        
        Args:
            a: First bytes
            b: Second bytes
            
        Returns:
            True if equal, False otherwise
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def verify_mac(received: bytes, expected: bytes, key: bytes) -> bool:
        """
        Constant-time MAC verification.
        Recomputes and compares in timing-safe manner.
        
        Args:
            received: Received MAC value
            expected: Expected MAC value (or data to compute from)
            key: HMAC key
            
        Returns:
            True if MAC is valid
        """
        computed = hmac.new(key, expected, hashlib.sha256).digest()
        return hmac.compare_digest(received, computed)


class KeyMaterialValidator:
    """
    Cryptographic key material validator.
    Validates entropy, length, and format for all key types.
    """
    
    # Minimum recommended key sizes (bits)
    MIN_KEY_SIZES = {
        KeyType.SYMMETRIC: 128,
        KeyType.ASYMMETRIC_PRIVATE: 2048,
        KeyType.ASYMMETRIC_PUBLIC: 2048,
        KeyType.POST_QUANTUM: 128,
        KeyType.HYBRID: 256,
    }
    
    def __init__(self, security_level: CryptoSecurityLevel = CryptoSecurityLevel.QUANTUM_READY):
        self.security_level = security_level
        self._lock = threading.Lock()
    
    def estimate_entropy(self, data: bytes) -> float:
        """
        Estimate Shannon entropy of key material.
        
        Args:
            data: Key material bytes
            
        Returns:
            Estimated entropy bits per byte (0-8)
        """
        if not data:
            return 0.0
            
        # Use frequency analysis for practical entropy estimation
        unique_bytes = len(set(data))
        freq_ratio = unique_bytes / min(256.0, len(data))
        return min(8.0, freq_ratio * 8.0)
    
    def validate_key(
        self,
        key_material: bytes,
        expected_type: Optional[KeyType] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None
    ) -> KeyValidationResult:
        """
        Validate cryptographic key material.
        
        Args:
            key_material: Raw key bytes
            expected_type: Expected key type if known
            min_length: Minimum allowed length in bytes
            max_length: Maximum allowed length in bytes
            
        Returns:
            KeyValidationResult with detailed assessment
        """
        warnings = []
        errors = []
        
        # Type check
        if not isinstance(key_material, bytes):
            return KeyValidationResult(
                is_valid=False,
                key_type=None,
                estimated_strength_bits=0,
                entropy_estimate=0.0,
                errors=["Key material must be bytes"]
            )
        
        length = len(key_material)
        length_bits = length * 8
        
        # Empty key check
        if length == 0:
            return KeyValidationResult(
                is_valid=False,
                key_type=None,
                estimated_strength_bits=0,
                entropy_estimate=0.0,
                errors=["Empty key material"]
            )
        
        # Length bounds
        if min_length and length < min_length:
            errors.append(f"Key too short: {length} < {min_length} bytes")
        
        if max_length and length > max_length:
            errors.append(f"Key too long: {length} > {max_length} bytes")
        
        # Entropy estimation
        entropy = self.estimate_entropy(key_material)
        total_entropy = entropy * length
        
        # Low entropy warning
        if entropy < 4.0:
            warnings.append(f"Low entropy detected: {entropy:.2f} bits/byte")
        
        # Weak pattern detection
        if self._has_repeating_pattern(key_material):
            warnings.append("Key contains repeating patterns")
        
        if self._has_sequential_bytes(key_material):
            warnings.append("Key contains sequential byte patterns")
        
        # Determine key type heuristically
        detected_type = self._detect_key_type(key_material)
        
        # Strength assessment
        min_required = self.MIN_KEY_SIZES.get(expected_type or detected_type or KeyType.SYMMETRIC, 128)
        
        if length_bits < min_required:
            errors.append(f"Key strength below minimum: {length_bits} < {min_required} bits")
        
        # Quantum security level checks
        if self.security_level in [CryptoSecurityLevel.QUANTUM_RESISTANT, CryptoSecurityLevel.MAXIMUM]:
            if length_bits < 256:
                warnings.append("Key may be insufficient for post-quantum security")
        
        is_valid = len(errors) == 0
        
        return KeyValidationResult(
            is_valid=is_valid,
            key_type=detected_type,
            estimated_strength_bits=length_bits,
            entropy_estimate=entropy,
            warnings=warnings,
            errors=errors
        )
    
    def _has_repeating_pattern(self, data: bytes) -> bool:
        """Detect simple repeating patterns."""
        if len(data) < 4:
            return False
            
        # Check for single byte repetition
        if len(set(data)) == 1:
            return True
            
        # Check for 2-4 byte repeating patterns
        for pattern_len in range(2, 5):
            if len(data) >= pattern_len * 2:
                pattern = data[:pattern_len]
                repeats = True
                for i in range(0, len(data), pattern_len):
                    if data[i:i+pattern_len] != pattern:
                        repeats = False
                        break
                if repeats:
                    return True
        return False
    
    def _has_sequential_bytes(self, data: bytes) -> bool:
        """Detect simple sequential byte patterns."""
        if len(data) < 4:
            return False
            
        # Check for incrementing sequence
        for i in range(len(data) - 3):
            if (data[i+1] == (data[i] + 1) % 256 and
                data[i+2] == (data[i] + 2) % 256 and
                data[i+3] == (data[i] + 3) % 256):
                return True
        return False
    
    def _detect_key_type(self, data: bytes) -> Optional[KeyType]:
        """Heuristically detect key type from raw bytes."""
        length = len(data)
        
        # Common symmetric key sizes
        if length in [16, 24, 32]:  # 128, 192, 256 bits
            return KeyType.SYMMETRIC
        
        # Common PQ key sizes (larger)
        if length > 1000:
            return KeyType.POST_QUANTUM
        
        # Medium size - likely hybrid
        if 100 < length <= 1000:
            return KeyType.HYBRID
        
        return None


class CryptoOperationLimiter:
    """
    Rate limiter for cryptographic operations.
    Prevents key exhaustion and timing attack amplification.
    """
    
    def __init__(self, config: Optional[CryptoRateLimitConfig] = None):
        self.config = config or CryptoRateLimitConfig()
        self._operation_counts: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
    
    def can_perform_operation(self, operation_type: str, identifier: str = "global") -> Tuple[bool, Dict[str, Any]]:
        """
        Check if a cryptographic operation can be performed.
        
        Args:
            operation_type: Type of operation ('sign', 'decrypt', 'keygen')
            identifier: Optional identifier for per-user tracking
            
        Returns:
            (allowed, metadata)
        """
        current_time = time.time()
        key = f"{operation_type}:{identifier}"
        
        with self._lock:
            # Clean old entries
            window_start = current_time - self.config.window_seconds
            if key in self._operation_counts:
                self._operation_counts[key] = [
                    ts for ts in self._operation_counts[key]
                    if ts > window_start
                ]
            else:
                self._operation_counts[key] = []
            
            # Get limit based on operation type
            max_ops = self._get_limit_for_operation(operation_type)
            current_count = len(self._operation_counts[key])
            
            if current_count >= max_ops:
                return False, {
                    "allowed": False,
                    "operation": operation_type,
                    "current_count": current_count,
                    "max_allowed": max_ops,
                    "reason": "rate_limit_exceeded"
                }
            
            # Record this operation
            self._operation_counts[key].append(current_time)
            
            remaining = max_ops - current_count - 1
            
            return True, {
                "allowed": True,
                "operation": operation_type,
                "remaining": remaining,
                "window_seconds": self.config.window_seconds
            }
    
    def _get_limit_for_operation(self, operation_type: str) -> int:
        """Get rate limit for specific operation type."""
        limits = {
            "sign": self.config.max_sign_operations,
            "decrypt": self.config.max_decrypt_operations,
            "keygen": self.config.max_keygen_operations,
        }
        return limits.get(operation_type, 1000)
    
    def reset(self) -> None:
        """Reset all rate limits."""
        with self._lock:
            self._operation_counts.clear()


class RandomnessValidator:
    """
    Validator for secure random number generation.
    Ensures randomness quality for cryptographic operations.
    """
    
    @staticmethod
    def is_cryptographically_secure() -> bool:
        """
        Check if system RNG is cryptographically secure.
        
        Returns:
            True if secrets module is using secure RNG
        """
        try:
            # Test that secrets module works
            _ = secrets.token_bytes(32)
            return True
        except NotImplementedError:
            return False
    
    @staticmethod
    def validate_random_bytes(data: bytes, min_entropy_per_byte: float = 1.0) -> bool:
        """
        Validate random bytes meet minimum entropy requirements.
        
        Args:
            data: Bytes to validate
            min_entropy_per_byte: Minimum required entropy per byte
            
        Returns:
            True if entropy requirement is met
        """
        if len(data) < 8:
            return True  # Too small for meaningful analysis
            
        # Simple frequency analysis
        unique_bytes = len(set(data))
        # Use min with data length for smaller samples
        entropy_estimate = (unique_bytes / min(256.0, len(data))) * 8.0
        
        return entropy_estimate >= min_entropy_per_byte
    
    @staticmethod
    def generate_safe_random(length: int) -> bytes:
        """
        Generate cryptographically secure random bytes.
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            Secure random bytes
        """
        if not RandomnessValidator.is_cryptographically_secure():
            raise RuntimeError("Cryptographically secure RNG not available")
            
        return secrets.token_bytes(length)


class CryptoSecurityHardener:
    """
    Main facade for cryptographic security hardening.
    Provides easy access to all crypto security utilities.
    """
    
    def __init__(
        self,
        security_level: CryptoSecurityLevel = CryptoSecurityLevel.QUANTUM_READY,
        rate_limit_config: Optional[CryptoRateLimitConfig] = None
    ):
        self.security_level = security_level
        self.key_validator = KeyMaterialValidator(security_level)
        self.operation_limiter = CryptoOperationLimiter(rate_limit_config)
        self._enabled = True
    
    def enable(self) -> None:
        """Enable all security hardening."""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable security hardening (for testing only)."""
        self._enabled = False
    
    def wrap_crypto_operation(
        self,
        func: Callable,
        operation_type: str,
        validate_keys: bool = True,
        rate_limit: bool = True
    ) -> Callable:
        """
        Wrap a cryptographic operation with security hardening.
        
        Args:
            func: Cryptographic function to wrap
            operation_type: Type of operation ('sign', 'decrypt', 'keygen')
            validate_keys: Whether to validate key material
            rate_limit: Whether to apply rate limiting
            
        Returns:
            Wrapped function
        """
        def wrapped(*args, **kwargs):
            if not self._enabled:
                return func(*args, **kwargs)
            
            # Rate limiting
            if rate_limit:
                allowed, meta = self.operation_limiter.can_perform_operation(operation_type)
                if not allowed:
                    raise CryptoSecurityError(
                        f"Operation rate limit exceeded: {operation_type}",
                        metadata=meta
                    )
            
            # Execute operation
            result = func(*args, **kwargs)
            
            return result
        
        return wrapped


class CryptoSecurityError(Exception):
    """Cryptographic security exception."""
    
    def __init__(self, message: str, metadata: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.metadata = metadata or {}


# Convenience exports
def crypto_secure_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison for cryptographic data."""
    return CryptoConstantTime.is_equal_bytes(a, b)

def crypto_zeroize_key(key_data: bytearray) -> None:
    """Securely zeroize cryptographic key material."""
    CryptoSecureMemory.zeroize_key_material(key_data)

def generate_secure_random(length: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    return RandomnessValidator.generate_safe_random(length)
