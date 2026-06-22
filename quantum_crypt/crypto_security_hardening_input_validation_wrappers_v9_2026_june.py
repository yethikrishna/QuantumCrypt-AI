"""
QuantumCrypt-AI: Comprehensive Input Validation Wrappers (v9)
Dimension B - Security Hardening
ADD-ONLY implementation - wraps existing crypto operations

Provides validation wrappers for all cryptographic operations:
- Key material validation (size, format, entropy)
- Input sanitization (type, bounds, encoding)
- Algorithm parameter validation
- Reject known-bad inputs (weak keys, backdoor patterns)
- Type safety enforcement

All wrappers are OPT-IN and layered - no existing code modified.
"""

import re
import secrets
import hashlib
import base64
import math
from typing import Any, Optional, Union, Callable, TypeVar, Tuple, Dict, List
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import wraps
import logging

# Configure logging - OPT-IN only, disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar('T')
F = TypeVar('F', bound=Callable)

class ValidationSeverity(Enum):
    """Severity levels for validation failures"""
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()

class ValidationFailureCode(Enum):
    """Specific validation failure codes"""
    INVALID_TYPE = auto()
    INVALID_LENGTH = auto()
    INVALID_ENCODING = auto()
    WEAK_ENTROPY = auto()
    KNOWN_BAD_PATTERN = auto()
    INVALID_ALGORITHM = auto()
    INVALID_PARAMETER = auto()
    NULL_INPUT = auto()
    OUT_OF_BOUNDS = auto()
    INVALID_FORMAT = auto()

@dataclass
class ValidationResult:
    """Result of input validation operation"""
    valid: bool
    severity: ValidationSeverity
    failure_code: Optional[ValidationFailureCode] = None
    message: str = ""
    sanitized_value: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __bool__(self) -> bool:
        return self.valid

@dataclass
class ValidationConfig:
    """Configuration for validation strictness"""
    strict_key_validation: bool = True
    reject_weak_keys: bool = True
    check_entropy: bool = True
    min_entropy_bits: float = 64.0
    enforce_type_safety: bool = True
    reject_known_bad_patterns: bool = True
    max_input_size: int = 10 * 1024 * 1024  # 10MB
    allow_empty_inputs: bool = False

# Known weak/backdoor patterns - these are NEVER valid cryptographic material
KNOWN_BAD_PATTERNS: List[bytes] = [
    b'\x00' * 16, b'\x00' * 32, b'\x00' * 64,  # All zeros
    b'\xFF' * 16, b'\xFF' * 32, b'\xFF' * 64,  # All ones
    b'\x55' * 16, b'\xAA' * 16,                # Alternating
    b'0123456789ABCDEF',                        # Sequential
    b'DEADBEEFDEADBEEF',                        # Known pattern
    b'BACKDOOR', b'NOPAL', b'_NSAKEY',          # Suspicious
    b'abcdefghijklmnop',                        # Alphabet
]

# Standard key sizes (bytes)
STANDARD_KEY_SIZES: Dict[str, List[int]] = {
    'AES': [16, 24, 32],           # 128, 192, 256 bits
    'ChaCha20': [32],              # 256 bits
    'RSA': [256, 384, 512],        # 2048, 3072, 4096 bits (minimum)
    'ECDSA': [32, 48, 66],         # P-256, P-384, P-521
    'Kyber': [32, 64, 128],        # ML-KEM sizes
    'SHA256': [32],
    'SHA512': [64],
    'HMAC': [16, 32, 64],
}

class CryptoInputValidator:
    """
    Comprehensive cryptographic input validation engine.
    
    Validates and sanitizes all inputs to cryptographic operations
    to prevent algorithmic attacks, injection, and misuse.
    
    Usage is OPTIONAL - wrap functions or call directly:
        @validator.validate_key('AES')
        def encrypt(key, data):
            ...
    """
    
    def __init__(self, config: Optional[ValidationConfig] = None):
        self.config = config or ValidationConfig()
        self._validation_stats = {
            'total_validations': 0,
            'passed': 0,
            'failed': 0,
            'sanitized': 0
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        
        entropy = 0.0
        length = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy * len(data)  # Total entropy bits
    
    def _check_known_bad_patterns(self, data: bytes) -> bool:
        """Check for known weak/backdoor patterns"""
        if not self.config.reject_known_bad_patterns:
            return False
        
        # Skip empty data - handled by length validation
        if len(data) == 0:
            return False
        
        for pattern in KNOWN_BAD_PATTERNS:
            if len(pattern) > 0 and (pattern in data or data in pattern):
                return True
        return False
    
    def validate_bytes(self, data: Any, 
                      min_length: int = 1,
                      max_length: Optional[int] = None,
                      allow_empty: bool = False) -> ValidationResult:
        """
        Validate input is proper bytes.
        
        Args:
            data: Input to validate
            min_length: Minimum acceptable length
            max_length: Maximum acceptable length
            allow_empty: Whether empty input is allowed
            
        Returns:
            ValidationResult with sanitized bytes
        """
        self._validation_stats['total_validations'] += 1
        
        # Check for None/null
        if data is None:
            if allow_empty and self.config.allow_empty_inputs:
                self._validation_stats['passed'] += 1
                return ValidationResult(True, ValidationSeverity.INFO, 
                                      sanitized_value=b'')
            self._validation_stats['failed'] += 1
            return ValidationResult(False, ValidationSeverity.CRITICAL,
                                  ValidationFailureCode.NULL_INPUT,
                                  "Null input not allowed")
        
        # Type conversion and validation
        if isinstance(data, bytes):
            sanitized = data
        elif isinstance(data, bytearray):
            sanitized = bytes(data)
            self._validation_stats['sanitized'] += 1
        elif isinstance(data, str):
            # Try common encodings
            try:
                if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0:
                    sanitized = bytes.fromhex(data)
                elif re.match(r'^[A-Za-z0-9+/]+={0,2}$', data):
                    sanitized = base64.b64decode(data)
                else:
                    sanitized = data.encode('utf-8')
                self._validation_stats['sanitized'] += 1
            except Exception:
                self._validation_stats['failed'] += 1
                return ValidationResult(False, ValidationSeverity.ERROR,
                                      ValidationFailureCode.INVALID_ENCODING,
                                      "Invalid string encoding")
        else:
            if self.config.enforce_type_safety:
                self._validation_stats['failed'] += 1
                return ValidationResult(False, ValidationSeverity.ERROR,
                                      ValidationFailureCode.INVALID_TYPE,
                                      f"Expected bytes, got {type(data).__name__}")
            try:
                sanitized = bytes(data)
                self._validation_stats['sanitized'] += 1
            except Exception:
                self._validation_stats['failed'] += 1
                return ValidationResult(False, ValidationSeverity.ERROR,
                                      ValidationFailureCode.INVALID_TYPE,
                                      "Cannot convert to bytes")
        
        # Length validation
        actual_max = max_length or self.config.max_input_size
        if len(sanitized) < min_length and not (allow_empty and len(sanitized) == 0):
            self._validation_stats['failed'] += 1
            return ValidationResult(False, ValidationSeverity.ERROR,
                                  ValidationFailureCode.INVALID_LENGTH,
                                  f"Input too short: {len(sanitized)} < {min_length}")
        
        if len(sanitized) > actual_max:
            self._validation_stats['failed'] += 1
            return ValidationResult(False, ValidationSeverity.ERROR,
                                  ValidationFailureCode.INVALID_LENGTH,
                                  f"Input too large: {len(sanitized)} > {actual_max}")
        
        # Check known bad patterns
        if self._check_known_bad_patterns(sanitized):
            self._validation_stats['failed'] += 1
            return ValidationResult(False, ValidationSeverity.CRITICAL,
                                  ValidationFailureCode.KNOWN_BAD_PATTERN,
                                  "Known weak/backdoor pattern detected")
        
        self._validation_stats['passed'] += 1
        return ValidationResult(True, ValidationSeverity.INFO,
                              sanitized_value=sanitized,
                              metadata={'length': len(sanitized)})
    
    def validate_key(self, key: Any, algorithm: str = 'AES') -> ValidationResult:
        """
        Validate cryptographic key material.
        
        Args:
            key: Key material to validate
            algorithm: Target algorithm (for size checking)
            
        Returns:
            ValidationResult with sanitized key bytes
        """
        # First validate as bytes
        bytes_result = self.validate_bytes(key)
        if not bytes_result:
            return bytes_result
        
        key_bytes = bytes_result.sanitized_value
        
        # Check standard key sizes
        if self.config.strict_key_validation and algorithm in STANDARD_KEY_SIZES:
            allowed_sizes = STANDARD_KEY_SIZES[algorithm]
            if len(key_bytes) not in allowed_sizes:
                self._validation_stats['failed'] += 1
                return ValidationResult(False, ValidationSeverity.ERROR,
                                      ValidationFailureCode.INVALID_LENGTH,
                                      f"Invalid {algorithm} key size: {len(key_bytes)} bytes. "
                                      f"Expected one of: {allowed_sizes}")
        
        # Entropy check - warn but don't reject (random data can have low entropy by chance)
        if self.config.check_entropy:
            entropy = self._calculate_entropy(key_bytes)
            min_entropy = self.config.min_entropy_bits
            if entropy < min_entropy:
                # Just log warning, don't reject - statistical false positives are common
                logger.warning(f"Low key entropy detected: {entropy:.1f} bits")
        
        # Check for all-same bytes (extremely weak)
        if len(set(key_bytes)) == 1:
            if self.config.reject_weak_keys:
                self._validation_stats['failed'] += 1
                return ValidationResult(False, ValidationSeverity.CRITICAL,
                                      ValidationFailureCode.WEAK_ENTROPY,
                                      "Key consists of repeated bytes - extremely weak")
        
        return bytes_result
    
    def validate_nonce(self, nonce: Any, expected_length: int = 12) -> ValidationResult:
        """Validate nonce/IV material"""
        result = self.validate_bytes(nonce, min_length=expected_length, 
                                   max_length=expected_length)
        if result:
            # Nonces should be unique - check for common patterns
            if len(set(result.sanitized_value)) < 3:
                return ValidationResult(False, ValidationSeverity.WARNING,
                                      ValidationFailureCode.WEAK_ENTROPY,
                                      "Nonce has low diversity - may cause reuse")
        return result
    
    def validate_plaintext(self, data: Any) -> ValidationResult:
        """Validate plaintext input"""
        return self.validate_bytes(data, allow_empty=True)
    
    def validate_ciphertext(self, data: Any, min_length: int = 16) -> ValidationResult:
        """Validate ciphertext - must have proper block alignment"""
        result = self.validate_bytes(data, min_length=min_length)
        if result and len(result.sanitized_value) % 16 != 0:
            # Many modes don't require padding, just warn
            result.metadata['block_unaligned'] = True
        return result
    
    def validate_signature(self, signature: Any, min_length: int = 32) -> ValidationResult:
        """Validate digital signature"""
        return self.validate_bytes(signature, min_length=min_length)
    
    def validate_hash(self, hash_val: Any, algorithm: str = 'SHA256') -> ValidationResult:
        """Validate hash output"""
        expected_sizes = {'SHA256': 32, 'SHA512': 64, 'SHA1': 20, 'MD5': 16}
        expected = expected_sizes.get(algorithm, 32)
        return self.validate_bytes(hash_val, min_length=expected, max_length=expected)
    
    def wrap_function(self, param_validators: Dict[str, Callable]) -> Callable[[F], F]:
        """
        Decorator to validate function parameters.
        
        Example:
            @validator.wrap_function({
                'key': lambda k: validator.validate_key(k, 'AES'),
                'nonce': validator.validate_nonce
            })
            def encrypt(key, nonce, data):
                ...
        """
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapper(*args, **kwargs):
                import inspect
                sig = inspect.signature(func)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                
                for param_name, validator in param_validators.items():
                    if param_name in bound.arguments:
                        result = validator(bound.arguments[param_name])
                        if not result:
                            raise ValueError(
                                f"Parameter '{param_name}' validation failed: {result.message}"
                            )
                        # Replace with sanitized value
                        if result.sanitized_value is not None:
                            bound.arguments[param_name] = result.sanitized_value
                
                return func(*bound.args, **bound.kwargs)
            return wrapper  # type: ignore
        return decorator
    
    def get_stats(self) -> Dict[str, int]:
        """Get validation statistics"""
        return dict(self._validation_stats)


# Global singleton instance
_default_validator: Optional[CryptoInputValidator] = None

def get_crypto_validator() -> CryptoInputValidator:
    """Get default input validator instance"""
    global _default_validator
    if _default_validator is None:
        _default_validator = CryptoInputValidator()
    return _default_validator

def validate_key(key: Any, algorithm: str = 'AES') -> ValidationResult:
    """Convenience: Validate cryptographic key"""
    return get_crypto_validator().validate_key(key, algorithm)

def validate_bytes(data: Any) -> ValidationResult:
    """Convenience: Validate bytes input"""
    return get_crypto_validator().validate_bytes(data)

# Export public API
__all__ = [
    'CryptoInputValidator',
    'ValidationConfig',
    'ValidationResult',
    'ValidationSeverity',
    'ValidationFailureCode',
    'get_crypto_validator',
    'validate_key',
    'validate_bytes'
]
