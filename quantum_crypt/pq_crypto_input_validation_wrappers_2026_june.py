"""
Post-Quantum Crypto Input Validation Wrappers
DIMENSION B: Security Hardening

Layered security ON TOP of existing crypto code - NO modifications to core modules.
All validation is OPT-IN via decorators and wrapper functions.

Purpose: Validate cryptographic inputs (keys, nonces, algorithms, parameters)
to prevent algorithm confusion attacks, weak key material, and boundary violations.

API Stability: STABLE
Thread Safety: Thread-safe
Backward Compatible: 100% - no existing code modified
Side-Channel Resistant: Constant-time validation where applicable
"""

import re
import secrets
import logging
import functools
import threading
from typing import Any, Callable, Dict, List, Optional, Set, Type, Union, Pattern
from dataclasses import dataclass, field
from enum import Enum, auto
import hmac
import hashlib

# Configure null logger - opt-in only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class CryptoValidationSeverity(Enum):
    """Severity levels for crypto validation failures."""
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()


class CryptoValidationErrorCode(Enum):
    """Cryptographic validation error codes."""
    # Key validation
    WEAK_KEY = "WEAK_KEY"
    INVALID_KEY_LENGTH = "INVALID_KEY_LENGTH"
    INVALID_KEY_FORMAT = "INVALID_KEY_FORMAT"
    KEY_REUSE_DETECTED = "KEY_REUSE_DETECTED"
    
    # Nonce validation
    INVALID_NONCE_LENGTH = "INVALID_NONCE_LENGTH"
    NONCE_REUSE_DETECTED = "NONCE_REUSE_DETECTED"
    PREDICTABLE_NONCE = "PREDICTABLE_NONCE"
    
    # Algorithm validation
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    DEPRECATED_ALGORITHM = "DEPRECATED_ALGORITHM"
    INSECURE_ALGORITHM = "INSECURE_ALGORITHM"
    
    # Parameter validation
    INVALID_ITERATION_COUNT = "INVALID_ITERATION_COUNT"
    INVALID_SALT_LENGTH = "INVALID_SALT_LENGTH"
    PARAMETER_OUT_OF_RANGE = "PARAMETER_OUT_OF_RANGE"
    
    # General
    TYPE_MISMATCH = "TYPE_MISMATCH"
    MISSING_REQUIRED = "MISSING_REQUIRED"
    FORBIDDEN_VALUE = "FORBIDDEN_VALUE"


@dataclass
class CryptoValidationResult:
    """Result of a cryptographic validation check."""
    passed: bool
    error_code: Optional[CryptoValidationErrorCode] = None
    message: str = ""
    severity: CryptoValidationSeverity = CryptoValidationSeverity.ERROR
    field_name: Optional[str] = None
    algorithm: Optional[str] = None
    original_value: Any = None


@dataclass
class CryptoValidationContext:
    """Shared context for crypto validation operations."""
    strict_mode: bool = True  # Default strict for crypto
    fail_fast: bool = True
    allow_deprecated: bool = False
    allow_experimental: bool = False
    minimum_security_level: int = 128  # bits
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    
    def __post_init__(self):
        """Initialize context lock."""
        self._lock = threading.Lock()


class CryptoKeyValidator:
    """Cryptographic key material validation."""
    
    # Standard key lengths (bits) for common algorithms
    STANDARD_KEY_LENGTHS = {
        # AES
        'AES-128': {128},
        'AES-192': {192},
        'AES-256': {256},
        'AES': {128, 192, 256},
        
        # Post-quantum algorithms (typical key sizes)
        'CRYSTALS-KYBER': {1632, 2400, 3168},  # 512, 768, 1024 security levels
        'KYBER': {1632, 2400, 3168},
        'CRYSTALS-DILITHIUM': {1312, 1952, 2592},
        'DILITHIUM': {1312, 1952, 2592},
        'FALCON': {1280, 2304},
        'SPHINCS+': {64, 96, 128},
        
        # Hash-based
        'SHA256': {256},
        'SHA3-256': {256},
        'SHA512': {512},
        'SHA3-512': {512},
        
        # HMAC
        'HMAC-SHA256': {128, 160, 256, 512},
        'HMAC-SHA512': {256, 512},
        
        # Generic
        'SYMMETRIC': {128, 192, 256, 512},
        'ASYMMETRIC': {2048, 3072, 4096},
    }
    
    # Known weak patterns (constant-time detection)
    WEAK_KEY_PATTERNS = [
        b'\x00' * 8,      # All zeros
        b'\xff' * 8,      # All ones
        b'\x01' * 8,      # All 0x01
        b'01234567',      # Sequential
        b'password',      # Literal
        b'12345678',      # Numeric sequence
    ]
    
    @staticmethod
    def _constant_time_compare(a: bytes, b: bytes) -> bool:
        """Constant-time byte comparison to prevent timing attacks."""
        return hmac.compare_digest(a, b)
    
    @classmethod
    def validate_key_length(cls, key: bytes, 
                           algorithm: str = "SYMMETRIC",
                           field_name: str = "key") -> CryptoValidationResult:
        """
        Validate key length for a given algorithm.
        
        Args:
            key: Key bytes to validate
            algorithm: Algorithm name for length checking
            field_name: Field name for error reporting
            
        Returns:
            Validation result
        """
        if not isinstance(key, bytes):
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.TYPE_MISMATCH,
                message="Key must be bytes",
                field_name=field_name,
                algorithm=algorithm
            )
        
        key_bits = len(key) * 8
        allowed_lengths = cls.STANDARD_KEY_LENGTHS.get(
            algorithm.upper(), 
            cls.STANDARD_KEY_LENGTHS['SYMMETRIC']
        )
        
        if key_bits not in allowed_lengths:
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.INVALID_KEY_LENGTH,
                message=f"Invalid key length {key_bits} bits for {algorithm}. "
                       f"Expected one of: {sorted(allowed_lengths)}",
                field_name=field_name,
                algorithm=algorithm
            )
        
        return CryptoValidationResult(
            passed=True,
            field_name=field_name,
            algorithm=algorithm
        )
    
    @classmethod
    def detect_weak_key(cls, key: bytes, 
                       field_name: str = "key") -> CryptoValidationResult:
        """
        Detect weak/known-bad key patterns.
        Uses constant-time comparisons to prevent timing side-channels.
        
        Args:
            key: Key bytes to check
            field_name: Field name for error reporting
            
        Returns:
            Validation result
        """
        if not isinstance(key, bytes):
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.TYPE_MISMATCH,
                message="Key must be bytes",
                field_name=field_name
            )
        
        # Check for repeated byte patterns (constant-time approach)
        if len(key) >= 8:
            for pattern in cls.WEAK_KEY_PATTERNS:
                if len(key) >= len(pattern):
                    # Check if key starts with weak pattern (constant time)
                    if cls._constant_time_compare(key[:len(pattern)], pattern):
                        return CryptoValidationResult(
                            passed=False,
                            error_code=CryptoValidationErrorCode.WEAK_KEY,
                            message="Key contains known weak pattern",
                            severity=CryptoValidationSeverity.CRITICAL,
                            field_name=field_name
                        )
        
        # Check for low entropy (very basic check)
        if len(set(key)) < min(4, len(key)):
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.WEAK_KEY,
                message="Key has very low entropy",
                severity=CryptoValidationSeverity.WARNING,
                field_name=field_name
            )
        
        return CryptoValidationResult(passed=True, field_name=field_name)
    
    @classmethod
    def validate_nonce(cls, nonce: bytes, 
                      expected_length: Optional[int] = None,
                      field_name: str = "nonce") -> CryptoValidationResult:
        """
        Validate nonce/counter/IV format and length.
        
        Args:
            nonce: Nonce bytes to validate
            expected_length: Expected nonce length in bytes
            field_name: Field name for error reporting
            
        Returns:
            Validation result
        """
        if not isinstance(nonce, bytes):
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.TYPE_MISMATCH,
                message="Nonce must be bytes",
                field_name=field_name
            )
        
        if expected_length is not None and len(nonce) != expected_length:
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.INVALID_NONCE_LENGTH,
                message=f"Nonce length {len(nonce)} != expected {expected_length}",
                field_name=field_name
            )
        
        return CryptoValidationResult(passed=True, field_name=field_name)


class CryptoAlgorithmValidator:
    """Cryptographic algorithm validation."""
    
    # Algorithm classification
    SECURE_ALGORITHMS = {
        # Post-quantum (NIST selected)
        'CRYSTALS-KYBER', 'KYBER',
        'CRYSTALS-DILITHIUM', 'DILITHIUM',
        'FALCON', 'SPHINCS+',
        
        # Symmetric
        'AES-128-GCM', 'AES-192-GCM', 'AES-256-GCM',
        'AES-128-CCM', 'AES-256-CCM',
        'CHACHA20-POLY1305',
        
        # Hashes
        'SHA-256', 'SHA-384', 'SHA-512',
        'SHA3-256', 'SHA3-384', 'SHA3-512',
        
        # Key derivation
        'HKDF-SHA256', 'HKDF-SHA512',
        'PBKDF2-HMAC-SHA256', 'PBKDF2-HMAC-SHA512',
        'ARGON2ID',
    }
    
    DEPRECATED_ALGORITHMS = {
        'SHA-1', 'MD5', 'MD4',
        'DES', '3DES', 'RC4',
        'AES-ECB',
    }
    
    INSECURE_ALGORITHMS = {
        'NONE', 'NULL', 'PLAINTEXT',
        'XOR', 'ROT13',
    }
    
    @classmethod
    def validate_algorithm(cls, algorithm: str,
                          context: Optional[CryptoValidationContext] = None,
                          field_name: str = "algorithm") -> CryptoValidationResult:
        """
        Validate algorithm is secure and allowed.
        
        Args:
            algorithm: Algorithm name to validate
            context: Validation context
            field_name: Field name for error reporting
            
        Returns:
            Validation result
        """
        ctx = context or CryptoValidationContext()
        algo_upper = algorithm.upper().strip()
        
        if algo_upper in cls.INSECURE_ALGORITHMS:
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.INSECURE_ALGORITHM,
                message=f"Algorithm '{algorithm}' is cryptographically insecure",
                severity=CryptoValidationSeverity.CRITICAL,
                field_name=field_name,
                algorithm=algorithm
            )
        
        if algo_upper in cls.DEPRECATED_ALGORITHMS:
            if ctx.allow_deprecated:
                return CryptoValidationResult(
                    passed=True,
                    severity=CryptoValidationSeverity.WARNING,
                    message=f"Algorithm '{algorithm}' is deprecated",
                    field_name=field_name,
                    algorithm=algorithm
                )
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.DEPRECATED_ALGORITHM,
                message=f"Algorithm '{algorithm}' is deprecated and not allowed",
                severity=CryptoValidationSeverity.ERROR,
                field_name=field_name,
                algorithm=algorithm
            )
        
        if algo_upper not in cls.SECURE_ALGORITHMS:
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.UNSUPPORTED_ALGORITHM,
                message=f"Algorithm '{algorithm}' is not in approved list",
                field_name=field_name,
                algorithm=algorithm
            )
        
        return CryptoValidationResult(
            passed=True,
            field_name=field_name,
            algorithm=algorithm
        )


class CryptoParameterValidator:
    """Cryptographic parameter validation."""
    
    @staticmethod
    def validate_iterations(iterations: int,
                           min_iterations: int = 10000,
                           max_iterations: int = 1000000,
                           field_name: str = "iterations") -> CryptoValidationResult:
        """
        Validate KDF iteration count.
        
        Args:
            iterations: Number of iterations
            min_iterations: Minimum allowed
            max_iterations: Maximum allowed
            field_name: Field name for reporting
            
        Returns:
            Validation result
        """
        if not isinstance(iterations, int):
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.TYPE_MISMATCH,
                message="Iterations must be integer",
                field_name=field_name
            )
        
        if iterations < min_iterations:
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.INVALID_ITERATION_COUNT,
                message=f"Iterations {iterations} below minimum {min_iterations}",
                severity=CryptoValidationSeverity.WARNING,
                field_name=field_name
            )
        
        if iterations > max_iterations:
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.INVALID_ITERATION_COUNT,
                message=f"Iterations {iterations} above maximum {max_iterations}",
                field_name=field_name
            )
        
        return CryptoValidationResult(passed=True, field_name=field_name)
    
    @staticmethod
    def validate_salt(salt: bytes,
                     min_length: int = 16,
                     max_length: int = 64,
                     field_name: str = "salt") -> CryptoValidationResult:
        """
        Validate salt for KDF operations.
        
        Args:
            salt: Salt bytes
            min_length: Minimum salt length
            max_length: Maximum salt length
            field_name: Field name for reporting
            
        Returns:
            Validation result
        """
        if not isinstance(salt, bytes):
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.TYPE_MISMATCH,
                message="Salt must be bytes",
                field_name=field_name
            )
        
        if len(salt) < min_length:
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.INVALID_SALT_LENGTH,
                message=f"Salt length {len(salt)} below minimum {min_length}",
                field_name=field_name
            )
        
        if len(salt) > max_length:
            return CryptoValidationResult(
                passed=False,
                error_code=CryptoValidationErrorCode.INVALID_SALT_LENGTH,
                message=f"Salt length {len(salt)} above maximum {max_length}",
                field_name=field_name
            )
        
        return CryptoValidationResult(passed=True, field_name=field_name)


class CryptoValidationError(Exception):
    """Exception raised when crypto validation fails."""
    
    def __init__(self, result: CryptoValidationResult):
        self.result = result
        super().__init__(f"{result.error_code.value}: {result.message}")


def validate_crypto_input(**rules: Dict[str, Any]):
    """
    Decorator to validate cryptographic function inputs.
    
    Usage:
        @validate_crypto_input(
            key={'algorithm': 'AES-256', 'check_weak': True},
            nonce={'length': 12},
            algorithm={'secure_only': True}
        )
        def encrypt(key: bytes, nonce: bytes, plaintext: bytes, algorithm: str):
            ...
    
    Args:
        **rules: Validation rules per parameter name
        
    Returns:
        Decorated function with crypto input validation
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import inspect
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            
            ctx = CryptoValidationContext()
            
            for param_name, param_rules in rules.items():
                if param_name not in bound.arguments:
                    if param_rules.get('required', True):
                        raise CryptoValidationError(CryptoValidationResult(
                            passed=False,
                            error_code=CryptoValidationErrorCode.MISSING_REQUIRED,
                            message=f"Missing required crypto parameter: {param_name}",
                            field_name=param_name
                        ))
                    continue
                
                value = bound.arguments[param_name]
                
                # Key validation
                if 'algorithm' in param_rules:
                    result = CryptoKeyValidator.validate_key_length(
                        value, 
                        param_rules['algorithm'],
                        param_name
                    )
                    if not result.passed:
                        raise CryptoValidationError(result)
                
                if param_rules.get('check_weak', False):
                    result = CryptoKeyValidator.detect_weak_key(value, param_name)
                    if not result.passed and ctx.strict_mode:
                        raise CryptoValidationError(result)
                
                # Nonce validation
                if 'length' in param_rules and 'nonce' in param_name.lower():
                    result = CryptoKeyValidator.validate_nonce(
                        value,
                        param_rules['length'],
                        param_name
                    )
                    if not result.passed:
                        raise CryptoValidationError(result)
                
                # Algorithm validation
                if param_rules.get('secure_only', False):
                    result = CryptoAlgorithmValidator.validate_algorithm(
                        str(value), 
                        ctx,
                        param_name
                    )
                    if not result.passed:
                        raise CryptoValidationError(result)
                
                # Iterations validation
                if param_rules.get('validate_kdf_iterations', False):
                    result = CryptoParameterValidator.validate_iterations(value)
                    if not result.passed:
                        raise CryptoValidationError(result)
                
                # Salt validation
                if param_rules.get('validate_salt', False):
                    result = CryptoParameterValidator.validate_salt(value)
                    if not result.passed:
                        raise CryptoValidationError(result)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Global shared instances - thread-safe
_default_key_validator = CryptoKeyValidator()
_default_algo_validator = CryptoAlgorithmValidator()
_default_param_validator = CryptoParameterValidator()
_global_lock = threading.Lock()


def get_key_validator() -> CryptoKeyValidator:
    """Get shared key validator instance."""
    with _global_lock:
        return _default_key_validator


def get_algorithm_validator() -> CryptoAlgorithmValidator:
    """Get shared algorithm validator instance."""
    with _global_lock:
        return _default_algo_validator


def get_parameter_validator() -> CryptoParameterValidator:
    """Get shared parameter validator instance."""
    with _global_lock:
        return _default_param_validator


# Export public API
__all__ = [
    # Classes
    'CryptoKeyValidator',
    'CryptoAlgorithmValidator',
    'CryptoParameterValidator',
    'CryptoValidationContext',
    'CryptoValidationResult',
    'CryptoValidationError',
    'CryptoValidationSeverity',
    'CryptoValidationErrorCode',
    
    # Decorators
    'validate_crypto_input',
    
    # Factory functions
    'get_key_validator',
    'get_algorithm_validator',
    'get_parameter_validator',
]
