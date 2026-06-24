"""
Input Validation Wrappers v23 - QuantumCrypt-AI
Security Hardening - Dimension B

Provides input validation wrappers for cryptographic operations.
Validates all inputs BEFORE they reach core crypto functions.

API Stability: STABLE
Backward Compatible: YES
Layered ON TOP - does NOT modify core crypto code
"""

import re
from typing import Any, Callable, Optional, TypeVar, Union, List, Dict
from functools import wraps


class ValidationError(Exception):
    """Base exception for input validation failures."""
    pass


class InvalidInputError(ValidationError):
    """Raised when input fails validation."""
    pass


class SecurityViolationError(ValidationError):
    """Raised when a security policy is violated."""
    pass


T = TypeVar('T')


class InputValidator:
    """
    Comprehensive input validation utilities for cryptographic operations.
    
    All validations are performed BEFORE any cryptographic operations occur.
    """
    
    # Regex patterns
    HEX_PATTERN = re.compile(r'^[0-9a-fA-F]*$')
    BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    PRINTABLE_ASCII_PATTERN = re.compile(r'^[\x20-\x7E]*$')
    
    @staticmethod
    def validate_bytes(data: Any, min_len: int = 0, max_len: Optional[int] = None,
                      exact_len: Optional[int] = None, name: str = "data") -> bytes:
        """
        Validate input is bytes and meets length requirements.
        
        Args:
            data: Input to validate
            min_len: Minimum allowed length
            max_len: Maximum allowed length
            exact_len: Exact required length
            name: Name for error messages
            
        Returns:
            Validated bytes
            
        Raises:
            InvalidInputError: If validation fails
        """
        if not isinstance(data, (bytes, bytearray)):
            raise InvalidInputError(f"{name} must be bytes or bytearray")
        
        data_bytes = bytes(data)
        length = len(data_bytes)
        
        if exact_len is not None and length != exact_len:
            raise InvalidInputError(
                f"{name} must be exactly {exact_len} bytes, got {length}"
            )
        
        if length < min_len:
            raise InvalidInputError(
                f"{name} must be at least {min_len} bytes, got {length}"
            )
        
        if max_len is not None and length > max_len:
            raise InvalidInputError(
                f"{name} must be at most {max_len} bytes, got {length}"
            )
        
        return data_bytes
    
    @staticmethod
    def validate_key(key: Any, key_size: int, name: str = "key") -> bytes:
        """
        Validate a cryptographic key.
        
        Args:
            key: Key to validate
            key_size: Required key size in bytes
            name: Name for error messages
            
        Returns:
            Validated key bytes
        """
        return InputValidator.validate_bytes(
            key, exact_len=key_size, name=name
        )
    
    @staticmethod
    def validate_nonce(nonce: Any, nonce_size: int, name: str = "nonce") -> bytes:
        """
        Validate a nonce/IV.
        
        Args:
            nonce: Nonce to validate
            nonce_size: Required nonce size in bytes
            name: Name for error messages
            
        Returns:
            Validated nonce bytes
        """
        return InputValidator.validate_bytes(
            nonce, exact_len=nonce_size, name=name
        )
    
    @staticmethod
    def validate_hex_string(data: str, min_len: int = 0,
                           max_len: Optional[int] = None,
                           name: str = "hex string") -> str:
        """
        Validate a hexadecimal string.
        
        Args:
            data: String to validate
            min_len: Minimum character length
            max_len: Maximum character length
            name: Name for error messages
            
        Returns:
            Validated hex string
        """
        if not isinstance(data, str):
            raise InvalidInputError(f"{name} must be a string")
        
        if not InputValidator.HEX_PATTERN.match(data):
            raise InvalidInputError(f"{name} contains invalid hex characters")
        
        if len(data) < min_len:
            raise InvalidInputError(f"{name} too short")
        
        if max_len is not None and len(data) > max_len:
            raise InvalidInputError(f"{name} too long")
        
        return data
    
    @staticmethod
    def validate_base64_string(data: str, name: str = "base64 string") -> str:
        """
        Validate a base64 encoded string.
        
        Args:
            data: String to validate
            name: Name for error messages
            
        Returns:
            Validated base64 string
        """
        if not isinstance(data, str):
            raise InvalidInputError(f"{name} must be a string")
        
        if not InputValidator.BASE64_PATTERN.match(data):
            raise InvalidInputError(f"{name} contains invalid base64 characters")
        
        return data
    
    @staticmethod
    def validate_integer(value: Any, min_val: Optional[int] = None,
                        max_val: Optional[int] = None,
                        name: str = "integer") -> int:
        """
        Validate an integer within bounds.
        
        Args:
            value: Value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            name: Name for error messages
            
        Returns:
            Validated integer
        """
        if not isinstance(value, int):
            raise InvalidInputError(f"{name} must be an integer")
        
        if min_val is not None and value < min_val:
            raise InvalidInputError(f"{name} must be >= {min_val}")
        
        if max_val is not None and value > max_val:
            raise InvalidInputError(f"{name} must be <= {max_val}")
        
        return value
    
    @staticmethod
    def validate_plaintext(plaintext: Any, max_len: int = 10 * 1024 * 1024,
                          name: str = "plaintext") -> bytes:
        """
        Validate plaintext before encryption.
        
        Args:
            plaintext: Plaintext to validate
            max_len: Maximum allowed length (default 10MB)
            name: Name for error messages
            
        Returns:
            Validated plaintext bytes
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        return InputValidator.validate_bytes(
            plaintext, min_len=1, max_len=max_len, name=name
        )
    
    @staticmethod
    def validate_ciphertext(ciphertext: Any, min_len: int = 16,
                           max_len: int = 100 * 1024 * 1024,
                           name: str = "ciphertext") -> bytes:
        """
        Validate ciphertext before decryption.
        
        Args:
            ciphertext: Ciphertext to validate
            min_len: Minimum allowed length
            max_len: Maximum allowed length
            name: Name for error messages
            
        Returns:
            Validated ciphertext bytes
        """
        return InputValidator.validate_bytes(
            ciphertext, min_len=min_len, max_len=max_len, name=name
        )
    
    @staticmethod
    def sanitize_string(s: str, allow_unicode: bool = False) -> str:
        """
        Sanitize a string by removing potentially dangerous characters.
        
        Args:
            s: String to sanitize
            allow_unicode: Whether to allow non-ASCII characters
            
        Returns:
            Sanitized string
        """
        if not allow_unicode:
            # Only allow printable ASCII
            if not InputValidator.PRINTABLE_ASCII_PATTERN.match(s):
                # Filter to only printable ASCII
                s = ''.join(c for c in s if 0x20 <= ord(c) <= 0x7E)
        
        # Remove control characters
        s = ''.join(c for c in s if ord(c) >= 0x20 or c in '\n\r\t')
        
        return s
    
    @staticmethod
    def prevent_null_bytes(data: bytes, name: str = "data") -> None:
        """
        Check for and reject null bytes.
        
        Args:
            data: Bytes to check
            name: Name for error messages
            
        Raises:
            SecurityViolationError: If null bytes found
        """
        if b'\x00' in data:
            raise SecurityViolationError(f"{name} contains null bytes")


class ValidatedCryptoWrapper:
    """
    Wrapper class that adds input validation to cryptographic functions.
    
    Usage:
        wrapper = ValidatedCryptoWrapper()
        
        @wrapper.validate_inputs(
            key=lambda k: InputValidator.validate_key(k, 32),
            plaintext=lambda p: InputValidator.validate_plaintext(p)
        )
        def encrypt(key, plaintext):
            # core crypto function
            pass
    """
    
    def __init__(self):
        self.validation_count = 0
        self.rejection_count = 0
    
    def validate_inputs(self, **validators: Callable) -> Callable:
        """
        Decorator to validate function inputs.
        
        Args:
            **validators: Mapping of parameter names to validator functions
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            @wraps(func)
            def wrapper(*args, **kwargs) -> T:
                import inspect
                sig = inspect.signature(func)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                
                # Validate each parameter
                for param_name, validator in validators.items():
                    if param_name in bound.arguments:
                        try:
                            bound.arguments[param_name] = validator(
                                bound.arguments[param_name]
                            )
                            self.validation_count += 1
                        except ValidationError:
                            self.rejection_count += 1
                            raise
                
                # Call the original function with validated inputs
                return func(*bound.args, **bound.kwargs)
            
            return wrapper
        return decorator
    
    def get_stats(self) -> Dict[str, int]:
        """Get validation statistics."""
        return {
            'validations_performed': self.validation_count,
            'rejections': self.rejection_count
        }


class SecurityPolicy:
    """
    Enforce security policies on cryptographic operations.
    """
    
    MIN_KEY_SIZE_AES = 16  # 128 bits
    MIN_KEY_SIZE_STRONG = 32  # 256 bits
    
    @staticmethod
    def enforce_min_key_size(key: bytes, min_size: int = 32) -> None:
        """
        Enforce minimum key size policy.
        
        Args:
            key: Key to check
            min_size: Minimum required size in bytes
            
        Raises:
            SecurityViolationError: If policy violated
        """
        if len(key) < min_size:
            raise SecurityViolationError(
                f"Key size {len(key)} bytes below minimum {min_size} bytes"
            )
    
    @staticmethod
    def enforce_no_weak_keys(key: bytes) -> None:
        """
        Check for and reject weak keys.
        
        Args:
            key: Key to check
            
        Raises:
            SecurityViolationError: If weak key detected
        """
        # Check for all zeros
        if all(b == 0 for b in key):
            raise SecurityViolationError("All-zero key detected")
        
        # Check for all same bytes
        if len(set(key)) == 1:
            raise SecurityViolationError("Weak key: all bytes identical")
        
        # Check for repeated patterns (simple check)
        half = len(key) // 2
        if half > 0 and key[:half] == key[half:]:
            raise SecurityViolationError("Weak key: repeated pattern detected")
    
    @staticmethod
    def enforce_max_operations_per_second(count: int, max_ops: int = 1000) -> None:
        """
        Enforce rate limiting policy.
        
        Args:
            count: Current operation count
            max_ops: Maximum allowed operations
            
        Raises:
            SecurityViolationError: If rate exceeded
        """
        if count > max_ops:
            raise SecurityViolationError(
                f"Operation rate exceeded: {count} > {max_ops}"
            )


# Global wrapper instance for convenience
crypto_validator = ValidatedCryptoWrapper()


# Export public API
__all__ = [
    'ValidationError',
    'InvalidInputError',
    'SecurityViolationError',
    'InputValidator',
    'ValidatedCryptoWrapper',
    'SecurityPolicy',
    'crypto_validator',
]
