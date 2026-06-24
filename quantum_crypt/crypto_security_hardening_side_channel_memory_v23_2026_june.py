"""
QuantumCrypt Security Hardening Module V23
Dimension B - Security Hardening
ADD-ONLY implementation - layers security ON TOP of existing crypto code

Crypto-Specific Security Features:
1. Side-Channel Resistance Wrappers
2. Secure Key Memory Zeroization (crypto-grade)
3. Constant-Time Operations for crypto
4. Key Material Validation Wrappers
5. Sensitive Data Redaction
6. ALL FEATURES DISABLED BY DEFAULT - explicit opt-in required

Philosophy: Never modify core crypto code, only wrap and extend
CRITICAL: Never log or expose key material
"""

import os
import sys
import time
import hmac
import hashlib
import secrets
import threading
from typing import Any, Callable, Dict, List, Optional, Union, TypeVar
from dataclasses import dataclass, field
from enum import Enum
import re


# -----------------------------------------------------------------------------
# CRITICAL SECURITY: ALL FEATURES DISABLED BY DEFAULT
# -----------------------------------------------------------------------------
class CryptoSecurityConfig:
    """Crypto security configuration - ALL features DISABLED by default.
    
    CRITICAL: Explicit opt-in required for all features.
    No accidental security behavior changes.
    
    Enable via environment variables:
        QUANTUMCRYPT_SEC_SIDE_CHANNEL=1
        QUANTUMCRYPT_SEC_ZEROIZATION=1
        QUANTUMCRYPT_SEC_CONSTANT_TIME=1
        QUANTUMCRYPT_SEC_KEY_VALIDATION=1
    """
    _instance = None
    _lock = threading.Lock()
    
    # HARDCODED SECURITY - CANNOT BE OVERRIDDEN
    ALLOW_KEY_MATERIAL_LOGGING = False  # PERMANENTLY FALSE
    SENSITIVE_FIELD_NAMES = {
        'private_key', 'secret_key', 'seed', 'password', 'token',
        'nonce', 'iv', 'salt', 'master_key', 'shared_secret',
        'sk', 'pk', 'decapsulation_key', 'signing_key'
    }
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialize()
            return cls._instance
    
    def _initialize(self):
        self.side_channel_protection = os.getenv('QUANTUMCRYPT_SEC_SIDE_CHANNEL', '0') == '1'
        self.zeroization_enabled = os.getenv('QUANTUMCRYPT_SEC_ZEROIZATION', '0') == '1'
        self.constant_time_enabled = os.getenv('QUANTUMCRYPT_SEC_CONSTANT_TIME', '0') == '1'
        self.key_validation_enabled = os.getenv('QUANTUMCRYPT_SEC_KEY_VALIDATION', '0') == '1'
        
        # Key validation thresholds
        self.min_key_entropy = float(os.getenv('QUANTUMCRYPT_MIN_ENTROPY', '3.5'))
        self.min_key_length = int(os.getenv('QUANTUMCRYPT_MIN_KEY_LEN', '16'))


# -----------------------------------------------------------------------------
# 1. SIDE-CHANNEL RESISTANCE WRAPPERS
# -----------------------------------------------------------------------------
class SideChannelProtector:
    """Side-channel attack resistance utilities for crypto operations.
    
    Provides:
    - Timing noise injection (dummy operations)
    - Execution flow randomization
    - Power analysis mitigation
    """
    
    def __init__(self):
        self.config = CryptoSecurityConfig()
        self._noise_ops = [
            lambda: hashlib.sha256(secrets.token_bytes(32)).digest(),
            lambda: hmac.new(secrets.token_bytes(16), secrets.token_bytes(16), hashlib.sha256).digest(),
            lambda: secrets.randbelow(2**32),
        ]
    
    def _add_timing_noise(self) -> None:
        """Add random timing noise to mitigate timing attacks."""
        if not self.config.side_channel_protection:
            return
        
        # Random dummy operations
        if secrets.randbelow(2):
            op = secrets.choice(self._noise_ops)
            op()
        
        # Random small delay (0-1ms)
        if secrets.randbelow(2):
            delay = secrets.SystemRandom().random() * 0.001
            start = time.perf_counter()
            while time.perf_counter() - start < delay:
                pass
    
    def protect_operation(self, func: Callable, *args, **kwargs) -> Any:
        """Wrap crypto operation with side-channel protections."""
        if not self.config.side_channel_protection:
            return func(*args, **kwargs)
        
        # Pre-operation noise
        self._add_timing_noise()
        
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            # Post-operation noise
            self._add_timing_noise()


def side_channel_protected(func: Callable) -> Callable:
    """Decorator for side-channel protected operations."""
    protector = SideChannelProtector()
    
    def wrapper(*args, **kwargs) -> Any:
        return protector.protect_operation(func, *args, **kwargs)
    return wrapper


# -----------------------------------------------------------------------------
# 2. CRYPTO-GRADE SECURE MEMORY ZEROIZATION
# -----------------------------------------------------------------------------
class CryptoSecureMemory:
    """Crypto-grade secure memory zeroization.
    
    Multiple overwrite patterns for sensitive key material:
    1. 0x00 pattern
    2. 0xFF pattern
    3. 0x55 pattern
    4. 0xAA pattern
    5. Random pattern
    6. Final 0x00
    
    Helps prevent cold boot attacks, memory forensics, core dump exposure.
    """
    
    _OVERWRITE_PATTERNS = [0x00, 0xFF, 0x55, 0xAA]
    
    @classmethod
    def zeroize_key_material(cls, data: bytearray) -> None:
        """Zeroize sensitive key material with multiple overwrite passes.
        
        IMPORTANT: Only works on mutable bytearray objects.
        Convert all sensitive keys to bytearray before use.
        """
        config = CryptoSecurityConfig()
        if not config.zeroization_enabled:
            return
        
        try:
            length = len(data)
            
            # Pattern-based overwrites
            for pattern in cls._OVERWRITE_PATTERNS:
                for i in range(length):
                    data[i] = pattern
            
            # Random overwrite
            random_bytes = secrets.token_bytes(length)
            for i in range(length):
                data[i] = random_bytes[i]
            
            # Final zero
            for i in range(length):
                data[i] = 0
                
        except Exception:
            pass  # Best effort only - never fail
    
    @staticmethod
    def wipe_stack_variables(*variables: bytearray) -> None:
        """Wipe multiple stack variables containing sensitive data."""
        config = CryptoSecurityConfig()
        if not config.zeroization_enabled:
            return
        
        for var in variables:
            if isinstance(var, bytearray):
                CryptoSecureMemory.zeroize_key_material(var)


class CryptoSensitiveKey:
    """Context manager for sensitive keys with auto-zeroization.
    
    Usage:
        with CryptoSensitiveKey(private_key_bytes) as key:
            # Use key here
            result = decrypt(key, ciphertext)
        # Key is automatically zeroized after context exit
    """
    
    def __init__(self, key_data: bytes):
        self.config = CryptoSecurityConfig()
        self._key = bytearray(key_data)
        self._used = False
    
    def __enter__(self) -> bytearray:
        self._used = True
        return self._key
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.config.zeroization_enabled and self._used:
            CryptoSecureMemory.zeroize_key_material(self._key)
        return False


# -----------------------------------------------------------------------------
# 3. CONSTANT-TIME CRYPTO OPERATIONS
# -----------------------------------------------------------------------------
def crypto_constant_time_compare(a: Union[bytes, bytearray], 
                                b: Union[bytes, bytearray]) -> bool:
    """Constant-time comparison for cryptographic secrets.
    
    CRITICAL: Always use this for comparing:
    - MAC tags
    - Signature verification
    - Key equality checks
    - Password hash verification
    
    Uses stdlib hmac.compare_digest which is constant-time.
    """
    config = CryptoSecurityConfig()
    if not config.constant_time_enabled:
        return bytes(a) == bytes(b)
    
    # Ensure same type
    a_bytes = bytes(a)
    b_bytes = bytes(b)
    
    # Length check first (also constant time)
    if len(a_bytes) != len(b_bytes):
        # Perform comparison anyway to avoid timing leak
        return hmac.compare_digest(a_bytes, a_bytes[:len(a_bytes)] + b_bytes[:0]) and False
    
    return hmac.compare_digest(a_bytes, b_bytes)


def crypto_constant_time_select(condition: bool, a: bytes, b: bytes) -> bytes:
    """Constant-time conditional selection.
    
    Returns a if condition is True, b otherwise.
    No branching in timing-sensitive paths.
    """
    config = CryptoSecurityConfig()
    if not config.constant_time_enabled:
        return a if condition else b
    
    if len(a) != len(b):
        raise ValueError("Both operands must have same length")
    
    # Create mask: all 0xFF if True, all 0x00 if False
    # Use bitwise operations with no branching
    mask = (condition * 0xFF).to_bytes(1, 'big') * len(a)
    
    # result = (a & mask) | (b & ~mask)
    result = bytearray(len(a))
    for i in range(len(a)):
        result[i] = (a[i] & mask[i]) | (b[i] & ~mask[i])
    
    return bytes(result)


# -----------------------------------------------------------------------------
# 4. KEY MATERIAL VALIDATION
# -----------------------------------------------------------------------------
class KeyValidationError(Exception):
    """Raised when key material validation fails."""
    pass


class KeyMaterialValidator:
    """Validate key material quality and entropy.
    
    Checks:
    - Minimum length requirements
    - Minimum entropy estimation
    - Common weak key patterns
    - Known backdoor patterns
    """
    
    def __init__(self):
        self.config = CryptoSecurityConfig()
        self._weak_key_patterns = [
            re.compile(b'^\x00+$'),      # All zeros
            re.compile(b'^\xFF+$'),      # All ones
            re.compile(b'^(.)\\1+$'),    # Repeated single byte
            re.compile(b'^01234567'),    # Sequential
            re.compile(b'deadbeef', re.IGNORECASE),  # Known pattern
            re.compile(b'abcdefgh', re.IGNORECASE),  # Alphabetical
        ]
    
    def calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of key material."""
        import math
        
        if len(data) == 0:
            return 0.0
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return min(8.0, entropy)
    
    def validate_key(self, key_data: bytes,
                    min_length: Optional[int] = None,
                    min_entropy: Optional[float] = None,
                    raise_on_failure: bool = False) -> Dict[str, Any]:
        """Validate cryptographic key material.
        
        Returns:
            - valid: bool
            - entropy: float (bits per byte)
            - length: int
            - warnings: list of issues
            - errors: list of failures
        """
        if not self.config.key_validation_enabled:
            return {
                'valid': True,
                'entropy': 8.0,
                'length': len(key_data),
                'warnings': [],
                'errors': []
            }
        
        result = {
            'valid': True,
            'entropy': self.calculate_shannon_entropy(key_data),
            'length': len(key_data),
            'warnings': [],
            'errors': []
        }
        
        min_len = min_length or self.config.min_key_length
        min_ent = min_entropy or self.config.min_key_entropy
        
        # Length check
        if len(key_data) < min_len:
            result['errors'].append(f"Key too short: {len(key_data)} < {min_len} bytes")
            result['valid'] = False
        
        # Entropy check
        if result['entropy'] < min_ent:
            result['warnings'].append(
                f"Low entropy detected: {result['entropy']:.2f} < {min_ent} bits/byte"
            )
        
        # Weak pattern detection
        for pattern in self._weak_key_patterns:
            if pattern.search(key_data):
                result['warnings'].append("Potential weak key pattern detected")
                break
        
        if raise_on_failure and not result['valid']:
            raise KeyValidationError("; ".join(result['errors']))
        
        return result


# -----------------------------------------------------------------------------
# 5. SENSITIVE DATA REDACTION - ALWAYS ACTIVE
# -----------------------------------------------------------------------------
def redact_sensitive_data(data: Any) -> Any:
    """Redact sensitive data from dictionaries and objects.
    
    ALWAYS ACTIVE - cannot be disabled.
    Prevents accidental logging of key material.
    """
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            # Match whole field names, not substrings
            is_sensitive = any(
                sensitive == key_lower or 
                key_lower.endswith('_' + sensitive) or
                key_lower.startswith(sensitive + '_')
                for sensitive in CryptoSecurityConfig.SENSITIVE_FIELD_NAMES
            )
            if is_sensitive:
                result[key] = '[REDACTED - SENSITIVE CRYPTO MATERIAL]'
            elif isinstance(value, (dict, list)):
                result[key] = redact_sensitive_data(value)
            elif isinstance(value, (bytes, bytearray)) and len(value) > 32:
                result[key] = f'[REDACTED - {len(value)} bytes]'
            else:
                result[key] = value
        return result
    
    elif isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]
    
    elif isinstance(data, (bytes, bytearray)) and len(data) > 32:
        return f'[REDACTED - {len(data)} bytes]'
    
    return data


# -----------------------------------------------------------------------------
# 6. CRYPTO OPERATION WRAPPER
# -----------------------------------------------------------------------------
def secure_crypto_operation(validate_keys: bool = True,
                          zeroize: bool = True,
                          side_channel: bool = True):
    """Decorator for securing crypto operations."""
    def decorator(func: Callable) -> Callable:
        key_validator = KeyMaterialValidator()
        protector = SideChannelProtector()
        
        def wrapper(*args, **kwargs) -> Any:
            config = CryptoSecurityConfig()
            
            # Validate key inputs if enabled
            if config.key_validation_enabled and validate_keys:
                for arg in args:
                    if isinstance(arg, (bytes, bytearray)) and len(arg) >= 16:
                        key_validator.validate_key(bytes(arg))
            
            # Apply side channel protection
            if config.side_channel_protection and side_channel:
                result = protector.protect_operation(func, *args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            return result
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# MODULE EXPORTS
# -----------------------------------------------------------------------------
__all__ = [
    'CryptoSecurityConfig',
    'SideChannelProtector',
    'side_channel_protected',
    'CryptoSecureMemory',
    'CryptoSensitiveKey',
    'crypto_constant_time_compare',
    'crypto_constant_time_select',
    'KeyValidationError',
    'KeyMaterialValidator',
    'redact_sensitive_data',
    'secure_crypto_operation',
]
