"""
QuantumCrypt AI - Crypto Input Validation & Rate Limiting v23
Dimension B - Security Hardening
Incremental build - ADD-ONLY module, wraps existing functionality

Provides security hardening wrappers for cryptographic operations:
- Cryptographic input validation (key sizes, algorithm bounds)
- Operation rate limiting (DoS protection for expensive ops)
- Algorithm parameter validation
- Wraps existing crypto functions without modification
"""

import re
import time
from dataclasses import dataclass
from typing import Callable, Any, Dict, Optional, List
from functools import wraps
import logging

# Configure logging (opt-in only)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


@dataclass
class CryptoValidationResult:
    """Result of cryptographic input validation."""
    is_valid: bool
    error_message: Optional[str] = None
    validation_type: str = "general"
    sanitized_params: Optional[dict] = None


class CryptoInputValidator:
    """
    Cryptographic input validation wrapper.
    
    Validates parameters BEFORE they reach cryptographic operations:
    - Key sizes and formats
    - Algorithm parameters
    - Input bounds
    - Data length constraints
    
    Layers ON TOP of existing crypto functions - no core code modification.
    
    API Stability: STABLE
    """
    
    # Standard key size requirements (bits)
    KEY_SIZE_REQUIREMENTS = {
        'AES-128': 128,
        'AES-256': 256,
        'RSA-2048': 2048,
        'RSA-3072': 3072,
        'RSA-4096': 4096,
        'ECDSA-P256': 256,
        'ECDSA-P384': 384,
        'CRYSTALS-Kyber': 1568,  # Post-quantum
        'CRYSTALS-Dilithium': 1312,  # Post-quantum
    }
    
    # Minimum key sizes
    MIN_RSA_KEY_SIZE = 2048
    MIN_SYMMETRIC_KEY_SIZE = 128
    
    def __init__(self, enable_logging: bool = False):
        """
        Initialize crypto input validator.
        
        Args:
            enable_logging: Whether to enable operation logging (opt-in)
        """
        self._logging_enabled = enable_logging
        self._validation_count = 0
        self._rejection_count = 0
    
    def _log(self, message: str) -> None:
        """Conditional logging - only if explicitly enabled."""
        if self._logging_enabled:
            logger.debug(message)
    
    def validate_key_size(self, key_bytes: bytes, algorithm: str) -> CryptoValidationResult:
        """
        Validate key size matches algorithm requirements.
        
        Args:
            key_bytes: Key material as bytes
            algorithm: Algorithm name
            
        Returns:
            Validation result
        """
        key_bits = len(key_bytes) * 8
        
        if algorithm in self.KEY_SIZE_REQUIREMENTS:
            required = self.KEY_SIZE_REQUIREMENTS[algorithm]
            if key_bits != required:
                self._rejection_count += 1
                return CryptoValidationResult(
                    is_valid=False,
                    error_message=f"Invalid key size for {algorithm}: {key_bits} bits != {required} bits required",
                    validation_type="key_size"
                )
        
        # Generic minimums
        if algorithm.startswith('RSA') and key_bits < self.MIN_RSA_KEY_SIZE:
            self._rejection_count += 1
            return CryptoValidationResult(
                is_valid=False,
                error_message=f"RSA key too small: {key_bits} bits < {self.MIN_RSA_KEY_SIZE} minimum",
                validation_type="key_size_min"
            )
        
        self._validation_count += 1
        return CryptoValidationResult(is_valid=True, validation_type="key_size")
    
    def validate_nonce(self, nonce: bytes, expected_length: int) -> CryptoValidationResult:
        """
        Validate nonce/IV length.
        
        Args:
            nonce: Nonce bytes
            expected_length: Expected length in bytes
            
        Returns:
            Validation result
        """
        if len(nonce) != expected_length:
            self._rejection_count += 1
            return CryptoValidationResult(
                is_valid=False,
                error_message=f"Invalid nonce length: {len(nonce)} != {expected_length}",
                validation_type="nonce_length"
            )
        
        self._validation_count += 1
        return CryptoValidationResult(is_valid=True, validation_type="nonce")
    
    def validate_plaintext_length(self, plaintext: bytes, max_length: int = 10_000_000) -> CryptoValidationResult:
        """
        Validate plaintext/ciphertext doesn't exceed reasonable bounds.
        
        Args:
            plaintext: Input data
            max_length: Maximum allowed bytes
            
        Returns:
            Validation result
        """
        if len(plaintext) > max_length:
            self._rejection_count += 1
            return CryptoValidationResult(
                is_valid=False,
                error_message=f"Data exceeds max length: {len(plaintext)} > {max_length}",
                validation_type="data_length"
            )
        
        self._validation_count += 1
        return CryptoValidationResult(is_valid=True, validation_type="data_length")
    
    def validate_algorithm_name(self, algorithm: str, allowed: List[str]) -> CryptoValidationResult:
        """
        Validate algorithm is in allowed list (prevents algorithm switching attacks).
        
        Args:
            algorithm: Requested algorithm
            allowed: List of allowed algorithms
            
        Returns:
            Validation result
        """
        if algorithm not in allowed:
            self._rejection_count += 1
            return CryptoValidationResult(
                is_valid=False,
                error_message=f"Algorithm not allowed: {algorithm}",
                validation_type="algorithm"
            )
        
        self._validation_count += 1
        return CryptoValidationResult(is_valid=True, validation_type="algorithm")
    
    def validate_all_encryption_params(self, key: bytes, nonce: bytes, 
                                     plaintext: bytes, algorithm: str = 'AES-256') -> CryptoValidationResult:
        """Run all validations for encryption operation."""
        # Key validation
        key_result = self.validate_key_size(key, algorithm)
        if not key_result.is_valid:
            return key_result
        
        # Nonce validation (GCM mode = 12 bytes)
        nonce_result = self.validate_nonce(nonce, 12)
        if not nonce_result.is_valid:
            return nonce_result
        
        # Data validation
        data_result = self.validate_plaintext_length(plaintext)
        if not data_result.is_valid:
            return data_result
        
        self._log(f"Encryption params validated for {algorithm}")
        return CryptoValidationResult(is_valid=True, validation_type="complete_encryption")
    
    def get_validation_stats(self) -> dict:
        """Get validation statistics."""
        return {
            "total_validations": self._validation_count,
            "total_rejections": self._rejection_count,
            "rejection_rate": self._rejection_count / max(1, self._validation_count)
        }


class CryptoOperationRateLimiter:
    """
    Rate limiter for expensive cryptographic operations.
    
    Prevents DoS attacks against:
    - Key generation (asymmetric)
    - Signature verification
    - Post-quantum operations
    - Key derivation functions
    
    API Stability: STABLE
    """
    
    # Cost levels for different operations (requests per minute)
    OPERATION_COST = {
        'key_gen_rsa': 5,      # Expensive
        'key_gen_pq': 2,       # Very expensive (post-quantum)
        'sign_rsa': 10,
        'verify_rsa': 20,
        'sign_pq': 5,
        'verify_pq': 10,
        'encrypt_symmetric': 100,
        'decrypt_symmetric': 100,
        'kdf': 20,
    }
    
    def __init__(self, 
                 max_cost_per_minute: int = 500,
                 enable_logging: bool = False):
        """
        Initialize crypto operation rate limiter.
        
        Args:
            max_cost_per_minute: Maximum operation cost per window
            enable_logging: Whether to enable logging (opt-in)
        """
        self.max_cost = max_cost_per_minute
        self.window_seconds = 60
        self._logging_enabled = enable_logging
        
        # {client_id: [(timestamp, cost), ...]}
        self._client_ops: Dict[str, List[tuple]] = {}
    
    def _log(self, message: str) -> None:
        if self._logging_enabled:
            logger.debug(message)
    
    def _cleanup_old(self, client_id: str, now: float) -> None:
        """Remove operations outside current window."""
        cutoff = now - self.window_seconds
        if client_id in self._client_ops:
            self._client_ops[client_id] = [
                (ts, cost) for ts, cost in self._client_ops[client_id]
                if ts > cutoff
            ]
    
    def _get_current_cost(self, client_id: str, now: float) -> int:
        """Calculate total cost in current window."""
        self._cleanup_old(client_id, now)
        return sum(cost for _, cost in self._client_ops.get(client_id, []))
    
    def check_operation(self, operation_type: str, client_id: str = "global") -> bool:
        """
        Check if operation is allowed under rate limits.
        
        Args:
            operation_type: Type of crypto operation
            client_id: Client identifier
            
        Returns:
            True if allowed, False if rate limited
        """
        now = time.time()
        cost = self.OPERATION_COST.get(operation_type, 10)
        
        current_cost = self._get_current_cost(client_id, now)
        
        if current_cost + cost > self.max_cost:
            self._log(f"Rate limit exceeded for {operation_type}: {current_cost + cost}/{self.max_cost}")
            return False
        
        if client_id not in self._client_ops:
            self._client_ops[client_id] = []
        
        self._client_ops[client_id].append((now, cost))
        self._log(f"Operation {operation_type} allowed, cost={cost}, total={current_cost + cost}")
        return True
    
    def get_remaining_capacity(self, client_id: str = "global") -> int:
        """Get remaining capacity for client."""
        now = time.time()
        current = self._get_current_cost(client_id, now)
        return max(0, self.max_cost - current)


# Decorators for easy integration
def validate_crypto_input(validator: Optional[CryptoInputValidator] = None):
    """
    Decorator to validate cryptographic function inputs.
    
    Usage:
        @validate_crypto_input()
        def encrypt(key: bytes, nonce: bytes, plaintext: bytes):
            ...
    """
    val = validator or CryptoInputValidator()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(key: bytes, nonce: bytes, plaintext: bytes, **kwargs):
            result = val.validate_all_encryption_params(key, nonce, plaintext)
            if not result.is_valid:
                raise ValueError(f"Crypto validation failed: {result.error_message}")
            return func(key, nonce, plaintext, **kwargs)
        return wrapper
    return decorator


def rate_limited_crypto(limiter: Optional[CryptoOperationRateLimiter] = None):
    """
    Decorator to apply rate limiting to crypto operations.
    
    Usage:
        @rate_limited_crypto()
        def generate_rsa_key_pair(**kwargs):
            ...
    """
    lim = limiter or CryptoOperationRateLimiter()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            op_type = kwargs.get('operation_type', func.__name__)
            client_id = kwargs.get('client_id', 'global')
            
            if not lim.check_operation(op_type, client_id):
                raise RuntimeError("Crypto operation rate limit exceeded")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Global instances
default_crypto_validator = CryptoInputValidator()
default_crypto_limiter = CryptoOperationRateLimiter()
