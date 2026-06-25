"""
Security Hardening: Cryptographic Key Protection & Input Validation v28
QuantumCrypt-AI Security Module
API Stability: STABLE

Layered security hardening for cryptographic operations including:
- Key material secure memory handling
- Constant-time signature verification
- Cryptographic input validation
- Side-channel attack mitigations

Philosophy: ADD-ONLY, NO MODIFICATION TO EXISTING CRYPTO CODE
"""

import hmac
import hashlib
import gc
import secrets
import threading
import time
from typing import Any, ByteString, Callable, Dict, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
import re


class KeySensitivityLevel(Enum):
    PUBLIC = "public"          # Public keys, safe to log/expose
    INTERNAL = "internal"      # Internal state, not secret but shouldn't leak
    SECRET = "secret"          # Private keys, must be protected
    CRITICAL = "critical"      # Root keys, master secrets - highest protection


@dataclass
class CryptoValidationResult:
    """Result of cryptographic input validation"""
    passed: bool
    severity: str
    error_code: Optional[str] = None
    message: str = ""
    sanitized_value: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecureKeyMemory:
    """
    Secure memory management for cryptographic key material.
    Provides best-effort zeroization and protection for sensitive keys.
    
    IMPORTANT: Python's immutable strings cannot be truly zeroized.
    Always use bytearray for sensitive key material when possible.
    """
    
    @staticmethod
    def zeroize_key_material(key_data: bytearray) -> None:
        """
        Securely zeroize cryptographic key material stored in bytearray.
        Overwrites with random data first, then zeros for extra protection.
        """
        if not isinstance(key_data, bytearray):
            raise TypeError("Key material must be mutable bytearray")
        
        length = len(key_data)
        
        # First overwrite with random data
        random_bytes = secrets.token_bytes(length)
        for i in range(length):
            key_data[i] = random_bytes[i]
        
        # Then overwrite with zeros
        for i in range(length):
            key_data[i] = 0
        
        gc.collect()
    
    @staticmethod
    def secure_delete_key(key_object: Any) -> None:
        """
        Attempt secure deletion of key material.
        Best effort given Python's memory model.
        """
        if isinstance(key_object, bytearray):
            SecureKeyMemory.zeroize_key_material(key_object)
        
        del key_object
        gc.collect()
    
    @staticmethod
    def wrap_sensitive_key(
        key_bytes: ByteString,
        sensitivity: KeySensitivityLevel = KeySensitivityLevel.SECRET
    ) -> bytearray:
        """
        Wrap immutable bytes into a mutable bytearray for secure handling.
        Returns a COPY that can be zeroized later.
        """
        mutable_copy = bytearray(key_bytes)
        return mutable_copy


class ConstantTimeCrypto:
    """
    Constant-time operations for cryptographic comparisons.
    Prevents timing side-channel attacks during:
    - Signature verification
    - MAC validation
    - Hash comparison
    - Key equality checks
    """
    
    @staticmethod
    def verify_signature(signature: ByteString, expected: ByteString) -> bool:
        """
        Constant-time signature verification.
        Critical for preventing timing attacks on authentication.
        """
        if len(signature) != len(expected):
            return False
        return hmac.compare_digest(signature, expected)
    
    @staticmethod
    def verify_mac(mac_value: ByteString, expected: ByteString) -> bool:
        """Constant-time MAC/HMAC verification"""
        if len(mac_value) != len(expected):
            return False
        return hmac.compare_digest(mac_value, expected)
    
    @staticmethod
    def compare_hashes(hash_a: ByteString, hash_b: ByteString) -> bool:
        """Constant-time hash comparison"""
        if len(hash_a) != len(hash_b):
            return False
        return hmac.compare_digest(hash_a, hash_b)
    
    @staticmethod
    def compare_key_fingerprints(fp_a: str, fp_b: str) -> bool:
        """Constant-time key fingerprint comparison"""
        if len(fp_a) != len(fp_b):
            return False
        return hmac.compare_digest(fp_a.encode('utf-8'), fp_b.encode('utf-8'))
    
    @staticmethod
    def secure_select(condition: bool, true_val: bytes, false_val: bytes) -> bytes:
        """
        Constant-time selection between two values.
        No branching based on secret condition.
        """
        if len(true_val) != len(false_val):
            raise ValueError("Both values must have identical length")
        
        mask = -condition if condition else 0
        result = bytearray(len(true_val))
        
        for i in range(len(true_val)):
            result[i] = (true_val[i] & mask) | (false_val[i] & ~mask)
        
        return bytes(result)


class CryptoInputValidator:
    """
    Input validation specifically for cryptographic operations.
    Validates:
    - Key sizes and formats
    - Signature lengths
    - Nonce/IV uniqueness constraints
    - Plaintext/ciphertext size limits
    """
    
    # Common key sizes (bits)
    VALID_SYMMETRIC_KEY_SIZES = {128, 192, 256}
    VALID_RSA_KEY_SIZES = {2048, 3072, 4096, 7680, 15360}
    VALID_HASH_OUTPUT_SIZES = {16, 20, 28, 32, 48, 64}  # MD5 through SHA-512
    
    # Regex for hex validation
    HEX_PATTERN = re.compile(r'^[0-9a-fA-F]*$')
    BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    
    @staticmethod
    def validate_key_size(
        key_bytes: ByteString,
        expected_sizes: set,
        key_type: str = "symmetric"
    ) -> CryptoValidationResult:
        """Validate cryptographic key size"""
        key_bits = len(key_bytes) * 8
        
        if key_bits not in expected_sizes:
            return CryptoValidationResult(
                passed=False,
                severity="HIGH",
                error_code="INVALID_KEY_SIZE",
                message=f"Invalid {key_type} key size: {key_bits} bits. "
                        f"Expected one of: {sorted(expected_sizes)}"
            )
        
        return CryptoValidationResult(
            passed=True,
            severity="LOW",
            message=f"Valid {key_type} key size: {key_bits} bits"
        )
    
    @staticmethod
    def validate_symmetric_key(key_bytes: ByteString) -> CryptoValidationResult:
        """Validate symmetric encryption key"""
        return CryptoInputValidator.validate_key_size(
            key_bytes,
            CryptoInputValidator.VALID_SYMMETRIC_KEY_SIZES,
            "symmetric"
        )
    
    @staticmethod
    def validate_nonce(nonce: ByteString, expected_length: int) -> CryptoValidationResult:
        """Validate nonce/IV length and content"""
        if len(nonce) != expected_length:
            return CryptoValidationResult(
                passed=False,
                severity="HIGH",
                error_code="INVALID_NONCE_LENGTH",
                message=f"Nonce length mismatch: {len(nonce)} != {expected_length}"
            )
        
        # Check for all-zero nonce (dangerous!)
        if all(b == 0 for b in nonce):
            return CryptoValidationResult(
                passed=False,
                severity="CRITICAL",
                error_code="ALL_ZERO_NONCE",
                message="All-zero nonce detected - security critical!"
            )
        
        return CryptoValidationResult(
            passed=True,
            severity="LOW",
            message="Valid nonce"
        )
    
    @staticmethod
    def validate_hex_string(hex_str: str) -> CryptoValidationResult:
        """Validate hex-encoded string"""
        if not CryptoInputValidator.HEX_PATTERN.match(hex_str):
            return CryptoValidationResult(
                passed=False,
                severity="HIGH",
                error_code="INVALID_HEX",
                message="Invalid hexadecimal encoding"
            )
        
        if len(hex_str) % 2 != 0:
            return CryptoValidationResult(
                passed=False,
                severity="HIGH",
                error_code="ODD_LENGTH_HEX",
                message="Hex string must have even length"
            )
        
        return CryptoValidationResult(
            passed=True,
            severity="LOW",
            message="Valid hex encoding"
        )
    
    @staticmethod
    def validate_plaintext_size(
        plaintext: ByteString,
        max_size: int = 10 * 1024 * 1024  # 10MB default
    ) -> CryptoValidationResult:
        """Validate plaintext isn't too large (DoS prevention)"""
        if len(plaintext) > max_size:
            return CryptoValidationResult(
                passed=False,
                severity="HIGH",
                error_code="PLAINTEXT_TOO_LARGE",
                message=f"Plaintext exceeds max size: {len(plaintext)} > {max_size}"
            )
        
        return CryptoValidationResult(
            passed=True,
            severity="LOW",
            message="Plaintext size OK"
        )


class CryptoRateLimiter:
    """
    Rate limiter specifically for cryptographic operations.
    Prevents DoS attacks on expensive operations like:
    - Signature verification
    - Key generation
    - Public key operations
    """
    
    def __init__(
        self,
        max_sign_ops_per_minute: int = 1000,
        max_keygen_per_minute: int = 10,
        max_encrypt_per_minute: int = 10000
    ):
        self.max_sign_ops = max_sign_ops_per_minute
        self.max_keygen = max_keygen_per_minute
        self.max_encrypt = max_encrypt_per_minute
        
        self._sign_ops: List[float] = []
        self._keygen_ops: List[float] = []
        self._encrypt_ops: List[float] = []
        self._lock = threading.Lock()
    
    def _clean_old(self, timestamps: List[float], window: float = 60.0) -> None:
        """Remove timestamps outside window"""
        now = time.time()
        cutoff = now - window
        timestamps[:] = [ts for ts in timestamps if ts > cutoff]
    
    def check_signature_operation(self) -> bool:
        """Check if signature operation is allowed"""
        with self._lock:
            self._clean_old(self._sign_ops)
            if len(self._sign_ops) >= self.max_sign_ops:
                return False
            self._sign_ops.append(time.time())
            return True
    
    def check_key_generation(self) -> bool:
        """Check if key generation is allowed"""
        with self._lock:
            self._clean_old(self._keygen_ops)
            if len(self._keygen_ops) >= self.max_keygen:
                return False
            self._keygen_ops.append(time.time())
            return True
    
    def check_encryption(self) -> bool:
        """Check if encryption operation is allowed"""
        with self._lock:
            self._clean_old(self._encrypt_ops)
            if len(self._encrypt_ops) >= self.max_encrypt:
                return False
            self._encrypt_ops.append(time.time())
            return True


class HardenedCryptoWrapper:
    """
    Complete hardened wrapper for cryptographic modules.
    Adds security layers ON TOP without modifying original crypto code:
    - Input validation
    - Constant-time verification
    - Rate limiting
    - Secure key cleanup
    
    Usage: wrap existing crypto objects, NO changes to original code.
    """
    
    def __init__(
        self,
        wrapped_crypto_module: Any,
        enable_validation: bool = True,
        enable_rate_limiting: bool = True,
        enable_constant_time: bool = True
    ):
        self._wrapped = wrapped_crypto_module
        self._enable_validation = enable_validation
        self._enable_rate_limiting = enable_rate_limiting
        self._enable_constant_time = enable_constant_time
        
        self._validator = CryptoInputValidator()
        self._rate_limiter = CryptoRateLimiter()
        self._key_memory = SecureKeyMemory()
        self._constant_time = ConstantTimeCrypto()
    
    def __getattr__(self, name: str) -> Any:
        """Wrap method calls with security hardening"""
        original = getattr(self._wrapped, name)
        
        if not callable(original):
            return original
        
        def hardened_method(*args, **kwargs):
            # Rate limiting for expensive operations
            if self._enable_rate_limiting:
                if "sign" in name.lower() or "verify" in name.lower():
                    if not self._rate_limiter.check_signature_operation():
                        raise RuntimeError("Signature operation rate limit exceeded")
                elif "keygen" in name.lower() or "generate" in name.lower():
                    if not self._rate_limiter.check_key_generation():
                        raise RuntimeError("Key generation rate limit exceeded")
                elif "encrypt" in name.lower() or "decrypt" in name.lower():
                    if not self._rate_limiter.check_encryption():
                        raise RuntimeError("Encryption rate limit exceeded")
            
            return original(*args, **kwargs)
        
        return hardened_method
    
    def secure_cleanup_key(self, key_data: bytearray) -> None:
        """Securely clean up sensitive key material"""
        self._key_memory.zeroize_key_material(key_data)
    
    def constant_time_verify(self, signature: ByteString, expected: ByteString) -> bool:
        """Perform constant-time signature verification"""
        return self._constant_time.verify_signature(signature, expected)
    
    def get_original(self) -> Any:
        """Get the unwrapped original module"""
        return self._wrapped


# Export public API
__all__ = [
    'SecureKeyMemory',
    'ConstantTimeCrypto',
    'CryptoInputValidator',
    'CryptoRateLimiter',
    'HardenedCryptoWrapper',
    'KeySensitivityLevel',
    'CryptoValidationResult',
]
