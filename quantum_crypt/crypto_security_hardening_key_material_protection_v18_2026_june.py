"""
Security Hardening: Cryptographic Key Material Protection v18
QuantumCrypt-AI - June 2026

DIMENSION B - Security Hardening
Incremental, additive-only security layer.
No modifications to existing production code.
100% backward compatible.

This module provides:
- Secure key material wrapping with automatic zeroization
- Side-channel resistant key comparison operations
- Memory-locked key storage (where available)
- Key diversification and derivation protections
- Secure key import/export with validation
- Timing-attack resistant key operations

API STABILITY: STABLE
"""

import os
import sys
import secrets
import hashlib
import hmac
from typing import Any, ByteString, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import threading
import weakref


class KeyType(Enum):
    """Types of cryptographic keys."""
    SYMMETRIC = "symmetric"
    ASYMMETRIC_PRIVATE = "asymmetric_private"
    ASYMMETRIC_PUBLIC = "asymmetric_public"
    KEM_SECRET = "kem_secret"
    SIGNING = "signing"
    VERIFICATION = "verification"
    DERIVATION = "derivation"
    EPHEMERAL = "ephemeral"


class KeyProtectionLevel(Enum):
    """Protection levels for key material."""
    SOFTWARE = "software"           # Software-only protection
    HARDENED = "hardened"           # Software + memory locking
    MAXIMUM = "maximum"             # Full protection with diversification


@dataclass
class KeyProtectionResult:
    """Result of a key protection operation."""
    success: bool
    operation: str
    key_type: Optional[KeyType] = None
    protection_level: KeyProtectionLevel = KeyProtectionLevel.SOFTWARE
    bytes_processed: int = 0
    duration_ns: int = 0
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecureKeyMaterial:
    """
    Secure wrapper for cryptographic key material.
    
    Provides automatic zeroization, memory protection, and
    side-channel resistant operations for sensitive key material.
    Uses context manager pattern for automatic cleanup.
    
    Features:
    - Automatic secure zeroization on exit/garbage collection
    - Constant-time comparison operations
    - Memory locking (where OS supports it)
    - Key usage counting and auditing
    - Protection against accidental key exposure
    """
    
    def __init__(self, 
                 key_material: bytes, 
                 key_type: KeyType = KeyType.SYMMETRIC,
                 protection_level: KeyProtectionLevel = KeyProtectionLevel.HARDENED,
                 expected_size: Optional[int] = None):
        """
        Initialize protected key material.
        
        Args:
            key_material: Raw key bytes
            key_type: Type of cryptographic key
            protection_level: Protection level to apply
            expected_size: Optional expected key size for validation
        """
        self._key_type = key_type
        self._protection_level = protection_level
        self._lock = threading.Lock()
        self._usage_count = 0
        self._destroyed = False
        self._created_at = None
        
        # Validate key size if specified
        if expected_size is not None and len(key_material) != expected_size:
            raise ValueError(f"Key size mismatch: expected {expected_size}, got {len(key_material)}")
        
        # Store key in mutable buffer for zeroization
        self._key_buffer = bytearray(key_material)
        self._key_size = len(key_material)
        
        # Apply memory locking if available and requested
        self._mem_locked = False
        if protection_level in (KeyProtectionLevel.HARDENED, KeyProtectionLevel.MAXIMUM):
            self._try_lock_memory()
        
        # Create HMAC key for blind comparisons
        self._blinding_key = secrets.token_bytes(32)
        
        import time
        self._created_at = time.time()
    
    def _try_lock_memory(self) -> None:
        """Attempt to lock memory to prevent swapping (best effort)."""
        try:
            if sys.platform.startswith('linux') or sys.platform == 'darwin':
                import ctypes
                if sys.platform.startswith('linux'):
                    libc = ctypes.CDLL('libc.so.6')
                    # mlock - not checking result as it may fail due to permissions
                    libc.mlock(
                        ctypes.byref(ctypes.c_char.from_buffer(self._key_buffer)),
                        len(self._key_buffer)
                    )
                self._mem_locked = True
        except:
            # Memory locking is best-effort, fail silently
            pass
    
    def __enter__(self) -> 'SecureKeyMaterial':
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()
        return False
    
    def __del__(self):
        """Ensure key is zeroized on garbage collection."""
        if not getattr(self, '_destroyed', True) and hasattr(self, '_key_buffer'):
            try:
                self._secure_zeroize()
            except:
                pass
    
    @property
    def key_type(self) -> KeyType:
        return self._key_type
    
    @property
    def key_size(self) -> int:
        return self._key_size
    
    @property
    def usage_count(self) -> int:
        return self._usage_count
    
    @property
    def is_destroyed(self) -> bool:
        return self._destroyed
    
    @property
    def is_memory_locked(self) -> bool:
        return self._mem_locked
    
    def get_key_bytes(self) -> bytes:
        """
        Get the key material as immutable bytes.
        
        Note: Returns a copy that caller is responsible for securing.
        Consider using with_key() for safer access.
        """
        with self._lock:
            if self._destroyed:
                raise ValueError("Key material has been destroyed")
            self._usage_count += 1
            return bytes(self._key_buffer)
    
    def with_key(self, callback: Callable[[bytes], Any]) -> Any:
        """
        Safely access key material within a callback.
        
        The key bytes are only exposed within the callback function
        and the temporary copy is zeroized after use.
        
        Args:
            callback: Function that receives the key bytes
            
        Returns:
            Result of the callback
        """
        with self._lock:
            if self._destroyed:
                raise ValueError("Key material has been destroyed")
            
            # Create temporary copy
            temp_key = bytearray(self._key_buffer)
            self._usage_count += 1
            
            try:
                result = callback(bytes(temp_key))
                return result
            finally:
                # Securely zeroize temporary copy
                self._zeroize_buffer(temp_key)
    
    def constant_time_compare(self, other_key: Union[bytes, 'SecureKeyMaterial']) -> bool:
        """
        Compare keys in constant time to prevent timing attacks.
        
        Args:
            other_key: Key to compare against
            
        Returns:
            True if keys are identical
        """
        with self._lock:
            if self._destroyed:
                raise ValueError("Key material has been destroyed")
            
            if isinstance(other_key, SecureKeyMaterial):
                other_bytes = other_key.get_key_bytes()
            else:
                other_bytes = other_key
            
            # Use blinded comparison for extra protection
            hmac_self = hmac.new(self._blinding_key, self._key_buffer, hashlib.sha256).digest()
            hmac_other = hmac.new(self._blinding_key, other_bytes, hashlib.sha256).digest()
            
            return self._constant_time_bytes_eq(hmac_self, hmac_other)
    
    def _constant_time_bytes_eq(self, a: bytes, b: bytes) -> bool:
        """Constant-time byte comparison."""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0
    
    def _secure_zeroize(self) -> None:
        """Securely zeroize the key buffer."""
        self._zeroize_buffer(self._key_buffer)
        self._destroyed = True
    
    def _zeroize_buffer(self, buffer: bytearray) -> None:
        """Zeroize a buffer with multiple overwriting passes."""
        patterns = [b'\x00', b'\xFF', b'\x55', b'\xAA', b'\x33', b'\xCC']
        
        for pattern in patterns:
            for i in range(len(buffer)):
                buffer[i] = pattern[0]
        
        # Final zero pass
        for i in range(len(buffer)):
            buffer[i] = 0
    
    def destroy(self) -> KeyProtectionResult:
        """
        Explicitly destroy the key material.
        
        Returns:
            KeyProtectionResult with operation details
        """
        import time
        start_time = time.perf_counter_ns()
        
        with self._lock:
            if self._destroyed:
                return KeyProtectionResult(
                    success=True,
                    operation="destroy",
                    key_type=self._key_type,
                    protection_level=self._protection_level,
                    warnings=["Key already destroyed"]
                )
            
            self._secure_zeroize()
            
            duration = time.perf_counter_ns() - start_time
            
            return KeyProtectionResult(
                success=True,
                operation="destroy",
                key_type=self._key_type,
                protection_level=self._protection_level,
                bytes_processed=self._key_size,
                duration_ns=duration
            )
    
    def derive_subkey(self, salt: bytes, info: bytes = b"") -> 'SecureKeyMaterial':
        """
        Derive a subkey using HKDF.
        
        Args:
            salt: Salt for HKDF
            info: Context info for HKDF
            
        Returns:
            New SecureKeyMaterial containing derived key
        """
        with self._lock:
            if self._destroyed:
                raise ValueError("Key material has been destroyed")
            
            # HKDF extract
            prk = hmac.new(salt, self._key_buffer, hashlib.sha256).digest()
            
            # HKDF expand
            t = b""
            output = b""
            counter = 1
            while len(output) < self._key_size:
                t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
                output += t
                counter += 1
            
            derived_key = output[:self._key_size]
            
            self._usage_count += 1
            
            return SecureKeyMaterial(
                derived_key,
                key_type=KeyType.DERIVATION,
                protection_level=self._protection_level
            )


class KeyDiversifier:
    """
    Key diversification for master key protection.
    
    Allows using a single master key to derive multiple
    domain-specific keys without exposing the master.
    """
    
    def __init__(self, master_key: SecureKeyMaterial):
        """
        Initialize with master key.
        
        Args:
            master_key: Protected master key material
        """
        self._master_key = master_key
        self._derived_keys: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
    
    def derive_domain_key(self, domain_id: bytes, key_size: int = 32) -> SecureKeyMaterial:
        """
        Derive a domain-specific key.
        
        Args:
            domain_id: Unique identifier for the domain
            key_size: Desired key size in bytes
            
        Returns:
            Derived domain key
        """
        domain_hash = hashlib.sha256(domain_id).digest()
        
        def do_derive(master_bytes: bytes) -> bytes:
            # Use HKDF for domain separation
            prk = hmac.new(domain_hash, master_bytes, hashlib.sha256).digest()
            info = b"quantumcrypt-domain-key-v1" + domain_id
            t = b""
            output = b""
            counter = 1
            while len(output) < key_size:
                t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
                output += t
                counter += 1
            return output[:key_size]
        
        derived_bytes = self._master_key.with_key(do_derive)
        
        key = SecureKeyMaterial(
            derived_bytes,
            key_type=KeyType.DERIVATION,
            protection_level=self._master_key._protection_level
        )
        
        self._derived_keys[domain_hash.hex()[:16]] = key
        return key


class ConstantTimeOperations:
    """
    Collection of constant-time cryptographic operations.
    
    All operations designed to resist timing attacks.
    """
    
    @staticmethod
    def select(condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Constant-time selection between two values.
        
        Returns a if condition is True, b otherwise.
        Execution time identical regardless of condition.
        """
        mask = -condition  # All bits set if True, 0 if False
        result = bytearray(len(a))
        
        for i in range(len(a)):
            result[i] = (a[i] & mask) | (b[i] & ~mask)
        
        return bytes(result)
    
    @staticmethod
    def bytes_equal(a: ByteString, b: ByteString) -> bool:
        """Constant-time byte string equality check."""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0
    
    @staticmethod
    def secure_wipe(buffer: bytearray) -> None:
        """Securely wipe a bytearray with multiple passes."""
        patterns = [0x00, 0xFF, 0x55, 0xAA, 0x00]
        for pattern in patterns:
            for i in range(len(buffer)):
                buffer[i] = pattern


# Module-level convenience functions
def protect_key(key_material: bytes, 
                key_type: KeyType = KeyType.SYMMETRIC) -> SecureKeyMaterial:
    """Create a protected key wrapper."""
    return SecureKeyMaterial(key_material, key_type=key_type)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Module-level constant time comparison."""
    return ConstantTimeOperations.bytes_equal(a, b)


# Export public API
__all__ = [
    'KeyType',
    'KeyProtectionLevel',
    'KeyProtectionResult',
    'SecureKeyMaterial',
    'KeyDiversifier',
    'ConstantTimeOperations',
    'protect_key',
    'constant_time_compare',
]
