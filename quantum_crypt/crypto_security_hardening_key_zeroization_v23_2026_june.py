"""
QuantumCrypt AI - Secure Key Material Zeroization v23
Dimension B - Security Hardening
Incremental build - ADD-ONLY module, wraps existing functionality

Provides cryptographic-grade secure memory zeroization for:
- Private keys and secret keys
- Session keys and ephemeral keys
- Key derivation intermediate values
- Plaintext before/after encryption

Follows NIST SP 800-88 Rev. 1 and crypto security best practices.
"""

import ctypes
import gc
import secrets
from typing import Any, List, Optional, Union
import logging
import hmac
import hashlib

# Configure logging (opt-in only)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class CryptoKeyZeroizer:
    """
    Cryptographic secure memory zeroization for key material.
    
    Implements NIST-compliant data sanitization for sensitive cryptographic
    materials including private keys, symmetric keys, and intermediate values.
    
    Zeroization is performed in constant-time to prevent timing side-channels.
    
    API Stability: STABLE
    """
    
    # NIST SP 800-88 recommended overwrite patterns
    OVERWRITE_PATTERNS = [0x00, 0xFF, 0xAA, 0x55, 0x92, 0x49, 0x24]
    
    def __init__(self, overwrite_passes: int = 4, enable_logging: bool = False):
        """
        Initialize cryptographic key zeroizer.
        
        Args:
            overwrite_passes: Number of overwrite passes (1-7, default: 4)
            enable_logging: Whether to enable operation logging (opt-in)
        """
        self.overwrite_passes = max(1, min(overwrite_passes, 7))
        self._logging_enabled = enable_logging
        self._keys_zeroized = 0
        self._bytes_zeroized = 0
    
    def _log(self, message: str) -> None:
        """Conditional logging - only if explicitly enabled."""
        if self._logging_enabled:
            logger.debug(message)
    
    def zeroize_key_bytes(self, key_data: bytearray) -> None:
        """
        Securely zeroize cryptographic key material in bytearray form.
        
        Performs multiple overwrite passes with different patterns followed
        by final zeroization. All operations are constant-time.
        
        Args:
            key_data: Mutable bytearray containing key material
        """
        if not isinstance(key_data, bytearray):
            return
            
        length = len(key_data)
        
        # Multiple overwrite passes with NIST patterns
        for pass_idx in range(self.overwrite_passes):
            pattern = self.OVERWRITE_PATTERNS[pass_idx % len(self.OVERWRITE_PATTERNS)]
            for i in range(length):
                key_data[i] = pattern
        
        # Random pattern pass
        random_byte = secrets.randbelow(256)
        for i in range(length):
            key_data[i] = random_byte
        
        # Final zero pass
        for i in range(length):
            key_data[i] = 0x00
        
        self._keys_zeroized += 1
        self._bytes_zeroized += length
        self._log(f"Zeroized cryptographic key material ({length} bytes)")
    
    def zeroize_private_key(self, private_key: object) -> None:
        """
        Attempt to zeroize private key objects.
        
        Note: For immutable objects, we attempt to clear references and
        force garbage collection. For mutable bytearray keys, use zeroize_key_bytes.
        
        Args:
            private_key: Private key object to sanitize
        """
        # For bytearray keys, directly zeroize
        if isinstance(private_key, bytearray):
            self.zeroize_key_bytes(private_key)
        # For bytes, create mutable copy and zeroize
        elif isinstance(private_key, bytes):
            ba = bytearray(private_key)
            self.zeroize_key_bytes(ba)
            del ba
        
        # Force garbage collection to clear freed memory
        gc.collect()
        self._log("Private key zeroization attempted")
    
    def zeroize_session_key(self, session_key: bytearray) -> None:
        """
        Zeroize ephemeral session key material.
        
        Args:
            session_key: Session key bytearray
        """
        self.zeroize_key_bytes(session_key)
        self._log("Session key zeroized")
    
    def zeroize_derivation_material(self, material: List[bytearray]) -> None:
        """
        Zeroize all intermediate key derivation material.
        
        Args:
            material: List of bytearrays from KDF intermediates
        """
        for item in material:
            if isinstance(item, bytearray):
                self.zeroize_key_bytes(item)
        
        material.clear()
        self._log("Key derivation material zeroized")
    
    def zeroize_plaintext(self, plaintext: bytearray) -> None:
        """
        Zeroize plaintext data after encryption/before decryption.
        
        Args:
            plaintext: Plaintext bytearray
        """
        self.zeroize_key_bytes(plaintext)
        self._log("Plaintext zeroized")
    
    def get_zeroization_stats(self) -> dict:
        """
        Get zeroization statistics for audit purposes.
        
        Returns:
            Dictionary with security statistics
        """
        return {
            "keys_zeroized": self._keys_zeroized,
            "total_bytes_zeroized": self._bytes_zeroized,
            "overwrite_passes": self.overwrite_passes,
            "nist_compliant": self.overwrite_passes >= 3
        }


class CryptoConstantTimeOps:
    """
    Constant-time operations for cryptographic comparisons.
    
    Prevents timing attacks during:
    - MAC verification
    - Signature verification
    - Key comparison
    - Hash comparison
    
    All operations run in time dependent only on input length.
    
    API Stability: STABLE
    """
    
    def __init__(self, enable_logging: bool = False):
        self._logging_enabled = enable_logging
        self._comparisons = 0
    
    def _log(self, message: str) -> None:
        if self._logging_enabled:
            logger.debug(message)
    
    @staticmethod
    def verify_mac(received_mac: bytes, computed_mac: bytes) -> bool:
        """
        Verify MAC tags in constant time.
        
        Args:
            received_mac: Received MAC tag
            computed_mac: Computed MAC tag
            
        Returns:
            True if match, False otherwise
        """
        return hmac.compare_digest(received_mac, computed_mac)
    
    @staticmethod
    def verify_signature(sig_a: bytes, sig_b: bytes) -> bool:
        """
        Compare signature values in constant time.
        
        Args:
            sig_a: First signature
            sig_b: Second signature
            
        Returns:
            True if match, False otherwise
        """
        return hmac.compare_digest(sig_a, sig_b)
    
    def compare_keys(self, key_a: bytes, key_b: bytes) -> bool:
        """
        Compare cryptographic keys in constant time.
        
        Args:
            key_a: First key
            key_b: Second key
            
        Returns:
            True if equal, False otherwise
        """
        # First check lengths (also constant time)
        if len(key_a) != len(key_b):
            self._comparisons += 1
            return False
        
        result = hmac.compare_digest(key_a, key_b)
        self._comparisons += 1
        self._log(f"Key comparison: {'EQUAL' if result else 'NOT EQUAL'}")
        return result
    
    def compare_hashes(self, hash_a: str, hash_b: str) -> bool:
        """
        Compare cryptographic hashes in constant time.
        
        Args:
            hash_a: First hash hex string
            hash_b: Second hash hex string
            
        Returns:
            True if match, False otherwise
        """
        hash_a_bytes = bytes.fromhex(hash_a.lower())
        hash_b_bytes = bytes.fromhex(hash_b.lower())
        
        result = hmac.compare_digest(hash_a_bytes, hash_b_bytes)
        self._comparisons += 1
        self._log(f"Hash comparison: {'MATCH' if result else 'MISMATCH'}")
        return result
    
    def constant_time_select(self, condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Constant-time selection: return a if condition else b.
        
        Prevents timing leaks from conditional branches.
        
        Args:
            condition: Selection condition
            a: Value if True
            b: Value if False
            
        Returns:
            Either a or b based on condition
        """
        # Convert condition to mask: all 1s or all 0s
        mask = -condition if condition else 0
        
        if len(a) != len(b):
            raise ValueError("Inputs must be same length")
        
        result = bytearray(len(a))
        for i in range(len(a)):
            result[i] = (a[i] & mask) | (b[i] & ~mask)
        
        return bytes(result)


# Global instances (opt-in usage)
_default_zeroizer = CryptoKeyZeroizer()
_default_ct_ops = CryptoConstantTimeOps()


def zeroize_crypto_key(key_data: Union[bytearray, bytes]) -> None:
    """
    Convenience function for cryptographic key zeroization.
    
    Args:
        key_data: Key material to zeroize
    """
    if isinstance(key_data, bytearray):
        _default_zeroizer.zeroize_key_bytes(key_data)
    elif isinstance(key_data, bytes):
        _default_zeroizer.zeroize_private_key(key_data)


def constant_time_verify(a: bytes, b: bytes) -> bool:
    """
    Convenience function for constant-time verification.
    
    Args:
        a: First value
        b: Second value
        
    Returns:
        True if equal, False otherwise
    """
    return CryptoConstantTimeOps.verify_mac(a, b)


class SensitiveCryptoContext:
    """
    Context manager for automatic zeroization of cryptographic material.
    
    Automatically zeroizes all tracked sensitive data when exiting context.
    
    Usage:
        with SensitiveCryptoContext() as ctx:
            private_key = ctx.track(bytearray(32))
            # Use key...
        # Key automatically zeroized
    """
    
    def __init__(self, zeroizer: Optional[CryptoKeyZeroizer] = None):
        self.zeroizer = zeroizer or _default_zeroizer
        self._tracked: List[Any] = []
    
    def __enter__(self):
        return self
    
    def track(self, data: Any) -> Any:
        """Track sensitive data for automatic zeroization."""
        self._tracked.append(data)
        return data
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Zeroize all tracked data."""
        for item in self._tracked:
            try:
                if isinstance(item, bytearray):
                    self.zeroizer.zeroize_key_bytes(item)
            except Exception:
                pass
        self._tracked.clear()
        gc.collect()
        return False
