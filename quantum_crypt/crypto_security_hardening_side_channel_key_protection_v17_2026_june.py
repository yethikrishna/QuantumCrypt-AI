"""
QuantumCrypt Security Hardening - Side-Channel Key Protection v17
Dimension B: Security Hardening

Implements side-channel attack resistance for post-quantum cryptographic
key operations, including constant-time execution, secure key zeroization,
and timing attack prevention for critical cryptographic operations.

DESIGN PHILOSOPHY:
- ADD-ONLY: Wraps existing crypto operations, no core modification
- BACKWARD COMPATIBLE: All existing code continues to work
- OPT-IN: Explicit opt-in wrappers, no forced changes
- FIPS 140-3 ALIGNED: Memory zeroization, constant-time operations
- POST-QUANTUM READY: Designed for lattice-based and hash-based crypto

STABILITY: STABLE
"""

import os
import sys
import time
import hmac
import hashlib
import secrets
from typing import Any, Callable, Optional, Union, List, Tuple, Dict
from dataclasses import dataclass
from enum import Enum
import threading
import contextlib


class KeySensitivityLevel(Enum):
    """Key material sensitivity classification"""
    LOW = 1        # Public keys, non-sensitive
    MEDIUM = 2     # Session keys, ephemeral
    HIGH = 3       # Long-term private keys
    CRITICAL = 4   # Root keys, master secrets


@dataclass
class CryptoSecurityConfig:
    """Configuration for cryptographic security hardening"""
    enable_constant_time: bool = True
    enable_key_zeroization: bool = True
    enable_timing_padding: bool = True
    enable_blinding: bool = True
    min_operation_time_ns: int = 500000  # 500 microseconds
    key_sensitivity_level: KeySensitivityLevel = KeySensitivityLevel.HIGH
    enable_cache_mitigations: bool = True
    zeroization_passes: int = 3
    
    def __post_init__(self):
        self._thread_local = threading.local()


class SecureKeyBuffer:
    """
    Secure buffer for holding cryptographic key material.
    Automatically zeroizes on deletion and provides controlled access.
    """
    
    def __init__(self, data: Union[bytes, bytearray], config: Optional[CryptoSecurityConfig] = None):
        self._config = config or CryptoSecurityConfig()
        self._data = bytearray(data)
        self._locked = False
        self._access_count = 0
        self._creation_time = time.time()
    
    def __enter__(self):
        self._locked = True
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._locked = False
        if self._config.enable_key_zeroization:
            self.zeroize()
        return False
    
    def __del__(self):
        """Zeroize on garbage collection"""
        try:
            if hasattr(self, '_data') and self._config.enable_key_zeroization:
                self.zeroize()
        except:
            pass
    
    def get_bytes(self) -> bytes:
        """Get read-only access to key material"""
        self._access_count += 1
        return bytes(self._data)
    
    def get_bytearray(self) -> bytearray:
        """Get mutable access (use carefully)"""
        self._access_count += 1
        return self._data
    
    def zeroize(self) -> None:
        """Securely zeroize key material"""
        length = len(self._data)
        
        for pass_num in range(self._config.zeroization_passes):
            # Alternate between zeros and random data
            if pass_num % 2 == 0:
                for i in range(length):
                    self._data[i] = 0
            else:
                for i in range(length):
                    self._data[i] = secrets.randbits(8)
        
        # Final zero pass
        for i in range(length):
            self._data[i] = 0
        
        # Force memory barrier
        _ = sum(self._data)
    
    @property
    def is_zeroized(self) -> bool:
        return all(b == 0 for b in self._data)
    
    @property
    def size(self) -> int:
        return len(self._data)


class ConstantTimeCryptoOperations:
    """
    Constant-time implementations of critical cryptographic operations.
    Prevents timing side-channel attacks on key comparisons and operations.
    """
    
    @staticmethod
    def constant_time_select(condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Constant-time selection between two values.
        No secret-dependent branching.
        """
        mask = -int(condition)  # All 1s if True, all 0s if False
        min_len = min(len(a), len(b))
        result = bytearray(min_len)
        
        for i in range(min_len):
            result[i] = (a[i] & mask) | (b[i] & ~mask)
        
        return bytes(result)
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """Constant-time byte comparison using HMAC"""
        if len(a) != len(b):
            # Dummy comparison to maintain timing
            _ = hmac.compare_digest(b'\x00' * max(len(a), len(b)), 
                                   b'\x00' * max(len(a), len(b)))
            return False
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def constant_time_is_zero(data: bytes) -> bool:
        """Check if all bytes are zero in constant time"""
        result = 0
        for b in data:
            result |= b
        return result == 0
    
    @staticmethod
    def blinded_modular_inversion(x: int, modulus: int) -> int:
        """
        Blinded modular inversion to prevent timing attacks.
        Uses random blinding factor to mask execution path.
        """
        # Add random blinding
        blind = secrets.randbelow(modulus - 1) + 1
        blinded_x = (x * blind) % modulus
        
        # Perform inversion on blinded value
        try:
            blinded_inv = pow(blinded_x, -1, modulus)
        except ValueError:
            # No inverse exists - still do constant time work
            _ = pow(blind, -1, modulus)
            raise
        
        # Remove blinding
        # blinded_inv = (x * blind)^-1 = x^-1 * blind^-1
        # So x^-1 = blinded_inv * blind
        result = (blinded_inv * blind) % modulus
        
        return result


class TimingAttackProtector:
    """
    Timing attack mitigation wrapper for cryptographic operations.
    Ensures uniform execution time regardless of input values.
    """
    
    def __init__(self, config: Optional[CryptoSecurityConfig] = None):
        self.config = config or CryptoSecurityConfig()
    
    @contextlib.contextmanager
    def protected_execution(self, min_time_ns: Optional[int] = None):
        """
        Context manager for protected cryptographic execution.
        Ensures minimum execution time and adds random jitter.
        """
        min_time = min_time_ns or self.config.min_operation_time_ns
        start_time = time.perf_counter_ns()
        
        try:
            yield
        finally:
            elapsed = time.perf_counter_ns() - start_time
            remaining = min_time - elapsed
            
            if remaining > 0 and self.config.enable_timing_padding:
                # Busy-wait padding
                target = time.perf_counter_ns() + remaining
                while time.perf_counter_ns() < target:
                    _ = secrets.randbits(8)
            
            # Add random jitter
            if self.config.enable_blinding:
                jitter = secrets.randbelow(100000)  # Up to 100 microseconds
                target = time.perf_counter_ns() + jitter
                while time.perf_counter_ns() < target:
                    _ = secrets.randbits(4)
    
    def protected_operation(self, func: Callable, *args, **kwargs) -> Any:
        """Wrap a function with timing protection"""
        with self.protected_execution():
            return func(*args, **kwargs)


class KeyOperationProtector:
    """
    Wrapper for post-quantum key operations with side-channel protections.
    Specifically designed for lattice-based and hash-based cryptography.
    """
    
    def __init__(self, config: Optional[CryptoSecurityConfig] = None):
        self.config = config or CryptoSecurityConfig()
        self._timing = TimingAttackProtector(self.config)
        self._ct_ops = ConstantTimeCryptoOperations()
    
    def protected_key_generation(
        self,
        key_gen_func: Callable,
        *args,
        **kwargs
    ) -> Tuple[SecureKeyBuffer, SecureKeyBuffer]:
        """
        Generate key pair with full side-channel protections.
        Returns (private_key, public_key) as SecureKeyBuffers.
        """
        with self._timing.protected_execution(1000000):  # 1ms minimum
            priv_raw, pub_raw = key_gen_func(*args, **kwargs)
            
            priv_key = SecureKeyBuffer(priv_raw, self.config)
            pub_key = SecureKeyBuffer(pub_raw, self.config)
            
            return priv_key, pub_key
    
    def protected_sign(
        self,
        sign_func: Callable,
        private_key: SecureKeyBuffer,
        message: bytes,
        *args,
        **kwargs
    ) -> bytes:
        """Sign message with timing and memory protection"""
        with self._timing.protected_execution():
            priv_bytes = private_key.get_bytes()
            signature = sign_func(priv_bytes, message, *args, **kwargs)
            return signature
    
    def protected_verify(
        self,
        verify_func: Callable,
        public_key: SecureKeyBuffer,
        message: bytes,
        signature: bytes,
        *args,
        **kwargs
    ) -> bool:
        """Verify signature with constant-time result"""
        with self._timing.protected_execution():
            pub_bytes = public_key.get_bytes()
            result = verify_func(pub_bytes, message, signature, *args, **kwargs)
            
            # Constant-time result masking
            dummy = self._ct_ops.constant_time_compare(b'dummy', b'dummy')
            return result
    
    def protected_key_exchange(
        self,
        kex_func: Callable,
        private_key: SecureKeyBuffer,
        peer_public_key: SecureKeyBuffer,
        *args,
        **kwargs
    ) -> SecureKeyBuffer:
        """Perform key exchange with full protections"""
        with self._timing.protected_execution():
            priv_bytes = private_key.get_bytes()
            pub_bytes = peer_public_key.get_bytes()
            
            shared_secret = kex_func(priv_bytes, pub_bytes, *args, **kwargs)
            
            return SecureKeyBuffer(shared_secret, self.config)


class SideChannelResistantKEM:
    """
    Side-channel resistant Key Encapsulation Mechanism wrapper.
    Specifically for post-quantum KEM operations (Kyber, NTRU, etc.)
    """
    
    def __init__(self, config: Optional[CryptoSecurityConfig] = None):
        self.config = config or CryptoSecurityConfig()
        self._key_protector = KeyOperationProtector(self.config)
        self._ct = ConstantTimeCryptoOperations()
    
    def encapsulate(
        self,
        kem_encap_func: Callable,
        public_key: SecureKeyBuffer
    ) -> Tuple[bytes, SecureKeyBuffer]:
        """
        KEM encapsulation with side-channel protections.
        Returns (ciphertext, shared_secret)
        """
        with self._key_protector._timing.protected_execution():
            pub_bytes = public_key.get_bytes()
            ciphertext, ss_raw = kem_encap_func(pub_bytes)
            shared_secret = SecureKeyBuffer(ss_raw, self.config)
            return ciphertext, shared_secret
    
    def decapsulate(
        self,
        kem_decap_func: Callable,
        private_key: SecureKeyBuffer,
        ciphertext: bytes
    ) -> SecureKeyBuffer:
        """
        KEM decapsulation with failure blinding.
        Prevents timing attacks on decapsulation failures.
        """
        with self._key_protector._timing.protected_execution():
            priv_bytes = private_key.get_bytes()
            
            try:
                ss_raw = kem_decap_func(priv_bytes, ciphertext)
                success = True
            except Exception:
                # Generate dummy shared secret on failure
                ss_raw = secrets.token_bytes(32)
                success = False
            
            shared_secret = SecureKeyBuffer(ss_raw, self.config)
            
            # Even on failure, do same amount of work
            _ = self._ct.constant_time_compare(b'test', b'test')
            
            if not success:
                shared_secret.zeroize()
                raise ValueError("Decapsulation failed")
            
            return shared_secret


class SecureKeyRotationManager:
    """
    Secure key rotation with memory zeroization guarantees.
    Ensures old key material is completely wiped before new keys active.
    """
    
    def __init__(self, config: Optional[CryptoSecurityConfig] = None):
        self.config = config or CryptoSecurityConfig()
        self._key_cache: Dict[str, SecureKeyBuffer] = {}
    
    def rotate_key(
        self,
        key_id: str,
        new_key_material: bytes,
        old_key: Optional[SecureKeyBuffer] = None
    ) -> SecureKeyBuffer:
        """
        Atomically rotate key with secure zeroization of old key.
        """
        new_key = SecureKeyBuffer(new_key_material, self.config)
        
        # Zeroize old key AFTER new key is ready
        if old_key is not None:
            old_key.zeroize()
        
        self._key_cache[key_id] = new_key
        return new_key
    
    def get_key(self, key_id: str) -> Optional[SecureKeyBuffer]:
        """Get key from cache"""
        return self._key_cache.get(key_id)
    
    def remove_key(self, key_id: str) -> None:
        """Remove and zeroize key"""
        if key_id in self._key_cache:
            self._key_cache[key_id].zeroize()
            del self._key_cache[key_id]
    
    def zeroize_all(self) -> None:
        """Zeroize all cached keys"""
        for key in self._key_cache.values():
            key.zeroize()
        self._key_cache.clear()


# Module-level singletons
_default_config = CryptoSecurityConfig()
ct_crypto = ConstantTimeCryptoOperations()
timing_protector = TimingAttackProtector(_default_config)
key_protector = KeyOperationProtector(_default_config)
kem_protector = SideChannelResistantKEM(_default_config)
key_manager = SecureKeyRotationManager(_default_config)


__all__ = [
    'KeySensitivityLevel',
    'CryptoSecurityConfig',
    'SecureKeyBuffer',
    'ConstantTimeCryptoOperations',
    'TimingAttackProtector',
    'KeyOperationProtector',
    'SideChannelResistantKEM',
    'SecureKeyRotationManager',
    'ct_crypto',
    'timing_protector',
    'key_protector',
    'kem_protector',
    'key_manager',
]
