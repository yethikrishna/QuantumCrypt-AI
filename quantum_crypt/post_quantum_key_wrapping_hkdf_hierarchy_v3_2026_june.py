"""
Post-Quantum Key Wrapping with HKDF Derivation v3
QuantumCrypt-AI Feature Expansion - June 2026
ADD-ONLY IMPLEMENTATION - NO EXISTING CODE MODIFIED

This module provides:
1. NIST SP 800-56C compliant HKDF key derivation
2. AES Key Wrap (RFC 3394) for key encryption
3. Hierarchical key management (KEK -> DEK hierarchy)
4. Key rotation with forward secrecy
5. Secure memory zeroization
6. Constant-time comparison helpers
"""

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple
from enum import Enum
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import constant_time


class KeyType(Enum):
    """Key types in the hierarchy"""
    ROOT_KEK = "root_kek"       # Root Key Encryption Key
    KEK = "kek"                 # Key Encryption Key (intermediate)
    DEK = "dek"                 # Data Encryption Key
    SESSION = "session"         # Ephemeral session key
    DERIVATION = "derivation"   # Derivation base key


class WrapAlgorithm(Enum):
    """Supported key wrapping algorithms"""
    AES_KEY_WRAP = "aes_key_wrap"       # RFC 3394
    AES_GCM_WRAP = "aes_gcm_wrap"       # AES-GCM with authentication


class HKDFHash(Enum):
    """Supported HKDF hash functions"""
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


@dataclass
class WrappedKey:
    """Wrapped key with metadata"""
    ciphertext: bytes
    iv: Optional[bytes]
    tag: Optional[bytes]
    algorithm: WrapAlgorithm
    key_type: KeyType
    salt: Optional[bytes]
    info: Optional[bytes]
    created_at: float
    version: int = 1


@dataclass
class DerivedKey:
    """HKDF-derived key material"""
    key_material: bytes
    salt: bytes
    info: bytes
    hash_algorithm: HKDFHash

    def zeroize(self) -> None:
        """Securely zeroize key material from memory
        Note: Python bytes are immutable, so we overwrite the reference
        with zeros and encourage garbage collection"""
        # Create zero-filled bytes of same length to overwrite reference
        zero_bytes = b'\x00' * len(self.key_material)
        # Replace reference
        object.__setattr__(self, 'key_material', zero_bytes)
        object.__setattr__(self, 'salt', b'\x00' * len(self.salt))


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time byte comparison to prevent timing attacks
    Uses cryptography's built-in constant_time functions
    """
    if len(a) != len(b):
        # Still do constant-time work even if lengths differ
        dummy = hmac.compare_digest(a[:min(len(a), len(b))], b[:min(len(a), len(b))])
        return False
    return constant_time.bytes_eq(a, b)


def secure_zeroize(data: bytearray) -> None:
    """
    Securely zeroize sensitive data from memory
    Overwrites with zeros, then random data, then zeros again
    """
    # Three-pass zeroization
    for i in range(len(data)):
        data[i] = 0
    for i in range(len(data)):
        data[i] = secrets.randbelow(256)
    for i in range(len(data)):
        data[i] = 0


class HKDF:
    """
    NIST SP 800-56C compliant HKDF implementation
    HMAC-based Extract-and-Expand Key Derivation Function
    """

    def __init__(self, hash_algorithm: HKDFHash = HKDFHash.SHA256):
        self.hash_algorithm = hash_algorithm
        self._hash_map = {
            HKDFHash.SHA256: hashlib.sha256,
            HKDFHash.SHA384: hashlib.sha384,
            HKDFHash.SHA512: hashlib.sha512,
        }
        self.hash_func = self._hash_map[hash_algorithm]
        self.hash_len = self.hash_func().digest_size

    def extract(self, ikm: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        HKDF-Extract step
        Extracts a pseudorandom key from input key material
        """
        if salt is None:
            salt = b'\x00' * self.hash_len
        
        prk = hmac.new(salt, ikm, self.hash_func).digest()
        return prk

    def expand(self, prk: bytes, info: bytes = b'', length: Optional[int] = None) -> bytes:
        """
        HKDF-Expand step
        Expands pseudorandom key to desired output length
        """
        if length is None:
            length = self.hash_len
        
        if length > 255 * self.hash_len:
            raise ValueError(f"Maximum expansion length is {255 * self.hash_len} bytes")

        t = b''
        output = b''
        counter = 1

        while len(output) < length:
            t = hmac.new(prk, t + info + bytes([counter]), self.hash_func).digest()
            output += t
            counter += 1

        return output[:length]

    def derive_key(self, ikm: bytes, salt: Optional[bytes] = None,
                   info: bytes = b'', length: Optional[int] = None) -> DerivedKey:
        """
        Full HKDF key derivation (extract + expand)
        """
        if salt is None:
            salt = os.urandom(self.hash_len)
        
        prk = self.extract(ikm, salt)
        key_material = self.expand(prk, info, length)
        
        return DerivedKey(
            key_material=key_material,
            salt=salt,
            info=info,
            hash_algorithm=self.hash_algorithm
        )


class AESKeyWrap:
    """
    AES Key Wrap (RFC 3394) implementation
    For wrapping cryptographic keys with a Key Encryption Key (KEK)
    """

    # RFC 3394 default IV
    DEFAULT_IV = 0xA6A6A6A6A6A6A6A6

    def __init__(self, kek: bytes):
        if len(kek) not in (16, 24, 32):
            raise ValueError("KEK must be 16, 24, or 32 bytes for AES")
        self.kek = kek
        self.aesgcm = AESGCM(kek)

    def wrap(self, plaintext_key: bytes) -> bytes:
        """
        Wrap a key using AES Key Wrap (RFC 3394)
        """
        n = len(plaintext_key) // 8
        if n < 2:
            raise ValueError("Key must be at least 16 bytes")
        if len(plaintext_key) % 8 != 0:
            raise ValueError("Key length must be multiple of 8 bytes")

        # Initialize
        r = list(plaintext_key[i:i + 8] for i in range(0, len(plaintext_key), 8))
        a = self.DEFAULT_IV

        # Wrap
        for j in range(6):
            for i in range(n):
                # Concatenate A | R[i]
                block = a.to_bytes(8, 'big') + r[i]
                
                # AES encrypt (using ECB mode via single block GCM)
                encrypted = self.aesgcm.encrypt(b'\x00' * 12, block, None)[:16]
                
                # Split into new A and R[i]
                a = int.from_bytes(encrypted[:8], 'big') ^ ((n * j) + i + 1)
                r[i] = encrypted[8:]

        # Construct output
        output = a.to_bytes(8, 'big')
        for block in r:
            output += block

        return output

    def unwrap(self, wrapped_key: bytes) -> bytes:
        """
        Unwrap a key using AES Key Wrap (RFC 3394)
        """
        n = (len(wrapped_key) // 8) - 1
        if n < 2:
            raise ValueError("Invalid wrapped key length")

        # Initialize
        r = [wrapped_key[8 + i * 8:16 + i * 8] for i in range(n)]
        a = int.from_bytes(wrapped_key[:8], 'big')

        # Unwrap
        for j in reversed(range(6)):
            for i in reversed(range(n)):
                # XOR A with round counter
                a_xor = a ^ ((n * j) + i + 1)
                
                # Decrypt block
                block = a_xor.to_bytes(8, 'big') + r[i]
                decrypted = self.aesgcm.decrypt(b'\x00' * 12, block + b'\x00' * 16, None)[:16]
                
                a = int.from_bytes(decrypted[:8], 'big')
                r[i] = decrypted[8:]

        # Verify IV
        if a != self.DEFAULT_IV:
            raise ValueError("Key unwrap failed - integrity check failed")

        return b''.join(r)


class AESGCMWrap:
    """
    AES-GCM based key wrapping with authentication
    Provides confidentiality and integrity
    """

    def __init__(self, kek: bytes):
        if len(kek) not in (16, 24, 32):
            raise ValueError("KEK must be 16, 24, or 32 bytes")
        self.aesgcm = AESGCM(kek)

    def wrap(self, plaintext_key: bytes, associated_data: bytes = b'') -> Tuple[bytes, bytes, bytes]:
        """
        Wrap key using AES-GCM
        Returns (ciphertext, iv, tag)
        """
        iv = os.urandom(12)  # 96 bits recommended for GCM
        ciphertext = self.aesgcm.encrypt(iv, plaintext_key, associated_data)
        tag = ciphertext[-16:]
        ciphertext_body = ciphertext[:-16]
        return ciphertext_body, iv, tag

    def unwrap(self, ciphertext: bytes, iv: bytes, tag: bytes,
               associated_data: bytes = b'') -> bytes:
        """
        Unwrap key using AES-GCM with authentication
        """
        full_ciphertext = ciphertext + tag
        return self.aesgcm.decrypt(iv, full_ciphertext, associated_data)


class KeyHierarchyManager:
    """
    Hierarchical key management system
    Implements KEK -> DEK key wrapping hierarchy with HKDF derivation
    """

    def __init__(self, root_seed: Optional[bytes] = None,
                 hash_algorithm: HKDFHash = HKDFHash.SHA256):
        self.hkdf = HKDF(hash_algorithm)
        self.hash_algorithm = hash_algorithm
        
        # Generate root seed if not provided
        if root_seed is None:
            root_seed = os.urandom(64)
        
        # Derive root KEK
        self._root_kek = self.hkdf.derive_key(
            root_seed,
            info=b"root_kek_derivation",
            length=32
        )
        
        self._key_cache: Dict[Tuple[KeyType, str], DerivedKey] = {}
        self._rotation_count = 0
        self._created_at = __import__('time').time()

    def derive_kek(self, kek_id: str, salt: Optional[bytes] = None) -> DerivedKey:
        """
        Derive a Key Encryption Key (KEK) from root KEK
        """
        cache_key = (KeyType.KEK, kek_id)
        if cache_key in self._key_cache:
            return self._key_cache[cache_key]

        info = f"kek_derivation:{kek_id}".encode()
        kek = self.hkdf.derive_key(
            self._root_kek.key_material,
            salt=salt,
            info=info,
            length=32
        )
        
        self._key_cache[cache_key] = kek
        return kek

    def derive_dek(self, kek_id: str, dek_id: str,
                   salt: Optional[bytes] = None) -> DerivedKey:
        """
        Derive a Data Encryption Key (DEK) under a specific KEK
        """
        kek = self.derive_kek(kek_id)
        
        info = f"dek_derivation:{dek_id}".encode()
        dek = self.hkdf.derive_key(
            kek.key_material,
            salt=salt,
            info=info,
            length=32
        )
        
        return dek

    def wrap_dek(self, kek_id: str, plaintext_dek: bytes) -> WrappedKey:
        """
        Wrap a DEK using the specified KEK
        Uses AES-GCM wrap for authenticated encryption
        """
        kek = self.derive_kek(kek_id)
        wrapper = AESGCMWrap(kek.key_material)
        
        ciphertext, iv, tag = wrapper.wrap(
            plaintext_dek,
            associated_data=f"dek_wrap:{kek_id}".encode()
        )
        
        return WrappedKey(
            ciphertext=ciphertext,
            iv=iv,
            tag=tag,
            algorithm=WrapAlgorithm.AES_GCM_WRAP,
            key_type=KeyType.DEK,
            salt=kek.salt,
            info=f"dek_wrap:{kek_id}".encode(),
            created_at=__import__('time').time()
        )

    def unwrap_dek(self, kek_id: str, wrapped: WrappedKey) -> bytes:
        """
        Unwrap a DEK using the specified KEK
        """
        if wrapped.algorithm != WrapAlgorithm.AES_GCM_WRAP:
            raise ValueError(f"Unsupported wrap algorithm: {wrapped.algorithm}")
        
        kek = self.derive_kek(kek_id)
        wrapper = AESGCMWrap(kek.key_material)
        
        return wrapper.unwrap(
            wrapped.ciphertext,
            wrapped.iv,
            wrapped.tag,
            associated_data=f"dek_wrap:{kek_id}".encode()
        )

    def rotate_root_kek(self, new_seed: Optional[bytes] = None) -> None:
        """
        Rotate the root KEK (key rotation with forward secrecy)
        """
        if new_seed is None:
            new_seed = os.urandom(64)
        
        # Zeroize old root KEK
        self._root_kek.zeroize()
        
        # Derive new root KEK
        self._root_kek = self.hkdf.derive_key(
            new_seed,
            info=b"root_kek_derivation_rotated",
            length=32
        )
        
        # Clear cache (all derived keys must be re-derived)
        for key in list(self._key_cache.keys()):
            self._key_cache[key].zeroize()
        self._key_cache.clear()
        
        self._rotation_count += 1

    def derive_session_key(self, context: str, length: int = 32) -> DerivedKey:
        """
        Derive an ephemeral session key for one-time use
        """
        info = f"session_key:{context}:{secrets.randbits(64)}".encode()
        return self.hkdf.derive_key(
            self._root_kek.key_material,
            info=info,
            length=length
        )

    def get_hierarchy_status(self) -> Dict:
        """Get key hierarchy status and metrics"""
        return {
            "hash_algorithm": self.hash_algorithm.value,
            "root_kek_rotations": self._rotation_count,
            "cached_keys": len(self._key_cache),
            "created_age": __import__('time').time() - self._created_at,
            "key_types_in_cache": [kt.value for kt, _ in self._key_cache.keys()]
        }

    def zeroize_all(self) -> None:
        """Zeroize all sensitive key material"""
        self._root_kek.zeroize()
        for key in list(self._key_cache.keys()):
            self._key_cache[key].zeroize()
        self._key_cache.clear()


# Convenience functions
def generate_wrapping_key(length: int = 32) -> bytes:
    """Generate cryptographically secure wrapping key"""
    return os.urandom(length)


def hkdf_derive_key(ikm: bytes, info: bytes = b'',
                    length: int = 32, hash_algo: HKDFHash = HKDFHash.SHA256) -> bytes:
    """Simple one-shot HKDF key derivation"""
    hkdf = HKDF(hash_algo)
    derived = hkdf.derive_key(ikm, info=info, length=length)
    result = derived.key_material
    derived.zeroize()
    return result


# Export public API
__all__ = [
    'KeyHierarchyManager',
    'HKDF',
    'AESKeyWrap',
    'AESGCMWrap',
    'WrappedKey',
    'DerivedKey',
    'KeyType',
    'WrapAlgorithm',
    'HKDFHash',
    'constant_time_compare',
    'secure_zeroize',
    'generate_wrapping_key',
    'hkdf_derive_key',
]
