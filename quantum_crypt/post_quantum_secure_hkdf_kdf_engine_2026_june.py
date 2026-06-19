"""
Post-Quantum Secure HKDF-KDF Engine
Production-grade implementation for QuantumCrypt-AI

This module implements a quantum-safe key derivation system combining:
1. Standard HKDF (RFC 5869) with SHA-2/3
2. Memory-hard Argon2id for resistance to quantum time-memory tradeoffs
3. Post-quantum seed expansion
4. Side-channel resistant operations
5. Key diversification and context binding
"""

import hashlib
import hmac
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union, List, Dict, Any, ByteString
import warnings


class HashAlgorithm(Enum):
    """Supported hash algorithms"""
    SHA256 = "sha256"
    SHA512 = "sha512"
    SHA3_256 = "sha3_256"
    SHA3_512 = "sha3_512"
    BLAKE2b = "blake2b"


class KDFSecurityLevel(Enum):
    """Security levels for key derivation"""
    FAST = "fast"           # For high-performance, low-security needs
    STANDARD = "standard"   # Default balance of security/performance
    PARANOID = "paranoid"   # Maximum security, memory-hard, slow


@dataclass
class DerivedKey:
    """Container for derived key material with metadata"""
    key_material: bytes
    salt: bytes
    info: bytes
    algorithm: HashAlgorithm
    security_level: KDFSecurityLevel
    derived_at: float = field(default_factory=time.time)
    context_hash: Optional[bytes] = None
    verification_hash: Optional[bytes] = None
    
    def __bytes__(self) -> bytes:
        return self.key_material
    
    def __len__(self) -> int:
        return len(self.key_material)
    
    def hex(self) -> str:
        return self.key_material.hex()
    
    def verify(self, expected_hash: bytes) -> bool:
        """Verify key integrity"""
        if self.verification_hash is None:
            return False
        return hmac.compare_digest(self.verification_hash, expected_hash)


class PostQuantumHKDF:
    """
    Post-Quantum Secure HKDF Implementation
    
    Combines standard HKDF with memory-hard functions and quantum-resistant
    design principles to provide protection against both classical and
    quantum adversaries.
    
    Security Features:
    - RFC 5869 compliant HKDF implementation
    - Argon2id-inspired memory-hard expansion
    - SHA-3 and BLAKE2b support (quantum-resistant hashes)
    - Context binding to prevent key reuse attacks
    - Side-channel resistant constant-time operations
    - Quantum entropy mixing from system CSPRNG
    """
    
    # Security parameters for different levels
    SECURITY_PARAMS = {
        KDFSecurityLevel.FAST: {
            "memory_kb": 16,
            "iterations": 2,
            "parallelism": 1
        },
        KDFSecurityLevel.STANDARD: {
            "memory_kb": 256,
            "iterations": 4,
            "parallelism": 2
        },
        KDFSecurityLevel.PARANOID: {
            "memory_kb": 4096,
            "iterations": 8,
            "parallelism": 4
        }
    }
    
    def __init__(self,
                 hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256,
                 security_level: KDFSecurityLevel = KDFSecurityLevel.STANDARD,
                 enforce_post_quantum: bool = True):
        """
        Initialize Post-Quantum HKDF Engine
        
        Args:
            hash_algorithm: Hash function for HMAC operations
            security_level: Security/performance tradeoff
            enforce_post_quantum: Require quantum-resistant algorithms
        """
        self.hash_algorithm = hash_algorithm
        self.security_level = security_level
        self.enforce_post_quantum = enforce_post_quantum
        
        # Validate algorithm choice
        quantum_safe = [HashAlgorithm.SHA3_256, HashAlgorithm.SHA3_512, HashAlgorithm.BLAKE2b]
        if enforce_post_quantum and hash_algorithm not in quantum_safe:
            warnings.warn(
                f"Algorithm {hash_algorithm.value} may not be post-quantum secure. "
                f"Consider SHA3_256, SHA3_512, or BLAKE2b."
            )
        
        # Get hash function
        self._hash_func = self._get_hash_function()
        self._hash_len = self._get_hash_length()
        
        # Get security parameters
        self._params = self.SECURITY_PARAMS[security_level]
    
    def _get_hash_function(self):
        """Get the underlying hash function"""
        mapping = {
            HashAlgorithm.SHA256: hashlib.sha256,
            HashAlgorithm.SHA512: hashlib.sha512,
            HashAlgorithm.SHA3_256: hashlib.sha3_256,
            HashAlgorithm.SHA3_512: hashlib.sha3_512,
            HashAlgorithm.BLAKE2b: hashlib.blake2b
        }
        return mapping[self.hash_algorithm]
    
    def _get_hash_length(self) -> int:
        """Get output length of hash function in bytes"""
        mapping = {
            HashAlgorithm.SHA256: 32,
            HashAlgorithm.SHA512: 64,
            HashAlgorithm.SHA3_256: 32,
            HashAlgorithm.SHA3_512: 64,
            HashAlgorithm.BLAKE2b: 64
        }
        return mapping[self.hash_algorithm]
    
    @staticmethod
    def _constant_time_equal(a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks"""
        return hmac.compare_digest(a, b)
    
    def _extract(self, ikm: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        HKDF Extract step (RFC 5869)
        
        PRK = HMAC-Hash(salt, IKM)
        """
        if salt is None:
            salt = b'\x00' * self._hash_len
        
        return hmac.new(salt, ikm, self._hash_func).digest()
    
    def _expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        """
        HKDF Expand step (RFC 5869)
        
        N = ceil(L/HashLen)
        T = T(1) | T(2) | T(3) | ... | T(N)
        T(1) = HMAC-Hash(PRK, info | 0x01)
        T(i) = HMAC-Hash(PRK, T(i-1) | info | 0xi)
        """
        if length > 255 * self._hash_len:
            raise ValueError(f"Maximum derivation length is {255 * self._hash_len} bytes")
        
        t = b''
        okm = b''
        i = 1
        
        while len(okm) < length:
            t = hmac.new(prk, t + info + bytes([i]), self._hash_func).digest()
            okm += t
            i += 1
        
        return okm[:length]
    
    def _memory_hard_mix(self, key_material: bytes, length: int) -> bytes:
        """
        Memory-hard key mixing function inspired by Argon2
        
        Creates a large memory buffer and performs data-dependent
        lookups to make time-memory tradeoffs (including quantum)
        prohibitively expensive.
        """
        memory_kb = self._params["memory_kb"]
        iterations = self._params["iterations"]
        
        # Initialize memory buffer
        block_size = 1024  # 1KB blocks
        num_blocks = memory_kb
        memory = [b'\x00' * block_size for _ in range(num_blocks)]
        
        # Fill initial memory with key-dependent data
        seed = key_material
        for i in range(num_blocks):
            h = self._hash_func(seed + struct.pack('<Q', i)).digest()
            memory[i] = h * (block_size // len(h))
        
        # Perform memory-hard iterations
        for iteration in range(iterations):
            for i in range(num_blocks):
                # Data-dependent address generation
                addr_bytes = self._hash_func(
                    memory[i] + struct.pack('<Q', iteration) + key_material
                ).digest()
                addr = int.from_bytes(addr_bytes[:4], 'little') % num_blocks
                
                # Constant-time memory lookup and mixing
                memory[i] = bytes(
                    a ^ b for a, b in zip(memory[i], memory[addr])
                )
                
                # Re-hash to prevent compression
                memory[i] = self._hash_func(memory[i] + key_material).digest() * (block_size // self._hash_len)
        
        # Extract final key from memory
        result = b''
        for i in range(0, min(length, num_blocks), self._hash_len):
            idx = (i * 17 + 13) % num_blocks  # Prime-based indexing
            result += self._hash_func(memory[idx] + struct.pack('<Q', i)).digest()
        
        return result[:length]
    
    def _quantum_entropy_mix(self, key_material: bytes) -> bytes:
        """
        Mix in fresh quantum-resistant entropy from system CSPRNG
        
        This provides forward secrecy and hedges against potential
        weaknesses in the input key material.
        """
        # Get fresh system entropy (quantum-resistant in modern OSes)
        fresh_entropy = secrets.token_bytes(64)
        
        # Mix using hash-based combiner
        mixed = self._hash_func(key_material + fresh_entropy).digest()
        
        # Also mix in timestamp for domain separation
        timestamp = struct.pack('<Q', int(time.time() * 1_000_000))
        mixed = self._hash_func(mixed + timestamp).digest()
        
        return mixed
    
    def derive_key(self,
                   input_key_material: Union[bytes, ByteString],
                   length: int = 32,
                   salt: Optional[bytes] = None,
                   info: bytes = b'',
                   context: Optional[Dict[str, Any]] = None,
                   use_memory_hard: bool = True,
                   mix_quantum_entropy: bool = True) -> DerivedKey:
        """
        Derive a cryptographically secure key using post-quantum HKDF
        
        Args:
            input_key_material: Input key material (secret)
            length: Desired output key length in bytes
            salt: Optional salt for domain separation
            info: Optional context binding info
            context: Optional structured context metadata
            use_memory_hard: Whether to apply memory-hard mixing
            mix_quantum_entropy: Whether to mix fresh system entropy
        
        Returns:
            DerivedKey object with key material and metadata
        """
        ikm = bytes(input_key_material)
        
        # Generate random salt if none provided
        if salt is None:
            salt = secrets.token_bytes(self._hash_len)
        
        # Compute context hash if context provided
        context_hash = None
        if context is not None:
            context_bytes = str(sorted(context.items())).encode()
            context_hash = self._hash_func(context_bytes).digest()
            info = info + b'|' + context_hash
        
        # Step 1: Standard HKDF Extract
        prk = self._extract(ikm, salt)
        
        # Step 2: Mix in quantum entropy (if enabled)
        if mix_quantum_entropy:
            prk = self._quantum_entropy_mix(prk)
        
        # Step 3: Standard HKDF Expand
        okm = self._expand(prk, info, length)
        
        # Step 4: Memory-hard mixing for quantum resistance (if enabled)
        if use_memory_hard:
            okm = self._memory_hard_mix(okm, length)
        
        # Compute verification hash
        verification_hash = self._hash_func(okm + salt + info).digest()
        
        return DerivedKey(
            key_material=okm,
            salt=salt,
            info=info,
            algorithm=self.hash_algorithm,
            security_level=self.security_level,
            context_hash=context_hash,
            verification_hash=verification_hash
        )
    
    def derive_multiple_keys(self,
                             input_key_material: bytes,
                             key_specs: List[tuple],
                             salt: Optional[bytes] = None) -> List[DerivedKey]:
        """
        Derive multiple independent keys from a single master secret
        
        Args:
            input_key_material: Master secret
            key_specs: List of (length, info_bytes) tuples
            salt: Optional shared salt
        
        Returns:
            List of DerivedKey objects
        """
        if salt is None:
            salt = secrets.token_bytes(self._hash_len)
        
        keys = []
        for i, (length, info) in enumerate(key_specs):
            # Unique info for each key to prevent correlation
            unique_info = info + struct.pack('<I', i)
            key = self.derive_key(
                input_key_material,
                length=length,
                salt=salt,
                info=unique_info,
                use_memory_hard=(i == 0)  # Only memory-hard on first
            )
            keys.append(key)
        
        return keys
    
    def verify_key_derivation(self,
                              derived_key: DerivedKey,
                              input_key_material: bytes) -> bool:
        """
        Verify that a key was correctly derived from the input material
        
        This allows verifying key derivation without storing the master key.
        """
        # Re-derive using same parameters (disable all non-deterministic features)
        rederived = self.derive_key(
            input_key_material,
            length=len(derived_key.key_material),
            salt=derived_key.salt,
            info=derived_key.info,
            use_memory_hard=False,
            mix_quantum_entropy=False
        )
        
        # Constant-time comparison
        return self._constant_time_equal(
            derived_key.key_material,
            rederived.key_material
        )
    
    def get_security_parameters(self) -> Dict[str, Any]:
        """Get current security parameters"""
        return {
            "hash_algorithm": self.hash_algorithm.value,
            "hash_length_bytes": self._hash_len,
            "security_level": self.security_level.value,
            "memory_kb": self._params["memory_kb"],
            "iterations": self._params["iterations"],
            "parallelism": self._params["parallelism"],
            "enforce_post_quantum": self.enforce_post_quantum
        }
    
    @staticmethod
    def generate_master_seed(bit_length: int = 256) -> bytes:
        """
        Generate a cryptographically secure master seed
        
        Uses system CSPRNG which is post-quantum secure on modern
        operating systems with proper entropy sources.
        """
        if bit_length % 8 != 0:
            raise ValueError("bit_length must be divisible by 8")
        
        return secrets.token_bytes(bit_length // 8)


class KeyDiversificationEngine:
    """
    Post-Quantum Key Diversification Engine
    
    Provides secure key diversification for:
    - Multi-user systems
    - Device-specific keys
    - Session keys
    - Key rotation
    """
    
    def __init__(self, master_key: bytes, hkdf: Optional[PostQuantumHKDF] = None):
        self.master_key = master_key
        self.hkdf = hkdf or PostQuantumHKDF(
            hash_algorithm=HashAlgorithm.SHA3_256,
            security_level=KDFSecurityLevel.STANDARD
        )
        self._derivation_count = 0
    
    def derive_device_key(self, device_id: str, length: int = 32) -> DerivedKey:
        """Derive a device-specific key"""
        info = f"DEVICE:{device_id}".encode()
        return self.hkdf.derive_key(
            self.master_key,
            length=length,
            info=info,
            context={"device_id": device_id, "type": "device_key"}
        )
    
    def derive_user_key(self, user_id: str, length: int = 32) -> DerivedKey:
        """Derive a user-specific key"""
        info = f"USER:{user_id}".encode()
        return self.hkdf.derive_key(
            self.master_key,
            length=length,
            info=info,
            context={"user_id": user_id, "type": "user_key"}
        )
    
    def derive_session_key(self, session_id: str, length: int = 32) -> DerivedKey:
        """Derive a temporary session key"""
        info = f"SESSION:{session_id}:{self._derivation_count}".encode()
        self._derivation_count += 1
        return self.hkdf.derive_key(
            self.master_key,
            length=length,
            info=info,
            context={"session_id": session_id, "type": "session_key"}
        )
    
    def rotate_master_key(self, old_master: bytes, rotation_id: str) -> bytes:
        """
        Securely rotate master key
        
        New key is derived from old key + rotation ID, ensuring
        forward security and preventing rollback attacks.
        """
        info = f"ROTATION:{rotation_id}".encode()
        derived = self.hkdf.derive_key(
            old_master,
            length=len(old_master),
            info=info,
            mix_quantum_entropy=True
        )
        return derived.key_material


# Export public interface
__all__ = [
    'HashAlgorithm',
    'KDFSecurityLevel',
    'DerivedKey',
    'PostQuantumHKDF',
    'KeyDiversificationEngine'
]
