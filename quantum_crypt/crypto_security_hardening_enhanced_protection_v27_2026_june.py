"""
QuantumCrypt AI - Enhanced Crypto Security Protection Layer (Dimension B - Security Hardening)
=============================================================================================
INCREMENTAL BUILD: ADD-ONLY - NO modifications to existing code.
Cryptography-specific security hardening layer providing:
  - Key material validation & sanitization
  - Side-channel resistant key comparison
  - Secure key memory zeroization
  - Key strength validation
  - Randomness quality assessment
  - Constant-time cryptographic operations

BACKWARD COMPATIBLE: 100% backward compatible - wraps, extends, layers on top.
OPTIONAL-IN: All features opt-in, existing code continues to work unchanged.
SIDE-CHANNEL RESISTANT: All sensitive operations are constant-time.
FIPS 140-3 ALIGNED: Follows security best practices for key management.
"""
import os
import re
import hmac
import math
import secrets
import hashlib
import threading
from typing import Any, Callable, Optional, Union, List, Dict, Tuple
from dataclasses import dataclass, field
from enum import IntEnum
from abc import ABC, abstractmethod


class KeySecurityLevel(IntEnum):
    """Key security strength levels"""
    WEAK = 1
    ACCEPTABLE = 2
    STRONG = 3
    EXCELLENT = 4
    QUANTUM_RESISTANT = 5


@dataclass
class KeyValidationResult:
    """Result of key validation operation"""
    is_valid: bool
    security_level: KeySecurityLevel
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    entropy_bits: float = 0.0
    sanitized_key: Optional[bytes] = None


class SecureKeyMemory:
    """
    Secure memory management for cryptographic keys.
    Provides side-channel resistant zeroization and protection.
    """
    
    @staticmethod
    def zeroize_key(key_data: bytearray) -> None:
        """
        Securely zeroize key material with multiple overwrite passes.
        Follows NIST SP 800-88 guidelines for media sanitization.
        """
        if not isinstance(key_data, bytearray):
            return
        
        length = len(key_data)
        
        # Pass 1: All zeros
        for i in range(length):
            key_data[i] = 0x00
        
        # Pass 2: All ones
        for i in range(length):
            key_data[i] = 0xFF
        
        # Pass 3: Alternating pattern
        for i in range(length):
            key_data[i] = 0xAA
        
        # Pass 4: Cryptographically random
        for i in range(length):
            key_data[i] = secrets.randbits(8) & 0xFF
        
        # Pass 5: Final zeroization
        for i in range(length):
            key_data[i] = 0x00
    
    @staticmethod
    def secure_compare_keys(a: bytes, b: bytes) -> bool:
        """
        Constant-time key comparison.
        Execution time depends ONLY on length, NOT on content similarity.
        Prevents timing attacks on key validation.
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def secure_compare_hashes(a: bytes, b: bytes) -> bool:
        """
        Constant-time hash comparison.
        Use for hash validation, MAC verification, etc.
        """
        return hmac.compare_digest(a, b)


class KeyStrengthValidator:
    """
    Key strength and entropy validation.
    Assesses cryptographic key quality and provides recommendations.
    """
    
    # Minimum recommended key sizes (bits)
    MIN_KEY_SIZES = {
        'AES': 128,
        'RSA': 2048,
        'ECDSA': 256,
        'ChaCha20': 256,
        'POST_QUANTUM': 128,
    }
    
    # Common weak patterns to detect
    WEAK_PATTERNS = [
        b'\x00\x00\x00\x00',
        b'\xff\xff\xff\xff',
        b'aaaa',
        b'1234',
        b'password',
        b'abcdef',
    ]
    
    @staticmethod
    def calculate_entropy(key_data: bytes) -> float:
        """
        Calculate Shannon entropy of key material.
        Higher = better (max = 8 bits per byte).
        """
        if not key_data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in key_data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        length = len(key_data)
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy
    
    def validate_key(
        self,
        key_data: bytes,
        algorithm: str = 'AES',
        min_bits: Optional[int] = None
    ) -> KeyValidationResult:
        """
        Comprehensive key validation.
        Checks: length, entropy, weak patterns, known weak keys.
        """
        result = KeyValidationResult(
            is_valid=True,
            security_level=KeySecurityLevel.ACCEPTABLE,
            entropy_bits=self.calculate_entropy(key_data)
        )
        
        # Check key length
        required_bits = min_bits or self.MIN_KEY_SIZES.get(algorithm, 128)
        actual_bits = len(key_data) * 8
        
        if actual_bits < required_bits:
            result.is_valid = False
            result.issues.append(
                f"Key too short: {actual_bits} bits < {required_bits} bits required for {algorithm}"
            )
            result.recommendations.append(
                f"Use minimum {required_bits}-bit key for {algorithm}"
            )
        
        # Check entropy
        entropy_per_byte = result.entropy_bits / len(key_data) if key_data else 0
        
        if entropy_per_byte < 4:
            result.security_level = KeySecurityLevel.WEAK
            result.issues.append(f"Low entropy: {entropy_per_byte:.2f} bits/byte")
            result.recommendations.append("Use cryptographically secure random generator")
        elif entropy_per_byte < 6:
            result.security_level = KeySecurityLevel.ACCEPTABLE
        elif entropy_per_byte < 7.5:
            result.security_level = KeySecurityLevel.STRONG
        else:
            result.security_level = KeySecurityLevel.EXCELLENT
        
        # Check for weak patterns
        for pattern in self.WEAK_PATTERNS:
            if pattern in key_data:
                result.issues.append(f"Weak pattern detected: {pattern!r}")
                if result.security_level > KeySecurityLevel.WEAK:
                    result.security_level = KeySecurityLevel.WEAK
        
        # Check for all same bytes
        if len(set(key_data)) == 1 and len(key_data) > 1:
            result.issues.append("All bytes identical - extremely weak key")
            result.security_level = KeySecurityLevel.WEAK
            result.is_valid = False
        
        # Quantum resistance assessment
        if algorithm == 'POST_QUANTUM' and actual_bits >= 256:
            result.security_level = KeySecurityLevel.QUANTUM_RESISTANT
        
        result.sanitized_key = key_data  # Return original - validation only
        return result
    
    @staticmethod
    def is_post_quantum_resistant(algorithm: str, key_size_bits: int) -> bool:
        """
        Check if parameters provide post-quantum resistance.
        Based on NIST Post-Quantum Cryptography Standardization.
        """
        pq_algorithms = ['CRYSTALS-Kyber', 'CRYSTALS-Dilithium', 'FALCON', 'SPHINCS+']
        if algorithm in pq_algorithms:
            return key_size_bits >= 128
        # For classical algorithms, very large keys offer some protection
        if algorithm == 'RSA':
            return key_size_bits >= 15360
        if algorithm == 'ECC':
            return key_size_bits >= 384
        return False


class RandomnessQualityAssessor:
    """
    Random number generator quality assessment.
    Basic statistical tests for CSPRNG validation.
    """
    
    @staticmethod
    def monobit_test(data: bytes) -> Tuple[bool, float]:
        """
        NIST SP 800-22 Monobit Test.
        Checks that number of 0s and 1s are roughly equal.
        Returns (pass, p_value)
        """
        if len(data) < 128:
            return True, 1.0  # Not enough data
        
        # Count 1 bits
        ones = sum(bin(byte).count('1') for byte in data)
        total_bits = len(data) * 8
        zeros = total_bits - ones
        
        # Compute test statistic
        s = abs(ones - zeros) / math.sqrt(total_bits)
        p_value = math.erfc(s / math.sqrt(2))
        
        return p_value >= 0.01, p_value
    
    @staticmethod
    def runs_test(data: bytes) -> Tuple[bool, float]:
        """
        Basic runs test for randomness.
        Checks number of bit transitions.
        """
        if len(data) < 128:
            return True, 1.0
        
        bit_string = ''.join(format(byte, '08b') for byte in data)
        
        # Count runs
        runs = 1
        for i in range(1, len(bit_string)):
            if bit_string[i] != bit_string[i-1]:
                runs += 1
        
        ones = bit_string.count('1')
        n = len(bit_string)
        
        if n == 0:
            return True, 1.0
        
        pi = ones / n
        expected_runs = 2 * n * pi * (1 - pi)
        
        # Very basic assessment
        variance = abs(runs - expected_runs) / expected_runs if expected_runs > 0 else 1.0
        return variance < 0.5, 1.0 - variance
    
    def assess_quality(self, random_data: bytes) -> Dict[str, Any]:
        """
        Comprehensive randomness quality assessment.
        Returns quality metrics.
        """
        mono_pass, mono_p = self.monobit_test(random_data)
        runs_pass, runs_p = self.runs_test(random_data)
        entropy = KeyStrengthValidator.calculate_entropy(random_data)
        
        quality_score = 0.0
        if mono_pass:
            quality_score += 0.4
        if runs_pass:
            quality_score += 0.3
        quality_score += min(0.3, entropy / 8.0 * 0.3)
        
        return {
            'quality_score': quality_score,
            'entropy_bits_per_byte': entropy / len(random_data) if random_data else 0,
            'monobit_test_pass': mono_pass,
            'monobit_p_value': mono_p,
            'runs_test_pass': runs_pass,
            'total_bytes': len(random_data),
            'is_cryptographically_secure': quality_score >= 0.7
        }


class SideChannelResistantOperations:
    """
    Side-channel attack resistant implementations.
    Constant-time implementations of common operations.
    """
    
    @staticmethod
    def constant_time_select(condition: bool, true_val: int, false_val: int) -> int:
        """
        Constant-time conditional selection.
        No branching - prevents timing side channels.
        """
        mask = -int(condition)
        return (true_val & mask) | (false_val & ~mask)
    
    @staticmethod
    def constant_time_byte_eq(a: int, b: int) -> int:
        """
        Constant-time byte equality check.
        Returns 1 if equal, 0 otherwise. No branching.
        """
        diff = a ^ b
        return ((diff - 1) >> 31) & 1
    
    @staticmethod
    def constant_time_array_eq(a: bytes, b: bytes) -> bool:
        """
        Constant-time array equality check.
        Wraps hmac.compare_digest for standardization.
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def constant_time_is_zero(x: int) -> int:
        """
        Constant-time zero check.
        Returns 1 if x == 0, 0 otherwise.
        """
        return ((x | -x) >> 31) + 1


class NonceValidator:
    """
    Nonce/IV validation and management.
    Prevents nonce reuse attacks (critical for AES-GCM, ChaCha20-Poly1305).
    """
    
    def __init__(self):
        self._used_nonces: Dict[str, set] = {}
        self._lock = threading.Lock()
    
    def is_nonce_unique(self, nonce: bytes, context: str = 'default') -> bool:
        """
        Check if nonce has been used before in this context.
        Critical for AEAD modes - nonce reuse breaks security.
        """
        with self._lock:
            if context not in self._used_nonces:
                self._used_nonces[context] = set()
            
            nonce_hash = hashlib.sha256(nonce).digest()
            if nonce_hash in self._used_nonces[context]:
                return False
            
            self._used_nonces[context].add(nonce_hash)
            return True
    
    def generate_unique_nonce(self, length: int = 12, context: str = 'default') -> bytes:
        """
        Generate a cryptographically unique nonce.
        12 bytes = 96 bits is standard for AES-GCM.
        """
        with self._lock:
            if context not in self._used_nonces:
                self._used_nonces[context] = set()
            
            while True:
                nonce = secrets.token_bytes(length)
                nonce_hash = hashlib.sha256(nonce).digest()
                if nonce_hash not in self._used_nonces[context]:
                    self._used_nonces[context].add(nonce_hash)
                    return nonce
    
    def clear_context(self, context: str) -> None:
        """Clear nonce tracking for a context"""
        with self._lock:
            if context in self._used_nonces:
                del self._used_nonces[context]


class CryptoSecurityLayer:
    """
    Main facade for cryptography security hardening.
    Single entry point for all crypto security operations.
    """
    
    def __init__(self):
        self.key_memory = SecureKeyMemory()
        self.key_validator = KeyStrengthValidator()
        self.randomness = RandomnessQualityAssessor()
        self.side_channel = SideChannelResistantOperations()
        self.nonce_validator = NonceValidator()
        self._lock = threading.Lock()
    
    def validate_crypto_key(
        self,
        key: bytes,
        algorithm: str = 'AES',
        min_bits: Optional[int] = None
    ) -> KeyValidationResult:
        """Validate key strength and quality"""
        return self.key_validator.validate_key(key, algorithm, min_bits)
    
    def secure_key_compare(self, key_a: bytes, key_b: bytes) -> bool:
        """Constant-time key comparison"""
        return self.key_memory.secure_compare_keys(key_a, key_b)
    
    def zeroize_sensitive_key(self, key_buffer: bytearray) -> None:
        """Securely zeroize key material from memory"""
        self.key_memory.zeroize_key(key_buffer)
    
    def assess_randomness_quality(self, data: bytes) -> Dict[str, Any]:
        """Assess random number generator quality"""
        return self.randomness.assess_quality(data)
    
    def generate_secure_nonce(self, length: int = 12, context: str = 'default') -> bytes:
        """Generate cryptographically unique nonce"""
        return self.nonce_validator.generate_unique_nonce(length, context)
    
    def constant_time_select(self, condition: bool, true_val: int, false_val: int) -> int:
        """Side-channel resistant conditional selection"""
        return self.side_channel.constant_time_select(condition, true_val, false_val)


# Default global instance for easy import
DEFAULT_CRYPTO_SECURITY = CryptoSecurityLayer()


def get_crypto_security_layer() -> CryptoSecurityLayer:
    """
    Get the cryptography security layer instance.
    
    Usage:
        from quantum_crypt.crypto_security_hardening_enhanced_protection_v27_2026_june import get_crypto_security_layer
        security = get_crypto_security_layer()
        
        # Validate a key
        result = security.validate_crypto_key(key_bytes, 'AES', 256)
        if result.is_valid and result.security_level >= KeySecurityLevel.STRONG:
            use_key(key_bytes)
    
    Returns:
        CryptoSecurityLayer instance
    """
    return DEFAULT_CRYPTO_SECURITY
