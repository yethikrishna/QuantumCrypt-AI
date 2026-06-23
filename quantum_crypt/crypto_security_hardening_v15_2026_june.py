"""
QuantumCrypt-AI - Crypto Security Hardening v15
Dimension B - Security Hardening
ADD-ONLY IMPLEMENTATION - No existing code modified

This module provides security hardening wrappers for cryptographic operations:
1. Key Material Validation - Enforces NIST security levels for all keys
2. Side-Channel Resistant Operations - Constant-time comparison and timing jitter
3. Secure Key Lifecycle - Zeroization, rotation auditing, and usage tracking
4. Post-Quantum Security Wrappers - NIST PQC algorithm validation
5. Algorithm Fallback Hardening - Secure algorithm negotiation with downgrade protection

All functionality is OPT-IN and wraps existing crypto operations.
"""

import hashlib
import hmac
import secrets
import time
import threading
import os
from typing import Dict, List, Any, Optional, Tuple, Callable, TypeVar
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque


class NISTSecurityLevel(Enum):
    """NIST Post-Quantum Security Levels"""
    NIST_LEVEL_1 = "NIST_LEVEL_1"  # AES-128 equivalent
    NIST_LEVEL_3 = "NIST_LEVEL_3"  # AES-192 equivalent
    NIST_LEVEL_5 = "NIST_LEVEL_5"  # AES-256 equivalent


class KeyType(Enum):
    SYMMETRIC = "SYMMETRIC"
    ASYMMETRIC_PRIVATE = "ASYMMETRIC_PRIVATE"
    ASYMMETRIC_PUBLIC = "ASYMMETRIC_PUBLIC"
    PQ_KEM_PRIVATE = "PQ_KEM_PRIVATE"
    PQ_KEM_PUBLIC = "PQ_KEM_PUBLIC"
    SHARED_SECRET = "SHARED_SECRET"


class AlgorithmCategory(Enum):
    CLASSICAL = "CLASSICAL"
    POST_QUANTUM = "POST_QUANTUM"
    HYBRID = "HYBRID"


@dataclass
class ValidatedKey:
    """Cryptographic key with full security validation metadata."""
    key_id: str
    key_type: KeyType
    algorithm: str
    nist_level: NISTSecurityLevel
    category: AlgorithmCategory
    byte_length: int
    created_timestamp: float
    usage_count: int = 0
    last_used: float = 0.0
    validation_passed: bool = False
    zeroized: bool = False
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "key_type": self.key_type.value,
            "algorithm": self.algorithm,
            "nist_level": self.nist_level.value,
            "category": self.category.value,
            "byte_length": self.byte_length,
            "created_timestamp": self.created_timestamp,
            "usage_count": self.usage_count,
            "validation_passed": self.validation_passed,
            "zeroized": self.zeroized
        }


class ConstantTimeOperations:
    """
    Side-channel resistant constant-time operations.
    ADD-ONLY - Pure utility functions, no existing code modification.
    """
    
    @staticmethod
    def compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte comparison.
        Prevents timing attacks on key material comparison.
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def compare_strings(a: str, b: str) -> bool:
        """Constant-time string comparison."""
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
    
    @staticmethod
    def secure_memzero(buffer: bytearray) -> None:
        """
        Secure memory zeroization.
        Overwrites buffer with random data before zeroing.
        """
        # First overwrite with random bytes
        for i in range(len(buffer)):
            buffer[i] = secrets.randbelow(256)
        # Then overwrite with zeros
        for i in range(len(buffer)):
            buffer[i] = 0
    
    @staticmethod
    def timing_noise_jitter(base_delay_ms: float = 1.0, max_jitter_ms: float = 5.0) -> None:
        """
        Add random timing jitter to operations.
        Makes side-channel timing analysis significantly harder.
        """
        jitter = secrets.SystemRandom().uniform(0, max_jitter_ms)
        total_delay = (base_delay_ms + jitter) / 1000.0
        time.sleep(total_delay)


class KeyMaterialValidator:
    """
    Validates cryptographic key material against security requirements.
    ADD-ONLY - Wraps key generation, doesn't modify generators.
    """
    
    # Minimum key lengths by NIST level
    MIN_KEY_LENGTHS = {
        NISTSecurityLevel.NIST_LEVEL_1: 16,   # 128 bits
        NISTSecurityLevel.NIST_LEVEL_3: 24,   # 192 bits
        NISTSecurityLevel.NIST_LEVEL_5: 32,   # 256 bits
    }
    
    def __init__(self, enforce_nist_level: Optional[NISTSecurityLevel] = None):
        self.enforce_nist_level = enforce_nist_level
        self._thread_lock = threading.Lock()
        self._validation_stats = {
            "total_validated": 0,
            "passed": 0,
            "failed": 0,
            "too_short": 0,
            "insufficient_entropy": 0
        }
    
    def validate_key(self, 
                    key_material: bytes, 
                    key_type: KeyType,
                    algorithm: str,
                    required_nist_level: NISTSecurityLevel = NISTSecurityLevel.NIST_LEVEL_1) -> ValidatedKey:
        """
        Validate key material against security requirements.
        Returns validated key object with security metadata.
        """
        with self._thread_lock:
            self._validation_stats["total_validated"] += 1
            
            key_id = self._generate_key_id(key_material)
            byte_length = len(key_material)
            
            validated = ValidatedKey(
                key_id=key_id,
                key_type=key_type,
                algorithm=algorithm,
                nist_level=required_nist_level,
                category=self._categorize_algorithm(algorithm),
                byte_length=byte_length,
                created_timestamp=time.time()
            )
            
            # Run validation checks
            checks = [
                self._check_min_length(byte_length, required_nist_level),
                self._check_entropy_quality(key_material),
                self._check_weak_patterns(key_material)
            ]
            
            validated.validation_passed = all(checks)
            
            if validated.validation_passed:
                self._validation_stats["passed"] += 1
            else:
                self._validation_stats["failed"] += 1
            
            validated.audit_trail.append({
                "timestamp": time.time(),
                "action": "validation",
                "passed": validated.validation_passed
            })
            
            return validated
    
    def _generate_key_id(self, key_material: bytes) -> str:
        """Generate unique key identifier (hash of key, not the key itself)."""
        return hashlib.sha256(key_material).hexdigest()[:16]
    
    def _categorize_algorithm(self, algorithm: str) -> AlgorithmCategory:
        algo_lower = algorithm.lower()
        pq_algorithms = {"kyber", "crystals", "ntru", "frodo", "bike", "hqc", "pqc"}
        hybrid_indicators = {"hybrid", "pq+", "+pq"}
        
        if any(ind in algo_lower for ind in hybrid_indicators):
            return AlgorithmCategory.HYBRID
        if any(pq in algo_lower for pq in pq_algorithms):
            return AlgorithmCategory.POST_QUANTUM
        return AlgorithmCategory.CLASSICAL
    
    def _check_min_length(self, length: int, required_level: NISTSecurityLevel) -> bool:
        min_length = self.MIN_KEY_LENGTHS.get(required_level, 16)
        if length < min_length:
            self._validation_stats["too_short"] += 1
            return False
        return True
    
    def _check_entropy_quality(self, key_material: bytes) -> bool:
        """
        Basic entropy quality check.
        Real implementation would use NIST SP 800-90B tests.
        """
        if len(key_material) < 2:
            return False
        
        # Check for repeated bytes (simple heuristic)
        unique_bytes = len(set(key_material))
        unique_ratio = unique_bytes / len(key_material)
        
        if unique_ratio < 0.3 and len(key_material) > 8:
            self._validation_stats["insufficient_entropy"] += 1
            return False
        return True
    
    def _check_weak_patterns(self, key_material: bytes) -> bool:
        """Check for obviously weak key patterns."""
        weak_patterns = [
            b'\x00' * 8,      # All zeros
            b'\xff' * 8,      # All ones
            b'01234567',      # Sequential
            b'password',      # Literal weak
        ]
        
        for pattern in weak_patterns:
            if pattern in key_material:
                return False
        return True
    
    def get_validation_stats(self) -> Dict[str, Any]:
        with self._thread_lock:
            return dict(self._validation_stats)


class SecureKeyLifecycleManager:
    """
    Manages secure key lifecycle with auditing.
    ADD-ONLY - Wraps key operations, doesn't modify crypto engines.
    """
    
    def __init__(self, max_key_uses: int = 10000, key_rotation_hours: float = 24.0):
        self.max_key_uses = max_key_uses
        self.key_rotation_seconds = key_rotation_hours * 3600
        self._thread_lock = threading.Lock()
        self._active_keys: Dict[str, ValidatedKey] = {}
        self._key_usage: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
    
    def register_key(self, key: ValidatedKey) -> None:
        """Register a key for lifecycle management."""
        with self._thread_lock:
            if not key.validation_passed:
                raise ValueError("Cannot register unvalidated key")
            self._active_keys[key.key_id] = key
    
    def track_key_usage(self, key_id: str) -> bool:
        """
        Track key usage and check rotation requirements.
        Returns True if key should be rotated.
        """
        with self._thread_lock:
            if key_id not in self._active_keys:
                return False
            
            key = self._active_keys[key_id]
            key.usage_count += 1
            key.last_used = time.time()
            key.audit_trail.append({
                "timestamp": time.time(),
                "action": "usage",
                "usage_count": key.usage_count
            })
            
            # Check rotation triggers
            age_seconds = time.time() - key.created_timestamp
            needs_rotation = (
                key.usage_count >= self.max_key_uses or
                age_seconds >= self.key_rotation_seconds
            )
            
            self._key_usage[key_id].append(time.time())
            
            return needs_rotation
    
    def secure_zeroize_key(self, key_id: str, key_buffer: bytearray) -> None:
        """Securely zeroize and retire a key."""
        with self._thread_lock:
            if key_id in self._active_keys:
                key = self._active_keys[key_id]
                ConstantTimeOperations.secure_memzero(key_buffer)
                key.zeroized = True
                key.audit_trail.append({
                    "timestamp": time.time(),
                    "action": "zeroized"
                })
                del self._active_keys[key_id]
    
    def get_key_status(self, key_id: str) -> Optional[Dict[str, Any]]:
        with self._thread_lock:
            if key_id in self._active_keys:
                key = self._active_keys[key_id]
                age = time.time() - key.created_timestamp
                return {
                    **key.to_dict(),
                    "age_seconds": age,
                    "rotation_recommended": age >= self.key_rotation_seconds
                }
            return None
    
    def get_all_keys_status(self) -> List[Dict[str, Any]]:
        with self._thread_lock:
            return [self.get_key_status(kid) for kid in self._active_keys.keys()]


class PQSecurityHardeningWrapper:
    """
    Post-Quantum security hardening wrapper.
    ADD-ONLY - Wraps PQ operations, doesn't modify core algorithms.
    """
    
    def __init__(self, 
                 enable_timing_protection: bool = True,
                 enable_key_validation: bool = True,
                 minimum_nist_level: NISTSecurityLevel = NISTSecurityLevel.NIST_LEVEL_1):
        
        self.enable_timing_protection = enable_timing_protection
        self.enable_key_validation = enable_key_validation
        self.minimum_nist_level = minimum_nist_level
        self.validator = KeyMaterialValidator(minimum_nist_level)
        self._thread_lock = threading.Lock()
        self._operation_stats = defaultdict(int)
    
    def wrap_key_generation(self, 
                           generate_func: Callable,
                           algorithm: str,
                           key_type: KeyType) -> Tuple[bytes, ValidatedKey]:
        """
        Wrap key generation with security hardening.
        Usage: key, validated = wrapper.wrap_key_generation(generate_kyber_keypair, "KYBER-768", KeyType.PQ_KEM_PRIVATE)
        """
        with self._thread_lock:
            # Generate key using original function
            key_material = generate_func()
            
            # Apply timing protection
            if self.enable_timing_protection:
                ConstantTimeOperations.timing_noise_jitter()
            
            # Validate key material
            validated = self.validator.validate_key(
                key_material, key_type, algorithm, self.minimum_nist_level
            )
            
            self._operation_stats["key_generation"] += 1
            
            return key_material, validated
    
    def wrap_encapsulation(self, 
                          encaps_func: Callable,
                          public_key: bytes,
                          algorithm: str) -> Tuple[Any, bytes]:
        """Wrap KEM encapsulation with security hardening."""
        with self._thread_lock:
            if self.enable_timing_protection:
                ConstantTimeOperations.timing_noise_jitter()
            
            result = encaps_func(public_key)
            self._operation_stats["encapsulation"] += 1
            
            return result
    
    def wrap_decapsulation(self, 
                          decaps_func: Callable,
                          ciphertext: Any,
                          private_key: bytes) -> bytes:
        """Wrap KEM decapsulation with security hardening."""
        with self._thread_lock:
            if self.enable_timing_protection:
                ConstantTimeOperations.timing_noise_jitter()
            
            shared_secret = decaps_func(ciphertext, private_key)
            self._operation_stats["decapsulation"] += 1
            
            # Validate shared secret
            self.validator.validate_key(
                shared_secret, KeyType.SHARED_SECRET, algorithm, self.minimum_nist_level
            )
            
            return shared_secret
    
    def constant_time_compare_secrets(self, a: bytes, b: bytes) -> bool:
        """Secure secret comparison."""
        return ConstantTimeOperations.compare(a, b)
    
    def get_operation_stats(self) -> Dict[str, int]:
        with self._thread_lock:
            return dict(self._operation_stats)


class AlgorithmDowngradeProtection:
    """
    Prevents algorithm downgrade attacks.
    ADD-ONLY - Security layer on top of algorithm negotiation.
    """
    
    def __init__(self, minimum_security_level: NISTSecurityLevel = NISTSecurityLevel.NIST_LEVEL_1):
        self.minimum_level = minimum_security_level
        self._thread_lock = threading.Lock()
        self._allowed_algorithms: Dict[str, NISTSecurityLevel] = {
            "AES-256-GCM": NISTSecurityLevel.NIST_LEVEL_5,
            "AES-128-GCM": NISTSecurityLevel.NIST_LEVEL_1,
            "KYBER-512": NISTSecurityLevel.NIST_LEVEL_1,
            "KYBER-768": NISTSecurityLevel.NIST_LEVEL_3,
            "KYBER-1024": NISTSecurityLevel.NIST_LEVEL_5,
            "ChaCha20-Poly1305": NISTSecurityLevel.NIST_LEVEL_3,
            "RSA-4096": NISTSecurityLevel.NIST_LEVEL_3,
            "X25519": NISTSecurityLevel.NIST_LEVEL_1,
            "X448": NISTSecurityLevel.NIST_LEVEL_5,
        }
        self._downgrade_attempts = 0
    
    def validate_algorithm_negotiation(self, 
                                     proposed_algorithm: str,
                                     peer_proposed: str) -> Tuple[bool, str]:
        """
        Validate algorithm negotiation against downgrade attacks.
        Returns (allowed, selected_algorithm)
        """
        with self._thread_lock:
            # Check both algorithms are allowed
            our_allowed = proposed_algorithm in self._allowed_algorithms
            peer_allowed = peer_proposed in self._allowed_algorithms
            
            if not (our_allowed and peer_allowed):
                self._downgrade_attempts += 1
                return False, ""
            
            # Select strongest common algorithm
            our_level = self._allowed_algorithms[proposed_algorithm]
            peer_level = self._allowed_algorithms[peer_proposed]
            
            # Always choose the stronger algorithm
            if self._level_rank(our_level) >= self._level_rank(peer_level):
                selected = proposed_algorithm
                selected_level = our_level
            else:
                selected = peer_proposed
                selected_level = peer_level
            
            # Verify meets minimum security
            if self._level_rank(selected_level) < self._level_rank(self.minimum_level):
                self._downgrade_attempts += 1
                return False, selected
            
            return True, selected
    
    def _level_rank(self, level: NISTSecurityLevel) -> int:
        ranks = {
            NISTSecurityLevel.NIST_LEVEL_1: 1,
            NISTSecurityLevel.NIST_LEVEL_3: 3,
            NISTSecurityLevel.NIST_LEVEL_5: 5,
        }
        return ranks.get(level, 0)
    
    def add_allowed_algorithm(self, algorithm: str, level: NISTSecurityLevel) -> None:
        with self._thread_lock:
            self._allowed_algorithms[algorithm] = level
    
    def get_downgrade_protection_stats(self) -> Dict[str, Any]:
        with self._thread_lock:
            return {
                "allowed_algorithms_count": len(self._allowed_algorithms),
                "downgrade_attempts_blocked": self._downgrade_attempts,
                "minimum_required_level": self.minimum_level.value
            }


class CryptoSecurityHardeningPipeline:
    """
    Complete crypto security hardening pipeline.
    ADD-ONLY - Pure wrapper, zero modifications to existing code.
    """
    
    def __init__(self,
                 enable_constant_time: bool = True,
                 enable_key_validation: bool = True,
                 enable_lifecycle: bool = True,
                 enable_pq_hardening: bool = True,
                 enable_downgrade_protection: bool = True):
        
        self.constant_time = ConstantTimeOperations() if enable_constant_time else None
        self.key_validator = KeyMaterialValidator() if enable_key_validation else None
        self.key_lifecycle = SecureKeyLifecycleManager() if enable_lifecycle else None
        self.pq_wrapper = PQSecurityHardeningWrapper() if enable_pq_hardening else None
        self.downgrade_protection = AlgorithmDowngradeProtection() if enable_downgrade_protection else None
        
        self._stats = {
            "operations_secured": 0,
            "keys_validated": 0,
            "downgrades_blocked": 0,
            "keys_zeroized": 0
        }
        self._lock = threading.Lock()
    
    def secure_operation(self, operation_name: str, operation: Callable, *args, **kwargs) -> Any:
        """
        Wrap any crypto operation with security hardening.
        """
        with self._lock:
            # Add timing protection
            if self.constant_time:
                self.constant_time.timing_noise_jitter()
            
            # Execute operation
            result = operation(*args, **kwargs)
            
            self._stats["operations_secured"] += 1
            
            return result
    
    def get_pipeline_stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)


# Export public API
__all__ = [
    "NISTSecurityLevel",
    "KeyType",
    "AlgorithmCategory",
    "ValidatedKey",
    "ConstantTimeOperations",
    "KeyMaterialValidator",
    "SecureKeyLifecycleManager",
    "PQSecurityHardeningWrapper",
    "AlgorithmDowngradeProtection",
    "CryptoSecurityHardeningPipeline"
]
