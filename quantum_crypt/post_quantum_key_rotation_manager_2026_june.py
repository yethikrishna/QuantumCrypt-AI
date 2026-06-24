"""
Post-Quantum Key Rotation Manager - QuantumCrypt AI
Dimension A: Feature Expansion (Incremental, Add-Only)

Automated secure key rotation management for post-quantum cryptographic
algorithms with zero-downtime key switching, grace period handling,
and secure key retirement protocols.

STABLE API - Backward Compatible
"""

import time
import secrets
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Tuple
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict


class KeyStatus(Enum):
    """Key lifecycle status"""
    PENDING = "pending"
    ACTIVE = "active"
    GRACE_PERIOD = "grace_period"
    RETIRING = "retiring"
    RETIRED = "retired"
    COMPROMISED = "compromised"


class AlgorithmType(Enum):
    """Supported post-quantum algorithm types"""
    CRYSTALS_KYBER = "crystals_kyber"
    CRYSTALS_DILITHIUM = "crystals_dilithium"
    FALCON = "falcon"
    SPHINCS = "sphincs"
    NTRU = "ntru"
    CLASSIC_MCELIECE = "classic_mceliece"
    HYBRID_RSA_KYBER = "hybrid_rsa_kyber"
    HYBRID_ECDSA_DILITHIUM = "hybrid_ecdsa_dilithium"


class RotationStrategy(Enum):
    """Key rotation strategies"""
    TIME_BASED = "time_based"
    USAGE_BASED = "usage_based"
    HYBRID = "hybrid"
    ON_DEMAND = "on_demand"


@dataclass
class CryptographicKey:
    """Cryptographic key metadata"""
    key_id: str
    algorithm: AlgorithmType
    status: KeyStatus
    created_at: float
    activated_at: Optional[float] = None
    expires_at: Optional[float] = None
    retired_at: Optional[float] = None
    usage_count: int = 0
    max_usage: Optional[int] = None
    version: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)
    key_material_hash: str = ""
    
    def is_active(self) -> bool:
        """Check if key is currently active"""
        return self.status == KeyStatus.ACTIVE
    
    def is_valid(self) -> bool:
        """Check if key is valid for use"""
        if self.status in (KeyStatus.RETIRED, KeyStatus.COMPROMISED):
            return False
        if self.expires_at and time.time() > self.expires_at:
            return False
        if self.max_usage and self.usage_count >= self.max_usage:
            return False
        return True
    
    def increment_usage(self) -> None:
        """Increment usage counter"""
        self.usage_count += 1


@dataclass
class RotationEvent:
    """Record of a key rotation event"""
    event_id: str
    old_key_id: str
    new_key_id: str
    algorithm: AlgorithmType
    timestamp: float
    strategy: RotationStrategy
    reason: str
    success: bool
    duration_ms: float
    zero_downtime: bool


class PostQuantumKeyRotationManager:
    """
    Post-Quantum Key Rotation Manager.
    
    Incremental feature - adds key rotation capabilities without
    modifying existing cryptographic implementations.
    
    Features:
    - Automated time-based rotation
    - Usage-based rotation thresholds
    - Zero-downtime key switching
    - Grace period for key transition
    - Secure key retirement
    - Compromise response protocols
    - Full audit logging
    """
    
    def __init__(
        self,
        default_rotation_days: int = 90,
        grace_period_hours: int = 24,
        max_keys_per_algorithm: int = 5,
    ):
        self.default_rotation_days = default_rotation_days
        self.grace_period_seconds = grace_period_hours * 3600
        self.max_keys_per_algorithm = max_keys_per_algorithm
        
        self.keys: Dict[str, CryptographicKey] = {}
        self.keys_by_algorithm: Dict[str, List[str]] = defaultdict(list)
        self.rotation_history: List[RotationEvent] = []
        self.rotation_callbacks: List[Callable] = []
        self.key_generators: Dict[str, Callable] = {}
        self.usage_thresholds: Dict[str, int] = defaultdict(lambda: 100000)
        
        # Register default key generators (stub implementations - wrap actual crypto)
        self._register_default_generators()
    
    def _register_default_generators(self) -> None:
        """Register default key generator stubs"""
        for algo in AlgorithmType:
            self.key_generators[algo.value] = self._default_key_generator
    
    def _default_key_generator(self, algorithm: AlgorithmType) -> Tuple[str, Dict]:
        """Default key generator (stub - production would use actual crypto)"""
        # In production this would call actual PQ key generation
        key_material = secrets.token_hex(64)
        key_hash = hashlib.sha3_256(key_material.encode()).hexdigest()
        metadata = {
            "algorithm": algorithm.value,
            "generated_at": time.time(),
            "key_size": 512,
        }
        return key_hash, metadata
    
    def _generate_key_id(self) -> str:
        """Generate unique key ID"""
        return hashlib.sha256(
            f"{time.time()}:{secrets.token_hex(16)}".encode()
        ).hexdigest()[:24]
    
    def register_key_generator(
        self,
        algorithm: AlgorithmType,
        generator_fn: Callable[[AlgorithmType], Tuple[str, Dict]],
    ) -> None:
        """Register a custom key generator function"""
        self.key_generators[algorithm.value] = generator_fn
    
    def register_rotation_callback(self, callback: Callable[[RotationEvent], None]) -> None:
        """Register callback for rotation events"""
        self.rotation_callbacks.append(callback)
    
    def create_key(
        self,
        algorithm: AlgorithmType,
        activate_immediately: bool = True,
        rotation_days: Optional[int] = None,
        max_usage: Optional[int] = None,
        metadata: Optional[Dict] = None,
    ) -> CryptographicKey:
        """
        Create a new post-quantum cryptographic key.
        Add-only operation - does not modify existing keys.
        """
        now = time.time()
        key_id = self._generate_key_id()
        
        # Generate key material
        generator = self.key_generators.get(
            algorithm.value,
            self._default_key_generator,
        )
        key_hash, key_metadata = generator(algorithm)
        
        # Merge metadata
        final_metadata = {**key_metadata, **(metadata or {})}
        
        # Calculate expiration
        rotation_seconds = (rotation_days or self.default_rotation_days) * 86400
        expires_at = now + rotation_seconds
        
        key = CryptographicKey(
            key_id=key_id,
            algorithm=algorithm,
            status=KeyStatus.ACTIVE if activate_immediately else KeyStatus.PENDING,
            created_at=now,
            activated_at=now if activate_immediately else None,
            expires_at=expires_at,
            max_usage=max_usage,
            version=1,
            metadata=final_metadata,
            key_material_hash=key_hash,
        )
        
        self.keys[key_id] = key
        self.keys_by_algorithm[algorithm.value].append(key_id)
        
        # Enforce max keys per algorithm
        algo_keys = self.keys_by_algorithm[algorithm.value]
        if len(algo_keys) > self.max_keys_per_algorithm:
            # Retire oldest key
            oldest_key_id = min(
                algo_keys,
                key=lambda kid: self.keys[kid].created_at,
            )
            self.retire_key(oldest_key_id, reason="max_keys_exceeded")
        
        return key
    
    def get_active_key(self, algorithm: AlgorithmType) -> Optional[CryptographicKey]:
        """Get the currently active key for an algorithm"""
        algo_keys = self.keys_by_algorithm.get(algorithm.value, [])
        active_keys = [
            self.keys[kid] for kid in algo_keys
            if self.keys[kid].is_active() and self.keys[kid].is_valid()
        ]
        if not active_keys:
            return None
        # Return most recently activated
        return max(active_keys, key=lambda k: k.activated_at or 0)
    
    def get_key(self, key_id: str) -> Optional[CryptographicKey]:
        """Get key by ID"""
        return self.keys.get(key_id)
    
    def should_rotate(self, key: CryptographicKey) -> Tuple[bool, str]:
        """
        Check if a key should be rotated based on strategy.
        Returns (should_rotate, reason)
        """
        now = time.time()
        
        # Time-based check
        if key.expires_at and now >= key.expires_at:
            return True, "time_expired"
        
        # Usage-based check
        threshold = self.usage_thresholds[key.algorithm.value]
        if key.max_usage and key.usage_count >= key.max_usage:
            return True, "usage_limit_exceeded"
        if key.usage_count >= threshold:
            return True, "usage_threshold_exceeded"
        
        # Status-based
        if key.status == KeyStatus.COMPROMISED:
            return True, "key_compromised"
        
        return False, "key_valid"
    
    def rotate_key(
        self,
        old_key_id: str,
        strategy: RotationStrategy = RotationStrategy.HYBRID,
        reason: str = "scheduled_rotation",
    ) -> RotationEvent:
        """
        Perform zero-downtime key rotation.
        Creates new key, activates it, puts old key in grace period.
        """
        start_time = time.time()
        old_key = self.keys.get(old_key_id)
        
        if not old_key:
            return RotationEvent(
                event_id=self._generate_key_id(),
                old_key_id=old_key_id,
                new_key_id="",
                algorithm=AlgorithmType.CRYSTALS_KYBER,
                timestamp=start_time,
                strategy=strategy,
                reason=reason,
                success=False,
                duration_ms=0,
                zero_downtime=False,
            )
        
        # Create new key (activated immediately)
        new_key = self.create_key(
            algorithm=old_key.algorithm,
            activate_immediately=True,
        )
        
        # Put old key into grace period (unless already compromised)
        if old_key.status != KeyStatus.COMPROMISED:
            old_key.status = KeyStatus.GRACE_PERIOD
        old_key.expires_at = time.time() + self.grace_period_seconds
        
        duration_ms = (time.time() - start_time) * 1000
        
        event = RotationEvent(
            event_id=self._generate_key_id(),
            old_key_id=old_key_id,
            new_key_id=new_key.key_id,
            algorithm=old_key.algorithm,
            timestamp=start_time,
            strategy=strategy,
            reason=reason,
            success=True,
            duration_ms=duration_ms,
            zero_downtime=True,  # New key activated before old retired
        )
        
        self.rotation_history.append(event)
        
        # Trigger callbacks
        for callback in self.rotation_callbacks:
            try:
                callback(event)
            except Exception:
                pass  # Don't fail rotation for callback errors
        
        return event
    
    def rotate_if_needed(self, algorithm: AlgorithmType) -> Optional[RotationEvent]:
        """Automatically rotate key if rotation conditions are met"""
        active_key = self.get_active_key(algorithm)
        if not active_key:
            # No active key - create one
            new_key = self.create_key(algorithm)
            return RotationEvent(
                event_id=self._generate_key_id(),
                old_key_id="",
                new_key_id=new_key.key_id,
                algorithm=algorithm,
                timestamp=time.time(),
                strategy=RotationStrategy.ON_DEMAND,
                reason="no_active_key",
                success=True,
                duration_ms=0,
                zero_downtime=True,
            )
        
        should_rotate, reason = self.should_rotate(active_key)
        if should_rotate:
            return self.rotate_key(active_key.key_id, reason=reason)
        
        return None
    
    def retire_key(self, key_id: str, reason: str = "scheduled_retirement") -> bool:
        """Securely retire a key"""
        key = self.keys.get(key_id)
        if not key:
            return False
        
        key.status = KeyStatus.RETIRED
        key.retired_at = time.time()
        
        # Remove from active algorithm keys list
        algo_list = self.keys_by_algorithm.get(key.algorithm.value, [])
        if key_id in algo_list:
            algo_list.remove(key_id)
        
        return True
    
    def mark_compromised(self, key_id: str) -> bool:
        """Emergency: mark a key as compromised and rotate immediately"""
        key = self.keys.get(key_id)
        if not key:
            return False
        
        key.status = KeyStatus.COMPROMISED
        # Force rotation
        self.rotate_key(key_id, reason="compromised", strategy=RotationStrategy.ON_DEMAND)
        return True
    
    def get_rotation_status(self, algorithm: Optional[AlgorithmType] = None) -> Dict[str, Any]:
        """Get comprehensive rotation status"""
        now = time.time()
        status = {
            "total_keys": len(self.keys),
            "total_rotations": len(self.rotation_history),
            "keys_by_status": {
                status.value: sum(
                    1 for k in self.keys.values() if k.status == status
                )
                for status in KeyStatus
            },
            "average_rotation_duration_ms": (
                sum(e.duration_ms for e in self.rotation_history)
                / len(self.rotation_history) if self.rotation_history else 0
            ),
            "zero_downtime_success_rate": (
                sum(1 for e in self.rotation_history if e.zero_downtime)
                / len(self.rotation_history) if self.rotation_history else 1.0
            ),
        }
        
        if algorithm:
            algo_keys = [
                k for k in self.keys.values()
                if k.algorithm == algorithm
            ]
            status[f"{algorithm.value}_keys"] = len(algo_keys)
            status[f"{algorithm.value}_active"] = sum(
                1 for k in algo_keys if k.is_active()
            )
        
        return status
    
    def cleanup_expired_keys(self, older_than_days: int = 7) -> int:
        """Clean up retired keys older than specified days"""
        cutoff = time.time() - (older_than_days * 86400)
        removed = 0
        
        for key_id, key in list(self.keys.items()):
            if (
                key.status == KeyStatus.RETIRED
                and key.retired_at
                and key.retired_at < cutoff
            ):
                del self.keys[key_id]
                # Safe remove - key may have been removed already by retire_key
                algo_list = self.keys_by_algorithm.get(key.algorithm.value, [])
                if key_id in algo_list:
                    algo_list.remove(key_id)
                removed += 1
        
        return removed
    
    def record_key_usage(self, key_id: str) -> bool:
        """Record key usage (for usage-based rotation)"""
        key = self.keys.get(key_id)
        if not key:
            return False
        key.increment_usage()
        return True
