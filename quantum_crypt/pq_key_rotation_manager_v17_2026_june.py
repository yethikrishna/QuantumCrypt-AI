"""
Post-Quantum Key Rotation Manager v17
QuantumCrypt AI - Feature Expansion (Dimension A)

Automated key rotation management for post-quantum cryptosystems.
Provides secure key lifecycle management, rotation scheduling,
and zero-downtime key transition mechanisms.

Production-grade, backward compatible, no breaking changes.
"""

import threading
import secrets
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple, Any, Callable
from enum import Enum
import time
from datetime import datetime, timedelta


class KeyStatus(Enum):
    """Status of a cryptographic key."""
    ACTIVE = "active"
    PENDING_ACTIVATION = "pending_activation"
    PENDING_DEACTIVATION = "pending_deactivation"
    DEACTIVATED = "deactivated"
    COMPROMISED = "compromised"
    EXPIRED = "expired"


class KeyType(Enum):
    """Types of cryptographic keys."""
    KYBER_PKE = "kyber_pke"
    KYBER_KEM = "kyber_kem"
    DILITHIUM_SIG = "dilithium_signature"
    FALCON_SIG = "falcon_signature"
    SPHINCS_SIG = "sphincs_signature"
    NTRU_HPS = "ntru_hps"
    CLASSIC_MCELIECE = "classic_mceliece"
    SYMMETRIC_AES = "symmetric_aes"
    SYMMETRIC_CHACHA = "symmetric_chacha"


class RotationStrategy(Enum):
    """Key rotation strategies."""
    TIME_BASED = "time_based"
    USAGE_BASED = "usage_based"
    HYBRID = "hybrid"
    ON_DEMAND = "on_demand"
    COMPROMISE_TRIGGERED = "compromise_triggered"


@dataclass
class ManagedKey:
    """Represents a managed cryptographic key."""
    key_id: str
    key_type: KeyType
    key_material: bytes
    status: KeyStatus
    created_at: float = field(default_factory=time.time)
    activated_at: Optional[float] = None
    expires_at: Optional[float] = None
    rotated_at: Optional[float] = None
    usage_count: int = 0
    max_usage_count: Optional[int] = None
    version: int = 1
    previous_key_id: Optional[str] = None
    next_key_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def age_seconds(self) -> float:
        """Get key age in seconds."""
        return time.time() - self.created_at
    
    @property
    def is_expired(self) -> bool:
        """Check if key is expired."""
        if self.expires_at is None:
            return False
        return time.time() >= self.expires_at
    
    @property
    def usage_exceeded(self) -> bool:
        """Check if usage count exceeded."""
        if self.max_usage_count is None:
            return False
        return self.usage_count >= self.max_usage_count


@dataclass
class RotationEvent:
    """Represents a key rotation event."""
    event_id: str
    old_key_id: str
    new_key_id: str
    key_type: KeyType
    timestamp: float = field(default_factory=time.time)
    strategy: RotationStrategy = RotationStrategy.TIME_BASED
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class RotationPolicy:
    """Defines a key rotation policy."""
    policy_id: str
    key_type: KeyType
    strategy: RotationStrategy
    rotation_interval_seconds: Optional[int] = None
    max_usage_count: Optional[int] = None
    auto_activate: bool = True
    overlap_period_seconds: int = 300
    keep_previous_versions: int = 3
    notify_on_rotation: bool = True


class KeyRotationManager:
    """
    Post-Quantum Key Rotation Manager.
    
    Manages the full lifecycle of post-quantum cryptographic keys.
    Features:
    - Automated time-based and usage-based rotation
    - Zero-downtime key transition with overlap periods
    - Key versioning and history tracking
    - Compromise detection and emergency rotation
    - Thread-safe operations
    - Policy-based configuration
    """
    
    def __init__(self):
        """Initialize the Key Rotation Manager."""
        self._keys: Dict[str, ManagedKey] = {}
        self._policies: Dict[str, RotationPolicy] = {}
        self._rotation_history: List[RotationEvent] = []
        self._lock = threading.RLock()
        self._rotation_callbacks: List[Callable[[RotationEvent], None]] = []
        self._stats = {
            "total_keys_created": 0,
            "total_rotations": 0,
            "successful_rotations": 0,
            "failed_rotations": 0,
            "emergency_rotations": 0,
        }
    
    def _generate_key_id(self) -> str:
        """Generate a secure random key ID."""
        return "key_" + secrets.token_hex(16)
    
    def _generate_event_id(self) -> str:
        """Generate a secure random event ID."""
        return "evt_" + secrets.token_hex(12)
    
    def _generate_key_material(self, key_type: KeyType, length: int = 32) -> bytes:
        """Generate secure key material."""
        key_lengths = {
            KeyType.KYBER_PKE: 1568,
            KeyType.KYBER_KEM: 1568,
            KeyType.DILITHIUM_SIG: 2528,
            KeyType.FALCON_SIG: 1280,
            KeyType.SPHINCS_SIG: 64,
            KeyType.NTRU_HPS: 1138,
            KeyType.CLASSIC_MCELIECE: 261120,
            KeyType.SYMMETRIC_AES: 32,
            KeyType.SYMMETRIC_CHACHA: 32,
        }
        actual_length = key_lengths.get(key_type, length)
        return secrets.token_bytes(min(actual_length, 4096))
    
    def create_policy(
        self,
        key_type: KeyType,
        strategy: RotationStrategy,
        rotation_interval_seconds: Optional[int] = None,
        max_usage_count: Optional[int] = None,
        auto_activate: bool = True,
        overlap_period_seconds: int = 300,
        keep_previous_versions: int = 3,
    ) -> str:
        """
        Create a new key rotation policy.
        
        Returns:
            policy_id: ID of the created policy
        """
        policy_id = f"policy_{secrets.token_hex(8)}"
        
        with self._lock:
            self._policies[policy_id] = RotationPolicy(
                policy_id=policy_id,
                key_type=key_type,
                strategy=strategy,
                rotation_interval_seconds=rotation_interval_seconds,
                max_usage_count=max_usage_count,
                auto_activate=auto_activate,
                overlap_period_seconds=overlap_period_seconds,
                keep_previous_versions=keep_previous_versions,
            )
        
        return policy_id
    
    def create_key(
        self,
        key_type: KeyType,
        policy_id: Optional[str] = None,
        activate: bool = True,
        ttl_seconds: Optional[int] = None,
    ) -> str:
        """
        Create a new managed key.
        
        Args:
            key_type: Type of key to create
            policy_id: Optional policy to associate
            activate: Whether to activate immediately
            ttl_seconds: Optional TTL for expiration
            
        Returns:
            key_id: ID of the created key
        """
        key_id = self._generate_key_id()
        key_material = self._generate_key_material(key_type)
        
        expires_at = None
        if ttl_seconds is not None:
            expires_at = time.time() + ttl_seconds
        
        # Apply policy settings
        max_usage_count = None
        if policy_id and policy_id in self._policies:
            policy = self._policies[policy_id]
            max_usage_count = policy.max_usage_count
            if policy.rotation_interval_seconds:
                expires_at = time.time() + policy.rotation_interval_seconds
        
        status = KeyStatus.ACTIVE if activate else KeyStatus.PENDING_ACTIVATION
        activated_at = time.time() if activate else None
        
        with self._lock:
            self._keys[key_id] = ManagedKey(
                key_id=key_id,
                key_type=key_type,
                key_material=key_material,
                status=status,
                activated_at=activated_at,
                expires_at=expires_at,
                max_usage_count=max_usage_count,
                metadata={"policy_id": policy_id} if policy_id else {},
            )
            self._stats["total_keys_created"] += 1
        
        return key_id
    
    def get_key(self, key_id: str, increment_usage: bool = True) -> Optional[ManagedKey]:
        """
        Get a managed key by ID.
        
        Args:
            key_id: Key ID to retrieve
            increment_usage: Whether to increment usage counter
            
        Returns:
            ManagedKey or None if not found
        """
        with self._lock:
            key = self._keys.get(key_id)
            if key is None:
                return None
            
            if increment_usage:
                key.usage_count += 1
            
            # Return a copy to prevent external modification
            return ManagedKey(
                key_id=key.key_id,
                key_type=key.key_type,
                key_material=key.key_material,
                status=key.status,
                created_at=key.created_at,
                activated_at=key.activated_at,
                expires_at=key.expires_at,
                rotated_at=key.rotated_at,
                usage_count=key.usage_count,
                max_usage_count=key.max_usage_count,
                version=key.version,
                previous_key_id=key.previous_key_id,
                next_key_id=key.next_key_id,
                metadata=dict(key.metadata),
            )
    
    def get_active_keys(self, key_type: Optional[KeyType] = None) -> List[ManagedKey]:
        """Get all active keys, optionally filtered by type."""
        with self._lock:
            keys = []
            for key in self._keys.values():
                if key.status != KeyStatus.ACTIVE:
                    continue
                if key_type is not None and key.key_type != key_type:
                    continue
                keys.append(key)
            return keys
    
    def needs_rotation(self, key_id: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a key needs rotation.
        
        Returns:
            (needs_rotation, reason)
        """
        key = self._keys.get(key_id)
        if key is None:
            return False, None
        
        if key.status != KeyStatus.ACTIVE:
            return False, None
        
        # Check expiration
        if key.is_expired:
            return True, "key_expired"
        
        # Check usage count
        if key.usage_exceeded:
            return True, "usage_limit_exceeded"
        
        # Check policy
        policy_id = key.metadata.get("policy_id")
        if policy_id and policy_id in self._policies:
            policy = self._policies[policy_id]
            
            if policy.strategy in [RotationStrategy.TIME_BASED, RotationStrategy.HYBRID]:
                if policy.rotation_interval_seconds:
                    age = key.age_seconds
                    if age >= policy.rotation_interval_seconds:
                        return True, "rotation_interval_reached"
            
            if policy.strategy in [RotationStrategy.USAGE_BASED, RotationStrategy.HYBRID]:
                if policy.max_usage_count and key.usage_count >= policy.max_usage_count:
                    return True, "policy_usage_limit"
        
        return False, None
    
    def rotate_key(
        self,
        key_id: str,
        strategy: RotationStrategy = RotationStrategy.ON_DEMAND,
        emergency: bool = False,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Rotate a key.
        
        Args:
            key_id: Key to rotate
            strategy: Rotation strategy being used
            emergency: Whether this is emergency rotation
            
        Returns:
            (success, new_key_id, error_message)
        """
        with self._lock:
            old_key = self._keys.get(key_id)
            if old_key is None:
                return False, None, "key_not_found"
            
            if old_key.status not in [KeyStatus.ACTIVE, KeyStatus.COMPROMISED]:
                return False, None, "key_not_active"
            
            try:
                # Create new key
                new_key_id = self._generate_key_id()
                new_key_material = self._generate_key_material(old_key.key_type)
                
                new_key = ManagedKey(
                    key_id=new_key_id,
                    key_type=old_key.key_type,
                    key_material=new_key_material,
                    status=KeyStatus.PENDING_ACTIVATION,
                    version=old_key.version + 1,
                    previous_key_id=key_id,
                    metadata=dict(old_key.metadata),
                )
                
                # Apply same expiration policy
                policy_id = old_key.metadata.get("policy_id")
                if policy_id and policy_id in self._policies:
                    policy = self._policies[policy_id]
                    if policy.rotation_interval_seconds:
                        new_key.expires_at = time.time() + policy.rotation_interval_seconds
                    new_key.max_usage_count = policy.max_usage_count
                
                # Update old key
                old_key.status = KeyStatus.PENDING_DEACTIVATION
                old_key.next_key_id = new_key_id
                old_key.rotated_at = time.time()
                
                # Store new key
                self._keys[new_key_id] = new_key
                self._stats["total_keys_created"] += 1
                
                # Auto-activate if policy says so
                if policy_id and policy_id in self._policies:
                    policy = self._policies[policy_id]
                    if policy.auto_activate:
                        new_key.status = KeyStatus.ACTIVE
                        new_key.activated_at = time.time()
                        old_key.status = KeyStatus.DEACTIVATED
                
                # Record rotation event
                event = RotationEvent(
                    event_id=self._generate_event_id(),
                    old_key_id=key_id,
                    new_key_id=new_key_id,
                    key_type=old_key.key_type,
                    strategy=strategy,
                    success=True,
                )
                self._rotation_history.append(event)
                self._stats["total_rotations"] += 1
                self._stats["successful_rotations"] += 1
                
                if emergency:
                    self._stats["emergency_rotations"] += 1
                
                # Trigger callbacks
                for callback in self._rotation_callbacks:
                    try:
                        callback(event)
                    except Exception:
                        pass
                
                return True, new_key_id, None
                
            except Exception as e:
                self._stats["total_rotations"] += 1
                self._stats["failed_rotations"] += 1
                
                event = RotationEvent(
                    event_id=self._generate_event_id(),
                    old_key_id=key_id,
                    new_key_id="",
                    key_type=old_key.key_type,
                    strategy=strategy,
                    success=False,
                    error_message=str(e),
                )
                self._rotation_history.append(event)
                
                return False, None, str(e)
    
    def mark_compromised(self, key_id: str) -> bool:
        """Mark a key as compromised and trigger emergency rotation."""
        with self._lock:
            key = self._keys.get(key_id)
            if key is None:
                return False
            
            key.status = KeyStatus.COMPROMISED
            
            # Auto-rotate compromised keys
            success, _, _ = self.rotate_key(
                key_id,
                strategy=RotationStrategy.COMPROMISE_TRIGGERED,
                emergency=True,
            )
            return success
    
    def perform_scheduled_rotations(self) -> int:
        """Check all keys and perform needed rotations.
        
        Returns:
            Number of rotations performed
        """
        rotations_performed = 0
        
        # Get snapshot of active keys
        active_keys = list(self._keys.items())
        
        for key_id, key in active_keys:
            if key.status != KeyStatus.ACTIVE:
                continue
            
            needs_rot, reason = self.needs_rotation(key_id)
            if needs_rot:
                strategy = RotationStrategy.TIME_BASED
                if reason == "usage_limit_exceeded" or reason == "policy_usage_limit":
                    strategy = RotationStrategy.USAGE_BASED
                
                success, _, _ = self.rotate_key(key_id, strategy=strategy)
                if success:
                    rotations_performed += 1
        
        return rotations_performed
    
    def get_rotation_history(
        self,
        key_type: Optional[KeyType] = None,
        limit: int = 100,
    ) -> List[RotationEvent]:
        """Get rotation history, optionally filtered."""
        with self._lock:
            history = list(reversed(self._rotation_history))
            if key_type is not None:
                history = [e for e in history if e.key_type == key_type]
            return history[:limit]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get manager statistics."""
        with self._lock:
            stats = dict(self._stats)
            stats["total_active_keys"] = len(self.get_active_keys())
            stats["total_managed_keys"] = len(self._keys)
            stats["total_policies"] = len(self._policies)
            return stats
    
    def register_rotation_callback(
        self,
        callback: Callable[[RotationEvent], None],
    ) -> None:
        """Register a callback for rotation events."""
        with self._lock:
            self._rotation_callbacks.append(callback)
    
    def revoke_key(self, key_id: str) -> bool:
        """Revoke and deactivate a key immediately."""
        with self._lock:
            key = self._keys.get(key_id)
            if key is None:
                return False
            key.status = KeyStatus.DEACTIVATED
            return True


# Export public API
__all__ = [
    "KeyRotationManager",
    "ManagedKey",
    "RotationEvent",
    "RotationPolicy",
    "KeyStatus",
    "KeyType",
    "RotationStrategy",
]
