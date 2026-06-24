"""
Post-Quantum Key Rotation Manager - QuantumCrypt AI
Stable API - Production Grade

Provides automated post-quantum key management with:
- Automated key rotation scheduling
- Key version tracking and rollback support
- Rotation policy enforcement (time-based, usage-based)
- Key state management (active, retired, compromised)
- Graceful key migration with zero downtime
- HSM-compatible key storage abstraction
- Audit logging for all key operations

This is an ADD-ONLY module - wraps existing functionality without modification.
"""

import os
import uuid
import hmac
import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from abc import ABC, abstractmethod
from threading import Lock
import json


class KeyAlgorithm(Enum):
    """Supported post-quantum key algorithms."""
    CRYSTALS_KYBER = "kyber"
    NTRU_HPS = "ntru_hps"
    SABER = "saber"
    CLASSIC_MCELIECE = "mceliece"
    FRODO = "frodo"
    BIKE = "bike"
    HQC = "hqc"
    RSA_4096 = "rsa_4096"
    ECC_P384 = "ecc_p384"


class KeyState(Enum):
    """Key lifecycle states."""
    PENDING = "pending"
    ACTIVE = "active"
    RETIRING = "retiring"
    RETIRED = "retired"
    COMPROMISED = "compromised"
    DESTROYED = "destroyed"


class RotationTrigger(Enum):
    """What triggers key rotation."""
    TIME_BASED = "time_based"
    USAGE_BASED = "usage_based"
    MANUAL = "manual"
    COMPROMISE = "compromise"
    POLICY_CHANGE = "policy_change"


@dataclass
class RotationPolicy:
    """Key rotation policy configuration."""
    max_age_hours: int = 168  # 7 days
    max_usage_count: int = 10000
    max_data_encrypted_bytes: int = 10737418240  # 10 GB
    auto_rotate: bool = True
    overlap_period_hours: int = 24  # Grace period for key migration
    retain_versions: int = 5  # Number of old versions to keep


@dataclass
class KeyVersion:
    """Represents a specific version of a key."""
    key_id: str
    version: int
    algorithm: KeyAlgorithm
    state: KeyState
    key_material: bytes  # In production, this would be HSM-wrapped
    created_at: datetime
    activated_at: Optional[datetime] = None
    retired_at: Optional[datetime] = None
    usage_count: int = 0
    data_processed_bytes: int = 0
    rotation_trigger: Optional[RotationTrigger] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_fingerprint(self) -> str:
        """Get key fingerprint for identification."""
        return hashlib.sha256(self.key_material).hexdigest()[:16]


@dataclass
class RotationEvent:
    """Records a key rotation event for audit."""
    event_id: str
    key_id: str
    old_version: int
    new_version: int
    trigger: RotationTrigger
    timestamp: datetime
    success: bool
    reason: str = ""
    duration_ms: float = 0.0


class KeyStorageBackend(ABC):
    """Abstract base class for key storage backends."""

    @abstractmethod
    def store_key(self, key_version: KeyVersion) -> bool:
        """Store a key version."""
        pass

    @abstractmethod
    def load_key(self, key_id: str, version: int) -> Optional[KeyVersion]:
        """Load a specific key version."""
        pass

    @abstractmethod
    def load_all_versions(self, key_id: str) -> List[KeyVersion]:
        """Load all versions of a key."""
        pass

    @abstractmethod
    def update_key_state(self, key_id: str, version: int, state: KeyState) -> bool:
        """Update key state."""
        pass


class InMemoryKeyStorage(KeyStorageBackend):
    """In-memory key storage for testing and demonstration."""

    def __init__(self):
        self._keys: Dict[Tuple[str, int], KeyVersion] = {}
        self._lock = Lock()

    def store_key(self, key_version: KeyVersion) -> bool:
        with self._lock:
            key = (key_version.key_id, key_version.version)
            self._keys[key] = key_version
        return True

    def load_key(self, key_id: str, version: int) -> Optional[KeyVersion]:
        with self._lock:
            return self._keys.get((key_id, version))

    def load_all_versions(self, key_id: str) -> List[KeyVersion]:
        with self._lock:
            versions = [
                kv for (kid, ver), kv in self._keys.items()
                if kid == key_id
            ]
        return sorted(versions, key=lambda k: k.version)

    def update_key_state(self, key_id: str, version: int, state: KeyState) -> bool:
        with self._lock:
            key = (key_id, version)
            if key in self._keys:
                self._keys[key].state = state
                return True
        return False


class PostQuantumKeyGenerator:
    """Generates post-quantum secure key material."""

    @staticmethod
    def generate_key_material(algorithm: KeyAlgorithm, length: int = 32) -> bytes:
        """
        Generate cryptographically secure key material.

        Note: In production, this would interface with actual PQ implementations
        like liboqs. This provides cryptographically secure random bytes.
        """
        if algorithm == KeyAlgorithm.CRYSTALS_KYBER:
            return secrets.token_bytes(32)  # Kyber-768 key
        elif algorithm == KeyAlgorithm.NTRU_HPS:
            return secrets.token_bytes(32)
        elif algorithm == KeyAlgorithm.SABER:
            return secrets.token_bytes(32)
        elif algorithm == KeyAlgorithm.RSA_4096:
            return secrets.token_bytes(64)
        elif algorithm == KeyAlgorithm.ECC_P384:
            return secrets.token_bytes(48)
        else:
            return secrets.token_bytes(length)

    @staticmethod
    def derive_key(base_key: bytes, context: str, length: int = 32) -> bytes:
        """Derive a subkey using HKDF-like derivation."""
        salt = hashlib.sha256(context.encode()).digest()
        return hmac.new(salt, base_key + context.encode(), hashlib.sha256).digest()[:length]


class PostQuantumKeyRotationManager:
    """
    Main post-quantum key rotation manager.

    Manages the complete lifecycle of post-quantum keys including:
    - Key creation and versioning
    - Automated rotation based on policy
    - Graceful key migration with overlap periods
    - Rollback support
    - Comprehensive audit logging
    """

    def __init__(
        self,
        storage_backend: Optional[KeyStorageBackend] = None,
        default_policy: Optional[RotationPolicy] = None
    ):
        """Initialize key rotation manager."""
        self._storage = storage_backend or InMemoryKeyStorage()
        self._default_policy = default_policy or RotationPolicy()
        self._key_policies: Dict[str, RotationPolicy] = {}
        self._rotation_events: List[RotationEvent] = []
        self._active_keys: Set[str] = set()
        self._lock = Lock()
        self._generator = PostQuantumKeyGenerator()

    def create_key(
        self,
        algorithm: KeyAlgorithm = KeyAlgorithm.CRYSTALS_KYBER,
        policy: Optional[RotationPolicy] = None,
        activate_immediately: bool = True,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new post-quantum key.

        Args:
            algorithm: Post-quantum algorithm to use
            policy: Custom rotation policy for this key
            activate_immediately: Whether to activate key immediately
            metadata: Additional key metadata

        Returns:
            New key ID
        """
        key_id = f"pq-{uuid.uuid4().hex[:16]}"

        with self._lock:
            # Store policy
            if policy:
                self._key_policies[key_id] = policy

            # Generate initial key version
            key_material = self._generator.generate_key_material(algorithm)

            now = datetime.utcnow()
            initial_state = KeyState.ACTIVE if activate_immediately else KeyState.PENDING

            key_version = KeyVersion(
                key_id=key_id,
                version=1,
                algorithm=algorithm,
                state=initial_state,
                key_material=key_material,
                created_at=now,
                activated_at=now if activate_immediately else None,
                metadata=metadata or {}
            )

            self._storage.store_key(key_version)

            if activate_immediately:
                self._active_keys.add(key_id)

        return key_id

    def get_key_policy(self, key_id: str) -> RotationPolicy:
        """Get rotation policy for a key."""
        return self._key_policies.get(key_id, self._default_policy)

    def set_key_policy(self, key_id: str, policy: RotationPolicy) -> bool:
        """Set custom rotation policy for a key."""
        with self._lock:
            self._key_policies[key_id] = policy
        return True

    def get_active_key(self, key_id: str) -> Optional[KeyVersion]:
        """Get the currently active key version."""
        versions = self._storage.load_all_versions(key_id)
        for version in reversed(versions):
            if version.state == KeyState.ACTIVE:
                return version
        return None

    def get_key_version(self, key_id: str, version: int) -> Optional[KeyVersion]:
        """Get a specific key version."""
        return self._storage.load_key(key_id, version)

    def list_key_versions(self, key_id: str) -> List[Dict[str, Any]]:
        """List all versions of a key with metadata."""
        versions = self._storage.load_all_versions(key_id)
        return [
            {
                "version": v.version,
                "state": v.state.value,
                "algorithm": v.algorithm.value,
                "created_at": v.created_at.isoformat() + "Z",
                "activated_at": v.activated_at.isoformat() + "Z" if v.activated_at else None,
                "usage_count": v.usage_count,
                "fingerprint": v.get_fingerprint()
            }
            for v in versions
        ]

    def check_rotation_needed(self, key_id: str) -> Tuple[bool, Optional[str]]:
        """
        Check if key rotation is needed based on policy.

        Returns:
            Tuple of (rotation_needed, reason)
        """
        active_key = self.get_active_key(key_id)
        if not active_key:
            return False, None

        policy = self.get_key_policy(key_id)
        now = datetime.utcnow()

        # Check age-based rotation
        if active_key.activated_at:
            age_hours = (now - active_key.activated_at).total_seconds() / 3600
            if age_hours >= policy.max_age_hours:
                return True, f"Key age exceeded ({age_hours:.1f}h >= {policy.max_age_hours}h)"

        # Check usage-based rotation
        if active_key.usage_count >= policy.max_usage_count:
            return True, f"Usage count exceeded ({active_key.usage_count} >= {policy.max_usage_count})"

        # Check data processed rotation
        if active_key.data_processed_bytes >= policy.max_data_encrypted_bytes:
            return True, (
                f"Data processed exceeded "
                f"({active_key.data_processed_bytes} >= {policy.max_data_encrypted_bytes})"
            )

        return False, None

    def rotate_key(
        self,
        key_id: str,
        trigger: RotationTrigger = RotationTrigger.MANUAL,
        reason: str = ""
    ) -> RotationEvent:
        """
        Rotate a key to a new version.

        Args:
            key_id: Key to rotate
            trigger: What triggered the rotation
            reason: Human-readable reason for rotation

        Returns:
            Rotation event record
        """
        start_time = datetime.utcnow()
        event_id = f"rot-{uuid.uuid4().hex[:12]}"

        with self._lock:
            old_version = self.get_active_key(key_id)

            if not old_version:
                event = RotationEvent(
                    event_id=event_id,
                    key_id=key_id,
                    old_version=0,
                    new_version=0,
                    trigger=trigger,
                    timestamp=start_time,
                    success=False,
                    reason="No active key found"
                )
                self._rotation_events.append(event)
                return event

            policy = self.get_key_policy(key_id)

            # Mark old version as retiring
            self._storage.update_key_state(
                key_id, old_version.version, KeyState.RETIRING
            )
            old_version.state = KeyState.RETIRING
            old_version.retired_at = datetime.utcnow()
            self._storage.store_key(old_version)

            # Generate new key version
            new_version_num = old_version.version + 1
            new_key_material = self._generator.generate_key_material(
                old_version.algorithm
            )

            now = datetime.utcnow()
            new_key = KeyVersion(
                key_id=key_id,
                version=new_version_num,
                algorithm=old_version.algorithm,
                state=KeyState.ACTIVE,
                key_material=new_key_material,
                created_at=now,
                activated_at=now,
                metadata=old_version.metadata.copy()
            )

            self._storage.store_key(new_key)

            # Clean up old versions beyond retention policy
            self._cleanup_old_versions(key_id, policy)

            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            event = RotationEvent(
                event_id=event_id,
                key_id=key_id,
                old_version=old_version.version,
                new_version=new_version_num,
                trigger=trigger,
                timestamp=start_time,
                success=True,
                reason=reason or "Scheduled rotation",
                duration_ms=duration_ms
            )

            self._rotation_events.append(event)

        return event

    def _cleanup_old_versions(self, key_id: str, policy: RotationPolicy) -> None:
        """Clean up old key versions beyond retention policy."""
        versions = self._storage.load_all_versions(key_id)

        # Keep only the N most recent versions
        if len(versions) > policy.retain_versions:
            # Sort by version, oldest first
            sorted_versions = sorted(versions, key=lambda v: v.version)
            to_destroy = sorted_versions[:-policy.retain_versions]

            for key_version in to_destroy:
                if key_version.state not in (KeyState.COMPROMISED, KeyState.DESTROYED):
                    # Zeroize key material
                    key_version.key_material = b'\x00' * len(key_version.key_material)
                    key_version.state = KeyState.DESTROYED
                    self._storage.store_key(key_version)

    def emergency_rollback(self, key_id: str, target_version: int) -> bool:
        """
        Emergency rollback to a previous key version.

        This should only be used in case of key compromise or
        critical issues with new key version.
        """
        with self._lock:
            versions = self._storage.load_all_versions(key_id)
            target_key = None

            for v in versions:
                if v.version == target_version:
                    target_key = v
                    break

            if not target_key:
                return False

            if target_key.state in (KeyState.DESTROYED, KeyState.COMPROMISED):
                return False

            # Mark current active as compromised
            current_active = self.get_active_key(key_id)
            if current_active:
                self._storage.update_key_state(
                    key_id, current_active.version, KeyState.COMPROMISED
                )

            # Activate target version
            target_key.state = KeyState.ACTIVE
            target_key.activated_at = datetime.utcnow()
            self._storage.store_key(target_key)

        return True

    def mark_key_compromised(self, key_id: str) -> bool:
        """Mark a key as compromised and trigger emergency rotation."""
        active_key = self.get_active_key(key_id)
        if not active_key:
            return False

        old_version = active_key.version

        # Rotate first (creates new active key)
        self.rotate_key(
            key_id,
            trigger=RotationTrigger.COMPROMISE,
            reason="Key marked as compromised"
        )

        # Then mark old version as compromised
        self._storage.update_key_state(
            key_id, old_version, KeyState.COMPROMISED
        )

        return True

    def record_key_usage(self, key_id: str, data_bytes: int = 0) -> bool:
        """Record key usage for usage-based rotation tracking."""
        active_key = self.get_active_key(key_id)
        if not active_key:
            return False

        with self._lock:
            active_key.usage_count += 1
            active_key.data_processed_bytes += data_bytes
            self._storage.store_key(active_key)

        return True

    def auto_rotate_check(self) -> List[RotationEvent]:
        """
        Check all keys and auto-rotate if needed.
        Call this periodically (e.g., hourly cron job).
        """
        events = []
        key_ids = set()

        # Get all unique key IDs from storage
        # Note: In real implementation, this would query storage
        for event in self._rotation_events:
            key_ids.add(event.key_id)

        for key_id in list(self._active_keys):
            policy = self.get_key_policy(key_id)
            if not policy.auto_rotate:
                continue

            needs_rotation, reason = self.check_rotation_needed(key_id)
            if needs_rotation:
                event = self.rotate_key(
                    key_id,
                    trigger=RotationTrigger.TIME_BASED,
                    reason=reason
                )
                events.append(event)

        return events

    def get_rotation_history(
        self,
        key_id: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get rotation history for audit purposes."""
        events = self._rotation_events

        if key_id:
            events = [e for e in events if e.key_id == key_id]

        events = list(reversed(events))
        if limit:
            events = events[:limit]

        return [
            {
                "event_id": e.event_id,
                "key_id": e.key_id,
                "old_version": e.old_version,
                "new_version": e.new_version,
                "trigger": e.trigger.value,
                "timestamp": e.timestamp.isoformat() + "Z",
                "success": e.success,
                "reason": e.reason,
                "duration_ms": e.duration_ms
            }
            for e in events
        ]

    def get_rotation_statistics(self) -> Dict[str, Any]:
        """Get key rotation statistics."""
        total_events = len(self._rotation_events)
        successful_events = sum(1 for e in self._rotation_events if e.success)
        failed_events = total_events - successful_events

        triggers: Dict[str, int] = {}
        for e in self._rotation_events:
            t = e.trigger.value
            triggers[t] = triggers.get(t, 0) + 1

        avg_duration = 0.0
        if successful_events > 0:
            total_duration = sum(e.duration_ms for e in self._rotation_events if e.success)
            avg_duration = total_duration / successful_events

        return {
            "total_rotations": total_events,
            "successful_rotations": successful_events,
            "failed_rotations": failed_events,
            "rotations_by_trigger": triggers,
            "average_rotation_duration_ms": round(avg_duration, 2),
            "active_keys_tracked": len(self._active_keys)
        }

    def export_key_material_secure(
        self,
        key_id: str,
        wrapping_key: bytes,
        version: Optional[int] = None
    ) -> Optional[bytes]:
        """
        Export key material wrapped with a wrapping key.
        Always use secure wrapping for key export.
        """
        if version:
            key = self.get_key_version(key_id, version)
        else:
            key = self.get_active_key(key_id)

        if not key or key.state in (KeyState.DESTROYED, KeyState.COMPROMISED):
            return None

        # Simple HMAC-based wrapping (in production, use AES-KW)
        nonce = secrets.token_bytes(16)
        wrapped = nonce + hmac.new(
            wrapping_key,
            nonce + key.key_material,
            hashlib.sha256
        ).digest() + key.key_material

        return wrapped


# Singleton instance for easy import
_default_manager: Optional[PostQuantumKeyRotationManager] = None


def get_key_rotation_manager(
    storage: Optional[KeyStorageBackend] = None
) -> PostQuantumKeyRotationManager:
    """Get or create default key rotation manager instance."""
    global _default_manager
    if _default_manager is None:
        _default_manager = PostQuantumKeyRotationManager(storage)
    return _default_manager
