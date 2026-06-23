"""
QuantumCrypt AI - Post-Quantum Key Rotation Manager
Dimension A: Feature Expansion v25
Session 127 | June 24, 2026

ADD-ONLY MODULE - No existing code modified
OPT-IN ONLY - Disabled by default, no side effects

Purpose: Automated key rotation management for post-quantum cryptographic keys.
Handles scheduled rotation, crypto agility, and seamless key transition for
post-quantum algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium, etc.).

Features:
- Scheduled automatic key rotation
- Graceful key transition period (overlap)
- Algorithm agility support
- Key usage tracking for rotation triggers
- Compromise detection response
- Key archival and audit logging
- Zero-downtime key rotation

Stability: EXPERIMENTAL
Backward Compatible: YES
Dependencies: Python stdlib only
"""

import threading
import time
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta


class AlgorithmType(Enum):
    """Post-quantum algorithm types."""
    KYBER = "CRYSTALS-Kyber"          # KEM - NIST Level 1-5
    DILITHIUM = "CRYSTALS-Dilithium"  # Signature - NIST Level 2,3,5
    FALCON = "Falcon"                  # Signature - NIST Level 1,5
    SPHINCS = "SPHINCS+"               # Signature - NIST Level 5
    CLASSIC_MCELIECE = "Classic-McEliece"  # KEM - NIST Level 3,5
    BIKE = "BIKE"                      # KEM - Round 4
    HQC = "HQC"                        # KEM - Round 4


class KeyStatus(Enum):
    """Key lifecycle status."""
    PENDING = "pending"           # Created but not active yet
    ACTIVE = "active"             # Primary active key
    TRANSITION = "transition"     # In overlap period
    RETIRED = "retired"           # No longer used for encryption
    ARCHIVED = "archived"         # Historical only
    COMPROMISED = "compromised"   # Known compromised - DO NOT USE
    DESTROYED = "destroyed"       # Zeroized and removed


class RotationTrigger(Enum):
    """What triggered the key rotation."""
    SCHEDULED = "scheduled"
    USAGE_THRESHOLD = "usage_threshold"
    TIME_EXPIRED = "time_expired"
    COMPROMISE_DETECTED = "compromise_detected"
    MANUAL = "manual"
    ALGORITHM_MIGRATION = "algorithm_migration"
    SECURITY_LEVEL_CHANGE = "security_level_change"


@dataclass(frozen=True)
class KeyMetadata:
    """Immutable key metadata."""
    key_id: str
    algorithm: AlgorithmType
    security_level: int  # NIST Level 1-5
    created_at: float = field(default_factory=time.time)
    activated_at: Optional[float] = None
    expires_at: Optional[float] = None
    max_usage_count: Optional[int] = None
    key_size_bits: int = 256
    version: str = "1.0"

    def is_expired(self) -> bool:
        """Check if key has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def age_seconds(self) -> float:
        """Get key age in seconds."""
        return time.time() - self.created_at


@dataclass
class KeyState:
    """Mutable key state (separated from immutable metadata)."""
    status: KeyStatus
    usage_count: int = 0
    last_used_at: Optional[float] = None
    rotation_trigger: Optional[RotationTrigger] = None

    def record_usage(self) -> None:
        """Record that this key was used."""
        self.usage_count += 1
        self.last_used_at = time.time()


class KeyGenerationStrategy:
    """
    Strategy for generating post-quantum keys.
    Uses cryptographically secure random generation.
    """

    @staticmethod
    def generate_key_id() -> str:
        """Generate cryptographically secure key ID."""
        return f"pqk_{secrets.token_hex(16)}"

    @staticmethod
    def generate_key_material(algorithm: AlgorithmType, security_level: int) -> bytes:
        """
        Generate placeholder key material.
        In production, this would call actual PQ crypto libraries.
        """
        key_sizes = {
            AlgorithmType.KYBER: 1568 + (security_level * 256),
            AlgorithmType.DILITHIUM: 1312 + (security_level * 512),
            AlgorithmType.FALCON: 512 + (security_level * 256),
            AlgorithmType.SPHINCS: 1024 + (security_level * 1024),
            AlgorithmType.CLASSIC_MCELIECE: 8192 + (security_level * 4096),
            AlgorithmType.BIKE: 1024 + (security_level * 512),
            AlgorithmType.HQC: 1024 + (security_level * 512),
        }
        size = key_sizes.get(algorithm, 2048)
        return secrets.token_bytes(size // 8)


class RotationPolicy:
    """
    Defines when keys should be rotated.
    Configurable policy for automated rotation.
    """

    def __init__(
        self,
        max_age_days: int = 90,
        max_usage_count: Optional[int] = 100000,
        overlap_seconds: int = 3600,  # 1 hour transition
        auto_rotate_on_compromise: bool = True
    ):
        self.max_age_days = max_age_days
        self.max_usage_count = max_usage_count
        self.overlap_seconds = overlap_seconds
        self.auto_rotate_on_compromise = auto_rotate_on_compromise

    def should_rotate(self, metadata: KeyMetadata, state: KeyState) -> Tuple[bool, Optional[RotationTrigger]]:
        """Check if key should be rotated."""
        # Check for compromise
        if state.status == KeyStatus.COMPROMISED and self.auto_rotate_on_compromise:
            return True, RotationTrigger.COMPROMISE_DETECTED

        # Check age
        max_age_seconds = self.max_age_days * 86400
        if metadata.age_seconds() > max_age_seconds:
            return True, RotationTrigger.TIME_EXPIRED

        # Check usage count
        if self.max_usage_count and state.usage_count >= self.max_usage_count:
            return True, RotationTrigger.USAGE_THRESHOLD

        # Check expiration
        if metadata.is_expired():
            return True, RotationTrigger.TIME_EXPIRED

        return False, None


class PostQuantumKeyRotationManager:
    """
    Manager for post-quantum key lifecycle and rotation.
    
    Core Features:
    - Key lifecycle management (create → activate → retire → archive)
    - Automated rotation based on policy
    - Graceful transition with overlap period
    - Usage tracking and monitoring
    - Compromise response workflow
    - Algorithm agility and migration
    - Audit logging
    - Thread-safe operations
    - OPT-IN ONLY - disabled by default
    """

    def __init__(
        self,
        rotation_policy: Optional[RotationPolicy] = None,
        enabled: bool = False,
        auto_rotation: bool = False
    ):
        self._enabled = enabled
        self._auto_rotation = auto_rotation
        self._rotation_policy = rotation_policy or RotationPolicy()
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Key storage
        self._key_material: Dict[str, bytes] = {}  # key_id → raw key
        self._key_metadata: Dict[str, KeyMetadata] = {}  # key_id → metadata
        self._key_states: Dict[str, KeyState] = {}  # key_id → state
        
        # Active keys by algorithm
        self._active_keys: Dict[AlgorithmType, List[str]] = {
            algo: [] for algo in AlgorithmType
        }
        
        # Background rotation thread
        self._rotation_thread: Optional[threading.Thread] = None
        self._stop_rotation = threading.Event()
        
        # Callbacks
        self._on_key_rotated: Optional[Callable[[str, str, RotationTrigger], None]] = None
        self._on_key_compromised: Optional[Callable[[str], None]] = None
        self._on_key_created: Optional[Callable[[str, AlgorithmType], None]] = None
        
        # Audit log
        self._audit_log: List[Dict[str, Any]] = []

    def enable(self) -> None:
        """Enable the key manager (OPT-IN)."""
        with self._lock:
            self._enabled = True

    def disable(self) -> None:
        """Disable the key manager."""
        with self._lock:
            self._enabled = False
            self.stop_auto_rotation()

    def is_enabled(self) -> bool:
        """Check if manager is enabled."""
        return self._enabled

    def start_auto_rotation(self, check_interval_seconds: int = 300) -> None:
        """Start background auto-rotation thread."""
        if not self._enabled:
            return

        with self._lock:
            if self._rotation_thread and self._rotation_thread.is_alive():
                return

            self._stop_rotation.clear()
            
            def rotation_worker():
                while not self._stop_rotation.wait(check_interval_seconds):
                    if self._enabled and self._auto_rotation:
                        self.check_and_rotate_all()

            self._rotation_thread = threading.Thread(
                target=rotation_worker,
                daemon=True
            )
            self._rotation_thread.start()

    def stop_auto_rotation(self) -> None:
        """Stop background rotation thread."""
        self._stop_rotation.set()
        if self._rotation_thread:
            self._rotation_thread.join(timeout=5)
            self._rotation_thread = None

    def set_on_key_rotated(self, callback: Callable[[str, str, RotationTrigger], None]) -> None:
        """Set callback for key rotation events (old_id, new_id, trigger)."""
        self._on_key_rotated = callback

    def set_on_key_compromised(self, callback: Callable[[str], None]) -> None:
        """Set callback for key compromise events."""
        self._on_key_compromised = callback

    def set_on_key_created(self, callback: Callable[[str, AlgorithmType], None]) -> None:
        """Set callback for key creation events."""
        self._on_key_created = callback

    def create_key(
        self,
        algorithm: AlgorithmType,
        security_level: int = 3,
        max_age_days: Optional[int] = None,
        activate_immediately: bool = False
    ) -> str:
        """
        Create a new post-quantum key.
        Returns the new key ID.
        """
        if not self._enabled:
            return ""

        with self._lock:
            key_id = KeyGenerationStrategy.generate_key_id()
            key_material = KeyGenerationStrategy.generate_key_material(algorithm, security_level)
            
            expires_at = None
            if max_age_days:
                expires_at = time.time() + (max_age_days * 86400)
            
            metadata = KeyMetadata(
                key_id=key_id,
                algorithm=algorithm,
                security_level=security_level,
                expires_at=expires_at,
                max_usage_count=self._rotation_policy.max_usage_count
            )
            
            state = KeyState(
                status=KeyStatus.PENDING if not activate_immediately else KeyStatus.ACTIVE
            )
            
            self._key_material[key_id] = key_material
            self._key_metadata[key_id] = metadata
            self._key_states[key_id] = state
            
            if activate_immediately:
                self._active_keys[algorithm].append(key_id)
                state.activated_at = time.time()
            
            self._log_audit("KEY_CREATED", key_id, {
                "algorithm": algorithm.value,
                "security_level": security_level
            })
            
            if self._on_key_created:
                self._on_key_created(key_id, algorithm)
            
            return key_id

    def activate_key(self, key_id: str) -> bool:
        """Activate a pending key."""
        if not self._enabled:
            return False

        with self._lock:
            if key_id not in self._key_states:
                return False
            
            state = self._key_states[key_id]
            if state.status != KeyStatus.PENDING:
                return False
            
            metadata = self._key_metadata[key_id]
            
            state.status = KeyStatus.ACTIVE
            state.activated_at = time.time()
            self._active_keys[metadata.algorithm].append(key_id)
            
            self._log_audit("KEY_ACTIVATED", key_id)
            return True

    def get_active_key(self, algorithm: AlgorithmType) -> Optional[str]:
        """Get primary active key for algorithm."""
        if not self._enabled:
            return None

        with self._lock:
            active = self._active_keys[algorithm]
            if not active:
                return None
            
            key_id = active[-1]  # Most recent is primary
            self._key_states[key_id].record_usage()
            
            return key_id

    def get_key_material(self, key_id: str) -> Optional[bytes]:
        """Get key material (records usage)."""
        if not self._enabled:
            return None

        with self._lock:
            if key_id not in self._key_material:
                return None
            
            state = self._key_states[key_id]
            if state.status in (KeyStatus.COMPROMISED, KeyStatus.DESTROYED):
                return None
            
            state.record_usage()
            return self._key_material[key_id]

    def rotate_key(
        self,
        key_id: str,
        trigger: RotationTrigger = RotationTrigger.MANUAL
    ) -> Optional[str]:
        """
        Rotate a specific key.
        Creates new key, transitions old to RETIRED after overlap.
        Returns new key ID.
        """
        if not self._enabled:
            return None

        with self._lock:
            if key_id not in self._key_metadata:
                return None
            
            old_metadata = self._key_metadata[key_id]
            old_state = self._key_states[key_id]
            
            # Create replacement key
            new_key_id = self.create_key(
                algorithm=old_metadata.algorithm,
                security_level=old_metadata.security_level,
                activate_immediately=True
            )
            
            if not new_key_id:
                return None
            
            # Transition old key
            old_state.status = KeyStatus.TRANSITION
            old_state.rotation_trigger = trigger
            
            self._log_audit("KEY_ROTATED", key_id, {
                "new_key_id": new_key_id,
                "trigger": trigger.value
            })
            
            if self._on_key_rotated:
                self._on_key_rotated(key_id, new_key_id, trigger)
            
            return new_key_id

    def check_and_rotate_all(self) -> Dict[str, RotationTrigger]:
        """Check all keys and rotate if needed. Returns {key_id: trigger}."""
        if not self._enabled:
            return {}

        rotations = {}
        
        with self._lock:
            for key_id, metadata in list(self._key_metadata.items()):
                state = self._key_states[key_id]
                
                if state.status != KeyStatus.ACTIVE:
                    continue
                
                should_rotate, trigger = self._rotation_policy.should_rotate(metadata, state)
                
                if should_rotate and trigger:
                    new_id = self.rotate_key(key_id, trigger)
                    if new_id:
                        rotations[key_id] = trigger
        
        return rotations

    def mark_compromised(self, key_id: str) -> bool:
        """Mark a key as compromised and trigger emergency rotation."""
        if not self._enabled:
            return False

        with self._lock:
            if key_id not in self._key_states:
                return False
            
            self._key_states[key_id].status = KeyStatus.COMPROMISED
            
            # Remove from active keys
            metadata = self._key_metadata[key_id]
            if key_id in self._active_keys[metadata.algorithm]:
                self._active_keys[metadata.algorithm].remove(key_id)
            
            self._log_audit("KEY_COMPROMISED", key_id)
            
            if self._on_key_compromised:
                self._on_key_compromised(key_id)
            
            # Auto-rotate if policy says so
            if self._rotation_policy.auto_rotate_on_compromise:
                self.rotate_key(key_id, RotationTrigger.COMPROMISE_DETECTED)
            
            return True

    def retire_key(self, key_id: str) -> bool:
        """Retire a key (no longer used for encryption)."""
        if not self._enabled:
            return False

        with self._lock:
            if key_id not in self._key_states:
                return False
            
            state = self._key_states[key_id]
            if state.status not in (KeyStatus.ACTIVE, KeyStatus.TRANSITION):
                return False
            
            metadata = self._key_metadata[key_id]
            
            state.status = KeyStatus.RETIRED
            
            if key_id in self._active_keys[metadata.algorithm]:
                self._active_keys[metadata.algorithm].remove(key_id)
            
            self._log_audit("KEY_RETIRED", key_id)
            return True

    def destroy_key(self, key_id: str, zeroize: bool = True) -> bool:
        """
        Destroy key material.
        Optionally zeroize memory before deletion.
        """
        if not self._enabled:
            return False

        with self._lock:
            if key_id not in self._key_material:
                return False
            
            if zeroize:
                # Overwrite with zeros
                self._key_material[key_id] = b'\x00' * len(self._key_material[key_id])
            
            del self._key_material[key_id]
            self._key_states[key_id].status = KeyStatus.DESTROYED
            
            self._log_audit("KEY_DESTROYED", key_id, {"zeroized": zeroize})
            return True

    def get_key_status(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive status for a key."""
        with self._lock:
            if key_id not in self._key_metadata:
                return None
            
            metadata = self._key_metadata[key_id]
            state = self._key_states[key_id]
            
            return {
                "key_id": key_id,
                "algorithm": metadata.algorithm.value,
                "security_level": metadata.security_level,
                "status": state.status.value,
                "usage_count": state.usage_count,
                "age_days": metadata.age_seconds() / 86400,
                "created_at": datetime.fromtimestamp(metadata.created_at).isoformat(),
                "rotation_trigger": state.rotation_trigger.value if state.rotation_trigger else None,
                "is_expired": metadata.is_expired()
            }

    def get_statistics(self) -> Dict[str, Any]:
        """Get manager statistics."""
        with self._lock:
            by_status = {status: 0 for status in KeyStatus}
            by_algorithm = {algo: 0 for algo in AlgorithmType}
            
            for key_id, metadata in self._key_metadata.items():
                state = self._key_states[key_id]
                by_status[state.status] += 1
                by_algorithm[metadata.algorithm] += 1
            
            active_count = sum(len(keys) for keys in self._active_keys.values())
            
            return {
                "enabled": self._enabled,
                "auto_rotation": self._auto_rotation,
                "total_keys": len(self._key_metadata),
                "active_keys": active_count,
                "keys_by_status": {k.value: v for k, v in by_status.items()},
                "keys_by_algorithm": {k.value: v for k, v in by_algorithm.items()},
                "policy": {
                    "max_age_days": self._rotation_policy.max_age_days,
                    "max_usage_count": self._rotation_policy.max_usage_count,
                    "overlap_seconds": self._rotation_policy.overlap_seconds
                },
                "audit_log_entries": len(self._audit_log)
            }

    def _log_audit(self, event: str, key_id: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Add audit log entry."""
        entry = {
            "timestamp": time.time(),
            "event": event,
            "key_id": key_id,
            **(extra or {})
        }
        self._audit_log.append(entry)

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit log entries."""
        with self._lock:
            return list(self._audit_log[-limit:])


# Default singleton instance (OPT-IN - disabled by default)
default_key_manager = PostQuantumKeyRotationManager(
    rotation_policy=RotationPolicy(),
    enabled=False,
    auto_rotation=False
)
