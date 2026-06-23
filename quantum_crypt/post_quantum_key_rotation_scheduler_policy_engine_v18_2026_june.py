"""
Post-Quantum Key Rotation Scheduler & Policy Engine v18
QuantumCrypt-AI Feature Expansion (Dimension A)
Adds automated key rotation scheduling with configurable policies

DESIGN PHILOSOPHY: ADD-ONLY, no modifications to existing code
Backward compatible: 100%
"""

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any, Set, Tuple
from enum import Enum
from datetime import datetime, timedelta


class RotationTrigger(Enum):
    """Types of events that can trigger key rotation"""
    TIME_BASED = "time_based"
    USAGE_BASED = "usage_based"
    COMPROMISE_SUSPECTED = "compromise_suspected"
    MANUAL = "manual"
    POLICY_VIOLATION = "policy_violation"
    SECURITY_ADVISORY = "security_advisory"


class KeyStatus(Enum):
    """Lifecycle status of a key"""
    ACTIVE = "active"
    ROTATING = "rotating"
    DEPRECATED = "deprecated"
    DESTROYED = "destroyed"


class AlgorithmClass(Enum):
    """Post-quantum algorithm classifications"""
    KEM_CLASSIC = "kem_classic"
    KEM_PQC = "kem_pqc"
    KEM_HYBRID = "kem_hybrid"
    SIGNATURE_CLASSIC = "signature_classic"
    SIGNATURE_PQC = "signature_pqc"
    SIGNATURE_HYBRID = "signature_hybrid"


@dataclass
class KeyMetadata:
    """Metadata for tracking key lifecycle"""
    key_id: str
    algorithm: str
    algorithm_class: AlgorithmClass
    created_at: float = field(default_factory=time.time)
    last_rotated: float = field(default_factory=time.time)
    usage_count: int = 0
    status: KeyStatus = KeyStatus.ACTIVE
    version: int = 1
    policy_id: str = "default"
    
    # Security properties
    key_strength_bits: int = 256
    is_compromised: bool = False
    compromise_reason: Optional[str] = None
    
    # Rotation tracking
    rotation_count: int = 0
    previous_key_ids: List[str] = field(default_factory=list)


@dataclass
class RotationPolicy:
    """Defines when and how keys should be rotated"""
    policy_id: str
    name: str
    
    # Time-based rotation
    max_age_seconds: float = 86400 * 30  # 30 days default
    
    # Usage-based rotation
    max_usage_count: int = 10000
    
    # Security thresholds
    min_key_strength_bits: int = 256
    auto_rotate_on_compromise: bool = True
    
    # Grace period settings
    overlap_period_seconds: float = 3600  # 1 hour overlap
    deprecation_grace_seconds: float = 86400  # 24h grace period
    
    # Algorithm preferences
    preferred_algorithms: List[str] = field(default_factory=list)
    fallback_algorithms: List[str] = field(default_factory=list)
    
    # Callbacks (optional)
    pre_rotation_hook: Optional[Callable] = None
    post_rotation_hook: Optional[Callable] = None
    on_compromise_hook: Optional[Callable] = None


@dataclass
class RotationEvent:
    """Records a key rotation event for audit purposes"""
    event_id: str
    key_id: str
    trigger: RotationTrigger
    timestamp: float = field(default_factory=time.time)
    old_version: int = 0
    new_version: int = 0
    reason: str = ""
    success: bool = True


class KeyRotationScheduler:
    """
    Automated post-quantum key rotation scheduler
    ADD-ONLY: Operates alongside existing key management
    No modifications to existing crypto code
    """
    
    def __init__(self, default_policy: Optional[RotationPolicy] = None):
        self._keys: Dict[str, KeyMetadata] = {}
        self._policies: Dict[str, RotationPolicy] = {}
        self._rotation_history: List[RotationEvent] = []
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._scheduler_thread: Optional[threading.Thread] = None
        
        # Default policy
        self._default_policy = default_policy or RotationPolicy(
            policy_id="default",
            name="Default Security Policy",
            max_age_seconds=86400 * 30,
            max_usage_count=10000,
            min_key_strength_bits=256
        )
        self._policies["default"] = self._default_policy
        
        # Statistics
        self._stats = {
            "total_keys_registered": 0,
            "total_rotations_performed": 0,
            "total_compromises_detected": 0,
            "scheduled_rotations": 0,
            "manual_rotations": 0
        }
    
    def register_policy(self, policy: RotationPolicy) -> None:
        """Register a new rotation policy"""
        with self._lock:
            self._policies[policy.policy_id] = policy
    
    def register_key(
        self,
        key_id: str,
        algorithm: str,
        algorithm_class: AlgorithmClass,
        policy_id: str = "default",
        key_strength_bits: int = 256
    ) -> None:
        """
        Register a key for rotation management
        ADD-ONLY: Pure registration, no existing keys modified
        """
        with self._lock:
            if key_id in self._keys:
                return  # Already registered, idempotent
            
            self._keys[key_id] = KeyMetadata(
                key_id=key_id,
                algorithm=algorithm,
                algorithm_class=algorithm_class,
                policy_id=policy_id,
                key_strength_bits=key_strength_bits
            )
            self._stats["total_keys_registered"] += 1
    
    def unregister_key(self, key_id: str) -> None:
        """Remove a key from rotation management"""
        with self._lock:
            if key_id in self._keys:
                del self._keys[key_id]
    
    def _get_policy(self, key_id: str) -> RotationPolicy:
        """Get the policy for a given key"""
        key = self._keys.get(key_id)
        if not key:
            return self._default_policy
        return self._policies.get(key.policy_id, self._default_policy)
    
    def _needs_rotation(self, key: KeyMetadata, policy: RotationPolicy) -> Tuple[bool, Optional[str]]:
        """Check if a key needs rotation based on policy"""
        now = time.time()
        
        # Check age
        age = now - key.last_rotated
        if age >= policy.max_age_seconds:
            return True, f"Key age exceeded: {age:.1f}s >= {policy.max_age_seconds}s"
        
        # Check usage count
        if key.usage_count >= policy.max_usage_count:
            return True, f"Usage count exceeded: {key.usage_count} >= {policy.max_usage_count}"
        
        # Check compromise status
        if key.is_compromised and policy.auto_rotate_on_compromise:
            return True, f"Key marked as compromised: {key.compromise_reason}"
        
        # Check key strength
        if key.key_strength_bits < policy.min_key_strength_bits:
            return True, f"Key strength insufficient: {key.key_strength_bits}bits < {policy.min_key_strength_bits}bits"
        
        return False, None
    
    def check_key_rotation_needed(self, key_id: str) -> Tuple[bool, Optional[str]]:
        """Public method to check if key needs rotation"""
        with self._lock:
            key = self._keys.get(key_id)
            if not key:
                return False, "Key not registered"
            policy = self._get_policy(key_id)
            return self._needs_rotation(key, policy)
    
    def increment_key_usage(self, key_id: str) -> None:
        """Track key usage for usage-based rotation"""
        with self._lock:
            if key_id in self._keys:
                self._keys[key_id].usage_count += 1
    
    def mark_key_compromised(self, key_id: str, reason: str) -> None:
        """Mark a key as potentially compromised"""
        with self._lock:
            if key_id in self._keys:
                self._keys[key_id].is_compromised = True
                self._keys[key_id].compromise_reason = reason
                self._stats["total_compromises_detected"] += 1
                
                policy = self._get_policy(key_id)
                if policy.on_compromise_hook:
                    try:
                        policy.on_compromise_hook(key_id, reason)
                    except Exception:
                        pass  # Hook failures don't break core functionality
    
    def perform_rotation(
        self,
        key_id: str,
        trigger: RotationTrigger,
        reason: str = "",
        key_generator: Optional[Callable[[], str]] = None
    ) -> Tuple[bool, str]:
        """
        Perform key rotation
        ADD-ONLY: Calls user-provided generator, no existing crypto modified
        """
        with self._lock:
            key = self._keys.get(key_id)
            if not key:
                return False, "Key not registered"
            
            if key.status == KeyStatus.ROTATING:
                return False, "Rotation already in progress"
            
            policy = self._get_policy(key_id)
            
            # Pre-rotation hook
            if policy.pre_rotation_hook:
                try:
                    policy.pre_rotation_hook(key_id)
                except Exception:
                    pass
            
            # Update status
            key.status = KeyStatus.ROTATING
            
            # Generate new key (if generator provided)
            new_key_id = key_id
            if key_generator:
                try:
                    new_key_id = key_generator()
                except Exception as e:
                    key.status = KeyStatus.ACTIVE
                    return False, f"Key generation failed: {str(e)}"
            
            # Record rotation
            old_version = key.version
            key.previous_key_ids.append(key_id)
            key.version += 1
            key.last_rotated = time.time()
            key.usage_count = 0
            key.rotation_count += 1
            key.status = KeyStatus.ACTIVE
            
            # Record event
            event = RotationEvent(
                event_id=str(uuid.uuid4()),
                key_id=key_id,
                trigger=trigger,
                old_version=old_version,
                new_version=key.version,
                reason=reason,
                success=True
            )
            self._rotation_history.append(event)
            
            # Update stats
            self._stats["total_rotations_performed"] += 1
            if trigger == RotationTrigger.MANUAL:
                self._stats["manual_rotations"] += 1
            else:
                self._stats["scheduled_rotations"] += 1
            
            # Post-rotation hook
            if policy.post_rotation_hook:
                try:
                    policy.post_rotation_hook(key_id, new_key_id)
                except Exception:
                    pass
            
            return True, new_key_id
    
    def check_all_rotations(self) -> List[Tuple[str, str]]:
        """Check all keys and return those needing rotation"""
        needs_rotation = []
        
        with self._lock:
            for key_id, key in self._keys.items():
                if key.status != KeyStatus.ACTIVE:
                    continue
                
                policy = self._get_policy(key_id)
                needs, reason = self._needs_rotation(key, policy)
                
                if needs:
                    needs_rotation.append((key_id, reason))
        
        return needs_rotation
    
    def get_key_status(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive status of a key"""
        with self._lock:
            key = self._keys.get(key_id)
            if not key:
                return None
            
            policy = self._get_policy(key_id)
            needs_rotation, rotation_reason = self._needs_rotation(key, policy)
            
            age = time.time() - key.last_rotated
            time_until_rotation = max(0, policy.max_age_seconds - age)
            usage_until_rotation = max(0, policy.max_usage_count - key.usage_count)
            
            return {
                "key_id": key.key_id,
                "algorithm": key.algorithm,
                "algorithm_class": key.algorithm_class.value,
                "status": key.status.value,
                "version": key.version,
                "rotation_count": key.rotation_count,
                "age_seconds": age,
                "usage_count": key.usage_count,
                "needs_rotation": needs_rotation,
                "rotation_reason": rotation_reason,
                "time_until_rotation_seconds": time_until_rotation,
                "usage_until_rotation": usage_until_rotation,
                "is_compromised": key.is_compromised,
                "compromise_reason": key.compromise_reason,
                "policy_id": key.policy_id
            }
    
    def get_all_key_statuses(self) -> List[Dict[str, Any]]:
        """Get status for all registered keys"""
        with self._lock:
            return [
                status
                for key_id in self._keys.keys()
                if (status := self.get_key_status(key_id)) is not None
            ]
    
    def get_rotation_history(
        self,
        key_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get rotation audit history"""
        with self._lock:
            history = self._rotation_history
            
            if key_id:
                history = [e for e in history if e.key_id == key_id]
            
            return [
                {
                    "event_id": e.event_id,
                    "key_id": e.key_id,
                    "trigger": e.trigger.value,
                    "timestamp": e.timestamp,
                    "old_version": e.old_version,
                    "new_version": e.new_version,
                    "reason": e.reason,
                    "success": e.success
                }
                for e in history[-limit:]
            ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics"""
        with self._lock:
            active_keys = sum(
                1 for k in self._keys.values()
                if k.status == KeyStatus.ACTIVE
            )
            
            return {
                **self._stats,
                "active_keys": active_keys,
                "registered_keys": len(self._keys),
                "policies_registered": len(self._policies),
                "rotation_events_recorded": len(self._rotation_history),
                "avg_rotations_per_key": (
                    self._stats["total_rotations_performed"] / max(1, len(self._keys))
                )
            }
    
    def start_background_scheduler(self, check_interval_seconds: float = 60) -> None:
        """Start background thread for automatic rotation checks"""
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            return
        
        self._stop_event.clear()
        
        def scheduler_loop():
            while not self._stop_event.is_set():
                try:
                    # Check for needed rotations
                    to_rotate = self.check_all_rotations()
                    
                    # Perform automatic rotations for time/usage triggers
                    for key_id, reason in to_rotate:
                        if "age" in reason.lower() or "usage" in reason.lower():
                            self.perform_rotation(
                                key_id,
                                RotationTrigger.TIME_BASED if "age" in reason.lower() else RotationTrigger.USAGE_BASED,
                                reason
                            )
                except Exception:
                    pass  # Background failures shouldn't crash system
                
                self._stop_event.wait(check_interval_seconds)
        
        self._scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
        self._scheduler_thread.start()
    
    def stop_background_scheduler(self) -> None:
        """Stop the background scheduler"""
        self._stop_event.set()
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5)


# Module-level singleton for easy integration
_default_scheduler = KeyRotationScheduler()


def register_key_for_rotation(
    key_id: str,
    algorithm: str,
    algorithm_class: str = "kem_hybrid",
    policy_id: str = "default",
    key_strength_bits: int = 256
) -> None:
    """Convenience function: Register a key for rotation management"""
    algo_class = AlgorithmClass(algorithm_class) if algorithm_class else AlgorithmClass.KEM_HYBRID
    _default_scheduler.register_key(key_id, algorithm, algo_class, policy_id, key_strength_bits)


def check_key_rotation(key_id: str) -> Tuple[bool, Optional[str]]:
    """Convenience function: Check if key needs rotation"""
    return _default_scheduler.check_key_rotation_needed(key_id)


def perform_key_rotation(
    key_id: str,
    reason: str = "manual",
    key_generator: Optional[Callable] = None
) -> Tuple[bool, str]:
    """Convenience function: Perform manual key rotation"""
    return _default_scheduler.perform_rotation(
        key_id,
        RotationTrigger.MANUAL,
        reason,
        key_generator
    )


def get_key_rotation_status(key_id: str) -> Optional[Dict[str, Any]]:
    """Convenience function: Get key rotation status"""
    return _default_scheduler.get_key_status(key_id)


def get_key_rotation_stats() -> Dict[str, Any]:
    """Convenience function: Get scheduler statistics"""
    return _default_scheduler.get_stats()


"""
BACKWARD COMPATIBILITY VERIFICATION:
- All functions are NEW - no existing code modified
- All operations are ADD-ONLY - no existing keys overwritten
- Key generation is delegated to caller - no existing crypto modified
- Happy path behavior: 100% preserved
- Can be completely disabled - no impact on existing modules
- Zero dependencies on existing QuantumCrypt code
"""
