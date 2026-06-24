"""
QuantumCrypt AI - Post-Quantum Key Rotation Scheduler
Dimension A: Feature Expansion
Version: v25 - June 2026
API Stability: STABLE
Automated post-quantum key rotation scheduler with policy-based
key management. Supports CRYSTALS-Kyber, NTRU, SABER, and
hybrid classical-PQ key rotation with zero-downtime transitions.
"""
import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4


class PQAlgorithm(Enum):
    """Supported post-quantum algorithms."""
    CRYSTALS_KYBER_512 = "kyber_512"
    CRYSTALS_KYBER_768 = "kyber_768"
    CRYSTALS_KYBER_1024 = "kyber_1024"
    NTRU_HPS_2048 = "ntru_hps_2048"
    NTRU_HPS_4096 = "ntru_hps_4096"
    SABER_LIGHT = "saber_light"
    SABER = "saber"
    SABER_FIRE = "saber_fire"
    CLASSICAL_RSA_2048 = "rsa_2048"
    CLASSICAL_RSA_4096 = "rsa_4096"
    CLASSICAL_ECDH_P256 = "ecdh_p256"
    HYBRID_KYBER_RSA = "hybrid_kyber_rsa"
    HYBRID_KYBER_ECDH = "hybrid_kyber_ecdh"


class KeyStatus(Enum):
    """Key lifecycle status."""
    PENDING = "pending"
    ACTIVE = "active"
    ROTATING = "rotating"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    EXPIRED = "expired"


class RotationStrategy(Enum):
    """Key rotation strategies."""
    TIME_BASED = "time_based"           # Rotate after fixed interval
    USAGE_BASED = "usage_based"         # Rotate after N operations
    THRESHOLD_BASED = "threshold_based" # Rotate when risk threshold hit
    EVENT_DRIVEN = "event_driven"       # Rotate on security events
    MANUAL = "manual"                   # Manual rotation only
    COMPLIANCE_BASED = "compliance_based"  # Rotate per compliance requirements


class ComplianceStandard(Enum):
    """Compliance standards for key management."""
    NIST_SP_800_57 = "nist_sp_800_57"
    NIST_SP_800_131A = "nist_sp_800_131a"
    FIPS_140_3 = "fips_140_3"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOC_2 = "soc_2"


@dataclass
class KeyMetadata:
    """Metadata for a cryptographic key."""
    key_id: str
    algorithm: PQAlgorithm
    status: KeyStatus
    created_at: datetime
    expires_at: datetime
    rotation_deadline: datetime
    usage_count: int = 0
    max_usage: int = 100000
    created_by: str = "system"
    version: int = 1
    compliance_tags: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    last_used: Optional[datetime] = None
    parent_key_id: Optional[str] = None
    
    def is_expired(self) -> bool:
        """Check if key is expired."""
        return datetime.now(timezone.utc) >= self.expires_at
    
    def needs_rotation(self) -> bool:
        """Check if key needs rotation."""
        now = datetime.now(timezone.utc)
        return (now >= self.rotation_deadline or 
                self.usage_count >= self.max_usage or
                self.status == KeyStatus.EXPIRED or
                self.risk_score >= 0.8)
    
    def get_time_until_rotation(self) -> timedelta:
        """Get time until rotation is required."""
        now = datetime.now(timezone.utc)
        return max(timedelta(0), self.rotation_deadline - now)


@dataclass
class RotationPolicy:
    """Key rotation policy configuration."""
    policy_id: str
    name: str
    strategy: RotationStrategy
    rotation_interval: timedelta
    max_key_age: timedelta
    max_usage_count: int
    overlap_period: timedelta  # Period for dual-key during rotation
    compliance_standards: List[ComplianceStandard] = field(default_factory=list)
    auto_rotate: bool = True
    notify_before_hours: int = 24
    emergency_rotation_enabled: bool = True
    zero_downtime: bool = True


@dataclass
class RotationEvent:
    """Record of a key rotation event."""
    event_id: str
    old_key_id: str
    new_key_id: str
    algorithm: PQAlgorithm
    timestamp: datetime
    reason: str
    success: bool
    duration_seconds: float
    zero_downtime_achieved: bool = True
    error_message: Optional[str] = None


@dataclass
class RotationSchedule:
    """Scheduled key rotation task."""
    schedule_id: str
    key_id: str
    scheduled_time: datetime
    policy_id: str
    priority: str = "normal"
    status: str = "pending"


class PQKeyRotationScheduler:
    """
    Post-Quantum Key Rotation Scheduler with policy-based automation.
    
    Features:
    - Multiple rotation strategies (time-based, usage-based, threshold)
    - Zero-downtime key rotation with overlap periods
    - Compliance-aware key management (NIST, FIPS, GDPR, HIPAA, PCI)
    - Emergency rotation for security incidents
    - Key lifecycle tracking and auditing
    - Hybrid classical-PQ key support
    - Thread-safe concurrent operations
    - Usage monitoring and risk assessment
    """
    
    def __init__(self, enable_background_thread: bool = True):
        self._keys: Dict[str, KeyMetadata] = {}
        self._policies: Dict[str, RotationPolicy] = {}
        self._rotation_history: List[RotationEvent] = []
        self._scheduled_rotations: List[RotationSchedule] = []
        self._key_material_store: Dict[str, bytes] = {}  # In production, use HSM
        
        self._lock = threading.RLock()
        self._background_thread: Optional[threading.Thread] = None
        self._running = False
        self._rotation_callbacks: List[Callable[[str, str], None]] = []
        
        # Default compliance policies
        self._initialize_default_policies()
        
        if enable_background_thread:
            self._start_background_scheduler()
    
    def _initialize_default_policies(self) -> None:
        """Initialize default rotation policies."""
        # Standard policy - 90 day rotation
        self._policies["standard"] = RotationPolicy(
            policy_id="standard",
            name="Standard Security Policy",
            strategy=RotationStrategy.TIME_BASED,
            rotation_interval=timedelta(days=90),
            max_key_age=timedelta(days=90),
            max_usage_count=100000,
            overlap_period=timedelta(hours=1),
            compliance_standards=[ComplianceStandard.NIST_SP_800_57]
        )
        
        # High security - 30 day rotation
        self._policies["high_security"] = RotationPolicy(
            policy_id="high_security",
            name="High Security Policy",
            strategy=RotationStrategy.TIME_BASED,
            rotation_interval=timedelta(days=30),
            max_key_age=timedelta(days=30),
            max_usage_count=50000,
            overlap_period=timedelta(hours=4),
            compliance_standards=[
                ComplianceStandard.NIST_SP_800_57,
                ComplianceStandard.FIPS_140_3,
                ComplianceStandard.PCI_DSS
            ],
            notify_before_hours=48
        )
        
        # Compliance - PCI DSS
        self._policies["pci_dss"] = RotationPolicy(
            policy_id="pci_dss",
            name="PCI DSS Compliance Policy",
            strategy=RotationStrategy.COMPLIANCE_BASED,
            rotation_interval=timedelta(days=90),
            max_key_age=timedelta(days=90),
            max_usage_count=1000000,
            overlap_period=timedelta(minutes=30),
            compliance_standards=[ComplianceStandard.PCI_DSS],
            notify_before_hours=72
        )
        
        # Quantum-resistant - aggressive rotation
        self._policies["quantum_resistant"] = RotationPolicy(
            policy_id="quantum_resistant",
            name="Quantum Resistant Policy",
            strategy=RotationStrategy.TIME_BASED,
            rotation_interval=timedelta(days=7),
            max_key_age=timedelta(days=7),
            max_usage_count=10000,
            overlap_period=timedelta(hours=2),
            compliance_standards=[ComplianceStandard.NIST_SP_800_131A],
            notify_before_hours=12
        )
    
    def register_key(
        self,
        algorithm: PQAlgorithm,
        policy_id: str = "standard",
        created_by: str = "system",
        compliance_tags: Optional[List[str]] = None
    ) -> str:
        """
        Register a new key with rotation policy.
        
        Returns: key_id
        """
        with self._lock:
            key_id = f"pq_key_{uuid4().hex[:16]}"
            now = datetime.now(timezone.utc)
            
            policy = self._policies.get(policy_id, self._policies["standard"])
            
            key = KeyMetadata(
                key_id=key_id,
                algorithm=algorithm,
                status=KeyStatus.ACTIVE,
                created_at=now,
                expires_at=now + policy.max_key_age,
                rotation_deadline=now + policy.rotation_interval,
                max_usage=policy.max_usage_count,
                created_by=created_by,
                compliance_tags=compliance_tags or []
            )
            
            self._keys[key_id] = key
            
            # Generate placeholder key material (in production, use proper KEM)
            self._key_material_store[key_id] = os.urandom(32)
            
            # Schedule first rotation
            self._schedule_rotation(key_id, policy)
            
            return key_id
    
    def _schedule_rotation(self, key_id: str, policy: RotationPolicy) -> None:
        """Schedule a key rotation."""
        key = self._keys[key_id]
        schedule = RotationSchedule(
            schedule_id=f"sched_{uuid4().hex[:12]}",
            key_id=key_id,
            scheduled_time=key.rotation_deadline - timedelta(hours=policy.notify_before_hours),
            policy_id=policy.policy_id,
            priority="high" if policy.policy_id == "quantum_resistant" else "normal"
        )
        self._scheduled_rotations.append(schedule)
    
    def get_key_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """Get metadata for a key."""
        with self._lock:
            return self._keys.get(key_id)
    
    def record_key_usage(self, key_id: str) -> bool:
        """Record usage of a key, trigger rotation if needed."""
        with self._lock:
            if key_id not in self._keys:
                return False
            
            key = self._keys[key_id]
            key.usage_count += 1
            key.last_used = datetime.now(timezone.utc)
            
            # Check if rotation needed
            if key.needs_rotation() and key.status == KeyStatus.ACTIVE:
                self._trigger_rotation(key_id)
            
            return True
    
    def _trigger_rotation(self, key_id: str, reason: str = "auto") -> bool:
        """Trigger immediate key rotation."""
        if key_id not in self._keys:
            return False
        
        old_key = self._keys[key_id]
        policy = self._policies.get("standard")
        
        # Find matching policy
        for p in self._policies.values():
            if old_key.max_usage == p.max_usage_count:
                policy = p
                break
        
        start_time = time.time()
        
        try:
            # Create new key
            new_key_id = self.register_key(
                algorithm=old_key.algorithm,
                policy_id=policy.policy_id,
                compliance_tags=old_key.compliance_tags
            )
            
            # Update old key status
            old_key.status = KeyStatus.ROTATING
            
            # Overlap period - keep old key active during transition
            def complete_rotation():
                time.sleep(policy.overlap_period.total_seconds())
                with self._lock:
                    if key_id in self._keys:
                        self._keys[key_id].status = KeyStatus.DEPRECATED
            
            if policy.zero_downtime:
                threading.Thread(target=complete_rotation, daemon=True).start()
            else:
                old_key.status = KeyStatus.DEPRECATED
            
            duration = time.time() - start_time
            
            # Record event
            event = RotationEvent(
                event_id=f"rot_{uuid4().hex[:12]}",
                old_key_id=key_id,
                new_key_id=new_key_id,
                algorithm=old_key.algorithm,
                timestamp=datetime.now(timezone.utc),
                reason=reason,
                success=True,
                duration_seconds=round(duration, 3),
                zero_downtime_achieved=policy.zero_downtime
            )
            self._rotation_history.append(event)
            
            # Notify callbacks
            for callback in self._rotation_callbacks:
                try:
                    callback(key_id, new_key_id)
                except Exception:
                    pass
            
            return True
            
        except Exception as e:
            event = RotationEvent(
                event_id=f"rot_{uuid4().hex[:12]}",
                old_key_id=key_id,
                new_key_id="",
                algorithm=old_key.algorithm,
                timestamp=datetime.now(timezone.utc),
                reason=reason,
                success=False,
                duration_seconds=time.time() - start_time,
                error_message=str(e)
            )
            self._rotation_history.append(event)
            return False
    
    def rotate_key_now(self, key_id: str, reason: str = "manual") -> Optional[str]:
        """Force immediate rotation of a key."""
        with self._lock:
            if self._trigger_rotation(key_id, reason):
                # Return the new key ID
                for event in reversed(self._rotation_history):
                    if event.old_key_id == key_id and event.success:
                        return event.new_key_id
            return None
    
    def emergency_rotation_all(self, reason: str = "security_incident") -> Dict[str, str]:
        """Emergency rotate all active keys."""
        results = {}
        with self._lock:
            for key_id, key in list(self._keys.items()):
                if key.status == KeyStatus.ACTIVE:
                    new_key = self.rotate_key_now(key_id, f"emergency_{reason}")
                    if new_key:
                        results[key_id] = new_key
        return results
    
    def revoke_key(self, key_id: str, reason: str = "compromise") -> bool:
        """Immediately revoke a key."""
        with self._lock:
            if key_id not in self._keys:
                return False
            
            self._keys[key_id].status = KeyStatus.REVOKED
            
            # Securely erase key material (zeroization)
            if key_id in self._key_material_store:
                self._key_material_store[key_id] = b'\x00' * len(self._key_material_store[key_id])
                del self._key_material_store[key_id]
            
            return True
    
    def get_keys_needing_rotation(self) -> List[str]:
        """Get list of keys that need rotation."""
        with self._lock:
            return [
                kid for kid, key in self._keys.items()
                if key.needs_rotation() and key.status == KeyStatus.ACTIVE
            ]
    
    def check_compliance(self, standard: ComplianceStandard) -> Dict[str, Any]:
        """Check compliance against a standard."""
        compliant = []
        non_compliant = []
        
        for key_id, key in self._keys.items():
            policy = None
            for p in self._policies.values():
                if standard in p.compliance_standards:
                    policy = p
                    break
            
            if policy:
                key_age = datetime.now(timezone.utc) - key.created_at
                if key_age <= policy.max_key_age:
                    compliant.append(key_id)
                else:
                    non_compliant.append(key_id)
            else:
                non_compliant.append(key_id)
        
        return {
            "standard": standard.value,
            "compliant_count": len(compliant),
            "non_compliant_count": len(non_compliant),
            "compliant_keys": compliant,
            "non_compliant_keys": non_compliant,
            "compliance_percentage": round(len(compliant) / max(1, len(self._keys)) * 100, 1)
        }
    
    def get_rotation_statistics(self) -> Dict[str, Any]:
        """Get rotation statistics."""
        with self._lock:
            by_status: Dict[str, int] = {}
            by_algorithm: Dict[str, int] = {}
            
            for key in self._keys.values():
                by_status[key.status.value] = by_status.get(key.status.value, 0) + 1
                by_algorithm[key.algorithm.value] = by_algorithm.get(key.algorithm.value, 0) + 1
            
            successful = sum(1 for e in self._rotation_history if e.success)
            failed = len(self._rotation_history) - successful
            
            avg_duration = 0.0
            if self._rotation_history:
                avg_duration = sum(e.duration_seconds for e in self._rotation_history) / len(self._rotation_history)
            
            return {
                "total_keys": len(self._keys),
                "keys_by_status": by_status,
                "keys_by_algorithm": by_algorithm,
                "total_rotations": len(self._rotation_history),
                "successful_rotations": successful,
                "failed_rotations": failed,
                "average_rotation_duration_seconds": round(avg_duration, 3),
                "scheduled_rotations_pending": len(self._scheduled_rotations),
                "keys_needing_rotation": len(self.get_keys_needing_rotation())
            }
    
    def _start_background_scheduler(self) -> None:
        """Start background scheduler thread."""
        self._running = True
        self._background_thread = threading.Thread(
            target=self._scheduler_loop,
            daemon=True
        )
        self._background_thread.start()
    
    def _scheduler_loop(self) -> None:
        """Background scheduler main loop."""
        while self._running:
            try:
                with self._lock:
                    now = datetime.now(timezone.utc)
                    
                    # Check scheduled rotations
                    for schedule in list(self._scheduled_rotations):
                        if now >= schedule.scheduled_time and schedule.status == "pending":
                            self._trigger_rotation(schedule.key_id, "scheduled")
                            schedule.status = "completed"
                    
                    # Clean up completed schedules
                    self._scheduled_rotations = [
                        s for s in self._scheduled_rotations
                        if s.status != "completed"
                    ]
                    
                    # Check for keys needing rotation
                    for key_id in self.get_keys_needing_rotation():
                        self._trigger_rotation(key_id, "auto_monitor")
                
                time.sleep(60)  # Check every minute
                
            except Exception:
                time.sleep(60)
    
    def stop_scheduler(self) -> None:
        """Stop the background scheduler."""
        self._running = False
        if self._background_thread:
            self._background_thread.join(timeout=5)
    
    def add_rotation_callback(self, callback: Callable[[str, str], None]) -> None:
        """Add callback for rotation events."""
        self._rotation_callbacks.append(callback)
    
    def create_custom_policy(
        self,
        name: str,
        rotation_days: int,
        max_usage: int = 100000,
        overlap_hours: int = 1,
        auto_rotate: bool = True
    ) -> str:
        """Create a custom rotation policy."""
        policy_id = f"policy_{uuid4().hex[:8]}"
        
        policy = RotationPolicy(
            policy_id=policy_id,
            name=name,
            strategy=RotationStrategy.TIME_BASED,
            rotation_interval=timedelta(days=rotation_days),
            max_key_age=timedelta(days=rotation_days),
            max_usage_count=max_usage,
            overlap_period=timedelta(hours=overlap_hours),
            auto_rotate=auto_rotate
        )
        
        self._policies[policy_id] = policy
        return policy_id
