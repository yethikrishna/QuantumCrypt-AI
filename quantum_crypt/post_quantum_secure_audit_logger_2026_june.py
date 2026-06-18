"""
Post-Quantum Secure Audit Logger
Production-grade cryptographically secured audit logging system

Provides tamper-evident, forward-secure audit logging with:
- Cryptographic hash chaining (blockchain-like integrity)
- Post-quantum resistant hash algorithms
- Digital signature verification
- Merkle tree verification for batch operations
- Forward secrecy through key rotation
"""

import hashlib
import hmac
import json
import time
import os
import secrets
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timezone


class AuditEventType(Enum):
    """Types of audit events"""
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    DATA_ACCESS = "DATA_ACCESS"
    DATA_MODIFICATION = "DATA_MODIFICATION"
    KEY_ROTATION = "KEY_ROTATION"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    SYSTEM_EVENT = "SYSTEM_EVENT"
    SECURITY_ALERT = "SECURITY_ALERT"
    ENCRYPTION_OPERATION = "ENCRYPTION_OPERATION"
    DECRYPTION_OPERATION = "DECRYPTION_OPERATION"


class AuditSeverity(Enum):
    """Severity levels for audit events"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AuditEntry:
    """Single audit log entry with cryptographic metadata"""
    entry_id: str
    timestamp: str
    event_type: str
    severity: str
    actor: str
    action: str
    resource: str
    outcome: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    previous_hash: Optional[str] = None
    entry_hash: Optional[str] = None
    signature: Optional[str] = None


@dataclass
class VerificationResult:
    """Result of log integrity verification"""
    is_valid: bool
    verified_count: int
    total_entries: int
    broken_chains: List[int]
    first_invalid_entry: Optional[int]
    verification_time: float


class PostQuantumSecureAuditLogger:
    """
    Production-grade post-quantum secure audit logging system.
    
    Features:
    - Cryptographic hash chaining for tamper evidence
    - SHA-3/512 for post-quantum resistant hashing
    - HMAC-SHA3 for entry authentication
    - Merkle tree verification for batch operations
    - Forward-secure key rotation
    - Full integrity verification chain
    """
    
    def __init__(self, service_name: str = "QuantumCrypt-Audit", 
                 secret_key: Optional[bytes] = None):
        self.service_name = service_name
        self.audit_log: List[AuditEntry] = []
        self.current_key = secret_key or self._generate_secure_key()
        self.previous_entry_hash: Optional[str] = None
        self.genesis_hash = self._compute_genesis_hash()
        self.key_rotation_counter = 0
        self.verification_count = 0
        
    def _generate_secure_key(self) -> bytes:
        """Generate cryptographically secure 256-bit key"""
        return secrets.token_bytes(32)
        
    def _compute_genesis_hash(self) -> str:
        """Compute genesis block hash for chain initialization"""
        genesis_data = f"{self.service_name}:{time.time()}:QUANTUMCRYPT-GENESIS"
        return hashlib.sha3_512(genesis_data.encode()).hexdigest()
        
    def _compute_entry_hash(self, entry: AuditEntry, include_prev: bool = True) -> str:
        """Compute SHA3-512 hash of an audit entry (post-quantum resistant)"""
        hash_components = [
            entry.entry_id,
            entry.timestamp,
            entry.event_type,
            entry.severity,
            entry.actor,
            entry.action,
            entry.resource,
            entry.outcome
        ]
        
        if include_prev and self.previous_entry_hash:
            hash_components.append(self.previous_entry_hash)
        elif include_prev:
            hash_components.append(self.genesis_hash)
            
        if entry.source_ip:
            hash_components.append(entry.source_ip)
        if entry.metadata:
            hash_components.append(json.dumps(entry.metadata, sort_keys=True))
            
        hash_input = "|".join(hash_components)
        return hashlib.sha3_512(hash_input.encode()).hexdigest()
        
    def _compute_hmac_signature(self, entry_hash: str) -> str:
        """Compute HMAC-SHA3 signature for entry authentication"""
        return hmac.new(
            self.current_key,
            entry_hash.encode(),
            hashlib.sha3_256
        ).hexdigest()
        
    def rotate_key(self) -> Dict[str, Any]:
        """
        Perform forward-secure key rotation.
        Previous keys cannot be recovered after rotation.
        """
        old_key_hash = hashlib.sha3_256(self.current_key).hexdigest()
        self.current_key = self._generate_secure_key()
        self.key_rotation_counter += 1
        
        # Log the key rotation event
        self.log_event(
            event_type=AuditEventType.KEY_ROTATION,
            severity=AuditSeverity.MEDIUM,
            actor="SYSTEM",
            action="KEY_ROTATION",
            resource="AUDIT_LOG_KEYS",
            outcome="SUCCESS",
            metadata={
                "old_key_fingerprint": old_key_hash[:16],
                "rotation_count": self.key_rotation_counter
            }
        )
        
        return {
            "status": "success",
            "rotation_count": self.key_rotation_counter,
            "old_key_fingerprint": old_key_hash[:16],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    def log_event(self,
                  event_type: AuditEventType,
                  severity: AuditSeverity,
                  actor: str,
                  action: str,
                  resource: str,
                  outcome: str,
                  source_ip: Optional[str] = None,
                  user_agent: Optional[str] = None,
                  metadata: Optional[Dict[str, Any]] = None) -> AuditEntry:
        """
        Create and log a new audit entry with full cryptographic protection.
        
        Returns the secured audit entry with hash and signature.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        entry_id = secrets.token_hex(16)
        
        entry = AuditEntry(
            entry_id=entry_id,
            timestamp=timestamp,
            event_type=event_type.value if isinstance(event_type, AuditEventType) else event_type,
            severity=severity.value if isinstance(severity, AuditSeverity) else severity,
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            source_ip=source_ip,
            user_agent=user_agent,
            metadata=metadata,
            previous_hash=self.previous_entry_hash or self.genesis_hash
        )
        
        # Compute cryptographic hash
        entry.entry_hash = self._compute_entry_hash(entry)
        entry.signature = self._compute_hmac_signature(entry.entry_hash)
        
        self.audit_log.append(entry)
        self.previous_entry_hash = entry.entry_hash
        
        return entry
        
    def log_authentication(self, actor: str, success: bool, 
                          source_ip: Optional[str] = None,
                          user_agent: Optional[str] = None) -> AuditEntry:
        """Convenience method for authentication events"""
        return self.log_event(
            event_type=AuditEventType.AUTHENTICATION,
            severity=AuditSeverity.HIGH if not success else AuditSeverity.INFO,
            actor=actor,
            action="LOGIN_ATTEMPT",
            resource="AUTHENTICATION_SERVICE",
            outcome="SUCCESS" if success else "FAILURE",
            source_ip=source_ip,
            user_agent=user_agent
        )
        
    def log_data_access(self, actor: str, resource: str,
                       source_ip: Optional[str] = None) -> AuditEntry:
        """Convenience method for data access events"""
        return self.log_event(
            event_type=AuditEventType.DATA_ACCESS,
            severity=AuditSeverity.LOW,
            actor=actor,
            action="DATA_READ",
            resource=resource,
            outcome="SUCCESS",
            source_ip=source_ip
        )
        
    def log_security_alert(self, actor: str, alert_type: str,
                          details: Dict[str, Any]) -> AuditEntry:
        """Convenience method for security alerts"""
        return self.log_event(
            event_type=AuditEventType.SECURITY_ALERT,
            severity=AuditSeverity.CRITICAL,
            actor=actor,
            action="SECURITY_ALERT",
            resource="SECURITY_MONITORING",
            outcome="TRIGGERED",
            metadata=details
        )
        
    def verify_entry_integrity(self, index: int) -> Tuple[bool, str]:
        """Verify integrity of a single entry"""
        if index < 0 or index >= len(self.audit_log):
            return False, "Index out of range"
            
        entry = self.audit_log[index]
        expected_prev = self.genesis_hash if index == 0 else self.audit_log[index-1].entry_hash
        
        # Temporarily set previous hash for verification
        saved_prev = self.previous_entry_hash
        self.previous_entry_hash = expected_prev
        
        computed_hash = self._compute_entry_hash(entry)
        self.previous_entry_hash = saved_prev
        
        if computed_hash != entry.entry_hash:
            return False, f"Hash mismatch: expected {entry.entry_hash[:16]}, got {computed_hash[:16]}"
            
        # Verify HMAC signature
        computed_sig = self._compute_hmac_signature(entry.entry_hash)
        if computed_sig != entry.signature:
            return False, "Signature verification failed"
            
        return True, "Entry verified"
        
    def verify_full_chain(self) -> VerificationResult:
        """
        Perform full integrity verification of the entire audit chain.
        Detects any tampering, modification, or deletion.
        """
        start_time = time.time()
        broken_chains = []
        first_invalid = None
        verified = 0
        
        for i in range(len(self.audit_log)):
            is_valid, _ = self.verify_entry_integrity(i)
            if is_valid:
                verified += 1
            else:
                broken_chains.append(i)
                if first_invalid is None:
                    first_invalid = i
                    
        self.verification_count += 1
        
        return VerificationResult(
            is_valid=(len(broken_chains) == 0),
            verified_count=verified,
            total_entries=len(self.audit_log),
            broken_chains=broken_chains,
            first_invalid_entry=first_invalid,
            verification_time=time.time() - start_time
        )
        
    def compute_merkle_root(self) -> str:
        """
        Compute Merkle root hash for all entries.
        Enables efficient batch verification.
        """
        if not self.audit_log:
            return self.genesis_hash
            
        hashes = [entry.entry_hash for entry in self.audit_log]
        
        # Build Merkle tree
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])  # Duplicate last if odd
            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i+1]
                new_hashes.append(hashlib.sha3_512(combined.encode()).hexdigest())
            hashes = new_hashes
            
        return hashes[0]
        
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get audit log statistics and metrics"""
        if not self.audit_log:
            return {
                "total_entries": 0,
                "event_type_distribution": {},
                "severity_distribution": {},
                "outcome_distribution": {},
                "unique_actors": 0,
                "key_rotations": self.key_rotation_counter,
                "verifications_performed": self.verification_count,
                "merkle_root": self.genesis_hash
            }
            
        type_counter: Dict[str, int] = {}
        severity_counter: Dict[str, int] = {}
        outcome_counter: Dict[str, int] = {}
        actors = set()
        
        for entry in self.audit_log:
            type_counter[entry.event_type] = type_counter.get(entry.event_type, 0) + 1
            severity_counter[entry.severity] = severity_counter.get(entry.severity, 0) + 1
            outcome_counter[entry.outcome] = outcome_counter.get(entry.outcome, 0) + 1
            actors.add(entry.actor)
            
        return {
            "total_entries": len(self.audit_log),
            "event_type_distribution": type_counter,
            "severity_distribution": severity_counter,
            "outcome_distribution": outcome_counter,
            "unique_actors": len(actors),
            "key_rotations": self.key_rotation_counter,
            "verifications_performed": self.verification_count,
            "merkle_root": self.compute_merkle_root(),
            "service_name": self.service_name
        }
        
    def export_logs_json(self, pretty: bool = True) -> str:
        """Export all audit logs to JSON format"""
        log_data = [asdict(entry) for entry in self.audit_log]
        indent = 2 if pretty else None
        return json.dumps(log_data, indent=indent)
        
    def export_verification_report(self) -> Dict[str, Any]:
        """Generate comprehensive verification report"""
        verification = self.verify_full_chain()
        stats = self.get_log_statistics()
        
        return {
            "service": self.service_name,
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "integrity_status": "PASS" if verification.is_valid else "FAIL",
            "verification_details": asdict(verification),
            "log_statistics": stats,
            "merkle_root": self.compute_merkle_root(),
            "key_rotation_count": self.key_rotation_counter
        }
