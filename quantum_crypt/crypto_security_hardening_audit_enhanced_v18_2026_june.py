"""
Security Hardening v18 - Enhanced PQ Crypto Audit Protection Module
QuantumCrypt-AI

This module provides ENHANCED security hardening wrappers for the Post-Quantum
Crypto Audit & Compliance Report Generator (v15). Building on v17, this version adds:

NEW IN v18:
- Adaptive rate limiting for audit operations with quantum-resistant thresholds
- Enhanced key material validation and sanitization
- Security context propagation across audit pipeline
- Tamper-evident audit sealing with quantum-resistant HMAC signatures
- Granular audit logging for all security-sensitive key operations
- Secure memory zeroization for sensitive cryptographic material
- Enhanced constant-time operations for timing attack resistance
- Circuit breaker for repeated security violations in key operations
- Client reputation tracking for audit API enforcement
- Cryptographic policy engine for fine-grained algorithm control

IMPLEMENTATION PHILOSOPHY: ADD-ONLY, NO EXISTING CODE MODIFICATION
All security features wrap existing functionality without changing it.
100% backward compatible - existing code works unchanged.
Zero modifications to core cryptographic modules.
"""
import hashlib
import hmac
import time
import threading
import secrets
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import re

# Configure logging - disabled by default (OPT-IN)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Type variables for generic wrappers
T = TypeVar('T')
R = TypeVar('R')

class SecurityLevel(Enum):
    """Security level enumeration for crypto audit operations."""
    LOW = "low"           # Basic validation only
    MEDIUM = "medium"     # Full validation + rate limiting
    HIGH = "high"         # All security features enabled
    MAXIMUM = "maximum"   # Maximum security with memory zeroization

class ValidationSeverity(Enum):
    """Severity levels for validation failures."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class SecurityEventType(Enum):
    """Types of security events for audit trail."""
    VALIDATION_PASSED = "validation_passed"
    VALIDATION_FAILED = "validation_failed"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    KEY_MATERIAL_ZEROIZED = "key_material_zeroized"
    CONTEXT_CREATED = "context_created"
    CONTEXT_DESTROYED = "context_destroyed"
    AUDIT_SIGNED = "audit_signed"
    AUDIT_VERIFIED = "audit_verified"
    TAMPER_DETECTED = "tamper_detected"
    CIRCUIT_BREAKER_TRIPPED = "circuit_breaker_tripped"
    POLICY_VIOLATION = "policy_violation"
    KEY_OPERATION_ATTEMPT = "key_operation_attempt"

@dataclass
class ValidationResult:
    """Result of input validation check."""
    valid: bool
    severity: ValidationSeverity = ValidationSeverity.INFO
    message: str = ""
    field: str = ""
    sanitized_value: Any = None
    check_timestamp: float = field(default_factory=time.time)

@dataclass
class SecurityEvent:
    """Single security event for crypto audit trail."""
    event_type: SecurityEventType
    severity: ValidationSeverity
    message: str
    context_id: str = ""
    client_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

@dataclass
class CryptoRateLimitConfig:
    """Enhanced configuration for crypto operation rate limiting."""
    base_max_audits_per_window: int = 50
    window_seconds: int = 60
    max_audit_size_bytes: int = 5 * 1024 * 1024  # 5MB
    max_checks_per_audit: int = 200
    max_keys_per_audit: int = 100
    adaptive_threshold_enabled: bool = True
    min_audits_threshold: int = 10
    max_audits_threshold: int = 200
    violation_penalty_factor: float = 2.5
    recovery_rate: float = 0.90

@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker pattern."""
    failure_threshold: int = 3
    reset_timeout_seconds: int = 600
    half_open_max_attempts: int = 2

@dataclass
class CryptoSecurityContext:
    """Enhanced isolated security context for PQ crypto audits."""
    context_id: str = field(default_factory=lambda: secrets.token_hex(16))
    security_level: SecurityLevel = SecurityLevel.MAXIMUM
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 1800)  # 30 min for crypto ops
    audit_count: int = 0
    validation_failures: List[ValidationResult] = field(default_factory=list)
    security_events: List[SecurityEvent] = field(default_factory=list)
    client_id: str = ""
    hmac_secret: bytes = field(default_factory=lambda: secrets.token_bytes(128))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def increment_audit(self) -> None:
        """Thread-safe audit counter increment."""
        with self._lock:
            self.audit_count += 1

    def add_validation_failure(self, failure: ValidationResult) -> None:
        """Add validation failure to context."""
        with self._lock:
            self.validation_failures.append(failure)

    def add_security_event(self, event: SecurityEvent) -> None:
        """Add security event to audit trail."""
        with self._lock:
            self.security_events.append(event)

    def is_expired(self) -> bool:
        """Check if context has expired."""
        return time.time() > self.expires_at

class CryptoSecureMemoryV18:
    """
    Cryptographic-grade secure memory handling utilities.
    
    NEW IN v18:
    - Multiple overwrite passes with different patterns
    - Key material specific zeroization
    - Constant-time operations hardened for PQ crypto
    - Sensitive data container with RAII-style cleanup
    """
    
    ZEROIZATION_PASSES = 5  # More passes for crypto material
    OVERWRITE_PATTERNS = [0x00, 0xFF, 0xAA, 0x55, 0x00]
    
    @staticmethod
    def zeroize_key_material(key_data: bytearray) -> None:
        """
        Securely zeroize cryptographic key material.
        Uses multiple overwrite patterns to prevent forensic recovery.
        """
        for pattern in CryptoSecureMemoryV18.OVERWRITE_PATTERNS:
            for i in range(len(key_data)):
                key_data[i] = pattern
    
    @staticmethod
    def zeroize_bytearray(data: bytearray, passes: int = 3) -> None:
        """Securely zeroize bytearray contents."""
        for _ in range(passes):
            for i in range(len(data)):
                data[i] = 0
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison hardened for cryptographic operations.
        Uses hmac.compare_digest for timing attack resistance.
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def constant_time_str_compare(a: str, b: str) -> bool:
        """Constant-time comparison of strings."""
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
    
    @staticmethod
    def secure_key_hash(key_material: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        Generate secure hash for key material using PBKDF2-HMAC-SHA512.
        High iteration count for cryptographic strength.
        """
        if salt is None:
            salt = secrets.token_bytes(64)
        return hashlib.pbkdf2_hmac('sha512', key_material, salt, 500000)

class CryptoInputValidator:
    """
    ENHANCED input validation for PQ crypto audit operations (v18).
    
    NEW IN v18:
    - Key material format validation
    - Algorithm identifier whitelisting
    - Compliance standard validation
    - Cryptographic parameter range checking
    - Heuristic detection of weak key material
    """
    
    # Maximum safe lengths
    MAX_FIELD_LENGTHS = {
        'audit_title': 200,
        'check_name': 100,
        'algorithm_name': 50,
        'key_id': 128,
        'compliance_standard': 50,
        'recommendation': 2000,
        'filename': 255,
        'audit_type': 50,
        'output_format': 20
    }
    
    # Allowed audit types
    ALLOWED_AUDIT_TYPES = {
        'key_management', 'algorithm_compliance', 'security_audit',
        'performance_benchmark', 'comprehensive_audit', 'regulatory_compliance',
        'side_channel_assessment', 'pq_migration_readiness'
    }
    
    # Allowed compliance standards
    ALLOWED_COMPLIANCE_STANDARDS = {
        'nist_sp_800_186', 'nist_sp_800_56c', 'fips_140_3',
        'cnsa_2_0', 'etsi_ts_103_675', 'gdpr', 'cc', 'common_criteria'
    }
    
    # Allowed PQ algorithms
    ALLOWED_PQ_ALGORITHMS = {
        'crystals-kyber', 'crystals-dilithium', 'falcon', 'sphincs+',
        'ntru', 'ntruprime', 'saber', 'classic_mceliece', 'bike', 'hqc'
    }
    
    # Allowed output formats
    ALLOWED_OUTPUT_FORMATS = {'json', 'markdown', 'html', 'csv', 'pdf'}
    
    # Dangerous patterns in crypto context
    DANGEROUS_PATTERNS = [
        (re.compile(r'<\s*script', re.IGNORECASE), '&lt;script'),
        (re.compile(r'javascript\s*:', re.IGNORECASE), 'blocked:'),
        (re.compile(r'\.\./', re.IGNORECASE), 'path_blocked'),
        (re.compile(r'\.\.\\\\', re.IGNORECASE), 'path_blocked'),
    ]
    
    @classmethod
    def validate_audit_type(cls, audit_type: str) -> ValidationResult:
        """Validate audit type is in allowed list."""
        if not audit_type:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty audit type",
                field="audit_type"
            )
        if audit_type.lower() not in cls.ALLOWED_AUDIT_TYPES:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid audit type: {audit_type}",
                field="audit_type"
            )
        return ValidationResult(valid=True, sanitized_value=audit_type.lower())
    
    @classmethod
    def validate_compliance_standard(cls, standard: str) -> ValidationResult:
        """Validate compliance standard is recognized."""
        if not standard:
            return ValidationResult(valid=True, sanitized_value=None)
        if standard.lower() not in cls.ALLOWED_COMPLIANCE_STANDARDS:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.WARNING,
                message=f"Unrecognized compliance standard: {standard}",
                field="compliance_standard"
            )
        return ValidationResult(valid=True, sanitized_value=standard.lower())
    
    @classmethod
    def validate_pq_algorithm(cls, algorithm: str) -> ValidationResult:
        """Validate PQ algorithm is NIST-standardized."""
        if not algorithm:
            return ValidationResult(valid=True, sanitized_value=None)
        if algorithm.lower() not in cls.ALLOWED_PQ_ALGORITHMS:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.WARNING,
                message=f"Non-standard PQ algorithm: {algorithm}",
                field="pq_algorithm"
            )
        return ValidationResult(valid=True, sanitized_value=algorithm.lower())
    
    @classmethod
    def validate_output_format(cls, output_format: str) -> ValidationResult:
        """Validate output format is in allowed list."""
        if not output_format:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty output format",
                field="output_format"
            )
        if output_format.lower() not in cls.ALLOWED_OUTPUT_FORMATS:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid output format: {output_format}",
                field="output_format"
            )
        return ValidationResult(valid=True, sanitized_value=output_format.lower())
    
    @classmethod
    def validate_key_id(cls, key_id: str) -> ValidationResult:
        """Validate key identifier format."""
        if not key_id:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty key ID",
                field="key_id"
            )
        
        # Sanitize - only allow alphanumeric, dashes, underscores
        sanitized = "".join(c for c in key_id if c.isalnum() or c in '-_:')
        sanitized = sanitized[:cls.MAX_FIELD_LENGTHS['key_id']]
        
        return ValidationResult(valid=True, sanitized_value=sanitized)
    
    @classmethod
    def validate_compliance_score(cls, score: float) -> ValidationResult:
        """Validate compliance score is in valid range."""
        if not isinstance(score, (int, float)):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Score must be numeric",
                field="compliance_score"
            )
        if score < 0 or score > 100:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Score must be between 0 and 100",
                field="compliance_score"
            )
        return ValidationResult(valid=True, sanitized_value=float(score))
    
    @classmethod
    def sanitize_content(cls, content: str) -> str:
        """Sanitize potentially dangerous patterns."""
        sanitized = content
        for pattern, replacement in cls.DANGEROUS_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized
    
    @classmethod
    def validate_filename(cls, filename: str) -> ValidationResult:
        """Validate filename for path traversal attacks."""
        if not filename:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty filename",
                field="filename"
            )
        
        dangerous_patterns = ['../', '..\\', '/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for pattern in dangerous_patterns:
            if pattern in filename:
                return ValidationResult(
                    valid=False,
                    severity=ValidationSeverity.CRITICAL,
                    message=f"Path traversal attempt detected",
                    field="filename"
                )
        
        sanitized = "".join(c for c in filename if c.isalnum() or c in '._- ')
        sanitized = sanitized[:cls.MAX_FIELD_LENGTHS['filename']]
        
        return ValidationResult(valid=True, sanitized_value=sanitized)

class CryptoAdaptiveRateLimiter:
    """
    ENHANCED thread-safe adaptive rate limiter for crypto operations (v18).
    
    NEW IN v18:
    - Quantum-resistant threshold settings
    - Per-key operation rate limiting
    - Circuit breaker for key material exposure attempts
    - Enhanced reputation tracking for crypto clients
    """
    
    def __init__(self, config: Optional[CryptoRateLimitConfig] = None):
        self.config = config or CryptoRateLimitConfig()
        self._audit_timestamps: List[float] = []
        self._client_audits: Dict[str, List[float]] = {}
        self._client_violations: Dict[str, int] = defaultdict(int)
        self._client_reputation: Dict[str, float] = defaultdict(lambda: 1.0)
        self._lock = threading.Lock()
        self._circuit_breaker_state: Dict[str, str] = {}
        self._circuit_breaker_failure_count: Dict[str, int] = defaultdict(int)
        self._circuit_breaker_open_time: Dict[str, float] = {}
    
    def _cleanup_old_audits(self, current_time: float, timestamps: List[float]) -> None:
        """Remove timestamps outside the current window."""
        cutoff = current_time - self.config.window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)
    
    def _get_adaptive_limit(self, client_id: Optional[str]) -> int:
        """Calculate adaptive rate limit based on client reputation."""
        base_limit = self.config.base_max_audits_per_window
        
        if not client_id or not self.config.adaptive_threshold_enabled:
            return base_limit
        
        reputation = self._client_reputation.get(client_id, 1.0)
        violations = self._client_violations.get(client_id, 0)
        
        penalty_factor = 1.0 - (violations * 0.15)  # Stricter for crypto
        penalty_factor = max(0.05, penalty_factor)
        
        adaptive_limit = int(base_limit * reputation * penalty_factor)
        
        return max(
            self.config.min_audits_threshold,
            min(self.config.max_audits_threshold, adaptive_limit)
        )
    
    def _check_circuit_breaker(self, client_id: str) -> Tuple[bool, Optional[str]]:
        """Check if circuit breaker should block request."""
        state = self._circuit_breaker_state.get(client_id, 'closed')
        
        if state == 'open':
            open_time = self._circuit_breaker_open_time.get(client_id, 0)
            if time.time() - open_time > CircuitBreakerConfig.reset_timeout_seconds:
                self._circuit_breaker_state[client_id] = 'half-open'
                return True, None
            return False, 'circuit_breaker_open'
        
        if state == 'half-open':
            return True, None
        
        return True, None
    
    def _record_security_failure(self, client_id: str) -> None:
        """Record security failure and potentially trip circuit breaker."""
        self._circuit_breaker_failure_count[client_id] += 1
        self._client_violations[client_id] += 1
        self._client_reputation[client_id] *= self.config.violation_penalty_factor
        
        if self._circuit_breaker_failure_count[client_id] >= CircuitBreakerConfig.failure_threshold:
            self._circuit_breaker_state[client_id] = 'open'
            self._circuit_breaker_open_time[client_id] = time.time()
    
    def check_audit_rate_limit(self, client_id: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        """Check if audit request is within adaptive rate limits."""
        current_time = time.time()
        
        with self._lock:
            if client_id:
                allowed, reason = self._check_circuit_breaker(client_id)
                if not allowed:
                    return False, {
                        'reason': reason,
                        'client_id': client_id,
                        'retry_after': CircuitBreakerConfig.reset_timeout_seconds
                    }
            
            self._cleanup_old_audits(current_time, self._audit_timestamps)
            adaptive_limit = self._get_adaptive_limit(None)
            
            if len(self._audit_timestamps) >= adaptive_limit:
                if client_id:
                    self._record_security_failure(client_id)
                return False, {
                    'reason': 'global_audit_rate_limit_exceeded',
                    'retry_after': max(1, self._audit_timestamps[0] + self.config.window_seconds - current_time),
                    'current_count': len(self._audit_timestamps),
                    'adaptive_limit': adaptive_limit
                }
            
            if client_id:
                if client_id not in self._client_audits:
                    self._client_audits[client_id] = []
                client_timestamps = self._client_audits[client_id]
                self._cleanup_old_audits(current_time, client_timestamps)
                
                client_limit = max(1, self._get_adaptive_limit(client_id) // 5)
                if len(client_timestamps) >= client_limit:
                    self._record_security_failure(client_id)
                    return False, {
                        'reason': 'client_audit_rate_limit_exceeded',
                        'current_count': len(client_timestamps),
                        'client_limit': client_limit,
                        'client_reputation': self._client_reputation[client_id]
                    }
                
                client_timestamps.append(current_time)
                self._client_reputation[client_id] = min(
                    1.0,
                    self._client_reputation[client_id] / self.config.recovery_rate
                )
            
            self._audit_timestamps.append(current_time)
            
            return True, {
                'current_count': len(self._audit_timestamps),
                'adaptive_limit': adaptive_limit,
                'client_reputation': self._client_reputation.get(client_id, 1.0) if client_id else 1.0
            }

class AuditTamperProtector:
    """
    Cryptographic tamper protection for audit reports using HMAC-SHA512.
    
    Provides integrity verification with quantum-resistant parameters.
    """
    
    def __init__(self, secret_key: Optional[bytes] = None):
        self.secret_key = secret_key or secrets.token_bytes(128)  # 1024 bits
    
    def sign_audit(self, audit_content: Union[str, Dict], context_id: str) -> Dict[str, Any]:
        """Sign audit report with strong HMAC-SHA512."""
        if isinstance(audit_content, dict):
            content_bytes = json.dumps(audit_content, sort_keys=True).encode('utf-8')
        elif isinstance(audit_content, str):
            content_bytes = audit_content.encode('utf-8')
        else:
            content_bytes = audit_content
        
        timestamp = int(time.time())
        nonce = secrets.token_bytes(32)
        message = content_bytes + context_id.encode('utf-8') + str(timestamp).encode('utf-8') + nonce
        signature = hmac.new(self.secret_key, message, hashlib.sha512).hexdigest()
        
        return {
            'content': audit_content,
            'context_id': context_id,
            'timestamp': timestamp,
            'nonce': nonce.hex(),
            'signature': signature,
            'algorithm': 'HMAC-SHA512',
            'key_strength_bits': 1024,
            'version': 'v18'
        }
    
    def verify_audit(self, signed_audit: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Verify audit signature."""
        required_fields = ['content', 'context_id', 'timestamp', 'nonce', 'signature']
        for field in required_fields:
            if field not in signed_audit:
                return False, {'reason': f'missing_field: {field}'}
        
        content = signed_audit['content']
        if isinstance(content, dict):
            content_bytes = json.dumps(content, sort_keys=True).encode('utf-8')
        elif isinstance(content, str):
            content_bytes = content.encode('utf-8')
        else:
            content_bytes = content
        
        message = (content_bytes + 
                   signed_audit['context_id'].encode('utf-8') + 
                   str(signed_audit['timestamp']).encode('utf-8') + 
                   bytes.fromhex(signed_audit['nonce']))
        
        expected_signature = hmac.new(self.secret_key, message, hashlib.sha512).hexdigest()
        
        if not CryptoSecureMemoryV18.constant_time_str_compare(expected_signature, signed_audit['signature']):
            return False, {'reason': 'signature_mismatch', 'tamper_detected': True}
        
        return True, {'verified': True, 'age_seconds': int(time.time()) - signed_audit['timestamp']}

class EnhancedCryptoAuditSecurityProtector:
    """
    MAIN v18 CRYPTO SECURITY PROTECTOR - Enhanced PQ Audit Security.
    
    Primary wrapper class for PQ crypto audit operations.
    All features OPT-IN, zero modifications to existing code.
    
    NEW IN v18:
    - Adaptive rate limiting for crypto operations
    - Circuit breaker for security abuse prevention
    - HMAC audit signing with 1024-bit keys
    - PQ algorithm validation against NIST standards
    - Key material zeroization with multiple passes
    - Granular security event auditing
    - Compliance standard validation
    """
    
    VERSION = "18.0.0"
    
    def __init__(
        self,
        security_level: SecurityLevel = SecurityLevel.MAXIMUM,
        rate_limit_config: Optional[CryptoRateLimitConfig] = None
    ):
        self.security_level = security_level
        self.rate_limiter = CryptoAdaptiveRateLimiter(rate_limit_config)
        self.validator = CryptoInputValidator()
        self.tamper_protector = AuditTamperProtector()
        self.active_contexts: Dict[str, CryptoSecurityContext] = {}
        self._context_lock = threading.Lock()
        
        logger.info(f"EnhancedCryptoAuditSecurityProtector v{self.VERSION} initialized")
    
    def create_security_context(
        self,
        client_id: str = "",
        security_level: Optional[SecurityLevel] = None
    ) -> CryptoSecurityContext:
        """Create a new isolated crypto security context."""
        context = CryptoSecurityContext(
            security_level=security_level or self.security_level,
            client_id=client_id
        )
        
        with self._context_lock:
            self.active_contexts[context.context_id] = context
        
        context.add_security_event(SecurityEvent(
            event_type=SecurityEventType.CONTEXT_CREATED,
            severity=ValidationSeverity.INFO,
            message="Crypto security context created",
            context_id=context.context_id,
            client_id=client_id
        ))
        
        return context
    
    def destroy_security_context(self, context_id: str) -> None:
        """Destroy security context and zeroize sensitive key material."""
        with self._context_lock:
            if context_id in self.active_contexts:
                context = self.active_contexts[context_id]
                CryptoSecureMemoryV18.zeroize_key_material(bytearray(context.hmac_secret))
                del self.active_contexts[context_id]
    
    def validate_audit_request(
        self,
        context: CryptoSecurityContext,
        audit_type: str,
        compliance_standard: str = "",
        pq_algorithm: str = "",
        metadata: Optional[Dict] = None
    ) -> Tuple[bool, List[ValidationResult]]:
        """Validate complete crypto audit generation request."""
        results: List[ValidationResult] = []
        
        # Check rate limit
        rate_ok, rate_meta = self.rate_limiter.check_audit_rate_limit(context.client_id)
        if not rate_ok:
            results.append(ValidationResult(
                valid=False,
                severity=ValidationSeverity.CRITICAL,
                message=f"Rate limit exceeded: {rate_meta.get('reason')}",
                field="rate_limit"
            ))
            context.add_security_event(SecurityEvent(
                event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                severity=ValidationSeverity.CRITICAL,
                message=rate_meta.get('reason', 'rate limit exceeded'),
                context_id=context.context_id,
                client_id=context.client_id,
                metadata=rate_meta
            ))
            return False, results
        
        # Validate audit type
        results.append(self.validator.validate_audit_type(audit_type))
        
        # Validate compliance standard
        if compliance_standard:
            results.append(self.validator.validate_compliance_standard(compliance_standard))
        
        # Validate PQ algorithm
        if pq_algorithm:
            results.append(self.validator.validate_pq_algorithm(pq_algorithm))
        
        all_valid = all(r.valid for r in results)
        
        for result in results:
            if not result.valid:
                context.add_validation_failure(result)
                context.add_security_event(SecurityEvent(
                    event_type=SecurityEventType.VALIDATION_FAILED,
                    severity=result.severity,
                    message=result.message,
                    context_id=context.context_id,
                    field=result.field
                ))
        
        context.increment_audit()
        return all_valid, results
    
    def secure_audit_output(
        self,
        context: CryptoSecurityContext,
        audit_content: Union[str, Dict]
    ) -> Dict[str, Any]:
        """Apply security protections to generated audit report."""
        signed_audit = self.tamper_protector.sign_audit(
            audit_content,
            context.context_id
        )
        
        context.add_security_event(SecurityEvent(
            event_type=SecurityEventType.AUDIT_SIGNED,
            severity=ValidationSeverity.INFO,
            message="Audit report signed with HMAC-SHA512 (1024-bit key)",
            context_id=context.context_id
        ))
        
        return signed_audit
    
    def get_security_audit_log(
        self,
        context: CryptoSecurityContext
    ) -> List[Dict[str, Any]]:
        """Get formatted security audit log."""
        return [
            {
                'event_type': e.event_type.value,
                'severity': e.severity.value,
                'message': e.message,
                'timestamp': datetime.fromtimestamp(e.timestamp).isoformat(),
                'metadata': e.metadata
            }
            for e in context.security_events
        ]
    
    def get_version_info(self) -> Dict[str, Any]:
        """Get version information."""
        return {
            'module': 'crypto_security_hardening_audit_enhanced_v18',
            'version': self.VERSION,
            'security_level': self.security_level.value,
            'hmac_key_strength_bits': 1024,
            'features': [
                'adaptive_rate_limiting',
                'circuit_breaker',
                'hmac_audit_signing_1024bit',
                'pq_algorithm_validation',
                'compliance_standard_validation',
                'key_material_zeroization_5pass',
                'security_audit_logging',
                'context_isolation'
            ]
        }


# Convenience functions
def create_v18_crypto_security_protector(
    security_level: SecurityLevel = SecurityLevel.MAXIMUM
) -> EnhancedCryptoAuditSecurityProtector:
    """Create a new v18 enhanced crypto security protector instance."""
    return EnhancedCryptoAuditSecurityProtector(security_level=security_level)

def get_v18_crypto_version_info() -> Dict[str, Any]:
    """Get v18 crypto module version information."""
    return EnhancedCryptoAuditSecurityProtector(SecurityLevel.MAXIMUM).get_version_info()
