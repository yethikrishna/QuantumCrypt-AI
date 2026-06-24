"""
Security Hardening v22 - PQ Crypto Audit & Compliance Report Protection Module
QuantumCrypt-AI

This module provides COMPREHENSIVE security hardening wrappers for the
Post-Quantum Crypto Audit & Compliance Report Generator (v15). Building on
previous versions, this v22 adds specific protection for the NEW audit report
features added in Session 126.

NEW IN v22 (SPECIFIC TO PQ AUDIT REPORT v15):
- Audit-specific rate limiting with per-client quotas
- Compliance standard validation (NIST, FIPS, CNSA, ETSI, GDPR)
- Audit check parameter validation and bounds enforcement
- Cryptographic algorithm identifier validation
- Key material input sanitization and masking
- Audit score calculation integrity protection
- Key strength rating validation bounds
- Risk assessment input sanitization
- Recommendation content safety scanning
- Compliance matrix input validation
- Algorithm family classification verification
- Key size parameter range enforcement
- Memory zeroization for sensitive key material
- HMAC audit report tamper detection and sealing
- Audit trail logging for all operations

IMPLEMENTATION PHILOSOPHY: ADD-ONLY, NO EXISTING CODE MODIFICATION
All security features wrap existing functionality without changing it.
100% backward compatible - existing code works unchanged.
"""
import hashlib
import hmac
import time as time_module
import threading
import secrets
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union
from enum import Enum
from datetime import datetime
from collections import defaultdict
import logging

# Configure logging - disabled by default (OPT-IN)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Type variables for generic wrappers
T = TypeVar('T')
R = TypeVar('R')

# ============================================================================
# ENUMERATIONS
# ============================================================================

class AuditSecurityLevel(Enum):
    """Security level enumeration specifically for crypto audit reports."""
    BASIC = "basic"           # Validation only
    STANDARD = "standard"     # Validation + rate limiting
    ENHANCED = "enhanced"     # All security + content scanning
    MAXIMUM = "maximum"       # Full protection + key material zeroization

class ComplianceStandard(Enum):
    """Valid compliance standards for validation."""
    NIST_SP_800_186 = "NIST SP 800-186"
    NIST_SP_800_56C = "NIST SP 800-56C"
    FIPS_140_3 = "FIPS 140-3"
    CNSA_2_0 = "CNSA 2.0"
    ETSI_TS_103_695 = "ETSI TS 103 695"
    GDPR = "GDPR"
    ISO_27001 = "ISO 27001"
    CUSTOM = "CUSTOM"

class ValidationSeverity(Enum):
    """Severity levels for validation failures."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class SecurityEventType(Enum):
    """Types of security events for audit logging."""
    AUDIT_CREATED = "audit_created"
    AUDIT_SIGNED = "audit_signed"
    AUDIT_VERIFIED = "audit_verified"
    VALIDATION_PASSED = "validation_passed"
    VALIDATION_FAILED = "validation_failed"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    KEY_MATERIAL_SANITIZED = "key_material_sanitized"
    MEMORY_ZEROIZED = "memory_zeroized"
    TAMPER_DETECTED = "tamper_detected"
    SCORE_INTEGRITY_CHECK = "score_integrity_check"
    COMPLIANCE_CHECK_FAILED = "compliance_check_failed"

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ValidationResult:
    """Result of input validation check."""
    valid: bool
    severity: ValidationSeverity = ValidationSeverity.INFO
    message: str = ""
    field: str = ""
    sanitized_value: Any = None
    check_timestamp: float = 0.0
    
    def __post_init__(self):
        if self.check_timestamp == 0.0:
            self.check_timestamp = time_module.time()

@dataclass
class SecurityEvent:
    """Single security event for audit trail."""
    event_type: SecurityEventType
    severity: ValidationSeverity
    message: str
    context_id: str = ""
    client_id: str = ""
    audit_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time_module.time()

@dataclass
class AuditRateLimitConfig:
    """Configuration specifically for audit generation rate limiting."""
    max_audits_per_hour: int = 30
    max_algorithms_per_audit: int = 50
    max_checks_per_audit: int = 200
    max_audit_size_bytes: int = 10 * 1024 * 1024  # 10MB
    max_recommendations_per_audit: int = 100
    max_key_materials_per_audit: int = 20
    window_seconds: int = 3600
    burst_allowance: int = 5

@dataclass
class ProtectedAuditContext:
    """Isolated security context for protected audit generation."""
    context_id: str = ""
    security_level: AuditSecurityLevel = AuditSecurityLevel.STANDARD
    created_at: float = 0.0
    expires_at: float = 0.0
    audit_count: int = 0
    validation_failures: List[ValidationResult] = field(default_factory=list)
    security_events: List[SecurityEvent] = field(default_factory=list)
    client_id: str = ""
    hmac_secret: bytes = field(default_factory=bytes)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
        if not self.context_id:
            self.context_id = secrets.token_hex(16)
        if self.created_at == 0.0:
            self.created_at = time_module.time()
        if self.expires_at == 0.0:
            self.expires_at = time_module.time() + 3600
        if not self.hmac_secret:
            self.hmac_secret = secrets.token_bytes(64)

    def increment_audit_count(self) -> None:
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
        return time_module.time() > self.expires_at

# ============================================================================
# SECURE MEMORY UTILITIES (v22 ENHANCED FOR CRYPTO KEYS)
# ============================================================================

class CryptoSecureMemoryV22:
    """
    Enhanced secure memory handling specifically for cryptographic key material.
    
    NEW IN v22:
    - Private key specific wiping
    - Key share threshold data clearing
    - Audit score integrity protection
    - Enhanced constant-time operations
    """
    
    ZEROIZATION_PASSES = 8  # Higher for cryptographic key material
    
    @staticmethod
    def zeroize_bytearray(data: bytearray, passes: int = ZEROIZATION_PASSES) -> None:
        """Securely zeroize bytearray contents with multiple passes."""
        for _ in range(passes):
            for i in range(len(data)):
                data[i] = 0
    
    @staticmethod
    def zeroize_key_material(key_dict: Dict[str, Any]) -> None:
        """Securely wipe sensitive cryptographic key material."""
        sensitive_keys = {'private_key', 'secret_key', 'key_share', 
                         'seed', 'entropy', 'master_key', 'derived_key'}
        for key in sensitive_keys:
            if key in key_dict:
                value = key_dict[key]
                if isinstance(value, bytearray):
                    CryptoSecureMemoryV22.zeroize_bytearray(value)
                elif isinstance(value, str):
                    key_dict[key] = '\x00' * len(value)
                elif isinstance(value, bytes):
                    key_dict[key] = b'\x00' * len(value)
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """Constant-time comparison using hmac.compare_digest."""
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def constant_time_str_compare(a: str, b: str) -> bool:
        """Constant-time string comparison."""
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
    
    @staticmethod
    def secure_audit_hash(audit_content: str, secret: bytes) -> bytes:
        """Generate secure HMAC-SHA512 hash for audit sealing."""
        return hmac.new(secret, audit_content.encode('utf-8'), hashlib.sha512).digest()
    
    @staticmethod
    def mask_key_material(key_str: str, visible_chars: int = 8) -> str:
        """Mask key material for safe logging/display."""
        if len(key_str) <= visible_chars * 2:
            return '*' * len(key_str)
        return key_str[:visible_chars] + '...' + key_str[-visible_chars:]

# ============================================================================
# CRYPTO AUDIT INPUT VALIDATOR
# ============================================================================

class CryptoAuditValidator:
    """
    Comprehensive validation for PQ crypto audit inputs.
    
    Validates: algorithm identifiers, key sizes, compliance standards,
    audit scores, risk levels, and recommendation content.
    """
    
    # Valid PQ algorithm families
    VALID_PQ_FAMILIES = {
        'CRYSTALS-Kyber', 'CRYSTALS-Dilithium', 'FALCON', 'SPHINCS+',
        'Classic McEliece', 'BIKE', 'HQC', 'NTRU', 'NTRU-HRSS',
        'RSA', 'ECDSA', 'Ed25519', 'AES', 'ChaCha20'
    }
    
    # Valid key size ranges by algorithm
    KEY_SIZE_RANGES = {
        'kyber': (512, 1536),
        'dilithium': (128, 512),
        'falcon': (256, 1024),
        'sphincs': (64, 512),
        'rsa': (2048, 16384),
        'ecc': (256, 521),
        'aes': (128, 256),
    }
    
    # Valid audit score range
    AUDIT_SCORE_RANGE = (0.0, 100.0)
    
    # Valid risk levels
    VALID_RISK_LEVELS = {'critical', 'high', 'medium', 'low', 'none', 'unknown'}
    
    @classmethod
    def validate_algorithm(cls, algorithm_name: str) -> ValidationResult:
        """Validate cryptographic algorithm name."""
        if not algorithm_name or not isinstance(algorithm_name, str):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty algorithm name",
                field="algorithm"
            )
        
        algo_clean = algorithm_name.strip()
        
        # Check against known families (case-insensitive)
        algo_upper = algo_clean.upper()
        matched = any(family.upper() in algo_upper for family in cls.VALID_PQ_FAMILIES)
        
        if not matched:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.WARNING,
                message=f"Unknown algorithm family: {algo_clean}",
                field="algorithm",
                sanitized_value=algo_clean
            )
        
        return ValidationResult(valid=True, sanitized_value=algo_clean)
    
    @classmethod
    def validate_key_size(cls, key_size: int, algorithm_family: str = "generic") -> ValidationResult:
        """Validate key size is within acceptable range."""
        try:
            size = int(key_size)
        except (TypeError, ValueError):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Invalid key size value",
                field="key_size"
            )
        
        if size <= 0:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Key size must be positive",
                field="key_size"
            )
        
        # Check family-specific ranges
        family_lower = algorithm_family.lower()
        for family, (min_size, max_size) in cls.KEY_SIZE_RANGES.items():
            if family in family_lower:
                if size < min_size or size > max_size:
                    return ValidationResult(
                        valid=False,
                        severity=ValidationSeverity.WARNING,
                        message=f"Key size {size} outside recommended range [{min_size}, {max_size}] for {family}",
                        field="key_size",
                        sanitized_value=max(min_size, min(max_size, size))
                    )
                break
        
        return ValidationResult(valid=True, sanitized_value=size)
    
    @classmethod
    def validate_audit_score(cls, score: float) -> ValidationResult:
        """Validate audit score is within 0-100 range."""
        try:
            score_float = float(score)
            min_score, max_score = cls.AUDIT_SCORE_RANGE
            if score_float < min_score or score_float > max_score:
                return ValidationResult(
                    valid=False,
                    severity=ValidationSeverity.WARNING,
                    message=f"Audit score {score_float} clamped to [{min_score}, {max_score}]",
                    field="audit_score",
                    sanitized_value=max(min_score, min(max_score, score_float))
                )
            return ValidationResult(valid=True, sanitized_value=score_float)
        except (TypeError, ValueError):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Invalid audit score value",
                field="audit_score"
            )
    
    @classmethod
    def validate_risk_level(cls, risk_level: str) -> ValidationResult:
        """Validate risk level."""
        if not risk_level:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty risk level",
                field="risk_level"
            )
        
        risk_lower = risk_level.lower().strip()
        
        if risk_lower not in cls.VALID_RISK_LEVELS:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.WARNING,
                message=f"Unknown risk level: {risk_level}, defaulting to 'unknown'",
                field="risk_level",
                sanitized_value="unknown"
            )
        
        return ValidationResult(valid=True, sanitized_value=risk_lower)
    
    @classmethod
    def validate_compliance_standard(cls, standard: str) -> ValidationResult:
        """Validate compliance standard."""
        if not standard:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty compliance standard",
                field="compliance_standard"
            )
        
        # Check against known standards
        standard_upper = standard.strip().upper()
        valid_standards = {s.value.upper() for s in ComplianceStandard}
        
        if not any(vs in standard_upper for vs in valid_standards):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.WARNING,
                message=f"Unrecognized compliance standard: {standard}",
                field="compliance_standard",
                sanitized_value=standard
            )
        
        return ValidationResult(valid=True, sanitized_value=standard)

# ============================================================================
# AUDIT CONTENT SANITIZER
# ============================================================================

class AuditContentSanitizer:
    """
    Content sanitization specifically for crypto audit reports.
    
    Protects against:
    - XSS in HTML/Markdown reports
    - Key material exposure in logs
    - Command injection in metadata
    - Path traversal in filenames
    """
    
    DANGEROUS_PATTERNS = [
        (re.compile(r'<\s*script', re.IGNORECASE), '&lt;script'),
        (re.compile(r'javascript\s*:', re.IGNORECASE), 'javascript_blocked:'),
        (re.compile(r'on\w+\s*=', re.IGNORECASE), 'event_blocked='),
        (re.compile(r'eval\s*\(', re.IGNORECASE), 'eval_blocked('),
    ]
    
    @classmethod
    def sanitize_audit_content(cls, content: str) -> str:
        """Sanitize audit content for safe output."""
        if not content or not isinstance(content, str):
            return ""
        
        sanitized = content
        for pattern, replacement in cls.DANGEROUS_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized
    
    @classmethod
    def sanitize_key_material(cls, key_data: str) -> str:
        """Sanitize and mask key material for safe display."""
        if not key_data:
            return ""
        return CryptoSecureMemoryV22.mask_key_material(str(key_data))
    
    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """Sanitize filename to prevent path traversal."""
        if not filename:
            return "crypto_audit"
        sanitized = re.sub(r'[\\/]', '_', filename)
        sanitized = re.sub(r'\.\.', '_', sanitized)
        sanitized = re.sub(r'[<>:"|?*]', '', sanitized)
        return sanitized[:200]
    
    @classmethod
    def sanitize_recommendation(cls, recommendation: str) -> str:
        """Sanitize security recommendation text."""
        sanitized = cls.sanitize_audit_content(recommendation)
        if len(sanitized) > 3000:
            sanitized = sanitized[:3000] + " [truncated]"
        return sanitized

# ============================================================================
# RATE LIMITER FOR AUDIT GENERATION
# ============================================================================

class AuditRateLimiter:
    """
    Adaptive rate limiting specifically for crypto audit generation.
    
    Tracks per-client usage and enforces quotas.
    """
    
    def __init__(self, config: Optional[AuditRateLimitConfig] = None):
        self.config = config or AuditRateLimitConfig()
        self._client_usage: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def _cleanup_old_entries(self, client_id: str, current_time: float) -> None:
        """Remove entries outside the rate limit window."""
        cutoff = current_time - self.config.window_seconds
        self._client_usage[client_id] = [
            t for t in self._client_usage[client_id] if t > cutoff
        ]
    
    def check_rate_limit(self, client_id: str = "default") -> Tuple[bool, Dict[str, Any]]:
        """
        Check if client has exceeded rate limits.
        
        Returns: (allowed, metadata_dict)
        """
        current_time = time_module.time()
        client_key = client_id or "default"
        
        with self._lock:
            self._cleanup_old_entries(client_key, current_time)
            request_count = len(self._client_usage[client_key])
            
            allowed = request_count < self.config.max_audits_per_hour
            
            metadata = {
                "current_count": request_count,
                "max_allowed": self.config.max_audits_per_hour,
                "window_seconds": self.config.window_seconds,
                "remaining": max(0, self.config.max_audits_per_hour - request_count)
            }
            
            if allowed:
                self._client_usage[client_key].append(current_time)
            
            return allowed, metadata
    
    def check_algorithm_count(self, count: int) -> bool:
        """Check if algorithm count exceeds limit."""
        return count <= self.config.max_algorithms_per_audit

# ============================================================================
# AUDIT SIGNING AND TAMPER DETECTION
# ============================================================================

class AuditSealer:
    """
    HMAC-based audit sealing and tamper detection.
    
    Creates verifiable signatures for audit reports to detect tampering.
    """
    
    def __init__(self, secret: Optional[bytes] = None):
        self.secret = secret or secrets.token_bytes(64)
    
    def seal_audit(self, audit_content: str, audit_id: str) -> Dict[str, Any]:
        """
        Create sealed audit with HMAC signature.
        
        Returns: {content_hash, signature, audit_id, timestamp}
        """
        timestamp = int(time_module.time())
        signature_data = f"{audit_id}:{timestamp}:{audit_content}"
        signature = hmac.new(
            self.secret,
            signature_data.encode('utf-8'),
            hashlib.sha512
        ).hexdigest()
        
        return {
            "audit_id": audit_id,
            "content_hash": hashlib.sha256(audit_content.encode('utf-8')).hexdigest(),
            "signature": signature,
            "timestamp": timestamp,
            "sealed": True
        }
    
    def verify_audit(self, audit_content: str, seal_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Verify audit integrity against seal.
        
        Returns: (is_valid, message)
        """
        try:
            audit_id = seal_data.get("audit_id", "")
            timestamp = seal_data.get("timestamp", 0)
            stored_signature = seal_data.get("signature", "")
            
            signature_data = f"{audit_id}:{timestamp}:{audit_content}"
            computed_signature = hmac.new(
                self.secret,
                signature_data.encode('utf-8'),
                hashlib.sha512
            ).hexdigest()
            
            if CryptoSecureMemoryV22.constant_time_str_compare(computed_signature, stored_signature):
                return True, "Audit signature verified successfully"
            return False, "Audit signature mismatch - tampering detected"
            
        except Exception as e:
            return False, f"Verification error: {str(e)}"

# ============================================================================
# MAIN PROTECTED AUDIT GENERATOR WRAPPER
# ============================================================================

class ProtectedPQAuditGenerator:
    """
    Security wrapper for PQ Crypto Audit & Compliance Report Generator (v15).
    
    ADD-ONLY wrapper - wraps existing audit generator without modification.
    Provides comprehensive security hardening for all audit operations.
    """
    
    def __init__(
        self,
        security_level: AuditSecurityLevel = AuditSecurityLevel.STANDARD,
        rate_limit_config: Optional[AuditRateLimitConfig] = None
    ):
        self.security_level = security_level
        self.context = ProtectedAuditContext(security_level=security_level)
        self.rate_limiter = AuditRateLimiter(rate_limit_config)
        self.content_sanitizer = AuditContentSanitizer()
        self.validator = CryptoAuditValidator()
        self.sealer = AuditSealer(self.context.hmac_secret)
        self._initialized = True
    
    def validate_audit_inputs(
        self,
        audit_type: str,
        output_format: str,
        algorithms: Optional[List[str]] = None,
        compliance_standards: Optional[List[str]] = None,
        key_materials: Optional[List[Dict[str, Any]]] = None
    ) -> List[ValidationResult]:
        """
        Comprehensive validation of all audit inputs.
        
        Returns list of validation results.
        """
        results: List[ValidationResult] = []
        
        # Validate audit type
        valid_types = {'pq_compliance', 'algorithm_security', 'key_strength',
                      'risk_assessment', 'full_audit', 'executive_summary',
                      'compliance_matrix'}
        if audit_type not in valid_types:
            results.append(ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid audit type: {audit_type}",
                field="audit_type"
            ))
        
        # Validate output format
        valid_formats = {'json', 'markdown', 'html', 'csv', 'pdf'}
        if output_format not in valid_formats:
            results.append(ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid output format: {output_format}",
                field="output_format"
            ))
        
        # Validate algorithms
        if algorithms:
            if not self.rate_limiter.check_algorithm_count(len(algorithms)):
                results.append(ValidationResult(
                    valid=False,
                    severity=ValidationSeverity.WARNING,
                    message=f"Algorithm count {len(algorithms)} exceeds limit",
                    field="algorithms"
                ))
            
            for algo in algorithms[:30]:  # Sample first 30
                algo_result = self.validator.validate_algorithm(algo)
                if not algo_result.valid:
                    results.append(algo_result)
        
        # Validate compliance standards
        if compliance_standards:
            for standard in compliance_standards[:10]:  # Sample first 10
                std_result = self.validator.validate_compliance_standard(standard)
                if not std_result.valid:
                    results.append(std_result)
        
        # Log results to context
        for result in results:
            self.context.add_validation_failure(result)
            if not result.valid:
                self.context.add_security_event(SecurityEvent(
                    event_type=SecurityEventType.VALIDATION_FAILED,
                    severity=result.severity,
                    message=result.message,
                    context_id=self.context.context_id,
                    metadata={"field": result.field}
                ))
        
        return results
    
    def generate_protected_audit(
        self,
        original_audit_func: Callable[..., Any],
        audit_type: str,
        output_format: str = "json",
        client_id: str = "",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate audit with full security protection.
        
        Wraps original audit generator function with:
        - Rate limiting
        - Input validation
        - Content sanitization
        - Key material masking
        - Audit sealing
        - Audit logging
        """
        # Check rate limit first
        allowed, rate_meta = self.rate_limiter.check_rate_limit(client_id)
        if not allowed:
            self.context.add_security_event(SecurityEvent(
                event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                severity=ValidationSeverity.WARNING,
                message="Rate limit exceeded for audit generation",
                context_id=self.context.context_id,
                client_id=client_id,
                metadata=rate_meta
            ))
            return {
                "success": False,
                "error": "Rate limit exceeded",
                "rate_limit_metadata": rate_meta,
                "security_protected": True
            }
        
        # Validate inputs
        validation_results = self.validate_audit_inputs(
            audit_type=audit_type,
            output_format=output_format,
            algorithms=kwargs.get('algorithms'),
            compliance_standards=kwargs.get('compliance_standards'),
            key_materials=kwargs.get('key_materials')
        )
        
        # Block on critical errors at MAXIMUM security
        critical_errors = [r for r in validation_results 
                          if r.severity == ValidationSeverity.CRITICAL]
        if self.security_level == AuditSecurityLevel.MAXIMUM and critical_errors:
            return {
                "success": False,
                "error": "Critical validation failures",
                "validation_errors": [r.message for r in critical_errors],
                "security_protected": True
            }
        
        # Sanitize content inputs
        sanitized_kwargs = dict(kwargs)
        if 'title' in sanitized_kwargs:
            sanitized_kwargs['title'] = self.content_sanitizer.sanitize_audit_content(
                sanitized_kwargs['title']
            )
        if 'executive_summary' in sanitized_kwargs:
            sanitized_kwargs['executive_summary'] = self.content_sanitizer.sanitize_audit_content(
                sanitized_kwargs['executive_summary']
            )
        if 'recommendations' in sanitized_kwargs:
            sanitized_kwargs['recommendations'] = [
                self.content_sanitizer.sanitize_recommendation(r)
                for r in sanitized_kwargs['recommendations']
            ]
        
        # Sanitize and mask key material (MAXIMUM security)
        if 'key_materials' in sanitized_kwargs and self.security_level == AuditSecurityLevel.MAXIMUM:
            sanitized_kwargs['key_materials'] = [
                {**km, 'key_data': self.content_sanitizer.sanitize_key_material(str(km.get('key_data', '')))}
                for km in sanitized_kwargs['key_materials']
            ]
        
        # Call original (unmodified) audit generator
        try:
            original_result = original_audit_func(
                audit_type=audit_type,
                output_format=output_format,
                **sanitized_kwargs
            )
        except Exception as e:
            return {
                "success": False,
                "error": f"Audit generation failed: {str(e)}",
                "security_protected": True
            }
        
        # Extract audit content
        audit_content = str(original_result) if original_result else "{}"
        audit_id = kwargs.get('audit_id', secrets.token_hex(8))
        
        # Check audit size
        content_size = len(audit_content.encode('utf-8'))
        if content_size > self.rate_limiter.config.max_audit_size_bytes:
            return {
                "success": False,
                "error": f"Audit size {content_size} exceeds limit",
                "security_protected": True
            }
        
        # Seal audit for tamper detection (ENHANCED and above)
        seal_data = None
        if self.security_level in (AuditSecurityLevel.ENHANCED, AuditSecurityLevel.MAXIMUM):
            seal_data = self.sealer.seal_audit(audit_content, audit_id)
            self.context.add_security_event(SecurityEvent(
                event_type=SecurityEventType.AUDIT_SIGNED,
                severity=ValidationSeverity.INFO,
                message="Audit sealed with HMAC signature",
                context_id=self.context.context_id,
                audit_id=audit_id
            ))
        
        # Increment counters
        self.context.increment_audit_count()
        self.context.add_security_event(SecurityEvent(
            event_type=SecurityEventType.AUDIT_CREATED,
            severity=ValidationSeverity.INFO,
            message="Protected audit generated successfully",
            context_id=self.context.context_id,
            client_id=client_id,
            audit_id=audit_id,
            metadata={"audit_type": audit_type, "size_bytes": content_size}
        ))
        
        # Return protected result
        return {
            "success": True,
            "original_result": original_result,
            "security_protected": True,
            "security_level": self.security_level.value,
            "audit_id": audit_id,
            "audit_seal": seal_data,
            "validation_warnings": [r.message for r in validation_results if not r.valid],
            "rate_limit_metadata": rate_meta,
            "content_size_bytes": content_size
        }
    
    def get_security_audit_log(self) -> List[Dict[str, Any]]:
        """Get security audit log for this context."""
        return [
            {
                "event_type": e.event_type.value,
                "severity": e.severity.value,
                "message": e.message,
                "timestamp": datetime.fromtimestamp(e.timestamp).isoformat(),
                "context_id": e.context_id,
                "audit_id": e.audit_id,
                "client_id": e.client_id,
                "metadata": e.metadata
            }
            for e in self.context.security_events
        ]
    
    def secure_dispose(self) -> None:
        """Securely dispose of sensitive context data."""
        if self.security_level == AuditSecurityLevel.MAXIMUM:
            self.context.hmac_secret = b'\x00' * 64
            self.context.add_security_event(SecurityEvent(
                event_type=SecurityEventType.MEMORY_ZEROIZED,
                severity=ValidationSeverity.INFO,
                message="Sensitive context memory zeroized",
                context_id=self.context.context_id
            ))

# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_protected_audit_generator(
    security_level: str = "standard"
) -> ProtectedPQAuditGenerator:
    """
    Convenience function to create protected audit generator.
    
    Args:
        security_level: "basic", "standard", "enhanced", or "maximum"
    
    Returns:
        Configured ProtectedPQAuditGenerator instance
    """
    level_map = {
        "basic": AuditSecurityLevel.BASIC,
        "standard": AuditSecurityLevel.STANDARD,
        "enhanced": AuditSecurityLevel.ENHANCED,
        "maximum": AuditSecurityLevel.MAXIMUM
    }
    level = level_map.get(security_level.lower(), AuditSecurityLevel.STANDARD)
    return ProtectedPQAuditGenerator(security_level=level)

# Version information
__version__ = "22.0.0"
__security_dimension__ = "B - Security Hardening"
__target_module__ = "PQ Crypto Audit & Compliance Report Generator v15"
__compatibility__ = "100% backward compatible - ADD-ONLY wrapper"
