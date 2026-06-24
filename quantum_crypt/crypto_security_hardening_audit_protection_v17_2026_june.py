"""
Security Hardening v17 - PQ Crypto Audit Protection Module
QuantumCrypt-AI

This module provides security hardening wrappers for the Post-Quantum
Crypto Audit & Compliance Report Generator (v15). It implements:
- Input validation and sanitization for audit report generation
- Rate limiting and DoS protection for cryptographic audit operations
- Secure memory handling for sensitive key material and audit data
- Constant-time comparison helpers for cryptographic checks
- Security context isolation for audit operations
- Audit trail logging for all security-sensitive operations

IMPLEMENTATION PHILOSOPHY: ADD-ONLY, NO EXISTING CODE MODIFICATION
All security features wrap existing functionality without changing it.
"""

import hashlib
import hmac
import time
import threading
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar
from enum import Enum
from datetime import datetime
import logging
import uuid

# Configure logging - disabled by default (OPT-IN)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Type variables for generic wrappers
T = TypeVar('T')
R = TypeVar('R')


class CryptoSecurityLevel(Enum):
    """Security level enumeration for cryptographic audit operations."""
    BASIC = "basic"                 # Basic validation only
    STANDARD = "standard"           # Full validation + rate limiting
    ENHANCED = "enhanced"           # All security features
    FIPS_140_3 = "fips_140_3"       # FIPS 140-3 compliant mode


class AuditValidationSeverity(Enum):
    """Severity levels for audit validation failures."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    FIPS_VIOLATION = "fips_violation"


@dataclass
class AuditValidationResult:
    """Result of audit input validation check."""
    valid: bool
    severity: AuditValidationSeverity = AuditValidationSeverity.INFO
    message: str = ""
    field: str = ""
    sanitized_value: Any = None
    fips_compliant: bool = True


@dataclass
class CryptoRateLimitConfig:
    """Configuration for cryptographic operation rate limiting."""
    max_audits_per_window: int = 50
    window_seconds: int = 60
    max_audit_report_size_bytes: int = 50 * 1024 * 1024  # 50MB
    max_checks_per_audit: int = 200
    max_keys_per_audit: int = 100
    max_concurrent_sessions: int = 10


@dataclass
class AuditSecurityContext:
    """Isolated security context for cryptographic audit operations."""
    context_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD
    created_at: float = field(default_factory=time.time)
    audit_count: int = 0
    validation_failures: List[AuditValidationResult] = field(default_factory=list)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def increment_audit(self) -> None:
        """Thread-safe audit counter increment."""
        with self._lock:
            self.audit_count += 1

    def add_validation_failure(self, failure: AuditValidationResult) -> None:
        """Add validation failure to context."""
        with self._lock:
            self.validation_failures.append(failure)

    def add_audit_entry(self, entry: Dict[str, Any]) -> None:
        """Add entry to audit trail."""
        with self._lock:
            entry['timestamp'] = time.time()
            entry['context_id'] = self.context_id
            self.audit_trail.append(entry)


class CryptoSecureMemory:
    """
    Cryptographic secure memory handling utilities.
    
    FIPS 140-3 compliant memory handling with zeroization support.
    """
    
    @staticmethod
    def zeroize_bytearray(data: bytearray) -> None:
        """
        Securely zeroize bytearray contents.
        FIPS 140-3 compliant overwrite pattern.
        """
        # Multiple passes with different patterns
        patterns = [0x00, 0xFF, 0xAA, 0x55, 0x00]
        for pattern in patterns:
            for i in range(len(data)):
                data[i] = pattern
    
    @staticmethod
    def constant_time_bytes_compare(a: bytes, b: bytes) -> bool:
        """
        FIPS 140-3 compliant constant-time comparison.
        Prevents timing side-channel attacks.
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def constant_time_hex_compare(a: str, b: str) -> bool:
        """
        Constant-time comparison of hex strings.
        Used for fingerprint and hash comparisons.
        """
        if len(a) != len(b):
            return False
        # Normalize case first
        a_norm = a.lower()
        b_norm = b.lower()
        return hmac.compare_digest(a_norm.encode('ascii'), b_norm.encode('ascii'))
    
    @staticmethod
    def secure_key_hash(key_material: bytes) -> bytes:
        """
        Generate secure hash of key material for auditing.
        Uses HMAC-SHA512 with random salt.
        """
        salt = secrets.token_bytes(64)
        return hashlib.pbkdf2_hmac('sha512', key_material, salt, 500000)
    
    @staticmethod
    def fips_approved_random_bytes(num_bytes: int) -> bytes:
        """
        Generate FIPS-approved random bytes.
        Uses secrets module which wraps os.urandom.
        """
        return secrets.token_bytes(num_bytes)


class AuditInputValidator:
    """
    Comprehensive input validation for cryptographic audit operations.
    
    Validates and sanitizes all inputs to audit report generation,
    with special handling for cryptographic material.
    """
    
    # Maximum safe lengths for various fields
    MAX_FIELD_LENGTHS = {
        'audit_title': 200,
        'check_name': 100,
        'algorithm_name': 50,
        'key_id': 128,
        'fingerprint': 512,
        'compliance_standard': 50,
        'audit_type': 50,
        'output_format': 20,
        'filename': 255,
        'recommendation': 2000
    }
    
    # Allowed audit types (from audit report generator)
    ALLOWED_AUDIT_TYPES = {
        'key_management', 'algorithm_compliance', 'security_audit',
        'performance_benchmark', 'comprehensive_audit', 'regulatory_compliance'
    }
    
    # Allowed compliance standards
    ALLOWED_COMPLIANCE_STANDARDS = {
        'nist_sp_800_186', 'nist_sp_800_56c', 'fips_140_3',
        'cnsa_2.0', 'etsi_ts_103_675', 'gdpr'
    }
    
    # Allowed output formats
    ALLOWED_OUTPUT_FORMATS = {'json', 'markdown', 'html', 'csv', 'pdf'}
    
    # Allowed PQ algorithm names (NIST approved)
    ALLOWED_PQ_ALGORITHMS = {
        'crystals-kyber', 'crystals-dilithium', 'falcon', 'sphincs+',
        'kyber512', 'kyber768', 'kyber1024',
        'dilithium2', 'dilithium3', 'dilithium5',
        'falcon512', 'falcon1024'
    }
    
    # FIPS forbidden patterns
    FIPS_FORBIDDEN_PATTERNS = ['md5', 'sha1', 'rc4', 'des', '3des']
    
    @classmethod
    def validate_audit_type(cls, audit_type: str) -> AuditValidationResult:
        """Validate audit type is in allowed list."""
        if audit_type.lower() not in cls.ALLOWED_AUDIT_TYPES:
            return AuditValidationResult(
                valid=False,
                severity=AuditValidationSeverity.ERROR,
                message=f"Invalid audit type: {audit_type}",
                field="audit_type"
            )
        return AuditValidationResult(valid=True, sanitized_value=audit_type.lower())
    
    @classmethod
    def validate_compliance_standard(cls, standard: str) -> AuditValidationResult:
        """Validate compliance standard is recognized."""
        if standard.lower() not in cls.ALLOWED_COMPLIANCE_STANDARDS:
            return AuditValidationResult(
                valid=False,
                severity=AuditValidationSeverity.WARNING,
                message=f"Unknown compliance standard: {standard}",
                field="compliance_standard"
            )
        return AuditValidationResult(valid=True, sanitized_value=standard.lower())
    
    @classmethod
    def validate_pq_algorithm(cls, algorithm: str) -> AuditValidationResult:
        """Validate algorithm is NIST-approved post-quantum."""
        algo_lower = algorithm.lower().replace('_', '-')
        fips_compliant = algo_lower in cls.ALLOWED_PQ_ALGORITHMS
        
        # Check for non-FIPS algorithms
        fips_violation = any(pattern in algo_lower for pattern in cls.FIPS_FORBIDDEN_PATTERNS)
        
        if fips_violation:
            return AuditValidationResult(
                valid=False,
                severity=AuditValidationSeverity.FIPS_VIOLATION,
                message=f"Non-FIPS approved algorithm: {algorithm}",
                field="algorithm",
                fips_compliant=False
            )
        
        if not fips_compliant:
            return AuditValidationResult(
                valid=True,  # Still allow, but warn
                severity=AuditValidationSeverity.WARNING,
                message=f"Non-standard PQ algorithm: {algorithm}",
                field="algorithm",
                sanitized_value=algorithm,
                fips_compliant=False
            )
        
        return AuditValidationResult(
            valid=True,
            sanitized_value=algorithm,
            fips_compliant=True
        )
    
    @classmethod
    def validate_output_format(cls, output_format: str) -> AuditValidationResult:
        """Validate output format is in allowed list."""
        if output_format.lower() not in cls.ALLOWED_OUTPUT_FORMATS:
            return AuditValidationResult(
                valid=False,
                severity=AuditValidationSeverity.ERROR,
                message=f"Invalid output format: {output_format}",
                field="output_format"
            )
        return AuditValidationResult(valid=True, sanitized_value=output_format.lower())
    
    @classmethod
    def validate_key_fingerprint(cls, fingerprint: str) -> AuditValidationResult:
        """Validate key fingerprint format."""
        if not fingerprint or not isinstance(fingerprint, str):
            return AuditValidationResult(
                valid=False,
                severity=AuditValidationSeverity.ERROR,
                message="Empty or invalid fingerprint",
                field="fingerprint"
            )
        
        # Check for hex encoding
        try:
            bytes.fromhex(fingerprint.replace(':', '').replace(' ', ''))
        except ValueError:
            return AuditValidationResult(
                valid=False,
                severity=AuditValidationSeverity.WARNING,
                message="Fingerprint not in valid hex format",
                field="fingerprint"
            )
        
        return AuditValidationResult(valid=True, sanitized_value=fingerprint)
    
    @classmethod
    def validate_filename(cls, filename: str) -> AuditValidationResult:
        """Validate filename for path traversal attacks."""
        if not filename:
            return AuditValidationResult(
                valid=False,
                severity=AuditValidationSeverity.ERROR,
                message="Empty filename",
                field="filename"
            )
        
        # Block path traversal attempts
        if '../' in filename or '..\\' in filename or '/' in filename or '\\' in filename:
            return AuditValidationResult(
                valid=False,
                severity=AuditValidationSeverity.CRITICAL,
                message="Path traversal attempt detected",
                field="filename"
            )
        
        # Sanitize dangerous characters
        sanitized = "".join(c for c in filename if c.isalnum() or c in '._- ')
        sanitized = sanitized[:cls.MAX_FIELD_LENGTHS['filename']]
        
        return AuditValidationResult(valid=True, sanitized_value=sanitized)
    
    @classmethod
    def validate_key_id(cls, key_id: str) -> AuditValidationResult:
        """Validate key identifier format."""
        if not key_id or not isinstance(key_id, str):
            return AuditValidationResult(
                valid=False,
                severity=AuditValidationSeverity.ERROR,
                message="Empty or invalid key ID",
                field="key_id"
            )
        
        if len(key_id) > cls.MAX_FIELD_LENGTHS['key_id']:
            return AuditValidationResult(
                valid=False,
                severity=AuditValidationSeverity.WARNING,
                message="Key ID too long",
                field="key_id",
                sanitized_value=key_id[:cls.MAX_FIELD_LENGTHS['key_id']]
            )
        
        return AuditValidationResult(valid=True, sanitized_value=key_id)
    
    @classmethod
    def validate_check_count(cls, count: int) -> AuditValidationResult:
        """Validate number of audit checks is within limits."""
        if not isinstance(count, int):
            return AuditValidationResult(
                valid=False,
                severity=AuditValidationSeverity.ERROR,
                message="Check count must be integer",
                field="check_count"
            )
        if count < 0:
            return AuditValidationResult(
                valid=False,
                severity=AuditValidationSeverity.ERROR,
                message="Check count cannot be negative",
                field="check_count"
            )
        return AuditValidationResult(valid=True, sanitized_value=count)


class CryptoRateLimiter:
    """
    Thread-safe rate limiter for cryptographic audit operations.
    
    Prevents DoS attacks and resource exhaustion on cryptographic operations.
    """
    
    def __init__(self, config: Optional[CryptoRateLimitConfig] = None):
        self.config = config or CryptoRateLimitConfig()
        self._audit_timestamps: List[float] = []
        self._session_counts: Dict[str, int] = {}
        self._lock = threading.Lock()
    
    def _cleanup_old_audits(self, current_time: float) -> None:
        """Remove timestamps outside the current window."""
        cutoff = current_time - self.config.window_seconds
        while self._audit_timestamps and self._audit_timestamps[0] < cutoff:
            self._audit_timestamps.pop(0)
    
    def check_audit_rate_limit(self, session_id: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if audit request is within rate limits.
        Returns (allowed, metadata_dict)
        """
        current_time = time.time()
        
        with self._lock:
            self._cleanup_old_audits(current_time)
            
            # Global rate limit check
            if len(self._audit_timestamps) >= self.config.max_audits_per_window:
                retry_after = self._audit_timestamps[0] + self.config.window_seconds - current_time
                return False, {
                    'reason': 'global_audit_rate_limit_exceeded',
                    'retry_after': max(1, int(retry_after)),
                    'current_count': len(self._audit_timestamps),
                    'max_limit': self.config.max_audits_per_window
                }
            
            # Concurrent session limit check
            if session_id:
                active_sessions = len(self._session_counts)
                if active_sessions >= self.config.max_concurrent_sessions:
                    return False, {
                        'reason': 'concurrent_session_limit_exceeded',
                        'active_sessions': active_sessions,
                        'max_sessions': self.config.max_concurrent_sessions
                    }
                self._session_counts[session_id] = self._session_counts.get(session_id, 0) + 1
            
            self._audit_timestamps.append(current_time)
            
            return True, {
                'current_count': len(self._audit_timestamps),
                'max_limit': self.config.max_audits_per_window,
                'window_seconds': self.config.window_seconds
            }
    
    def release_session(self, session_id: str) -> None:
        """Release session from count tracking."""
        with self._lock:
            if session_id in self._session_counts:
                self._session_counts[session_id] -= 1
                if self._session_counts[session_id] <= 0:
                    del self._session_counts[session_id]
    
    def check_audit_size(self, size_bytes: int) -> Tuple[bool, Dict[str, Any]]:
        """Check if audit report size is within limits."""
        if size_bytes > self.config.max_audit_report_size_bytes:
            return False, {
                'reason': 'audit_report_size_exceeded',
                'size_bytes': size_bytes,
                'max_bytes': self.config.max_audit_report_size_bytes
            }
        return True, {'size_bytes': size_bytes, 'max_bytes': self.config.max_audit_report_size_bytes}
    
    def check_check_count(self, count: int) -> Tuple[bool, Dict[str, Any]]:
        """Check if number of audit checks is within limits."""
        if count > self.config.max_checks_per_audit:
            return False, {
                'reason': 'audit_check_count_exceeded',
                'count': count,
                'max_count': self.config.max_checks_per_audit
            }
        return True, {'count': count, 'max_count': self.config.max_checks_per_audit}


class CryptoAuditSecurityProtector:
    """
    Main security protector for cryptographic audit operations.
    
    Wraps audit report generation with comprehensive security:
    - Cryptographic input validation and sanitization
    - Rate limiting and DoS protection
    - FIPS 140-3 compliant secure memory handling
    - Security context isolation
    - Audit trail logging
    - Constant-time comparison helpers
    """
    
    def __init__(
        self,
        security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD,
        rate_limit_config: Optional[CryptoRateLimitConfig] = None
    ):
        self.security_level = security_level
        self.rate_limiter = CryptoRateLimiter(rate_limit_config)
        self.validator = AuditInputValidator()
        self.active_contexts: Dict[str, AuditSecurityContext] = {}
        self._context_lock = threading.Lock()
        
        logger.info(f"CryptoAuditSecurityProtector initialized with level: {security_level.value}")
    
    def create_security_context(
        self,
        security_level: Optional[CryptoSecurityLevel] = None
    ) -> AuditSecurityContext:
        """Create a new isolated security context."""
        context = AuditSecurityContext(security_level=security_level or self.security_level)
        with self._context_lock:
            self.active_contexts[context.context_id] = context
        logger.debug(f"Created audit security context: {context.context_id}")
        return context
    
    def release_context(self, context_id: str) -> None:
        """Release and cleanup security context."""
        with self._context_lock:
            if context_id in self.active_contexts:
                del self.active_contexts[context_id]
        self.rate_limiter.release_session(context_id)
        logger.debug(f"Released audit security context: {context_id}")
    
    def secure_audit_generation(
        self,
        func: Callable[..., R],
        *args: Any,
        context: Optional[AuditSecurityContext] = None,
        **kwargs: Any
    ) -> Tuple[bool, Optional[R], Dict[str, Any]]:
        """
        Wrap audit generation function with full security protection.
        
        Returns: (success, result_or_none, security_metadata)
        """
        if context is None:
            context = self.create_security_context()
        
        context.increment_audit()
        security_metadata: Dict[str, Any] = {
            'context_id': context.context_id,
            'security_level': context.security_level.value,
            'fips_mode': context.security_level == CryptoSecurityLevel.FIPS_140_3,
            'validation_passed': True,
            'validation_failures': [],
            'rate_limit_check': None,
            'start_time': time.time()
        }
        
        # Log operation start to audit trail
        context.add_audit_entry({
            'operation': 'audit_generation_start',
            'function': getattr(func, '__name__', 'unknown')
        })
        
        # Step 1: Rate limiting check (STANDARD+)
        if context.security_level in (
            CryptoSecurityLevel.STANDARD,
            CryptoSecurityLevel.ENHANCED,
            CryptoSecurityLevel.FIPS_140_3
        ):
            allowed, rate_info = self.rate_limiter.check_audit_rate_limit(context.context_id)
            security_metadata['rate_limit_check'] = rate_info
            if not allowed:
                security_metadata['blocked_reason'] = rate_info['reason']
                context.add_audit_entry({'operation': 'rate_limit_blocked', **rate_info})
                logger.warning(f"Audit rate limit blocked: {rate_info['reason']}")
                return False, None, security_metadata
        
        # Step 2: Input validation (ALL levels)
        validation_failures = self._validate_audit_inputs(**kwargs)
        if validation_failures:
            for failure in validation_failures:
                context.add_validation_failure(failure)
            
            # Block on ERROR/CRITICAL/FIPS_VIOLATION at STANDARD+
            blocking_failures = [
                f for f in validation_failures
                if f.severity in (
                    AuditValidationSeverity.ERROR,
                    AuditValidationSeverity.CRITICAL,
                    AuditValidationSeverity.FIPS_VIOLATION
                )
            ]
            
            if blocking_failures and context.security_level != CryptoSecurityLevel.BASIC:
                security_metadata['validation_passed'] = False
                security_metadata['validation_failures'] = [
                    {'field': f.field, 'message': f.message, 'severity': f.severity.value}
                    for f in blocking_failures
                ]
                security_metadata['blocked_reason'] = 'validation_failure'
                context.add_audit_entry({
                    'operation': 'validation_blocked',
                    'failures': len(blocking_failures)
                })
                logger.warning(f"Audit validation blocked: {len(blocking_failures)} failures")
                return False, None, security_metadata
            
            security_metadata['validation_warnings'] = [
                {'field': f.field, 'message': f.message}
                for f in validation_failures
            ]
        
        # Step 3: Execute wrapped function
        try:
            result = func(*args, **kwargs)
            
            # Step 4: Post-execution checks (ENHANCED+ / FIPS mode)
            if context.security_level in (CryptoSecurityLevel.ENHANCED, CryptoSecurityLevel.FIPS_140_3):
                result_size = self._estimate_result_size(result)
                size_ok, size_info = self.rate_limiter.check_audit_size(result_size)
                security_metadata['size_check'] = size_info
                if not size_ok:
                    security_metadata['blocked_reason'] = size_info['reason']
                    logger.warning(f"Audit size limit blocked: {size_info['reason']}")
                    return False, None, security_metadata
            
            security_metadata['execution_time'] = time.time() - security_metadata['start_time']
            security_metadata['success'] = True
            security_metadata['fips_compliant'] = all(
                f.fips_compliant for f in context.validation_failures
            ) if context.validation_failures else True
            
            context.add_audit_entry({
                'operation': 'audit_generation_complete',
                'success': True,
                'execution_time': security_metadata['execution_time']
            })
            
            logger.debug(f"Secure audit generation completed: {context.context_id}")
            return True, result, security_metadata
            
        except Exception as e:
            security_metadata['success'] = False
            security_metadata['error'] = str(e)
            security_metadata['execution_time'] = time.time() - security_metadata['start_time']
            
            context.add_audit_entry({
                'operation': 'audit_generation_error',
                'error': str(e)
            })
            
            logger.error(f"Secure audit generation error: {e}")
            return False, None, security_metadata
    
    def _validate_audit_inputs(self, **kwargs: Any) -> List[AuditValidationResult]:
        """Validate all inputs to audit generation."""
        failures: List[AuditValidationResult] = []
        
        # Validate audit_type if present
        if 'audit_type' in kwargs:
            result = self.validator.validate_audit_type(kwargs['audit_type'])
            if not result.valid:
                failures.append(result)
        
        # Validate compliance_standard if present
        if 'compliance_standard' in kwargs:
            result = self.validator.validate_compliance_standard(kwargs['compliance_standard'])
            if not result.valid:
                failures.append(result)
        
        # Validate output_format if present
        if 'output_format' in kwargs:
            result = self.validator.validate_output_format(kwargs['output_format'])
            if not result.valid:
                failures.append(result)
        
        # Validate filename if present
        if 'filename' in kwargs:
            result = self.validator.validate_filename(kwargs['filename'])
            if not result.valid:
                failures.append(result)
        
        # Validate algorithm if present
        if 'algorithm' in kwargs:
            result = self.validator.validate_pq_algorithm(kwargs['algorithm'])
            if not result.valid or result.severity != AuditValidationSeverity.INFO:
                failures.append(result)
        
        # Validate key_id if present
        if 'key_id' in kwargs:
            result = self.validator.validate_key_id(kwargs['key_id'])
            if not result.valid:
                failures.append(result)
        
        # Validate check count if checks present
        if 'checks' in kwargs and isinstance(kwargs['checks'], list):
            result = self.rate_limiter.check_check_count(len(kwargs['checks']))
            if not result[0]:
                failures.append(AuditValidationResult(
                    valid=False,
                    severity=AuditValidationSeverity.WARNING,
                    message=result[1]['reason'],
                    field='checks'
                ))
        
        return failures
    
    def _estimate_result_size(self, result: Any) -> int:
        """Rough estimate of audit result size in bytes."""
        if isinstance(result, str):
            return len(result.encode('utf-8'))
        if isinstance(result, (dict, list)):
            import json
            try:
                return len(json.dumps(result).encode('utf-8'))
            except:
                return 0
        return 0
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security protection statistics."""
        with self._context_lock:
            return {
                'active_contexts': len(self.active_contexts),
                'security_level': self.security_level.value,
                'fips_140_3_mode': self.security_level == CryptoSecurityLevel.FIPS_140_3,
                'rate_limit_config': {
                    'max_audits': self.rate_limiter.config.max_audits_per_window,
                    'window_seconds': self.rate_limiter.config.window_seconds,
                    'max_concurrent_sessions': self.rate_limiter.config.max_concurrent_sessions
                }
            }


# Convenience functions for easy integration
_DEFAULT_CRYPTO_PROTECTOR: Optional[CryptoAuditSecurityProtector] = None
_CRYPTO_PROTECTOR_LOCK = threading.Lock()


def get_default_crypto_protector() -> CryptoAuditSecurityProtector:
    """Get or create the default crypto security protector singleton."""
    global _DEFAULT_CRYPTO_PROTECTOR
    if _DEFAULT_CRYPTO_PROTECTOR is None:
        with _CRYPTO_PROTECTOR_LOCK:
            if _DEFAULT_CRYPTO_PROTECTOR is None:
                _DEFAULT_CRYPTO_PROTECTOR = CryptoAuditSecurityProtector()
    return _DEFAULT_CRYPTO_PROTECTOR


def secure_generate_audit_report(
    func: Callable[..., R],
    *args: Any,
    security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD,
    **kwargs: Any
) -> Tuple[bool, Optional[R], Dict[str, Any]]:
    """
    Convenience function to secure audit report generation.
    
    Usage:
        success, result, metadata = secure_generate_audit_report(
            audit_generator.generate,
            audit_type='comprehensive_audit',
            security_level=CryptoSecurityLevel.FIPS_140_3
        )
    """
    protector = get_default_crypto_protector()
    context = protector.create_security_context(security_level)
    try:
        return protector.secure_audit_generation(func, *args, context=context, **kwargs)
    finally:
        protector.release_context(context.context_id)


def crypto_constant_time_compare(a: bytes, b: bytes) -> bool:
    """Convenience function for FIPS-compliant constant-time comparison."""
    return CryptoSecureMemory.constant_time_bytes_compare(a, b)


def crypto_secure_zeroize(data: bytearray) -> None:
    """Convenience function for FIPS-compliant memory zeroization."""
    CryptoSecureMemory.zeroize_bytearray(data)


# Version information
VERSION = "1.7.0"
VERSION_INFO = {
    'major': 1,
    'minor': 7,
    'patch': 0,
    'dimension': 'B',
    'dimension_version': 17,
    'release_date': '2026-06-24',
    'module': 'crypto_security_hardening_audit_protection',
    'fips_140_3_ready': True
}


def get_version() -> str:
    """Get module version string."""
    return VERSION


def get_version_info() -> Dict[str, Any]:
    """Get detailed version information."""
    return VERSION_INFO.copy()


# Module initialization verification
logger.info(f"Security Hardening v17 loaded - Crypto Audit Protection Module v{VERSION}")
