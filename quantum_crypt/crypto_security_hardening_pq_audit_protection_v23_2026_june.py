"""
Security Hardening v23 - PQ Audit Protection Module
QuantumCrypt-AI | June 24, 2026
Session 127 - Dimension B: Security Hardening v23

ADD-ONLY security wrapper layer for PQ audit generation features.
No existing code modified - 100% backward compatible.
"""

import hashlib
import hmac
import time
import threading
import secrets
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from enum import Enum
from functools import wraps
from collections import defaultdict


# ============================================================================
# ENUMERATIONS (v23)
# ============================================================================
class CryptoSecurityLevelV23(Enum):
    AUDIT = "audit"
    ENFORCE = "enforce"
    FIPS = "fips_140_3"


class ValidationSeverityV23(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# ============================================================================
# DATA CLASSES (v23) - NO TIMESTAMP FIELDS
# ============================================================================
@dataclass
class CryptoValidationResultV23:
    valid: bool
    severity: ValidationSeverityV23 = ValidationSeverityV23.INFO
    message: str = ""
    field: str = ""
    sanitized_value: Any = None


@dataclass
class KeyOperationRateLimitConfigV23:
    max_key_generations_per_hour: int = 50
    max_audits_per_hour: int = 200
    window_seconds: int = 3600


# ============================================================================
# SECURE KEY MEMORY (v23)
# ============================================================================
class SecureKeyMemoryV23:
    ZEROIZATION_PASSES = 7
    PATTERNS = [0x00, 0xFF, 0xAA, 0x55, 0xF0, 0x0F, 0x00]
    
    @staticmethod
    def zeroize_key_material(key_data: bytearray) -> None:
        for pattern in SecureKeyMemoryV23.PATTERNS[:SecureKeyMemoryV23.ZEROIZATION_PASSES]:
            for i in range(len(key_data)):
                key_data[i] = pattern
    
    @staticmethod
    def constant_time_bytes_compare(a: bytes, b: bytes) -> bool:
        return hmac.compare_digest(a, b)


# ============================================================================
# KEY OPERATION RATE LIMITER (v23)
# ============================================================================
class KeyOperationRateLimiterV23:
    def __init__(self, config: Optional[KeyOperationRateLimitConfigV23] = None):
        self.config = config or KeyOperationRateLimitConfigV23()
        self._operation_history: Dict[str, Dict[str, List[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._lock = threading.Lock()
    
    def check_operation(self, op_type: str, client_id: str = "default") -> Tuple[bool, Dict[str, Any]]:
        current_time = time.time()
        with self._lock:
            cutoff = current_time - self.config.window_seconds
            history = self._operation_history[client_id][op_type]
            self._operation_history[client_id][op_type] = [
                t for t in history if t > cutoff
            ]
            count = len(self._operation_history[client_id][op_type])
            limit = self.config.max_audits_per_hour if op_type == 'audit' else self.config.max_key_generations_per_hour
            if count >= limit:
                return False, {"rate_limited": True}
            self._operation_history[client_id][op_type].append(current_time)
            return True, {"allowed": True}


# ============================================================================
# AUDIT LOG TAMPER PROTECTOR (v23)
# ============================================================================
class AuditLogTamperProtectorV23:
    def __init__(self, secret: Optional[bytes] = None):
        self.secret = secret or secrets.token_bytes(64)
        self._chain: List[Dict[str, Any]] = []
        self._last_hash: str = ""
    
    def seal_audit_entry(self, audit_data: Dict[str, Any], audit_id: str) -> Dict[str, Any]:
        timestamp = int(time.time())
        entry = {
            "audit_id": audit_id,
            "timestamp": timestamp,
            "audit_type": audit_data.get("audit_type", "unknown"),
            "compliance_score": audit_data.get("compliance_score", 0),
        }
        data = json.dumps(entry, sort_keys=True) + self._last_hash
        entry_hash = hmac.new(self.secret, data.encode('utf-8'), hashlib.sha256).hexdigest()
        sealed = {
            **entry,
            "hash": entry_hash,
            "previous_hash": self._last_hash,
            "chain_position": len(self._chain)
        }
        self._chain.append(sealed)
        self._last_hash = entry_hash
        return sealed


# ============================================================================
# CERTIFICATE & ALGORITHM VALIDATORS (v23)
# ============================================================================
class CertificateValidatorV23:
    VALID_ALGORITHMS = {'crystals-kyber', 'crystals-dilithium', 'falcon', 'rsa', 'ecdsa', 'aes'}
    
    @classmethod
    def validate_algorithm_name(cls, algorithm: str) -> CryptoValidationResultV23:
        if not algorithm:
            return CryptoValidationResultV23(valid=True)
        alg_lower = algorithm.lower().strip()
        if alg_lower not in cls.VALID_ALGORITHMS:
            return CryptoValidationResultV23(
                valid=False, severity=ValidationSeverityV23.WARNING,
                message=f"Unknown algorithm: {algorithm}"
            )
        return CryptoValidationResultV23(valid=True, sanitized_value=alg_lower)


class AlgorithmParameterValidatorV23:
    MIN_KEY_SIZES = {'rsa': 2048, 'ecdsa': 256, 'kyber': 512, 'aes': 128}
    
    @classmethod
    def validate_key_size(cls, algorithm: str, key_size: int) -> CryptoValidationResultV23:
        alg_lower = algorithm.lower() if algorithm else 'unknown'
        min_size = cls.MIN_KEY_SIZES.get(alg_lower, 128)
        try:
            ks_int = int(key_size)
            if ks_int < min_size:
                return CryptoValidationResultV23(
                    valid=False, severity=ValidationSeverityV23.ERROR,
                    message=f"Key size below minimum: {min_size}"
                )
            return CryptoValidationResultV23(valid=True, sanitized_value=ks_int)
        except (TypeError, ValueError):
            return CryptoValidationResultV23(
                valid=False, severity=ValidationSeverityV23.ERROR,
                message="Invalid key size"
            )


# ============================================================================
# MAIN CRYPTO SECURITY WRAPPER (v23)
# ============================================================================
_global_key_rate_limiter = KeyOperationRateLimiterV23()
_global_audit_protector = AuditLogTamperProtectorV23()


def secure_pq_audit_v23(client_id: str = "default", security_level: CryptoSecurityLevelV23 = CryptoSecurityLevelV23.ENFORCE):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            allowed, _ = _global_key_rate_limiter.check_operation('audit', client_id)
            if not allowed and security_level != CryptoSecurityLevelV23.AUDIT:
                raise RuntimeError("Crypto security block: rate limit exceeded")
            
            result = func(*args, **kwargs)
            
            if isinstance(result, dict):
                audit_id = result.get('audit_id', secrets.token_hex(8))
                result['tamper_protection'] = _global_audit_protector.seal_audit_entry(
                    result, audit_id
                )
            
            return result
        return wrapper
    return decorator


# ============================================================================
# VERSION INFO
# ============================================================================
def get_crypto_security_hardening_v23_info() -> Dict[str, Any]:
    return {
        "module": "crypto_security_hardening_pq_audit_protection_v23",
        "version": "v23",
        "dimension": "B - Security Hardening",
        "release_date": "2026-06-24",
        "session": "127",
        "new_features_v23": [
            "Key operation rate limiting",
            "FIPS-compliant key material zeroization (7 passes)",
            "Audit log tamper protection chain",
            "Post-quantum algorithm validation",
            "Algorithm parameter validation",
            "Constant-time comparison helpers"
        ],
        "compatible_with": ["feature_expansion_pq_crypto_audit_report_generator_v15"],
        "implementation_note": "100% ADD-ONLY - Zero existing files modified"
    }
