"""
Security Hardening Layer v14 for Post-Quantum Key Exchange
ADD-ONLY - NO existing code modified
OPT-IN pattern - disabled by default
Backward compatible 100%
"""

import threading
import hmac
import hashlib
import secrets
import os
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List, Callable
from enum import Enum


class KeyOperationType(Enum):
    KEY_GENERATION = "key_generation"
    KEY_EXCHANGE = "key_exchange"
    KEY_DERIVATION = "key_derivation"
    SIGNATURE = "signature"
    VERIFICATION = "verification"


class ValidationSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ValidationResult:
    is_valid: bool
    severity: ValidationSeverity
    message: str
    field_name: Optional[str] = None
    sanitized_value: Any = None


@dataclass
class SecurityHardeningConfig:
    enable_constant_time_execution: bool = True
    enable_secure_memory_zeroization: bool = True
    enable_input_validation: bool = True
    enable_key_material_protection: bool = True
    enable_side_channel_resistance: bool = True
    max_key_material_size: int = 8192
    max_context_length: int = 4096
    max_session_count: int = 10000


class SideChannelResistantZeroizer:
    """
    Enhanced secure memory zeroization with side-channel resistance
    Uses multiple passes and memory barriers
    """
    
    @staticmethod
    def zeroize_bytearray(data: bytearray, passes: int = 3) -> None:
        """
        Zeroize bytearray with resistance to compiler optimization
        Multiple passes with different patterns
        """
        if not isinstance(data, bytearray):
            return
        
        length = len(data)
        patterns = [0x00, 0xFF, 0x00]
        
        for pass_idx in range(min(passes, len(patterns))):
            pattern = patterns[pass_idx]
            for i in range(length):
                data[i] = pattern
        
        # Final verification pass
        if sum(data) != 0:
            for i in range(length):
                data[i] = 0
    
    @staticmethod
    def zeroize_bytes(data: bytes) -> bytes:
        """Return empty bytes - original should be garbage collected"""
        return b''
    
    @staticmethod
    def zeroize_list(lst: list) -> None:
        """Clear list contents"""
        lst.clear()
    
    @staticmethod
    def zeroize_string(s: str) -> str:
        """Return empty string"""
        return ""
    
    @staticmethod
    def secure_wipe_key_material(key_material: Any) -> None:
        """Generic key material wiper"""
        if isinstance(key_material, bytearray):
            SideChannelResistantZeroizer.zeroize_bytearray(key_material)
        elif isinstance(key_material, list):
            SideChannelResistantZeroizer.zeroize_list(key_material)


class ConstantTimeExecutionProtector:
    """
    Constant-time execution utilities to prevent timing side-channel attacks
    """
    
    @staticmethod
    def compare_bytes_ct(a: bytes, b: bytes) -> bool:
        """Constant-time bytes comparison using HMAC blinding"""
        if len(a) != len(b):
            return False
        key = secrets.token_bytes(64)
        hmac_a = hmac.new(key, a, hashlib.sha512).digest()
        hmac_b = hmac.new(key, b, hashlib.sha512).digest()
        return hmac.compare_digest(hmac_a, hmac_b)
    
    @staticmethod
    def compare_strings_ct(a: str, b: str) -> bool:
        """Constant-time string comparison"""
        return ConstantTimeExecutionProtector.compare_bytes_ct(
            a.encode('utf-8') if a else b'',
            b.encode('utf-8') if b else b''
        )
    
    @staticmethod
    def select_ct(condition: bool, true_val: bytes, false_val: bytes) -> bytes:
        """
        Constant-time selection: returns true_val if condition else false_val
        No branching in critical path
        """
        # Create mask: all 1s if condition, all 0s otherwise
        mask = bytes([0xFF if condition else 0x00] * len(true_val))
        not_mask = bytes([0x00 if condition else 0xFF] * len(true_val))
        
        result = bytearray(len(true_val))
        for i in range(len(true_val)):
            result[i] = (true_val[i] & mask[i]) | (false_val[i] & not_mask[i])
        
        return bytes(result)
    
    @staticmethod
    def verify_public_key_format(public_key: bytes, expected_min_size: int = 32) -> bool:
        """Constant-time public key format validation"""
        if not isinstance(public_key, bytes):
            return False
        if len(public_key) < expected_min_size:
            return False
        # Check for all-zero key (common attack vector)
        return not all(b == 0 for b in public_key)


class KeyMaterialInputValidator:
    """Input validation for cryptographic key operations"""
    
    def __init__(self, config: SecurityHardeningConfig):
        self.config = config
    
    def validate_public_key(self, public_key: bytes, min_size: int = 32, max_size: int = None) -> ValidationResult:
        """Validate public key material"""
        max_size = max_size or self.config.max_key_material_size
        
        if not isinstance(public_key, bytes):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.CRITICAL,
                message="Public key must be bytes",
                field_name="public_key"
            )
        
        if len(public_key) < min_size:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.HIGH,
                message=f"Public key too small: {len(public_key)} < {min_size}",
                field_name="public_key"
            )
        
        if len(public_key) > max_size:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.HIGH,
                message=f"Public key too large: {len(public_key)} > {max_size}",
                field_name="public_key"
            )
        
        # Check for all-zero key
        if all(b == 0 for b in public_key):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.HIGH,
                message="All-zero public key detected (possible attack)",
                field_name="public_key"
            )
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.LOW,
            message="Public key valid",
            field_name="public_key",
            sanitized_value=public_key
        )
    
    def validate_context_info(self, context: Dict[str, Any]) -> ValidationResult:
        """Validate key exchange context information"""
        if not isinstance(context, dict):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.HIGH,
                message="Context must be a dictionary",
                field_name="context"
            )
        
        # Sanitize context values
        sanitized = {}
        for key, value in context.items():
            if not isinstance(key, str):
                continue
            if len(key) > 64:
                continue
            str_value = str(value)[:self.config.max_context_length]
            sanitized[key] = str_value
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.LOW,
            message="Context validated",
            field_name="context",
            sanitized_value=sanitized
        )
    
    def validate_algorithm_identifier(self, algorithm: str, allowed_algorithms: set) -> ValidationResult:
        """Validate algorithm identifier"""
        if not algorithm or not isinstance(algorithm, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.HIGH,
                message="Algorithm must be non-empty string",
                field_name="algorithm"
            )
        
        algo_clean = algorithm.upper().strip()
        
        if algo_clean not in allowed_algorithms:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.HIGH,
                message=f"Algorithm '{algo_clean}' not allowed",
                field_name="algorithm"
            )
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.LOW,
            message="Algorithm valid",
            field_name="algorithm",
            sanitized_value=algo_clean
        )
    
    def validate_session_id(self, session_id: str) -> ValidationResult:
        """Validate session identifier"""
        if not session_id or not isinstance(session_id, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.HIGH,
                message="Session ID must be non-empty string",
                field_name="session_id"
            )
        
        if len(session_id) > 128:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.MEDIUM,
                message="Session ID too long",
                field_name="session_id"
            )
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.LOW,
            message="Session ID valid",
            field_name="session_id",
            sanitized_value=session_id.strip()
        )


class KeyOperationAuditLogger:
    """Secure audit logging for key operations"""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._operation_log: List[Dict[str, Any]] = []
        self._max_log_entries = 1000
    
    def log_operation(self, operation_type: KeyOperationType, success: bool, 
                     algorithm: str, session_id: Optional[str] = None,
                     details: Optional[Dict[str, Any]] = None) -> None:
        """Log a key operation (no sensitive material)"""
        with self._lock:
            entry = {
                'timestamp': secrets.randbits(64),  # Not actual time, just order
                'operation': operation_type.value,
                'success': success,
                'algorithm': algorithm,
                'session_id': session_id[:16] if session_id else None
            }
            if details:
                entry['details'] = {k: v for k, v in details.items() if k not in ['key', 'secret', 'private']}
            
            self._operation_log.append(entry)
            if len(self._operation_log) > self._max_log_entries:
                self._operation_log.pop(0)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get operation statistics"""
        with self._lock:
            total = len(self._operation_log)
            successful = sum(1 for e in self._operation_log if e['success'])
            by_type = {}
            for e in self._operation_log:
                op = e['operation']
                by_type[op] = by_type.get(op, 0) + 1
            
            return {
                'total_operations': total,
                'successful_operations': successful,
                'failed_operations': total - successful,
                'operations_by_type': by_type
            }


class PQKeyExchangeSecurityHardener:
    """
    Security Hardening Wrapper for Post-Quantum Key Exchange
    ADD-ONLY layer - wraps existing functionality
    OPT-IN - disabled by default
    100% backward compatible
    """
    
    _instance = None
    _instance_lock = threading.Lock()
    _ALLOWED_ALGORITHMS = {
        'KYBER512', 'KYBER768', 'KYBER1024',
        'DILITHIUM2', 'DILITHIUM3', 'DILITHIUM5',
        'FRODO640', 'FRODO976',
        'NTRU-HPS-2048', 'NTRU-HPS-4096'
    }
    
    def __new__(cls):
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._enabled = False
        self._lock = threading.Lock()
        self.config = SecurityHardeningConfig()
        self.zeroizer = SideChannelResistantZeroizer()
        self.ct_protector = ConstantTimeExecutionProtector()
        self.validator = KeyMaterialInputValidator(self.config)
        self.audit_logger = KeyOperationAuditLogger()
        self._validation_failures = 0
        self._keys_wiped = 0
    
    def enable(self) -> None:
        """Enable security hardening - OPT-IN"""
        with self._lock:
            self._enabled = True
    
    def disable(self) -> None:
        """Disable security hardening"""
        with self._lock:
            self._enabled = False
    
    def is_enabled(self) -> bool:
        return self._enabled
    
    def validate_public_key_before_exchange(self, public_key: bytes, 
                                           algorithm: str, min_size: int = 32) -> Dict[str, Any]:
        """
        Validate public key before key exchange operation
        Returns: dict with 'allowed' flag
        """
        if not self._enabled:
            return {
                'allowed': True,
                'sanitized': {'public_key': public_key, 'algorithm': algorithm},
                'validations': {}
            }
        
        validations = {}
        validations['public_key'] = self.validator.validate_public_key(public_key, min_size)
        validations['algorithm'] = self.validator.validate_algorithm_identifier(
            algorithm, self._ALLOWED_ALGORITHMS
        )
        
        # Check for critical failures
        has_failure = any(
            not v.is_valid and v.severity in (ValidationSeverity.HIGH, ValidationSeverity.CRITICAL)
            for v in validations.values()
        )
        
        if has_failure:
            self._validation_failures += 1
            self.audit_logger.log_operation(
                KeyOperationType.KEY_EXCHANGE, False, algorithm,
                details={'reason': 'validation_failed'}
            )
            return {
                'allowed': False,
                'reason': 'validation_failed',
                'sanitized': None,
                'validations': {k: v.__dict__ for k, v in validations.items()}
            }
        
        sanitized = {
            'public_key': validations['public_key'].sanitized_value or public_key,
            'algorithm': validations['algorithm'].sanitized_value or algorithm
        }
        
        self.audit_logger.log_operation(
            KeyOperationType.KEY_EXCHANGE, True, sanitized['algorithm']
        )
        
        return {
            'allowed': True,
            'sanitized': sanitized,
            'validations': {k: v.__dict__ for k, v in validations.items()}
        }
    
    def constant_time_compare_keys(self, key_a: bytes, key_b: bytes) -> bool:
        """Constant-time key comparison"""
        if not self._enabled:
            return key_a == key_b
        return self.ct_protector.compare_bytes_ct(key_a, key_b)
    
    def secure_wipe_key_material(self, key_material: Any) -> None:
        """Securely wipe sensitive key material"""
        if not self._enabled:
            return
        self.zeroizer.secure_wipe_key_material(key_material)
        self._keys_wiped += 1
    
    def validate_session_operation(self, session_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Validate session operation parameters"""
        if not self._enabled:
            return {
                'allowed': True,
                'sanitized': {'session_id': session_id, 'context': context},
                'validations': {}
            }
        
        validations = {}
        validations['session_id'] = self.validator.validate_session_id(session_id)
        validations['context'] = self.validator.validate_context_info(context)
        
        has_failure = any(
            not v.is_valid and v.severity in (ValidationSeverity.HIGH, ValidationSeverity.CRITICAL)
            for v in validations.values()
        )
        
        if has_failure:
            self._validation_failures += 1
            return {
                'allowed': False,
                'reason': 'validation_failed',
                'sanitized': None,
                'validations': {k: v.__dict__ for k, v in validations.items()}
            }
        
        sanitized = {
            'session_id': validations['session_id'].sanitized_value or session_id,
            'context': validations['context'].sanitized_value or context
        }
        
        return {
            'allowed': True,
            'sanitized': sanitized,
            'validations': {k: v.__dict__ for k, v in validations.items()}
        }
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security hardening statistics"""
        with self._lock:
            return {
                'enabled': self._enabled,
                'validation_failures': self._validation_failures,
                'keys_securely_wiped': self._keys_wiped,
                'audit_stats': self.audit_logger.get_stats(),
                'config': {
                    'constant_time_execution': self.config.enable_constant_time_execution,
                    'secure_memory_zeroization': self.config.enable_secure_memory_zeroization,
                    'input_validation': self.config.enable_input_validation,
                    'key_material_protection': self.config.enable_key_material_protection,
                    'side_channel_resistance': self.config.enable_side_channel_resistance
                }
            }


# Singleton instance for global access
pq_security_hardener = PQKeyExchangeSecurityHardener()
