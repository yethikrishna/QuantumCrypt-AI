"""
Cryptography Error Resilience: Enhanced Exception Hierarchy
Dimension E - Error Resilience
Stability: BETA
Last Updated: June 24, 2026

Cryptography-specific custom exception hierarchy providing:
- Granular exception types for cryptographic failure modes
- Security-sensitive error handling (no leaky error messages)
- Constant-time exception handling
- Side-channel resistant error reporting
"""

from typing import Optional, Dict, Any, List
from enum import Enum
import uuid
import hmac
import hashlib


class CryptoErrorSeverity(Enum):
    """Severity levels for cryptographic errors."""
    WARNING = 1
    ERROR = 2
    CRITICAL = 3
    FATAL = 4


class CryptoErrorCategory(Enum):
    """Categories for cryptographic error classification."""
    KEY_ERROR = "key_error"
    ENCRYPTION_ERROR = "encryption_error"
    DECRYPTION_ERROR = "decryption_error"
    SIGNATURE_ERROR = "signature_error"
    VERIFICATION_ERROR = "verification_error"
    KEY_DERIVATION_ERROR = "key_derivation_error"
    RANDOMNESS_ERROR = "randomness_error"
    INTEGRITY_ERROR = "integrity_error"
    AUTHENTICATION_ERROR = "authentication_error"
    TIMING_ERROR = "timing_error"
    SIDE_CHANNEL_RISK = "side_channel_risk"
    CONFIGURATION_ERROR = "configuration_error"
    VALIDATION_ERROR = "validation_error"


class QuantumCryptBaseException(Exception):
    """
    Base exception for all QuantumCrypt-AI exceptions.
    
    Security features:
    - No sensitive data in error messages
    - Constant-time string representation
    - Unique error ID for auditing
    - Security classification metadata
    """
    
    def __init__(
        self,
        message: str,
        error_code: str = "QC_ERR_001",
        severity: CryptoErrorSeverity = CryptoErrorSeverity.ERROR,
        category: CryptoErrorCategory = CryptoErrorCategory.ENCRYPTION_ERROR,
        context: Optional[Dict[str, Any]] = None,
        retryable: bool = False,
        sensitive: bool = True
    ):
        super().__init__(message)
        self.error_id = str(uuid.uuid4())
        self.error_code = error_code
        self._message = message
        self.severity = severity
        self.category = category
        self._context = context or {}
        self.retryable = retryable
        self.sensitive = sensitive
        self._timestamp = uuid.uuid1().time
        
    @property
    def context(self) -> Dict[str, Any]:
        """Get context (read-only for test compatibility)."""
        return self._context.copy()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to safe dictionary for logging (no sensitive data)."""
        return {
            "error_id": self.error_id,
            "error_code": self.error_code,
            "severity": self.severity.name,
            "category": self.category.value,
            "retryable": self.retryable,
            "sensitive": self.sensitive
        }
    
    def __str__(self) -> str:
        """Constant-time string representation (no timing leak)."""
        return f"[{self.error_code}] Cryptographic operation failed (ID: {self.error_id})"
        
    def __repr__(self) -> str:
        return f"QuantumCryptException({self.error_code}, {self.category.value})"


# =============================================================================
# Key Management Exceptions
# =============================================================================

class KeyError(QuantumCryptBaseException):
    """Raised for key-related failures."""
    
    def __init__(
        self,
        message: str = "Key operation failed",
        key_type: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        if key_type:
            ctx["key_type"] = key_type
            
        super().__init__(
            message=message,
            error_code="QC_KEY_001",
            severity=CryptoErrorSeverity.CRITICAL,
            category=CryptoErrorCategory.KEY_ERROR,
            context=ctx,
            retryable=False,
            sensitive=True
        )


class KeyGenerationError(KeyError):
    """Raised when key generation fails."""
    
    def __init__(
        self,
        algorithm: str,
        message: str = "Key generation failed",
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["algorithm"] = algorithm
        
        super().__init__(
            message=f"Key generation failed for {algorithm}",
            key_type=algorithm,
            context=ctx
        )
        self.error_code = "QC_KEY_002"


class KeyImportError(KeyError):
    """Raised when key import fails."""
    
    def __init__(
        self,
        reason: str = "invalid format",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Key import failed: {reason}",
            context=context
        )
        self.error_code = "QC_KEY_003"


class KeyExpiredError(KeyError):
    """Raised when key has expired."""
    
    def __init__(
        self,
        key_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message="Key has expired",
            context=context
        )
        self.error_code = "QC_KEY_004"
        self.retryable = False


class WeakKeyError(KeyError):
    """Raised when weak key is detected."""
    
    def __init__(
        self,
        weakness_type: str,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["weakness_type"] = weakness_type
        
        super().__init__(
            message=f"Weak key detected: {weakness_type}",
            context=ctx
        )
        self.error_code = "QC_KEY_005"
        self.severity = CryptoErrorSeverity.CRITICAL


# =============================================================================
# Encryption/Decryption Exceptions
# =============================================================================

class EncryptionError(QuantumCryptBaseException):
    """Raised when encryption fails."""
    
    def __init__(
        self,
        algorithm: Optional[str] = None,
        message: str = "Encryption failed",
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        if algorithm:
            ctx["algorithm"] = algorithm
            
        super().__init__(
            message=message,
            error_code="QC_ENC_001",
            severity=CryptoErrorSeverity.ERROR,
            category=CryptoErrorCategory.ENCRYPTION_ERROR,
            context=ctx,
            retryable=True,
            sensitive=True
        )


class DecryptionError(QuantumCryptBaseException):
    """Raised when decryption fails."""
    
    def __init__(
        self,
        algorithm: Optional[str] = None,
        message: str = "Decryption failed",
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        if algorithm:
            ctx["algorithm"] = algorithm
            
        super().__init__(
            message=message,
            error_code="QC_DEC_001",
            severity=CryptoErrorSeverity.ERROR,
            category=CryptoErrorCategory.DECRYPTION_ERROR,
            context=ctx,
            retryable=False,
            sensitive=True
        )


class AuthenticationFailedError(DecryptionError):
    """Raised when message authentication fails."""
    
    def __init__(
        self,
        message: str = "Message authentication failed - data may be tampered",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            context=context
        )
        self.error_code = "QC_DEC_002"
        self.severity = CryptoErrorSeverity.CRITICAL
        self.category = CryptoErrorCategory.AUTHENTICATION_ERROR


class IntegrityCheckFailedError(DecryptionError):
    """Raised when integrity check fails."""
    
    def __init__(
        self,
        message: str = "Integrity check failed - data corrupted or tampered",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            context=context
        )
        self.error_code = "QC_DEC_003"
        self.severity = CryptoErrorSeverity.CRITICAL
        self.category = CryptoErrorCategory.INTEGRITY_ERROR


class PaddingError(DecryptionError):
    """Raised when padding validation fails."""
    
    def __init__(
        self,
        message: str = "Invalid padding",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            context=context
        )
        self.error_code = "QC_DEC_004"
        self.category = CryptoErrorCategory.DECRYPTION_ERROR


# =============================================================================
# Signature & Verification Exceptions
# =============================================================================

class SignatureError(QuantumCryptBaseException):
    """Raised for signature-related failures."""
    
    def __init__(
        self,
        message: str = "Signature operation failed",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            error_code="QC_SIG_001",
            severity=CryptoErrorSeverity.ERROR,
            category=CryptoErrorCategory.SIGNATURE_ERROR,
            context=context,
            retryable=False,
            sensitive=True
        )


class SignatureVerificationFailedError(SignatureError):
    """Raised when signature verification fails."""
    
    def __init__(
        self,
        message: str = "Signature verification failed",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            context=context
        )
        self.error_code = "QC_SIG_002"
        self.severity = CryptoErrorSeverity.CRITICAL
        self.category = CryptoErrorCategory.VERIFICATION_ERROR


# =============================================================================
# Randomness & Entropy Exceptions
# =============================================================================

class RandomnessError(QuantumCryptBaseException):
    """Raised for random number generation failures."""
    
    def __init__(
        self,
        message: str = "Random number generation failed",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            error_code="QC_RND_001",
            severity=CryptoErrorSeverity.CRITICAL,
            category=CryptoErrorCategory.RANDOMNESS_ERROR,
            context=context,
            retryable=True,
            sensitive=True
        )


class InsufficientEntropyError(RandomnessError):
    """Raised when entropy is insufficient."""
    
    def __init__(
        self,
        available: float,
        required: float,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["available_entropy"] = available
        ctx["required_entropy"] = required
        
        super().__init__(
            message=f"Insufficient entropy: {available:.1f} bits available, {required:.1f} required",
            context=ctx
        )
        self.error_code = "QC_RND_002"


# =============================================================================
# Side-Channel & Timing Exceptions
# =============================================================================

class SideChannelRiskError(QuantumCryptBaseException):
    """Raised when side-channel vulnerability is detected."""
    
    def __init__(
        self,
        risk_type: str,
        message: str = "Side-channel vulnerability detected",
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["risk_type"] = risk_type
        
        super().__init__(
            message=f"{message}: {risk_type}",
            error_code="QC_SC_001",
            severity=CryptoErrorSeverity.WARNING,
            category=CryptoErrorCategory.SIDE_CHANNEL_RISK,
            context=ctx,
            retryable=False,
            sensitive=False
        )


class TimingAttackDetectedError(SideChannelRiskError):
    """Raised when timing attack pattern is detected."""
    
    def __init__(
        self,
        deviation: float,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["timing_deviation"] = deviation
        
        super().__init__(
            risk_type="timing_attack",
            message=f"Timing anomaly detected (deviation: {deviation:.3f}s)",
            context=ctx
        )
        self.error_code = "QC_SC_002"
        self.severity = CryptoErrorSeverity.CRITICAL


# =============================================================================
# Key Derivation Exceptions
# =============================================================================

class KeyDerivationError(QuantumCryptBaseException):
    """Raised when key derivation fails."""
    
    def __init__(
        self,
        kdf: str,
        message: str = "Key derivation failed",
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["kdf_algorithm"] = kdf
        
        super().__init__(
            message=f"{message} using {kdf}",
            error_code="QC_KDF_001",
            severity=CryptoErrorSeverity.ERROR,
            category=CryptoErrorCategory.KEY_DERIVATION_ERROR,
            context=ctx,
            retryable=False,
            sensitive=True
        )


# =============================================================================
# Validation & Configuration Exceptions
# =============================================================================

class CryptoValidationError(QuantumCryptBaseException):
    """Raised when cryptographic validation fails."""
    
    def __init__(
        self,
        message: str = "Cryptographic validation failed",
        field: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        if field:
            ctx["field"] = field
            
        super().__init__(
            message=message,
            error_code="QC_VAL_001",
            severity=CryptoErrorSeverity.ERROR,
            category=CryptoErrorCategory.VALIDATION_ERROR,
            context=ctx,
            retryable=False,
            sensitive=False
        )


class CryptoConfigurationError(QuantumCryptBaseException):
    """Raised for invalid cryptographic configuration."""
    
    def __init__(
        self,
        message: str = "Invalid cryptographic configuration",
        parameter: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        if parameter:
            ctx["parameter"] = parameter
            
        super().__init__(
            message=message,
            error_code="QC_CFG_001",
            severity=CryptoErrorSeverity.ERROR,
            category=CryptoErrorCategory.CONFIGURATION_ERROR,
            context=ctx,
            retryable=False,
            sensitive=False
        )


class InsecureConfigurationError(CryptoConfigurationError):
    """Raised when insecure configuration is detected."""
    
    def __init__(
        self,
        issue: str,
        recommendation: str,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["recommendation"] = recommendation
        
        super().__init__(
            message=f"Insecure configuration: {issue}",
            context=ctx
        )
        self.error_code = "QC_CFG_002"
        self.severity = CryptoErrorSeverity.WARNING


# =============================================================================
# Secure Error Comparison
# =============================================================================

def constant_time_error_compare(a: QuantumCryptBaseException, b: QuantumCryptBaseException) -> bool:
    """
    Compare two error objects in constant time.
    
    Prevents timing attacks based on error comparison.
    """
    a_bytes = a.error_id.encode('utf-8')
    b_bytes = b.error_id.encode('utf-8')
    
    # Use HMAC compare for constant-time
    return hmac.compare_digest(a_bytes, b_bytes)


def secure_error_hash(error: QuantumCryptBaseException) -> str:
    """Generate a secure hash of error for auditing."""
    data = f"{error.error_code}:{error.error_id}".encode('utf-8')
    return hashlib.sha256(data).hexdigest()
