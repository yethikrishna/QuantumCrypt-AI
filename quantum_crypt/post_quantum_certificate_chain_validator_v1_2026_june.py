"""
QuantumCrypt AI - Post-Quantum Certificate Chain Validator v1.0.0
Dimension A - Feature Expansion (2026 June)

ADD-ONLY IMPLEMENTATION: No existing code modified
This module provides X.509 certificate chain validation with
post-quantum algorithm support and hybrid validation modes.

API Stability: STABLE
"""

from __future__ import annotations

import enum
import hashlib
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from collections import deque


class CertificateAlgorithm(enum.Enum):
    """Certificate signature algorithms including post-quantum."""
    # Classical algorithms
    RSA_2048 = "rsa_2048"
    RSA_4096 = "rsa_4096"
    ECDSA_P256 = "ecdsa_p256"
    ECDSA_P384 = "ecdsa_p384"
    ED25519 = "ed25519"
    
    # Post-quantum algorithms (NIST selected)
    DILITHIUM_2 = "dilithium_2"
    DILITHIUM_3 = "dilithium_3"
    DILITHIUM_5 = "dilithium_5"
    FALCON_512 = "falcon_512"
    FALCON_1024 = "falcon_1024"
    SPHINCS_PLUS_128 = "sphincs_plus_128"
    SPHINCS_PLUS_192 = "sphincs_plus_192"
    SPHINCS_PLUS_256 = "sphincs_plus_256"
    
    # Hybrid (classical + post-quantum)
    HYBRID_RSA_DILITHIUM_3 = "hybrid_rsa_dilithium_3"
    HYBRID_ECDSA_FALCON_512 = "hybrid_ecdsa_falcon_512"


class ValidationMode(enum.Enum):
    """Certificate chain validation modes."""
    CLASSICAL_ONLY = "classical_only"
    POST_QUANTUM_ONLY = "post_quantum_only"
    HYBRID_BOTH_REQUIRED = "hybrid_both_required"
    HYBRID_EITHER_ACCEPTED = "hybrid_either_accepted"
    MIXED_FALLBACK = "mixed_fallback"


class ValidationStatus(enum.Enum):
    """Certificate validation status."""
    VALID = "valid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    REVOKED = "revoked"
    UNTRUSTED_ROOT = "untrusted_root"
    SIGNATURE_INVALID = "signature_invalid"
    CHAIN_BROKEN = "chain_broken"
    WEAK_ALGORITHM = "weak_algorithm"
    NAME_MISMATCH = "name_mismatch"
    POLICY_VIOLATION = "policy_violation"
    UNKNOWN_ERROR = "unknown_error"


class RevocationStatus(enum.Enum):
    """Certificate revocation status."""
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class SecurityLevel(enum.IntEnum):
    """NIST security levels for post-quantum algorithms."""
    LEVEL_1 = 1  # 128-bit security
    LEVEL_2 = 2
    LEVEL_3 = 3  # 192-bit security
    LEVEL_4 = 4
    LEVEL_5 = 5  # 256-bit security


@dataclass
class Certificate:
    """Simplified certificate representation for validation."""
    cert_id: str
    subject: str
    issuer: str
    public_key: bytes
    signature: bytes
    algorithm: CertificateAlgorithm
    serial_number: str
    valid_from: datetime
    valid_to: datetime
    fingerprint: str = ""
    is_ca: bool = False
    is_root: bool = False
    revocation_info: Optional[str] = None
    subject_alt_names: List[str] = field(default_factory=list)
    key_usage: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Generate fingerprint if not provided."""
        if not self.fingerprint:
            data = f"{self.subject}{self.issuer}{self.serial_number}".encode()
            self.fingerprint = hashlib.sha256(data).hexdigest()


@dataclass
class ValidationPolicy:
    """Policy controlling certificate validation behavior."""
    policy_id: str = field(default_factory=lambda: "default_policy")
    name: str = "Default Validation Policy"
    validation_mode: ValidationMode = ValidationMode.HYBRID_EITHER_ACCEPTED
    minimum_security_level: SecurityLevel = SecurityLevel.LEVEL_1
    reject_weak_algorithms: bool = True
    require_revocation_check: bool = True
    allow_expired: bool = False
    allow_not_yet_valid: bool = False
    max_chain_length: int = 10
    accepted_algorithms: Set[CertificateAlgorithm] = field(default_factory=set)
    trusted_roots: Set[str] = field(default_factory=set)
    required_key_usage: Set[str] = field(default_factory=set)
    maximum_validity_days: Optional[int] = None

    def __post_init__(self) -> None:
        """Set default accepted algorithms if empty."""
        if not self.accepted_algorithms:
            self.accepted_algorithms = {
                CertificateAlgorithm.RSA_4096,
                CertificateAlgorithm.ECDSA_P384,
                CertificateAlgorithm.ED25519,
                CertificateAlgorithm.DILITHIUM_3,
                CertificateAlgorithm.DILITHIUM_5,
                CertificateAlgorithm.FALCON_512,
                CertificateAlgorithm.FALCON_1024,
                CertificateAlgorithm.HYBRID_RSA_DILITHIUM_3,
            }


@dataclass
class ValidationResult:
    """Result of certificate chain validation."""
    overall_status: ValidationStatus
    certificate_results: List[Tuple[Certificate, ValidationStatus, List[str]]]
    validation_time: datetime = field(default_factory=datetime.now)
    policy_applied: Optional[ValidationPolicy] = None
    chain_length: int = 0
    strongest_algorithm: Optional[CertificateAlgorithm] = None
    weakest_algorithm: Optional[CertificateAlgorithm] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    validation_duration_ms: float = 0.0


@dataclass
class TrustAnchor:
    """Trusted root certificate anchor."""
    certificate: Certificate
    added_at: datetime = field(default_factory=datetime.now)
    trusted_by: str = "system"
    comment: str = ""


class AlgorithmRegistry:
    """Registry for algorithm properties and security levels."""
    
    ALGORITHM_PROPERTIES: Dict[CertificateAlgorithm, Dict[str, Any]] = {
        # Classical
        CertificateAlgorithm.RSA_2048: {
            "security_level": SecurityLevel.LEVEL_1,
            "is_post_quantum": False,
            "is_weak": True,
            "nist_approved": True,
        },
        CertificateAlgorithm.RSA_4096: {
            "security_level": SecurityLevel.LEVEL_3,
            "is_post_quantum": False,
            "is_weak": False,
            "nist_approved": True,
        },
        CertificateAlgorithm.ECDSA_P256: {
            "security_level": SecurityLevel.LEVEL_1,
            "is_post_quantum": False,
            "is_weak": False,
            "nist_approved": True,
        },
        CertificateAlgorithm.ECDSA_P384: {
            "security_level": SecurityLevel.LEVEL_3,
            "is_post_quantum": False,
            "is_weak": False,
            "nist_approved": True,
        },
        CertificateAlgorithm.ED25519: {
            "security_level": SecurityLevel.LEVEL_3,
            "is_post_quantum": False,
            "is_weak": False,
            "nist_approved": True,
        },
        # Post-quantum
        CertificateAlgorithm.DILITHIUM_2: {
            "security_level": SecurityLevel.LEVEL_2,
            "is_post_quantum": True,
            "is_weak": False,
            "nist_approved": True,
        },
        CertificateAlgorithm.DILITHIUM_3: {
            "security_level": SecurityLevel.LEVEL_3,
            "is_post_quantum": True,
            "is_weak": False,
            "nist_approved": True,
        },
        CertificateAlgorithm.DILITHIUM_5: {
            "security_level": SecurityLevel.LEVEL_5,
            "is_post_quantum": True,
            "is_weak": False,
            "nist_approved": True,
        },
        CertificateAlgorithm.FALCON_512: {
            "security_level": SecurityLevel.LEVEL_1,
            "is_post_quantum": True,
            "is_weak": False,
            "nist_approved": True,
        },
        CertificateAlgorithm.FALCON_1024: {
            "security_level": SecurityLevel.LEVEL_5,
            "is_post_quantum": True,
            "is_weak": False,
            "nist_approved": True,
        },
        CertificateAlgorithm.SPHINCS_PLUS_128: {
            "security_level": SecurityLevel.LEVEL_1,
            "is_post_quantum": True,
            "is_weak": False,
            "nist_approved": True,
        },
        CertificateAlgorithm.SPHINCS_PLUS_192: {
            "security_level": SecurityLevel.LEVEL_3,
            "is_post_quantum": True,
            "is_weak": False,
            "nist_approved": True,
        },
        CertificateAlgorithm.SPHINCS_PLUS_256: {
            "security_level": SecurityLevel.LEVEL_5,
            "is_post_quantum": True,
            "is_weak": False,
            "nist_approved": True,
        },
        # Hybrid
        CertificateAlgorithm.HYBRID_RSA_DILITHIUM_3: {
            "security_level": SecurityLevel.LEVEL_3,
            "is_post_quantum": True,
            "is_weak": False,
            "nist_approved": True,
            "is_hybrid": True,
        },
        CertificateAlgorithm.HYBRID_ECDSA_FALCON_512: {
            "security_level": SecurityLevel.LEVEL_3,
            "is_post_quantum": True,
            "is_weak": False,
            "nist_approved": True,
            "is_hybrid": True,
        },
    }

    @classmethod
    def get_security_level(cls, algorithm: CertificateAlgorithm) -> SecurityLevel:
        """Get security level for an algorithm."""
        props = cls.ALGORITHM_PROPERTIES.get(algorithm, {})
        return props.get("security_level", SecurityLevel.LEVEL_1)

    @classmethod
    def is_post_quantum(cls, algorithm: CertificateAlgorithm) -> bool:
        """Check if algorithm is post-quantum."""
        props = cls.ALGORITHM_PROPERTIES.get(algorithm, {})
        return props.get("is_post_quantum", False)

    @classmethod
    def is_weak(cls, algorithm: CertificateAlgorithm) -> bool:
        """Check if algorithm is considered weak."""
        props = cls.ALGORITHM_PROPERTIES.get(algorithm, {})
        return props.get("is_weak", True)

    @classmethod
    def is_hybrid(cls, algorithm: CertificateAlgorithm) -> bool:
        """Check if algorithm is hybrid classical + post-quantum."""
        props = cls.ALGORITHM_PROPERTIES.get(algorithm, {})
        return props.get("is_hybrid", False)


class RevocationChecker:
    """Certificate revocation checking with caching support."""

    def __init__(self, cache_ttl_seconds: int = 3600) -> None:
        self._cache: Dict[str, Tuple[RevocationStatus, float]] = {}
        self._cache_ttl = cache_ttl_seconds
        self._lock = threading.Lock()
        self._revoked_serials: Set[str] = set()

    def add_revoked_serial(self, serial_number: str) -> None:
        """Add a serial number to the revoked list."""
        with self._lock:
            self._revoked_serials.add(serial_number)

    def check_revocation(self, certificate: Certificate) -> RevocationStatus:
        """Check if a certificate is revoked."""
        cache_key = certificate.fingerprint
        
        with self._lock:
            # Check cache first
            if cache_key in self._cache:
                status, timestamp = self._cache[cache_key]
                if time.time() - timestamp < self._cache_ttl:
                    return status

            # Check explicit revocation list
            if certificate.serial_number in self._revoked_serials:
                status = RevocationStatus.REVOKED
            else:
                status = RevocationStatus.GOOD

            # Cache result
            self._cache[cache_key] = (status, time.time())
            return status

    def clear_cache(self) -> None:
        """Clear revocation cache."""
        with self._lock:
            self._cache.clear()


class SignatureVerifier:
    """Certificate signature verification framework."""

    def __init__(self) -> None:
        self._verifiers: Dict[CertificateAlgorithm, Callable] = {}
        self._lock = threading.Lock()
        self._register_default_verifiers()

    def _register_default_verifiers(self) -> None:
        """Register default (simulated) verifiers."""
        for alg in CertificateAlgorithm:
            self._verifiers[alg] = self._default_verifier

    def _default_verifier(
        self,
        public_key: bytes,
        signature: bytes,
        message: bytes
    ) -> Tuple[bool, Optional[str]]:
        """Default simulated signature verification."""
        # In production, this would use actual crypto libraries
        # For this framework, we simulate successful verification
        # based on basic sanity checks
        if not signature or len(signature) < 16:
            return False, "Signature too short"
        if not public_key or len(public_key) < 16:
            return False, "Public key too short"
        return True, None

    def register_verifier(
        self,
        algorithm: CertificateAlgorithm,
        verifier: Callable[[bytes, bytes, bytes], Tuple[bool, Optional[str]]]
    ) -> None:
        """Register a custom signature verifier."""
        with self._lock:
            self._verifiers[algorithm] = verifier

    def verify(
        self,
        certificate: Certificate,
        issuer_public_key: bytes,
        message: Optional[bytes] = None
    ) -> Tuple[bool, Optional[str]]:
        """Verify a certificate's signature."""
        if message is None:
            message = f"{certificate.subject}{certificate.serial_number}".encode()

        verifier = self._verifiers.get(certificate.algorithm, self._default_verifier)
        
        try:
            return verifier(issuer_public_key, certificate.signature, message)
        except Exception as e:
            return False, f"Verification error: {str(e)}"


class TrustStore:
    """Trusted root certificate store."""

    def __init__(self) -> None:
        self._anchors: Dict[str, TrustAnchor] = {}
        self._lock = threading.Lock()
        self._add_default_anchors()

    def _add_default_anchors(self) -> None:
        """Add default trusted root certificates."""
        # Add simulated PQ root CA
        pq_root = Certificate(
            cert_id="pq_root_ca_001",
            subject="CN=Post-Quantum Root CA, O=QuantumCrypt, C=US",
            issuer="CN=Post-Quantum Root CA, O=QuantumCrypt, C=US",
            public_key=b"pq_root_public_key_dilithium5_placeholder",
            signature=b"self_signed_signature_placeholder",
            algorithm=CertificateAlgorithm.DILITHIUM_5,
            serial_number="PQROOT001",
            valid_from=datetime.now() - timedelta(days=1),
            valid_to=datetime.now() + timedelta(days=3650),
            is_ca=True,
            is_root=True
        )
        self.add_trust_anchor(pq_root, "Default PQ Root CA")

        # Add hybrid root CA
        hybrid_root = Certificate(
            cert_id="hybrid_root_ca_001",
            subject="CN=Hybrid Root CA, O=QuantumCrypt, C=US",
            issuer="CN=Hybrid Root CA, O=QuantumCrypt, C=US",
            public_key=b"hybrid_root_public_key_placeholder",
            signature=b"self_signed_signature_placeholder",
            algorithm=CertificateAlgorithm.HYBRID_RSA_DILITHIUM_3,
            serial_number="HYBRIDROOT001",
            valid_from=datetime.now() - timedelta(days=1),
            valid_to=datetime.now() + timedelta(days=3650),
            is_ca=True,
            is_root=True
        )
        self.add_trust_anchor(hybrid_root, "Default Hybrid Root CA")

    def add_trust_anchor(self, certificate: Certificate, comment: str = "") -> str:
        """Add a trusted root certificate."""
        with self._lock:
            anchor = TrustAnchor(certificate=certificate, comment=comment)
            self._anchors[certificate.fingerprint] = anchor
            return certificate.fingerprint

    def remove_trust_anchor(self, fingerprint: str) -> bool:
        """Remove a trust anchor by fingerprint."""
        with self._lock:
            return self._anchors.pop(fingerprint, None) is not None

    def is_trusted_root(self, certificate: Certificate) -> bool:
        """Check if certificate is a trusted root."""
        return certificate.fingerprint in self._anchors

    def get_trust_anchor(self, fingerprint: str) -> Optional[TrustAnchor]:
        """Get a trust anchor by fingerprint."""
        return self._anchors.get(fingerprint)

    def get_all_anchors(self) -> List[TrustAnchor]:
        """Get all trust anchors."""
        return list(self._anchors.values())


class CertificateChainValidator:
    """
    Main certificate chain validator with post-quantum support.
    
    Validates certificate chains according to configurable policies,
    with full support for post-quantum and hybrid algorithms.
    """

    def __init__(self) -> None:
        self._trust_store = TrustStore()
        self._revocation_checker = RevocationChecker()
        self._signature_verifier = SignatureVerifier()
        self._default_policy = ValidationPolicy()
        self._validation_cache: deque[ValidationResult] = deque(maxlen=1000)
        self._lock = threading.Lock()

    @property
    def trust_store(self) -> TrustStore:
        """Access the trust store."""
        return self._trust_store

    @property
    def revocation_checker(self) -> RevocationChecker:
        """Access the revocation checker."""
        return self._revocation_checker

    @property
    def signature_verifier(self) -> SignatureVerifier:
        """Access the signature verifier."""
        return self._signature_verifier

    def validate_chain(
        self,
        chain: List[Certificate],
        policy: Optional[ValidationPolicy] = None,
        hostname: Optional[str] = None
    ) -> ValidationResult:
        """
        Validate a complete certificate chain.
        
        Args:
            chain: List of certificates from leaf to root
            policy: Validation policy to apply
            hostname: Optional hostname for name verification
            
        Returns:
            ValidationResult with complete validation details
        """
        start_time = time.time()
        policy = policy or self._default_policy

        errors: List[str] = []
        warnings: List[str] = []
        cert_results: List[Tuple[Certificate, ValidationStatus, List[str]]] = []

        if not chain:
            return ValidationResult(
                overall_status=ValidationStatus.CHAIN_BROKEN,
                certificate_results=[],
                errors=["Empty certificate chain"],
                chain_length=0
            )

        if len(chain) > policy.max_chain_length:
            errors.append(f"Chain length {len(chain)} exceeds maximum {policy.max_chain_length}")

        # Track algorithm strength
        algorithms = [cert.algorithm for cert in chain]
        strongest = max(algorithms, key=lambda a: AlgorithmRegistry.get_security_level(a))
        weakest = min(algorithms, key=lambda a: AlgorithmRegistry.get_security_level(a))

        # Validate each certificate in chain
        overall_status = ValidationStatus.VALID

        for i, cert in enumerate(chain):
            cert_status, cert_errors = self._validate_single_certificate(
                cert, chain, i, policy, hostname
            )
            cert_results.append((cert, cert_status, cert_errors))

            if cert_status != ValidationStatus.VALID:
                errors.extend(cert_errors)
                if overall_status == ValidationStatus.VALID:
                    overall_status = cert_status

        # Check that chain properly links to trusted root
        last_cert = chain[-1]
        if not last_cert.is_root and not self._trust_store.is_trusted_root(last_cert):
            if overall_status == ValidationStatus.VALID:
                overall_status = ValidationStatus.UNTRUSTED_ROOT
            errors.append(f"Root certificate '{last_cert.subject}' is not trusted")

        duration_ms = (time.time() - start_time) * 1000

        result = ValidationResult(
            overall_status=overall_status,
            certificate_results=cert_results,
            policy_applied=policy,
            chain_length=len(chain),
            strongest_algorithm=strongest,
            weakest_algorithm=weakest,
            errors=errors,
            warnings=warnings,
            validation_duration_ms=duration_ms
        )

        with self._lock:
            self._validation_cache.append(result)

        return result

    def _validate_single_certificate(
        self,
        cert: Certificate,
        chain: List[Certificate],
        index: int,
        policy: ValidationPolicy,
        hostname: Optional[str]
    ) -> Tuple[ValidationStatus, List[str]]:
        """Validate a single certificate within the chain."""
        errors: List[str] = []
        now = datetime.now()

        # 1. Validity period check
        if now < cert.valid_from:
            if not policy.allow_not_yet_valid:
                errors.append(f"Certificate not valid until {cert.valid_from}")
                return ValidationStatus.NOT_YET_VALID, errors
            else:
                errors.append(f"WARNING: Certificate not yet valid (allowed by policy)")

        if now > cert.valid_to:
            if not policy.allow_expired:
                errors.append(f"Certificate expired on {cert.valid_to}")
                return ValidationStatus.EXPIRED, errors
            else:
                errors.append(f"WARNING: Certificate expired (allowed by policy)")

        # 2. Validity duration check
        validity_days = (cert.valid_to - cert.valid_from).days
        if policy.maximum_validity_days and validity_days > policy.maximum_validity_days:
            errors.append(f"Validity period {validity_days} days exceeds policy limit {policy.maximum_validity_days}")
            return ValidationStatus.POLICY_VIOLATION, errors

        # 3. Algorithm validation
        if policy.reject_weak_algorithms and AlgorithmRegistry.is_weak(cert.algorithm):
            errors.append(f"Weak algorithm {cert.algorithm.value} rejected by policy")
            return ValidationStatus.WEAK_ALGORITHM, errors

        if cert.algorithm not in policy.accepted_algorithms:
            errors.append(f"Algorithm {cert.algorithm.value} not in accepted list")
            return ValidationStatus.WEAK_ALGORITHM, errors

        # 4. Security level check
        sec_level = AlgorithmRegistry.get_security_level(cert.algorithm)
        if sec_level < policy.minimum_security_level:
            errors.append(f"Security level {sec_level.value} below minimum {policy.minimum_security_level.value}")
            return ValidationStatus.POLICY_VIOLATION, errors

        # 5. Validation mode enforcement
        mode_errors = self._check_validation_mode(cert, policy)
        if mode_errors:
            errors.extend(mode_errors)
            return ValidationStatus.POLICY_VIOLATION, errors

        # 6. Revocation check
        if policy.require_revocation_check and not cert.is_root:
            rev_status = self._revocation_checker.check_revocation(cert)
            if rev_status == RevocationStatus.REVOKED:
                errors.append("Certificate has been revoked")
                return ValidationStatus.REVOKED, errors

        # 7. Signature verification (unless self-signed root)
        if not cert.is_root and index < len(chain) - 1:
            issuer = chain[index + 1]
            sig_valid, sig_error = self._signature_verifier.verify(cert, issuer.public_key)
            if not sig_valid:
                errors.append(f"Signature invalid: {sig_error}")
                return ValidationStatus.SIGNATURE_INVALID, errors

        # 8. Hostname verification for leaf
        if index == 0 and hostname:
            if not self._verify_hostname(cert, hostname):
                errors.append(f"Hostname {hostname} does not match certificate")
                return ValidationStatus.NAME_MISMATCH, errors

        # 9. Key usage check
        if policy.required_key_usage:
            missing = policy.required_key_usage - cert.key_usage
            if missing:
                errors.append(f"Missing required key usage: {missing}")
                return ValidationStatus.POLICY_VIOLATION, errors

        return ValidationStatus.VALID, errors

    def _check_validation_mode(
        self,
        cert: Certificate,
        policy: ValidationPolicy
    ) -> List[str]:
        """Check that certificate satisfies the validation mode."""
        errors: List[str] = []
        is_pq = AlgorithmRegistry.is_post_quantum(cert.algorithm)
        is_hybrid = AlgorithmRegistry.is_hybrid(cert.algorithm)

        if policy.validation_mode == ValidationMode.CLASSICAL_ONLY:
            if is_pq and not is_hybrid:
                errors.append("Post-quantum certificates rejected by classical-only mode")

        elif policy.validation_mode == ValidationMode.POST_QUANTUM_ONLY:
            if not is_pq:
                errors.append("Classical certificates rejected by post-quantum-only mode")

        elif policy.validation_mode == ValidationMode.HYBRID_BOTH_REQUIRED:
            if not is_hybrid:
                errors.append("Non-hybrid certificate in hybrid-required mode")

        return errors

    def _verify_hostname(self, cert: Certificate, hostname: str) -> bool:
        """Verify hostname matches certificate subject or SAN."""
        # Simple wildcard matching
        def matches(pattern: str, name: str) -> bool:
            if pattern.startswith("*."):
                suffix = pattern[1:]  # .example.com
                return name.endswith(suffix) or name == suffix[1:]
            return pattern.lower() == name.lower()

        # Check subject CN
        cn_match = re.search(r"CN=([^,]+)", cert.subject)
        if cn_match and matches(cn_match.group(1), hostname):
            return True

        # Check SANs
        for san in cert.subject_alt_names:
            if matches(san, hostname):
                return True

        return False

    def get_validation_statistics(self) -> Dict[str, Any]:
        """Get validation statistics."""
        with self._lock:
            total = len(self._validation_cache)
            by_status: Dict[str, int] = {}

            for result in self._validation_cache:
                status = result.overall_status.value
                by_status[status] = by_status.get(status, 0) + 1

        return {
            "total_validations": total,
            "by_status": by_status,
            "trusted_roots": len(self._trust_store.get_all_anchors()),
            "default_validation_mode": self._default_policy.validation_mode.value,
        }

    def create_strict_policy(self) -> ValidationPolicy:
        """Create a strict post-quantum-only validation policy."""
        return ValidationPolicy(
            name="Strict Post-Quantum Policy",
            validation_mode=ValidationMode.POST_QUANTUM_ONLY,
            minimum_security_level=SecurityLevel.LEVEL_3,
            reject_weak_algorithms=True,
            require_revocation_check=True,
            max_chain_length=5,
            maximum_validity_days=397,  # Apple limit
        )

    def create_hybrid_policy(self) -> ValidationPolicy:
        """Create a hybrid-friendly validation policy."""
        return ValidationPolicy(
            name="Hybrid Compatibility Policy",
            validation_mode=ValidationMode.HYBRID_EITHER_ACCEPTED,
            minimum_security_level=SecurityLevel.LEVEL_1,
        )


# Global singleton for easy import
_global_validator: Optional[CertificateChainValidator] = None
_global_lock = threading.Lock()


def get_certificate_validator() -> CertificateChainValidator:
    """Get the global certificate validator instance."""
    global _global_validator
    if _global_validator is None:
        with _global_lock:
            if _global_validator is None:
                _global_validator = CertificateChainValidator()
    return _global_validator
