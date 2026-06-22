"""
QuantumCrypt AI - Comprehensive Crypto API Documentation & Stability Catalog v12
================================================================================
STABILITY LEVEL: STABLE
API VERSION: 2026.06.23.v12
DEPRECATION POLICY: 6-month minimum notice period
NIST COMPLIANCE: SP 800-186, SP 800-56C, FIPS 140-3

This module provides a centralized catalog of all QuantumCrypt AI APIs with
comprehensive documentation, usage examples, NIST compliance markers, and
API stability classifications.

MAINTAINER: QuantumCrypt Security Team
CONTACT: security@quantumcrypt.ai
LICENSE: MIT
STANDARD: NIST Post-Quantum Cryptography Standard
"""

from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import datetime


class StabilityLevel(Enum):
    """API Stability Level Classification
    
    STABLE: Production-ready, guaranteed backward compatibility, FIPS-compliant
    BETA: Nearly stable, undergoing NIST certification, minor changes possible
    EXPERIMENTAL: Research-grade, academic implementations, breaking changes likely
    DEPRECATED: Scheduled for removal, migrate to recommended alternatives
    """
    STABLE = "STABLE"
    BETA = "BETA"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"


class NISTComplianceLevel(Enum):
    """NIST Compliance Classification
    
    STANDARDIZED: NIST standardized algorithm (CRYSTALS-Kyber, CRYSTALS-Dilithium)
    CANDIDATE: NIST round 3+ candidate algorithm
    RESEARCH: Research/academic implementation
    LEGACY: Pre-quantum classical algorithm
    """
    STANDARDIZED = "STANDARDIZED"
    CANDIDATE = "CANDIDATE"
    RESEARCH = "RESEARCH"
    LEGACY = "LEGACY"


@dataclass
class CryptoAPIEndpoint:
    """Crypto API Endpoint Metadata
    
    Comprehensive metadata for each cryptographic API endpoint including
    stability, NIST compliance, security levels, and usage examples.
    """
    name: str
    module: str
    function: str
    stability: StabilityLevel
    nist_compliance: NISTComplianceLevel
    version_added: str
    security_level: int = 1  # 1-5 per NIST PQC standards
    version_deprecated: Optional[str] = None
    deprecation_date: Optional[datetime.date] = None
    removal_date: Optional[datetime.date] = None
    description: str = ""
    usage_example: str = ""
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    exceptions: List[str] = field(default_factory=list)
    alternatives: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


class QuantumCryptAPIDocumentationCatalog:
    """
    Comprehensive API Documentation Catalog for QuantumCrypt AI
    
    STABILITY: STABLE
    VERSION: v12
    NIST COMPLIANT: Yes
    
    This catalog provides machine-readable documentation for all post-quantum
    cryptographic APIs. Use this to validate API usage, check stability levels,
    verify NIST compliance, and find alternatives for deprecated endpoints.
    
    USAGE EXAMPLE:
    ```python
    catalog = QuantumCryptAPIDocumentationCatalog()
    
    # Check stability and NIST compliance
    info = catalog.get_endpoint("kyber_kem_engine")
    print(f"Stability: {info.stability.value}")
    print(f"NIST: {info.nist_compliance.value}")
    
    # Get all NIST-standardized algorithms
    nist_apis = catalog.get_endpoints_by_nist_level(NISTComplianceLevel.STANDARDIZED)
    
    # Find deprecated algorithms with migration paths
    deprecated = catalog.get_deprecated_endpoints()
    ```
    """
    
    def __init__(self):
        self._endpoints: Dict[str, CryptoAPIEndpoint] = {}
        self._build_catalog()
    
    def _build_catalog(self) -> None:
        """Build the complete crypto API catalog with all endpoints"""
        
        # =====================================================================
        # KEY ENCAPSULATION MECHANISMS (KEM) - NIST STANDARDIZED
        # =====================================================================
        
        self._endpoints["kyber_kem_engine"] = CryptoAPIEndpoint(
            name="kyber_kem_engine",
            module="quantum_crypt.post_quantum_kyber_kem_engine_2026_june",
            function="generate_kyber_keypair",
            stability=StabilityLevel.STABLE,
            nist_compliance=NISTComplianceLevel.STANDARDIZED,
            version_added="2026.01.15",
            security_level=3,
            description="CRYSTALS-Kyber Key Encapsulation Mechanism - NIST PQC Standard",
            usage_example="""
# Generate Kyber-768 keypair (NIST security level 3)
pk, sk = generate_kyber_keypair(security_level=3)

# Encapsulate shared secret
ciphertext, shared_secret = encapsulate(pk)

# Decapsulate shared secret
recovered_secret = decapsulate(ciphertext, sk)

assert shared_secret == recovered_secret
            """,
            parameters=[
                {"name": "security_level", "type": "int", "description": "NIST security level (1, 3, or 5)"},
                {"name": "deterministic", "type": "bool", "description": "Use deterministic seed (testing only)"}
            ],
            returns="Tuple of (public_key, secret_key) bytes objects",
            exceptions=["ValueError", "SecurityLevelError", "RandomnessError"],
            references=["NIST FIPS 203 (Kyber Standard)", "CRYSTALS-Kyber Specification"],
            tags=["kem", "nist-standard", "kyber", "key-exchange"]
        )
        
        self._endpoints["hybrid_kem_engine"] = CryptoAPIEndpoint(
            name="hybrid_kem_engine",
            module="quantum_crypt.post_quantum_hybrid_kem_engine_2026_june",
            function="generate_hybrid_keypair",
            stability=StabilityLevel.STABLE,
            nist_compliance=NISTComplianceLevel.STANDARDIZED,
            version_added="2026.02.01",
            security_level=3,
            description="Hybrid post-quantum + classical KEM (Kyber + X25519)",
            usage_example="""
# Generate hybrid keypair for transitional deployments
pk, sk = generate_hybrid_keypair(
    classical_alg="x25519",
    pqc_alg="kyber-768"
)

# Hybrid encapsulation provides dual protection
ciphertext, shared_secret = hybrid_encapsulate(pk)
            """,
            parameters=[
                {"name": "classical_alg", "type": "str", "description": "Classical KEM: x25519, x448"},
                {"name": "pqc_alg", "type": "str", "description": "PQC KEM: kyber-512, kyber-768, kyber-1024"}
            ],
            returns="Hybrid keypair tuple",
            exceptions=["ValueError", "AlgorithmNotSupported"],
            references=["NIST SP 800-56C", "Hybrid PQC Transition Guide"],
            tags=["kem", "hybrid", "transition", "nist-standard"]
        )
        
        # =====================================================================
        # DIGITAL SIGNATURES - NIST STANDARDIZED
        # =====================================================================
        
        self._endpoints["dilithium_signature_engine"] = CryptoAPIEndpoint(
            name="dilithium_signature_engine",
            module="quantum_crypt.post_quantum_dilithium_signature_engine_2026_june",
            function="generate_dilithium_keypair",
            stability=StabilityLevel.STABLE,
            nist_compliance=NISTComplianceLevel.STANDARDIZED,
            version_added="2026.01.15",
            security_level=3,
            description="CRYSTALS-Dilithium Digital Signature - NIST PQC Standard",
            usage_example="""
# Generate Dilithium-3 keypair
pk, sk = generate_dilithium_keypair(mode=3)

# Sign message
signature = sign(message_bytes, sk)

# Verify signature
valid = verify(message_bytes, signature, pk)
assert valid is True
            """,
            parameters=[
                {"name": "mode", "type": "int", "description": "Dilithium mode: 2, 3, or 5"},
                {"name": "deterministic", "type": "bool", "description": "Deterministic signing"}
            ],
            returns="Tuple of (public_key, secret_key)",
            exceptions=["ValueError", "SigningError", "VerificationError"],
            references=["NIST FIPS 204 (Dilithium Standard)", "CRYSTALS-Dilithium Specification"],
            tags=["signature", "nist-standard", "dilithium", "authentication"]
        )
        
        self._endpoints["hybrid_signature_engine"] = CryptoAPIEndpoint(
            name="hybrid_signature_engine",
            module="quantum_crypt.post_quantum_hybrid_signature_engine_dilithium_2026_june",
            function="generate_hybrid_signature_keypair",
            stability=StabilityLevel.STABLE,
            nist_compliance=NISTComplianceLevel.STANDARDIZED,
            version_added="2026.03.01",
            security_level=3,
            description="Hybrid signature: Dilithium + Ed25519 for transition period",
            usage_example="""
# Generate hybrid signature keypair
pk, sk = generate_hybrid_signature_keypair(
    classical_sig="ed25519",
    pqc_sig="dilithium-3"
)

# Sign with both algorithms
hybrid_sig = hybrid_sign(message, sk)

# Verify both signatures
valid = hybrid_verify(message, hybrid_sig, pk)
            """,
            parameters=[
                {"name": "classical_sig", "type": "str", "description": "ed25519, ed448, ecdsa-p256"},
                {"name": "pqc_sig", "type": "str", "description": "dilithium-2, dilithium-3, dilithium-5"}
            ],
            returns="Hybrid signature keypair",
            exceptions=["ValueError", "AlgorithmNotSupported"],
            references=["NIST SP 800-186", "Hybrid Signature Transition Guide"],
            tags=["signature", "hybrid", "transition", "nist-standard"]
        )
        
        # =====================================================================
        # CONSTANT-TIME UTILITIES (STABLE)
        # =====================================================================
        
        self._endpoints["constant_time_comparison"] = CryptoAPIEndpoint(
            name="constant_time_comparison",
            module="quantum_crypt.enhanced_constant_time_comparison_utilities_v2_2026_june",
            function="constant_time_eq",
            stability=StabilityLevel.STABLE,
            nist_compliance=NISTComplianceLevel.STANDARDIZED,
            version_added="2026.06.22",
            security_level=1,
            description="Constant-time byte comparison to prevent timing side-channel attacks",
            usage_example="""
# Safe comparison - runs in constant time regardless of input
if constant_time_eq(received_hmac, expected_hmac):
    print("Authentication successful")
else:
    raise SecurityError("HMAC verification failed")
            """,
            parameters=[
                {"name": "a", "type": "bytes", "description": "First byte string"},
                {"name": "b", "type": "bytes", "description": "Second byte string"}
            ],
            returns="True if equal, False otherwise (constant-time execution)",
            exceptions=["TypeError"],
            references=["NIST SP 800-131A", "Side Channel Resistance Guidelines"],
            tags=["side-channel", "constant-time", "security", "utilities"]
        )
        
        self._endpoints["secure_memory_zeroizer"] = CryptoAPIEndpoint(
            name="secure_memory_zeroizer",
            module="quantum_crypt.post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june",
            function="secure_zeroize",
            stability=StabilityLevel.STABLE,
            nist_compliance=NISTComplianceLevel.STANDARDIZED,
            version_added="2026.04.01",
            security_level=1,
            description="Secure memory zeroization that cannot be optimized away by compiler",
            usage_example="""
# Process sensitive key material
secret_key = derive_session_key()
try:
    encrypt_data(data, secret_key)
finally:
    # Guarantee key material is wiped from memory
    secure_zeroize(secret_key)
            """,
            parameters=[
                {"name": "buffer", "type": "bytearray/memoryview", "description": "Buffer to zeroize"}
            ],
            returns="None - modifies buffer in place",
            exceptions=["TypeError", "ValueError"],
            references=["NIST SP 800-132", "Secure Key Management Guidelines"],
            tags=["key-management", "zeroization", "memory", "security"]
        )
        
        # =====================================================================
        # KEY MANAGEMENT (STABLE)
        # =====================================================================
        
        self._endpoints["key_lifecycle_management"] = CryptoAPIEndpoint(
            name="key_lifecycle_management",
            module="quantum_crypt.post_quantum_key_lifecycle_management_engine_2026_june",
            function="create_key_lifecycle_policy",
            stability=StabilityLevel.STABLE,
            nist_compliance=NISTComplianceLevel.STANDARDIZED,
            version_added="2026.03.15",
            security_level=3,
            description="Automated key lifecycle management with rotation and retirement",
            usage_example="""
policy = create_key_lifecycle_policy(
    algorithm="kyber-768",
    rotation_days=90,
    grace_period_days=7,
    auto_rotate=True
)

manager = KeyLifecycleManager(policy)
await manager.start()  # Auto-rotates keys per policy
            """,
            parameters=[
                {"name": "algorithm", "type": "str", "description": "Cryptographic algorithm"},
                {"name": "rotation_days", "type": "int", "description": "Key rotation interval"},
                {"name": "grace_period_days", "type": "int", "description": "Overlap period"},
                {"name": "auto_rotate", "type": "bool", "description": "Enable automatic rotation"}
            ],
            returns="KeyLifecyclePolicy configuration object",
            exceptions=["PolicyError", "ConfigurationError"],
            references=["NIST SP 800-57 Part 1", "Key Management Recommendation"],
            tags=["key-management", "lifecycle", "rotation", "automation"]
        )
        
        self._endpoints["hkdf_key_derivation"] = CryptoAPIEndpoint(
            name="hkdf_key_derivation",
            module="quantum_crypt.post_quantum_secure_hkdf_kdf_engine_2026_june",
            function="hkdf_derive",
            stability=StabilityLevel.STABLE,
            nist_compliance=NISTComplianceLevel.STANDARDIZED,
            version_added="2026.02.15",
            security_level=3,
            description="HMAC-based Key Derivation Function (HKDF) per RFC 5869",
            usage_example="""
# Derive multiple keys from a single master secret
derived_keys = hkdf_derive(
    master_secret=shared_secret,
    salt=salt_bytes,
    info=b"quantumcrypt-session-v1",
    output_length=64,
    hash_alg="sha3-512"
)
            """,
            parameters=[
                {"name": "master_secret", "type": "bytes", "description": "Input key material"},
                {"name": "salt", "type": "Optional[bytes]", "description": "Salt value"},
                {"name": "info", "type": "bytes", "description": "Context-specific info"},
                {"name": "output_length", "type": "int", "description": "Desired output length"},
                {"name": "hash_alg", "type": "str", "description": "Hash algorithm"}
            ],
            returns="Derived key bytes",
            exceptions=["ValueError", "HKDFError"],
            references=["RFC 5869", "NIST SP 800-56C"],
            tags=["kdf", "hkdf", "key-derivation", "nist-standard"]
        )
        
        # =====================================================================
        # TLS & SECURE CHANNELS (BETA)
        # =====================================================================
        
        self._endpoints["hybrid_tls13_handshake"] = CryptoAPIEndpoint(
            name="hybrid_tls13_handshake",
            module="quantum_crypt.post_quantum_hybrid_tls13_handshake_simulator_v12_2026_june",
            function="simulate_tls13_hybrid_handshake",
            stability=StabilityLevel.BETA,
            nist_compliance=NISTComplianceLevel.CANDIDATE,
            version_added="2026.04.15",
            security_level=3,
            description="Hybrid TLS 1.3 handshake with post-quantum key exchange",
            usage_example="""
# Simulate TLS 1.3 with hybrid key exchange
result = simulate_tls13_hybrid_handshake(
    client_suites=["kyber-768+x25519", "kyber-512+x25519"],
    server_preference="kyber-768+x25519"
)
print(f"Handshake time: {result.handshake_time_ms:.1f}ms")
            """,
            parameters=[
                {"name": "client_suites", "type": "List[str]", "description": "Client cipher suites"},
                {"name": "server_preference", "type": "str", "description": "Server preferred suite"}
            ],
            returns="HandshakeResult with timing and security info",
            exceptions=["HandshakeError", "CipherSuiteError"],
            references=["TLS 1.3 RFC 8446", "PQC TLS Integration Draft"],
            tags=["tls", "beta", "secure-channel", "handshake"]
        )
        
        # =====================================================================
        # OBSERVABILITY & HEALTH MONITORING (STABLE)
        # =====================================================================
        
        self._endpoints["crypto_health_monitor"] = CryptoAPIEndpoint(
            name="crypto_health_monitor",
            module="quantum_crypt.post_quantum_cryptographic_randomness_health_monitor_2026_june",
            function="monitor_randomness_health",
            stability=StabilityLevel.STABLE,
            nist_compliance=NISTComplianceLevel.STANDARDIZED,
            version_added="2026.03.01",
            security_level=1,
            description="Cryptographic randomness health monitoring and entropy validation",
            usage_example="""
health = monitor_randomness_health(
    samples=get_random_samples(10000),
    tests=["frequency", "runs", "longest_run", "fft"]
)
if not health.passed:
    alert_on_entropy_degradation(health.failures)
            """,
            parameters=[
                {"name": "samples", "type": "bytes", "description": "Randomness samples"},
                {"name": "tests", "type": "List[str]", "description": "NIST SP 800-90B tests"}
            ],
            returns="RandomnessHealth report with test results",
            exceptions=["EntropyError", "TestError"],
            references=["NIST SP 800-90B", "Entropy Sources Recommendation"],
            tags=["monitoring", "randomness", "entropy", "health"]
        )
        
        # =====================================================================
        # ERROR RESILIENCE (STABLE)
        # =====================================================================
        
        self._endpoints["crypto_error_resilience"] = CryptoAPIEndpoint(
            name="crypto_error_resilience",
            module="quantum_crypt.crypto_error_resilience_key_operation_protection_v17_2026_june",
            function="protect_key_operation",
            stability=StabilityLevel.STABLE,
            nist_compliance=NISTComplianceLevel.STANDARDIZED,
            version_added="2026.05.01",
            security_level=3,
            description="Protective wrapper for key operations with graceful degradation",
            usage_example="""
@protect_key_operation(
    max_attempts=3,
    fallback_algorithm="classical-aes-gcm",
    timeout_seconds=5
)
def encrypt_sensitive_data(data, key):
    return pqc_encrypt(data, key)
            """,
            parameters=[
                {"name": "max_attempts", "type": "int", "description": "Max retry attempts"},
                {"name": "fallback_algorithm", "type": "str", "description": "Fallback on failure"},
                {"name": "timeout_seconds", "type": "int", "description": "Operation timeout"}
            ],
            returns="Decorated function with resilience protection",
            exceptions=["CryptoOperationError", "FallbackActivated"],
            references=["Fault Tolerant Cryptography Guidelines"],
            tags=["resilience", "fault-tolerance", "fallback", "protection"]
        )
        
        # =====================================================================
        # DEPRECATED APIs
        # =====================================================================
        
        self._endpoints["legacy_rsa_2048"] = CryptoAPIEndpoint(
            name="legacy_rsa_2048",
            module="quantum_crypt.legacy",
            function="rsa_encrypt",
            stability=StabilityLevel.DEPRECATED,
            nist_compliance=NISTComplianceLevel.LEGACY,
            version_added="2025.01.01",
            version_deprecated="2026.01.01",
            deprecation_date=datetime.date(2026, 1, 1),
            removal_date=datetime.date(2026, 12, 31),
            security_level=1,
            description="[DEPRECATED] RSA-2048 - quantum-vulnerable, migrate to PQC",
            usage_example="# DEPRECATED - Use CRYSTALS-Kyber for key exchange",
            alternatives=["kyber_kem_engine", "hybrid_kem_engine"],
            references=["Quantum Computing Threat to RSA", "PQC Migration Guide"],
            tags=["deprecated", "legacy", "quantum-vulnerable"]
        )
    
    def get_endpoint(self, name: str) -> Optional[CryptoAPIEndpoint]:
        """Get endpoint metadata by name
        
        Args:
            name: Crypto API endpoint name
            
        Returns:
            CryptoAPIEndpoint metadata or None if not found
        """
        return self._endpoints.get(name)
    
    def get_endpoints_by_stability(self, stability: StabilityLevel) -> List[CryptoAPIEndpoint]:
        """Get all endpoints with specified stability level
        
        Args:
            stability: Stability level to filter by
            
        Returns:
            List of matching crypto API endpoints
        """
        return [ep for ep in self._endpoints.values() if ep.stability == stability]
    
    def get_endpoints_by_nist_level(self, nist_level: NISTComplianceLevel) -> List[CryptoAPIEndpoint]:
        """Get all endpoints with specified NIST compliance level
        
        Args:
            nist_level: NIST compliance level to filter by
            
        Returns:
            List of matching crypto API endpoints
        """
        return [ep for ep in self._endpoints.values() if ep.nist_compliance == nist_level]
    
    def get_deprecated_endpoints(self) -> List[CryptoAPIEndpoint]:
        """Get all deprecated endpoints
        
        Returns:
            List of deprecated crypto API endpoints
        """
        return self.get_endpoints_by_stability(StabilityLevel.DEPRECATED)
    
    def get_stable_endpoints(self) -> List[CryptoAPIEndpoint]:
        """Get all stable production-ready endpoints
        
        Returns:
            List of stable crypto API endpoints
        """
        return self.get_endpoints_by_stability(StabilityLevel.STABLE)
    
    def get_nist_standardized_algorithms(self) -> List[CryptoAPIEndpoint]:
        """Get all NIST-standardized post-quantum algorithms
        
        Returns:
            List of NIST standardized endpoints
        """
        return self.get_endpoints_by_nist_level(NISTComplianceLevel.STANDARDIZED)
    
    def get_all_tags(self) -> List[str]:
        """Get all unique tags across endpoints
        
        Returns:
            List of unique tags
        """
        tags = set()
        for ep in self._endpoints.values():
            tags.update(ep.tags)
        return sorted(tags)
    
    def get_endpoints_by_tag(self, tag: str) -> List[CryptoAPIEndpoint]:
        """Get endpoints by tag
        
        Args:
            tag: Tag to filter by
            
        Returns:
            List of matching crypto API endpoints
        """
        return [ep for ep in self._endpoints.values() if tag in ep.tags]
    
    def get_endpoints_by_security_level(self, level: int) -> List[CryptoAPIEndpoint]:
        """Get endpoints by NIST security level
        
        Args:
            level: Security level (1-5)
            
        Returns:
            List of matching crypto API endpoints
        """
        return [ep for ep in self._endpoints.values() if ep.security_level == level]
    
    def generate_markdown_docs(self) -> str:
        """Generate comprehensive Markdown documentation
        
        Returns:
            Markdown formatted documentation
        """
        md = ["# QuantumCrypt AI Crypto API Documentation\n"]
        md.append("## NIST Compliance Legend")
        md.append("- **STANDARDIZED**: NIST PQC Standard (FIPS 203/204)")
        md.append("- **CANDIDATE**: Round 3+ candidate algorithms")
        md.append("- **RESEARCH**: Academic implementations")
        md.append("- **LEGACY**: Quantum-vulnerable classical algorithms\n")
        
        for stability in [StabilityLevel.STABLE, StabilityLevel.BETA, 
                          StabilityLevel.EXPERIMENTAL, StabilityLevel.DEPRECATED]:
            endpoints = self.get_endpoints_by_stability(stability)
            if not endpoints:
                continue
                
            md.append(f"\n## {stability.value} APIs\n")
            for ep in endpoints:
                md.append(f"\n### {ep.name}")
                md.append(f"- **Module**: `{ep.module}`")
                md.append(f"- **Function**: `{ep.function}`")
                md.append(f"- **NIST Compliance**: {ep.nist_compliance.value}")
                md.append(f"- **Security Level**: {ep.security_level}")
                md.append(f"- **Added**: {ep.version_added}")
                if ep.version_deprecated:
                    md.append(f"- **Deprecated**: {ep.version_deprecated}")
                    md.append(f"- **Removal**: {ep.removal_date}")
                md.append(f"\n**Description**: {ep.description}")
                if ep.usage_example:
                    md.append(f"\n**Usage Example**:\n```python{ep.usage_example}\n```")
                if ep.alternatives:
                    md.append(f"\n**Migration Path**: {', '.join(ep.alternatives)}")
                if ep.references:
                    md.append(f"\n**References**: {', '.join(ep.references)}")
        
        return "\n".join(md)


# Export public API
__all__ = [
    "StabilityLevel",
    "NISTComplianceLevel",
    "CryptoAPIEndpoint",
    "QuantumCryptAPIDocumentationCatalog"
]
