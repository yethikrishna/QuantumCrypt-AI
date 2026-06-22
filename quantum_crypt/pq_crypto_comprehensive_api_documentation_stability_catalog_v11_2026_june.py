"""
QuantumCrypt AI - Comprehensive Post-Quantum Crypto API Documentation & Stability Catalog v11
============================================================================================
STABILITY LEVEL: STABLE
LAST UPDATED: 2026-06-23
MAINTAINER: QuantumCrypt Security Team

This module provides a centralized catalog of all post-quantum cryptographic APIs with:
- Stability markers (STABLE/EXPERIMENTAL/DEPRECATED)
- Comprehensive docstrings
- Usage examples
- NIST standard compliance information
- Migration guides
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime
import json
import hashlib


class StabilityLevel(Enum):
    """API Stability Level classification for cryptographic APIs.
    
    Attributes:
        STABLE: NIST-standardized, audited, production-ready
        EXPERIMENTAL: Research-grade, subject to change, NIST candidates
        DEPRECATED: Cryptographically weak, scheduled for removal
        LEGACY: Classical algorithms, maintained for compatibility
    """
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


class NISTStatus(Enum):
    """NIST standardization status for post-quantum algorithms."""
    STANDARDIZED = "STANDARDIZED"
    ROUND_4 = "ROUND_4"
    ROUND_3 = "ROUND_3"
    CANDIDATE = "CANDIDATE"
    RESEARCH = "RESEARCH"


@dataclass
class CryptoAPIEndpoint:
    """Metadata for a cryptographic API endpoint.
    
    Args:
        name: Human-readable API name
        function_path: Full module path to the function
        stability: Stability level classification
        nist_status: NIST standardization status
        algorithm: Cryptographic algorithm name
        version_added: Version when API was introduced
        version_deprecated: Version when deprecated (if applicable)
        description: Detailed API purpose and behavior
        security_level: NIST security level (1-5)
        parameters: List of parameter descriptions
        returns: Return value description
        exceptions: List of possible exceptions
        usage_example: Code example demonstrating usage
        see_also: Related APIs for cross-reference
        migration_guide: Migration instructions if deprecated
        compliance_notes: Security and compliance considerations
    """
    name: str
    function_path: str
    stability: StabilityLevel
    nist_status: NISTStatus
    algorithm: str
    version_added: str
    description: str
    security_level: int = 1
    version_deprecated: Optional[str] = None
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = "bytes"
    exceptions: List[str] = field(default_factory=list)
    usage_example: str = ""
    see_also: List[str] = field(default_factory=list)
    migration_guide: str = ""
    compliance_notes: str = ""


class CryptoDocumentationCatalog:
    """Centralized post-quantum crypto API documentation and stability catalog.
    
    This class provides a single source of truth for all cryptographic APIs
    in the QuantumCrypt platform. It enables:
    - Programmatic API discovery by security level
    - NIST compliance checking at runtime
    - Automated documentation generation
    - Algorithm migration guidance
    
    Example:
        >>> catalog = CryptoDocumentationCatalog()
        >>> catalog.get_nist_status("kyber_kem_encrypt")
        NISTStatus.STANDARDIZED
    """
    
    def __init__(self) -> None:
        """Initialize the documentation catalog with all registered APIs."""
        self._apis: Dict[str, CryptoAPIEndpoint] = {}
        self._build_catalog()
        self._catalog_version: str = "11.0.0"
        self._generated_at: datetime = datetime.utcnow()
    
    def _build_catalog(self) -> None:
        """Populate the catalog with all cryptographic API endpoints."""
        # ==================== STABLE - NIST STANDARDIZED ====================
        
        self._register_api(CryptoAPIEndpoint(
            name="CRYSTALS-Kyber KEM Encapsulation",
            function_path="quantum_crypt.post_quantum_kyber_kem_engine.encapsulate",
            stability=StabilityLevel.STABLE,
            nist_status=NISTStatus.STANDARDIZED,
            algorithm="CRYSTALS-Kyber",
            version_added="2.0.0",
            description="NIST FIPS 203 standardized key encapsulation mechanism.",
            security_level=3,
            parameters=[
                {"name": "public_key", "type": "bytes", "description": "Recipient's public key"},
                {"name": "variant", "type": "str", "description": "Kyber variant (512/768/1024)"}
            ],
            returns="Tuple of (shared_secret, ciphertext)",
            exceptions=["ValueError for invalid key format", "CryptographyError"],
            usage_example="""
            from quantum_crypt import post_quantum_kyber_kem_engine
            
            # NIST FIPS 203 - Level 3 security
            pk, sk = post_quantum_kyber_kem_engine.keygen(variant="768")
            shared_secret, ciphertext = post_quantum_kyber_kem_engine.encapsulate(pk)
            """,
            see_also=["hybrid_kem_engine", "secure_key_wrapping_engine"],
            compliance_notes="FIPS 203 compliant. Recommended for TLS 1.3, VPN, and general key exchange."
        ))
        
        self._register_api(CryptoAPIEndpoint(
            name="CRYSTALS-Dilithium Digital Signature",
            function_path="quantum_crypt.post_quantum_dilithium_signature_engine.sign",
            stability=StabilityLevel.STABLE,
            nist_status=NISTStatus.STANDARDIZED,
            algorithm="CRYSTALS-Dilithium",
            version_added="2.0.0",
            description="NIST FIPS 204 standardized digital signature algorithm.",
            security_level=3,
            parameters=[
                {"name": "message", "type": "bytes", "description": "Message to sign"},
                {"name": "private_key", "type": "bytes", "description": "Signer's private key"}
            ],
            returns="Digital signature bytes",
            usage_example="""
            from quantum_crypt import post_quantum_dilithium_signature_engine
            
            # NIST FIPS 204 - Level 3 security
            pk, sk = post_quantum_dilithium_signature_engine.keygen()
            signature = post_quantum_dilithium_signature_engine.sign(message, sk)
            valid = post_quantum_dilithium_signature_engine.verify(message, signature, pk)
            """,
            see_also=["hybrid_signature_engine", "certificate_transparency_logger"],
            compliance_notes="FIPS 204 compliant. Recommended for code signing, certificates, and document signing."
        ))
        
        self._register_api(CryptoAPIEndpoint(
            name="SPHINCS+ Hash-Based Signature",
            function_path="quantum_crypt.post_quantum_hash_based_signature_engine.sign",
            stability=StabilityLevel.STABLE,
            nist_status=NISTStatus.STANDARDIZED,
            algorithm="SPHINCS+",
            version_added="2.5.0",
            description="NIST FIPS 205 standardized stateless hash-based signature.",
            security_level=5,
            parameters=[
                {"name": "message", "type": "bytes", "description": "Message to sign"},
                {"name": "private_key", "type": "bytes", "description": "Signer's private key"}
            ],
            returns="Stateless digital signature",
            compliance_notes="FIPS 205 compliant. Stateless, no nonce reuse vulnerabilities."
        ))
        
        self._register_api(CryptoAPIEndpoint(
            name="Hybrid PQ-Classical Key Exchange",
            function_path="quantum_crypt.post_quantum_hybrid_key_exchange_engine.perform",
            stability=StabilityLevel.STABLE,
            nist_status=NISTStatus.STANDARDIZED,
            algorithm="Hybrid (Kyber + X25519)",
            version_added="3.0.0",
            description="Dual-key exchange combining post-quantum and classical algorithms.",
            security_level=3,
            returns="Hybrid shared secret with forward secrecy",
            see_also=["kyber_kem_engine", "forward_secrecy_engine"],
            compliance_notes="NIST SP 800-186 compliant hybrid mode. Provides transitional security during PQ migration. Recommended for all new TLS 1.3 deployments."
        ))
        
        # ==================== EXPERIMENTAL - RESEARCH CANDIDATES ====================
        
        self._register_api(CryptoAPIEndpoint(
            name="FALCON Signature Engine",
            function_path="quantum_crypt.post_quantum_falcon_signature_engine.sign",
            stability=StabilityLevel.EXPERIMENTAL,
            nist_status=NISTStatus.ROUND_3,
            algorithm="FALCON",
            version_added="4.0.0",
            description="NIST Round 3 alternate signature candidate (lattice-based).",
            security_level=5,
            usage_example="""
            # EXPERIMENTAL: API subject to change based on final standardization
            from quantum_crypt import post_quantum_falcon_signature_engine
            signature = post_quantum_falcon_signature_engine.sign(message, sk)
            """,
            compliance_notes="Round 3 alternate. Small signatures, high performance. Not yet FIPS standardized."
        ))
        
        self._register_api(CryptoAPIEndpoint(
            name="Zero-Knowledge Proof Authentication",
            function_path="quantum_crypt.post_quantum_zero_knowledge_proof_engine.prove",
            stability=StabilityLevel.EXPERIMENTAL,
            nist_status=NISTStatus.RESEARCH,
            algorithm="ZK-SNARK (Post-Quantum)",
            version_added="4.2.0",
            description="Post-quantum secure zero-knowledge proof generation.",
            security_level=3,
            see_also=["secure_authentication_engine"]
        ))
        
        self._register_api(CryptoAPIEndpoint(
            name="Homomorphic Encryption Scheme",
            function_path="quantum_crypt.post_quantum_homomorphic_encryption_scheme.encrypt",
            stability=StabilityLevel.EXPERIMENTAL,
            nist_status=NISTStatus.RESEARCH,
            algorithm="BFV/CKKS Variant",
            version_added="5.0.0",
            description="Partial homomorphic encryption for secure computation.",
            security_level=3,
            compliance_notes="Research grade. Performance optimizations ongoing."
        ))
        
        # ==================== LEGACY - CLASSICAL ALGORITHMS ====================
        
        self._register_api(CryptoAPIEndpoint(
            name="RSA-2048 Encryption (LEGACY)",
            function_path="quantum_crypt.classical.rsa_encrypt",
            stability=StabilityLevel.LEGACY,
            nist_status=NISTStatus.STANDARDIZED,
            algorithm="RSA-2048",
            version_added="1.0.0",
            description="Classical RSA encryption (vulnerable to quantum computers).",
            security_level=1,
            compliance_notes="NIST SP 800-56B rev 2. LEGACY - quantum-vulnerable. See migration guide.",
            migration_guide="""
            QUANTUM RISK MIGRATION:
            RSA-2048 will be broken by cryptographically relevant quantum computers.
            
            REPLACE:
                from quantum_crypt.classical import rsa_encrypt
                ciphertext = rsa_encrypt(message, public_key)
            
            WITH:
                from quantum_crypt import post_quantum_hybrid_kem_engine
                shared_secret, ciphertext = post_quantum_hybrid_kem_engine.encapsulate(pk)
            
            TIMELINE: Migrate by 2028 for critical systems.
            """
        ))
        
        self._register_api(CryptoAPIEndpoint(
            name="ECC P-256 Signature (LEGACY)",
            function_path="quantum_crypt.classical.ecdsa_sign",
            stability=StabilityLevel.LEGACY,
            nist_status=NISTStatus.STANDARDIZED,
            algorithm="ECDSA P-256",
            version_added="1.0.0",
            description="Classical ECDSA signature (vulnerable to Shor's algorithm).",
            security_level=1,
            compliance_notes="NIST SP 800-56A rev 3. LEGACY - quantum-vulnerable. See migration guide.",
            migration_guide="""
            QUANTUM RISK MIGRATION:
            ECDSA P-256 will be completely broken by Shor's algorithm on quantum computers.
            
            REPLACE ECDSA signing with CRYSTALS-Dilithium:
                from quantum_crypt import post_quantum_dilithium_signature_engine
                pk, sk = post_quantum_dilithium_signature_engine.keygen()
                signature = post_quantum_dilithium_signature_engine.sign(message, sk)
            
            This provides NIST FIPS 204 Level 3 security against quantum attacks.
            """
        ))
        
        # ==================== DEPRECATED ====================
        
        self._register_api(CryptoAPIEndpoint(
            name="NTRU-HPS v1 (DEPRECATED)",
            function_path="quantum_crypt.deprecated.ntru_hps_v1.encrypt",
            stability=StabilityLevel.DEPRECATED,
            nist_status=NISTStatus.ROUND_3,
            algorithm="NTRU-HPS v1",
            version_added="1.5.0",
            version_deprecated="2.0.0",
            description="Round 3 candidate superseded by CRYSTALS-Kyber standard.",
            security_level=2,
            migration_guide="""
            MIGRATE TO CRYSTALS-Kyber:
            NTRU-HPS was not selected for NIST standardization.
            
            Replace ntru_hps_v1.keygen() -> kyber_kem_engine.keygen(variant="768")
            Security level equivalent, better performance, standardized.
            """
        ))
    
    def _register_api(self, api: CryptoAPIEndpoint) -> None:
        """Register a crypto API endpoint in the catalog.
        
        Args:
            api: CryptoAPIEndpoint object to register
        """
        key = self._make_key(api.function_path)
        self._apis[key] = api
    
    @staticmethod
    def _make_key(function_path: str) -> str:
        """Create a normalized key from function path."""
        return function_path.lower().replace(".", "_")
    
    def get_stability(self, function_path: str) -> Optional[StabilityLevel]:
        """Get the stability level of a cryptographic API.
        
        Args:
            function_path: Full function path to query
            
        Returns:
            StabilityLevel or None if not found
        """
        key = self._make_key(function_path)
        api = self._apis.get(key)
        return api.stability if api else None
    
    def get_nist_status(self, function_path: str) -> Optional[NISTStatus]:
        """Get NIST standardization status of an algorithm.
        
        Args:
            function_path: Full function path to query
            
        Returns:
            NISTStatus or None if not found
        """
        key = self._make_key(function_path)
        api = self._apis.get(key)
        return api.nist_status if api else None
    
    def get_quantum_safe_apis(self) -> List[CryptoAPIEndpoint]:
        """Get all quantum-resistant APIs (STABLE or EXPERIMENTAL).
        
        Returns:
            List of quantum-safe CryptoAPIEndpoints
        """
        return [
            api for api in self._apis.values()
            if api.stability in (StabilityLevel.STABLE, StabilityLevel.EXPERIMENTAL)
        ]
    
    def list_by_security_level(self, min_level: int) -> List[CryptoAPIEndpoint]:
        """List APIs meeting minimum NIST security level.
        
        Args:
            min_level: Minimum NIST security level (1-5)
            
        Returns:
            List of CryptoAPIEndpoints meeting requirement
        """
        return [
            api for api in self._apis.values()
            if api.security_level >= min_level
        ]
    
    def generate_compliance_report(self) -> str:
        """Generate NIST compliance and migration report.
        
        Returns:
            JSON-formatted compliance report
        """
        quantum_risk = [
            api.name for api in self._apis.values()
            if api.stability in (StabilityLevel.LEGACY, StabilityLevel.DEPRECATED)
        ]
        
        return json.dumps({
            "report_version": self._catalog_version,
            "generated_at": self._generated_at.isoformat(),
            "nist_standardized": len([a for a in self._apis.values() if a.nist_status == NISTStatus.STANDARDIZED]),
            "quantum_safe_count": len(self.get_quantum_safe_apis()),
            "at_risk_legacy_count": len(quantum_risk),
            "at_risk_algorithms": quantum_risk,
            "recommendation": "Migrate LEGACY/DEPRECATED algorithms to STABLE NIST-standardized PQ algorithms by 2028"
        }, indent=2)
    
    def get_catalog_hash(self) -> str:
        """Get integrity hash of catalog contents.
        
        Returns:
            SHA256 hash string
        """
        content = json.dumps({
            k: {
                "name": v.name,
                "algorithm": v.algorithm,
                "stability": v.stability.value,
                "nist_status": v.nist_status.value,
                "security_level": v.security_level
            }
            for k, v in self._apis.items()
        }, sort_keys=True).encode()
        return hashlib.sha256(content).hexdigest()


# Global catalog instance
_global_catalog: Optional[CryptoDocumentationCatalog] = None


def get_crypto_catalog() -> CryptoDocumentationCatalog:
    """Get the global cryptography documentation catalog instance.
    
    Returns:
        Singleton CryptoDocumentationCatalog instance
    """
    global _global_catalog
    if _global_catalog is None:
        _global_catalog = CryptoDocumentationCatalog()
    return _global_catalog


def is_quantum_safe(function_path: str) -> bool:
    """Quick check if an API is quantum-resistant.
    
    Args:
        function_path: Full function path to check
        
    Returns:
        True if quantum-safe, False otherwise
    """
    catalog = get_crypto_catalog()
    stability = catalog.get_stability(function_path)
    return stability in (StabilityLevel.STABLE, StabilityLevel.EXPERIMENTAL)


if __name__ == "__main__":
    catalog = get_crypto_catalog()
    print(f"PQ Crypto Catalog v{catalog._catalog_version}")
    print(f"Total APIs: {len(catalog._apis)}")
    print(f"Quantum-Safe APIs: {len(catalog.get_quantum_safe_apis())}")
    print(f"NIST Standardized: {len([a for a in catalog._apis.values() if a.nist_status == NISTStatus.STANDARDIZED])}")
    print(f"Level 5 Security APIs: {len(catalog.list_by_security_level(5))}")
    print(f"Catalog integrity hash: {catalog.get_catalog_hash()}")
