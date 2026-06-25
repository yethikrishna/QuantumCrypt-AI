"""
QuantumCrypt AI - Crypto API Documentation & Stability Catalog v33
======================================================================
STABILITY MARKERS:
    @STABLE - Production-ready, backward-compatible, no breaking changes
    @EXPERIMENTAL - Under active development, API may change
    @DEPRECATED - Scheduled for removal, migrate to alternatives
    @INTERNAL - Not for public consumption, implementation detail

This module provides comprehensive API documentation, stability markers,
and usage examples for all QuantumCrypt post-quantum cryptography modules.

All documentation is ADD-ONLY - no production code logic is modified.
No cryptographic primitives are altered in any way.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable, TypeVar, Tuple
from datetime import datetime
import functools


class CryptoStabilityLevel(Enum):
    """Cryptographic API Stability Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    INTERNAL = "INTERNAL"


@dataclass
class CryptoAPIDocumentation:
    """Comprehensive Cryptographic API Documentation Entry"""
    module_name: str
    function_name: str
    stability: CryptoStabilityLevel
    signature: str
    description: str
    security_properties: List[str] = field(default_factory=list)
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    raises: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    migration_guide: Optional[str] = None
    nist_compliant: bool = False
    side_channel_resistant: bool = False
    since_version: str = "1.0.0"
    last_audited: Optional[str] = None
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class CryptoModuleDocumentation:
    """Cryptographic Module-level Documentation"""
    module_name: str
    description: str
    category: str
    algorithm_family: str
    stability: CryptoStabilityLevel
    security_level: str = "NIST Security Level 1"
    api_entries: List[CryptoAPIDocumentation] = field(default_factory=list)
    module_examples: List[str] = field(default_factory=list)
    standard_references: List[str] = field(default_factory=list)
    maintainer: str = "QuantumCrypt AI Cryptography Team"


class CryptoDocumentationCatalog:
    """Centralized Cryptographic API Documentation Catalog"""
    
    def __init__(self):
        self._modules: Dict[str, CryptoModuleDocumentation] = {}
        self._stability_counts: Dict[CryptoStabilityLevel, int] = {
            CryptoStabilityLevel.STABLE: 0,
            CryptoStabilityLevel.EXPERIMENTAL: 0,
            CryptoStabilityLevel.DEPRECATED: 0,
            CryptoStabilityLevel.INTERNAL: 0
        }
        self._nist_compliant_count = 0
        self._side_channel_resistant_count = 0
    
    def register_module(self, module_doc: CryptoModuleDocumentation) -> None:
        """Register a crypto module's documentation"""
        self._modules[module_doc.module_name] = module_doc
        for api in module_doc.api_entries:
            self._stability_counts[api.stability] += 1
            if api.nist_compliant:
                self._nist_compliant_count += 1
            if api.side_channel_resistant:
                self._side_channel_resistant_count += 1
    
    def get_stable_apis(self) -> List[CryptoAPIDocumentation]:
        """Get all STABLE cryptographic APIs"""
        results = []
        for mod in self._modules.values():
            results.extend([api for api in mod.api_entries if api.stability == CryptoStabilityLevel.STABLE])
        return results
    
    def get_nist_compliant_apis(self) -> List[CryptoAPIDocumentation]:
        """Get all NIST-compliant cryptographic APIs"""
        results = []
        for mod in self._modules.values():
            results.extend([api for api in mod.api_entries if api.nist_compliant])
        return results
    
    def get_side_channel_resistant_apis(self) -> List[CryptoAPIDocumentation]:
        """Get all side-channel resistant APIs"""
        results = []
        for mod in self._modules.values():
            results.extend([api for api in mod.api_entries if api.side_channel_resistant])
        return results
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get summary of API stability levels"""
        return {
            level.value: count for level, count in self._stability_counts.items()
        }
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security compliance summary"""
        return {
            "nist_compliant_apis": self._nist_compliant_count,
            "side_channel_resistant_apis": self._side_channel_resistant_count,
            "total_audited_modules": sum(
                1 for mod in self._modules.values()
                if any(api.last_audited for api in mod.api_entries)
            )
        }
    
    def generate_readme_section(self) -> str:
        """Generate README documentation section for crypto APIs"""
        stability = self.get_stability_summary()
        security = self.get_security_summary()
        return f"""
## QuantumCrypt AI API Stability & Security Summary

### API Stability Levels

| Stability Level | Count | Description |
|-----------------|-------|-------------|
| **STABLE**      | {stability['STABLE']} | Production-ready, audited, backward-compatible |
| **EXPERIMENTAL**| {stability['EXPERIMENTAL']} | Research-grade, under cryptanalysis |
| **DEPRECATED**  | {stability['DEPRECATED']} | Cryptographically weak, migrate immediately |
| **INTERNAL**    | {stability['INTERNAL']} | Implementation details, do not call directly |

### Security Compliance

| Metric | Count |
|--------|-------|
| NIST-Compliant APIs | {security['nist_compliant_apis']} |
| Side-Channel Resistant APIs | {security['side_channel_resistant_apis']} |
| Audited Modules | {security['total_audited_modules']} |

### Critical Usage Guidelines for Cryptography
1. **ALWAYS** prefer **STABLE** APIs for production key material
2. **NEVER** use **EXPERIMENTAL** APIs for long-term key storage
3. **MIGRATE IMMEDIATELY** from **DEPRECATED** APIs - cryptographic weakness
4. **NIST-COMPLIANT** APIs are required for FIPS 140-2/3 environments
5. **SIDE-CHANNEL RESISTANT** APIs must be used for HSM/secure element operations
"""


def crypto_stable_api(since: str = "1.0.0", nist_compliant: bool = False) -> Callable:
    """
    Decorator to mark cryptographic API as STABLE
    
    Args:
        since: Version when this API became stable
        nist_compliant: Whether this API is NIST standardized
    
    Example:
        @crypto_stable_api(since="2.1.0", nist_compliant=True)
        def generate_keypair():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        wrapper._crypto_stability = CryptoStabilityLevel.STABLE
        wrapper._crypto_since = since
        wrapper._crypto_nist_compliant = nist_compliant
        wrapper._crypto_deprecated = False
        return wrapper
    return decorator


def crypto_experimental_api(research_paper: Optional[str] = None) -> Callable:
    """
    Decorator to mark cryptographic API as EXPERIMENTAL
    
    EXPERIMENTAL APIs are research-grade and under active cryptanalysis.
    NOT suitable for production key material or long-term security.
    
    Args:
        research_paper: Reference to supporting cryptanalysis paper
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        wrapper._crypto_stability = CryptoStabilityLevel.EXPERIMENTAL
        wrapper._crypto_research_paper = research_paper
        wrapper._crypto_deprecated = False
        return wrapper
    return decorator


def crypto_deprecated_api(
    removal_version: str,
    migration_guide: str,
    security_issue: str
) -> Callable:
    """
    Decorator to mark cryptographic API as DEPRECATED
    
    IMPORTANT: Deprecated crypto APIs have known security weaknesses.
    Migrate immediately - these WILL be removed in future versions.
    
    Args:
        removal_version: Version when this API will be removed
        migration_guide: Instructions for migrating to secure alternative
        security_issue: Description of the cryptographic weakness
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import warnings
            warnings.warn(
                f"CRYPTOGRAPHIC SECURITY WARNING: {func.__name__} is DEPRECATED due to: {security_issue}. "
                f"Will be removed in {removal_version}. Migration: {migration_guide}",
                DeprecationWarning,
                stacklevel=2
            )
            return func(*args, **kwargs)
        wrapper._crypto_stability = CryptoStabilityLevel.DEPRECATED
        wrapper._crypto_removal_version = removal_version
        wrapper._crypto_migration_guide = migration_guide
        wrapper._crypto_security_issue = security_issue
        wrapper._crypto_deprecated = True
        return wrapper
    return decorator


def crypto_internal_api() -> Callable:
    """
    Decorator to mark cryptographic API as INTERNAL
    
    Internal crypto APIs are implementation details. They perform
    raw mathematical operations without input validation or
    side-channel countermeasures. DO NOT CALL DIRECTLY.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        wrapper._crypto_stability = CryptoStabilityLevel.INTERNAL
        wrapper._crypto_deprecated = False
        return wrapper
    return decorator


def side_channel_protected() -> Callable:
    """
    Decorator marking API as having side-channel attack countermeasures
    
    APIs with this decorator use constant-time operations, memory
    zeroization, and timing attack resistance. Required for HSMs.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        wrapper._crypto_side_channel_protected = True
        return wrapper
    return decorator


# ============================================================
# PRE-REGISTERED CRYPTO MODULE DOCUMENTATION
# ============================================================

def build_complete_crypto_documentation_catalog() -> CryptoDocumentationCatalog:
    """Build complete documentation catalog for QuantumCrypt AI"""
    catalog = CryptoDocumentationCatalog()
    
    # ========================================
    # Post-Quantum Key Encapsulation (KEM)
    # ========================================
    kem_doc = CryptoModuleDocumentation(
        module_name="pq_kem",
        description="NIST-standardized Post-Quantum Key Encapsulation Mechanisms",
        category="Key Exchange",
        algorithm_family="CRYSTALS-Kyber",
        stability=CryptoStabilityLevel.STABLE,
        security_level="NIST Security Level 5",
        standard_references=["NIST FIPS 203", "RFC 9180 (HPKE)"],
        module_examples=[
            """
            from quantum_crypt import pq_kem
            
            # Generate NIST-compliant keypair
            pub_key, priv_key = pq_kem.kyber_768_generate_keypair()
            
            # Encapsulate shared secret
            ciphertext, shared_secret = pq_kem.kyber_768_encapsulate(pub_key)
            
            # Decapsulate on receiver side
            recovered_secret = pq_kem.kyber_768_decapsulate(ciphertext, priv_key)
            """,
            """
            # Hybrid classical + post-quantum key exchange
            session_key = pq_kem.hybrid_key_exchange(
                classical_curve="X25519",
                pq_algorithm="KYBER-768"
            )
            """
        ]
    )
    
    kem_doc.api_entries.extend([
        CryptoAPIDocumentation(
            module_name="pq_kem",
            function_name="kyber_768_generate_keypair",
            stability=CryptoStabilityLevel.STABLE,
            signature="kyber_768_generate_keypair() -> Tuple[PublicKey, PrivateKey]",
            description="Generate CRYSTALS-Kyber-768 keypair (NIST Security Level 3)",
            security_properties=[
                "IND-CCA2 secure",
                "NIST FIPS 203 compliant",
                "Constant-time key generation"
            ],
            returns="Tuple of (public_key, private_key)",
            examples=[
                "pub, priv = kyber_768_generate_keypair()"
            ],
            nist_compliant=True,
            side_channel_resistant=True,
            since_version="1.0.0",
            last_audited="2026-03-15"
        ),
        CryptoAPIDocumentation(
            module_name="pq_kem",
            function_name="kyber_768_encapsulate",
            stability=CryptoStabilityLevel.STABLE,
            signature="kyber_768_encapsulate(pub_key: PublicKey) -> Tuple[Ciphertext, SharedSecret]",
            description="Encapsulate shared secret to Kyber-768 public key",
            security_properties=[
                "IND-CCA2 secure",
                "NIST FIPS 203 compliant",
                "Constant-time operations"
            ],
            parameters=[
                {"name": "pub_key", "type": "PublicKey", "description": "Recipient's Kyber-768 public key"}
            ],
            returns="Tuple of (ciphertext, shared_secret)",
            examples=[
                "ct, ss = kyber_768_encapsulate(recipient_pubkey)"
            ],
            nist_compliant=True,
            side_channel_resistant=True,
            since_version="1.0.0",
            last_audited="2026-03-15"
        ),
        CryptoAPIDocumentation(
            module_name="pq_kem",
            function_name="kyber_768_decapsulate",
            stability=CryptoStabilityLevel.STABLE,
            signature="kyber_768_decapsulate(ct: Ciphertext, priv_key: PrivateKey) -> SharedSecret",
            description="Decapsulate shared secret using Kyber-768 private key",
            security_properties=[
                "IND-CCA2 secure",
                "Failure-resistant",
                "Constant-time decapsulation"
            ],
            parameters=[
                {"name": "ct", "type": "Ciphertext", "description": "Received ciphertext"},
                {"name": "priv_key", "type": "PrivateKey", "description": "Recipient's private key"}
            ],
            returns="Recovered shared secret (32 bytes)",
            examples=[
                "ss = kyber_768_decapsulate(received_ct, my_privkey)"
            ],
            nist_compliant=True,
            side_channel_resistant=True,
            since_version="1.0.0",
            last_audited="2026-03-15"
        ),
        CryptoAPIDocumentation(
            module_name="pq_kem",
            function_name="hybrid_key_exchange",
            stability=CryptoStabilityLevel.EXPERIMENTAL,
            signature="hybrid_key_exchange(classical: str, pq: str) -> SessionKey",
            description="EXPERIMENTAL: Combined classical + PQ key exchange",
            security_properties=[
                "Dual security guarantee",
                "Downgrade-resistant"
            ],
            examples=[
                "key = hybrid_key_exchange('X25519', 'KYBER-768')"
            ],
            nist_compliant=False,
            side_channel_resistant=False,
            since_version="2.2.0"
        )
    ])
    
    catalog.register_module(kem_doc)
    
    # ========================================
    # Post-Quantum Digital Signatures
    # ========================================
    sig_doc = CryptoModuleDocumentation(
        module_name="pq_signature",
        description="NIST-standardized Post-Quantum Digital Signatures",
        category="Digital Signatures",
        algorithm_family="CRYSTALS-Dilithium",
        stability=CryptoStabilityLevel.STABLE,
        security_level="NIST Security Level 3",
        standard_references=["NIST FIPS 204"]
    )
    
    sig_doc.api_entries.extend([
        CryptoAPIDocumentation(
            module_name="pq_signature",
            function_name="dilithium_3_sign",
            stability=CryptoStabilityLevel.STABLE,
            signature="dilithium_3_sign(message: bytes, priv_key: PrivateKey) -> Signature",
            description="Sign message with CRYSTALS-Dilithium-3 private key",
            security_properties=[
                "EUF-CMA secure",
                "NIST FIPS 204 compliant",
                "Deterministic nonce generation"
            ],
            parameters=[
                {"name": "message", "type": "bytes", "description": "Message to sign"},
                {"name": "priv_key", "type": "PrivateKey", "description": "Signer's private key"}
            ],
            returns="Dilithium-3 signature",
            examples=[
                "sig = dilithium_3_sign(b'Hello', signing_key)"
            ],
            nist_compliant=True,
            side_channel_resistant=True,
            since_version="1.1.0",
            last_audited="2026-03-20"
        ),
        CryptoAPIDocumentation(
            module_name="pq_signature",
            function_name="dilithium_3_verify",
            stability=CryptoStabilityLevel.STABLE,
            signature="dilithium_3_verify(msg: bytes, sig: Signature, pub_key: PublicKey) -> bool",
            description="Verify Dilithium-3 signature",
            parameters=[
                {"name": "msg", "type": "bytes", "description": "Original message"},
                {"name": "sig", "type": "Signature", "description": "Signature to verify"},
                {"name": "pub_key", "type": "PublicKey", "description": "Signer's public key"}
            ],
            returns="True if valid, False otherwise",
            examples=[
                "valid = dilithium_3_verify(msg, sig, signer_pub)"
            ],
            nist_compliant=True,
            side_channel_resistant=True,
            since_version="1.1.0",
            last_audited="2026-03-20"
        )
    ])
    
    catalog.register_module(sig_doc)
    
    # ========================================
    # Secure Memory Management
    # ========================================
    memory_doc = CryptoModuleDocumentation(
        module_name="secure_memory",
        description="Secure memory management and zeroization",
        category="Security Primitives",
        algorithm_family="Memory Protection",
        stability=CryptoStabilityLevel.STABLE,
        security_level="Side-Channel Resistant"
    )
    
    memory_doc.api_entries.extend([
        CryptoAPIDocumentation(
            module_name="secure_memory",
            function_name="secure_zeroize",
            stability=CryptoStabilityLevel.STABLE,
            signature="secure_zeroize(buffer: bytearray) -> None",
            description="Securely zeroize sensitive memory (compiler barrier)",
            security_properties=[
                "Not optimized away by compiler",
                "Constant-time operation",
                "Works on all memory types"
            ],
            parameters=[
                {"name": "buffer", "type": "bytearray", "description": "Sensitive buffer to erase"}
            ],
            examples=[
                "secure_zeroize(private_key_bytes)"
            ],
            nist_compliant=True,
            side_channel_resistant=True,
            since_version="1.0.0"
        ),
        CryptoAPIDocumentation(
            module_name="secure_memory",
            function_name="constant_time_compare",
            stability=CryptoStabilityLevel.STABLE,
            signature="constant_time_compare(a: bytes, b: bytes) -> bool",
            description="Timing-attack resistant byte comparison",
            security_properties=[
                "Execution time independent of data",
                "No early termination",
                "FIPS 140-3 compliant"
            ],
            examples=[
                "if constant_time_compare(tag, expected_tag): accept()"
            ],
            nist_compliant=True,
            side_channel_resistant=True,
            since_version="1.0.0"
        )
    ])
    
    catalog.register_module(memory_doc)
    
    return catalog


# Global cryptographic documentation catalog instance
CRYPTO_DOCUMENTATION_CATALOG = build_complete_crypto_documentation_catalog()


def get_crypto_api_stability_summary() -> Dict[str, Any]:
    """
    Get cryptographic API stability and security summary
    
    @STABLE CRYPTO API - Production ready, audited, NIST-compliant
    """
    return {
        "catalog_version": "v33",
        "generated_at": datetime.now().isoformat(),
        "stability_summary": CRYPTO_DOCUMENTATION_CATALOG.get_stability_summary(),
        "security_summary": CRYPTO_DOCUMENTATION_CATALOG.get_security_summary(),
        "total_modules_documented": len(CRYPTO_DOCUMENTATION_CATALOG._modules),
        "total_apis_documented": sum(CRYPTO_DOCUMENTATION_CATALOG._stability_counts.values())
    }


if __name__ == "__main__":
    summary = get_crypto_api_stability_summary()
    print("=== QuantumCrypt AI Crypto API Documentation Catalog v33 ===")
    print(f"Generated: {summary['generated_at']}")
    print(f"Total Modules: {summary['total_modules_documented']}")
    print(f"Total APIs: {summary['total_apis_documented']}")
    print("\nStability Summary:")
    for level, count in summary['stability_summary'].items():
        print(f"  {level}: {count} APIs")
    print("\nSecurity Summary:")
    for metric, value in summary['security_summary'].items():
        print(f"  {metric}: {value}")
    print("\n" + CRYPTO_DOCUMENTATION_CATALOG.generate_readme_section())
