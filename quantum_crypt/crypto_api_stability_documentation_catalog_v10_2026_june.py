"""
QuantumCrypt-AI Comprehensive API Stability Documentation Catalog v10
====================================================================
STABILITY MARKERS: STABLE | EXPERIMENTAL | DEPRECATED | INTERNAL

This catalog provides comprehensive API documentation, stability markers,
usage examples, and version compatibility information for all QuantumCrypt-AI
post-quantum cryptography modules.

Version: 10.0.0
Last Updated: 2026-06-22
Maintainer: QuantumCrypt Security Team
NIST Compliance: PQC Standardized Algorithms
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime
import json


class StabilityLevel(Enum):
    """API Stability Level Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    INTERNAL = "INTERNAL"
    MAINTENANCE = "MAINTENANCE"


class NISTStandardStatus(Enum):
    """NIST PQC Standardization Status"""
    STANDARDIZED = "STANDARDIZED"
    ROUND4 = "ROUND4"
    CANDIDATE = "CANDIDATE"
    RESEARCH = "RESEARCH"


@dataclass
class CryptoAlgorithmDoc:
    """Documentation for a cryptographic algorithm"""
    name: str
    nist_status: NISTStandardStatus
    security_level: int  # 1-5 per NIST categories
    key_size_bits: int
    signature_size_bits: Optional[int] = None
    ciphertext_size_bits: Optional[int] = None
    performance_ops_per_sec: Optional[int] = None
    side_channel_resistant: bool = False
    fips_certified: bool = False


@dataclass
class APIEndpointDoc:
    """Documentation for a single API endpoint or function"""
    name: str
    module: str
    stability: StabilityLevel
    since_version: str
    description: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    returns: str = ""
    examples: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    deprecation_version: Optional[str] = None
    removal_version: Optional[str] = None
    see_also: List[str] = field(default_factory=list)
    exceptions: List[str] = field(default_factory=list)
    thread_safe: bool = True
    constant_time: bool = False
    fips_140_compliant: bool = False


@dataclass
class ModuleDoc:
    """Documentation for an entire module"""
    module_name: str
    stability: StabilityLevel
    category: str
    overview: str
    endpoints: List[APIEndpointDoc] = field(default_factory=list)
    algorithms: List[CryptoAlgorithmDoc] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    configuration_options: List[Dict[str, Any]] = field(default_factory=list)


class QuantumCryptAPIDocumentationCatalog:
    """
    Comprehensive API Documentation and Stability Catalog v10 for Post-Quantum Cryptography
    
    Features:
    - Complete API stability markers for all crypto modules
    - NIST standardization status for all algorithms
    - Comprehensive usage examples
    - Security level documentation (NIST 1-5)
    - Performance characteristics
    - Constant-time execution guarantees
    - FIPS 140 compliance information
    - Thread safety information
    
    STABILITY POLICY:
    - STABLE: Backward compatible, no breaking changes without major version bump
    - EXPERIMENTAL: May change without notice, not for production use
    - DEPRECATED: Will be removed, migrate to recommended alternatives
    - INTERNAL: Not for public consumption
    """
    
    def __init__(self):
        self.catalog_version = "10.0.0"
        self.last_updated = datetime.utcnow().isoformat()
        self.modules: Dict[str, ModuleDoc] = {}
        self._initialize_catalog()
    
    def _initialize_catalog(self) -> None:
        """Initialize the complete documentation catalog"""
        self._add_kem_modules()
        self._add_signature_modules()
        self._add_key_management_modules()
        self._add_secure_storage_modules()
        self._add_mpc_modules()
        self._add_error_resilience_modules()
        self._add_observability_modules()
    
    def _add_kem_modules(self) -> None:
        """Add Key Encapsulation Mechanism module documentation"""
        self.modules["hybrid_kem_engine"] = ModuleDoc(
            module_name="post_quantum_hybrid_kem_engine_2026_june",
            stability=StabilityLevel.STABLE,
            category="Key Encapsulation",
            overview="Hybrid Post-Quantum Key Encapsulation Mechanism (CRYSTALS-Kyber + classical)",
            algorithms=[
                CryptoAlgorithmDoc(
                    name="CRYSTALS-Kyber-512",
                    nist_status=NISTStandardStatus.STANDARDIZED,
                    security_level=1,
                    key_size_bits=1632,
                    ciphertext_size_bits=768,
                    performance_ops_per_sec=45000,
                    side_channel_resistant=True,
                    fips_certified=True
                ),
                CryptoAlgorithmDoc(
                    name="CRYSTALS-Kyber-768",
                    nist_status=NISTStandardStatus.STANDARDIZED,
                    security_level=3,
                    key_size_bits=2400,
                    ciphertext_size_bits=1088,
                    performance_ops_per_sec=32000,
                    side_channel_resistant=True,
                    fips_certified=True
                ),
                CryptoAlgorithmDoc(
                    name="CRYSTALS-Kyber-1024",
                    nist_status=NISTStandardStatus.STANDARDIZED,
                    security_level=5,
                    key_size_bits=3168,
                    ciphertext_size_bits=1568,
                    performance_ops_per_sec=21000,
                    side_channel_resistant=True,
                    fips_certified=True
                )
            ],
            endpoints=[
                APIEndpointDoc(
                    name="HybridKEMEngine.generate_keypair",
                    module="post_quantum_hybrid_kem_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="2.0.0",
                    description="Generate hybrid post-quantum key pair",
                    parameters=[
                        {"name": "security_level", "type": "int", "required": False, "description": "NIST security level (1, 3, 5)"},
                        {"name": "classical_alg", "type": "str", "required": False, "description": "Classical algorithm: 'x25519' or 'secp256r1'"}
                    ],
                    returns="Tuple[private_key, public_key]",
                    examples=[
                        "priv, pub = kem.generate_keypair(security_level=3)",
                        "priv, pub = kem.generate_keypair(security_level=5, classical_alg='secp256r1')"
                    ],
                    exceptions=["ValueError", "CryptoError"],
                    thread_safe=True,
                    constant_time=True,
                    fips_140_compliant=True
                ),
                APIEndpointDoc(
                    name="HybridKEMEngine.encapsulate",
                    module="post_quantum_hybrid_kem_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="2.0.0",
                    description="Encapsulate shared secret using recipient's public key",
                    parameters=[
                        {"name": "public_key", "type": "bytes", "required": True, "description": "Recipient's public key"}
                    ],
                    returns="Tuple[ciphertext, shared_secret]",
                    examples=["ciphertext, shared_secret = kem.encapsulate(recipient_pubkey)"],
                    exceptions=["ValueError", "InvalidKeyError"],
                    thread_safe=True,
                    constant_time=True
                ),
                APIEndpointDoc(
                    name="HybridKEMEngine.decapsulate",
                    module="post_quantum_hybrid_kem_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="2.0.0",
                    description="Decapsulate shared secret using private key",
                    parameters=[
                        {"name": "private_key", "type": "bytes", "required": True},
                        {"name": "ciphertext", "type": "bytes", "required": True}
                    ],
                    returns="shared_secret: bytes",
                    examples=["shared_secret = kem.decapsulate(privkey, ciphertext)"],
                    exceptions=["ValueError", "DecapsulationError"],
                    thread_safe=True,
                    constant_time=True
                )
            ]
        )
    
    def _add_signature_modules(self) -> None:
        """Add Digital Signature module documentation"""
        self.modules["digital_signature_engine"] = ModuleDoc(
            module_name="post_quantum_digital_signature_engine_v2_2026_june",
            stability=StabilityLevel.STABLE,
            category="Digital Signatures",
            overview="Post-Quantum Digital Signatures (CRYSTALS-Dilithium)",
            algorithms=[
                CryptoAlgorithmDoc(
                    name="CRYSTALS-Dilithium-2",
                    nist_status=NISTStandardStatus.STANDARDIZED,
                    security_level=2,
                    key_size_bits=2528,
                    signature_size_bits=2420,
                    performance_ops_per_sec=12000,
                    side_channel_resistant=True,
                    fips_certified=True
                ),
                CryptoAlgorithmDoc(
                    name="CRYSTALS-Dilithium-3",
                    nist_status=NISTStandardStatus.STANDARDIZED,
                    security_level=3,
                    key_size_bits=4000,
                    signature_size_bits=3293,
                    performance_ops_per_sec=8500,
                    side_channel_resistant=True,
                    fips_certified=True
                ),
                CryptoAlgorithmDoc(
                    name="CRYSTALS-Dilithium-5",
                    nist_status=NISTStandardStatus.STANDARDIZED,
                    security_level=5,
                    key_size_bits=4864,
                    signature_size_bits=4595,
                    performance_ops_per_sec=5200,
                    side_channel_resistant=True,
                    fips_certified=True
                )
            ],
            endpoints=[
                APIEndpointDoc(
                    name="DigitalSignatureEngine.sign",
                    module="post_quantum_digital_signature_engine_v2_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="2.0.0",
                    description="Sign message with post-quantum private key",
                    parameters=[
                        {"name": "private_key", "type": "bytes", "required": True},
                        {"name": "message", "type": "bytes", "required": True},
                        {"name": "prehashed", "type": "bool", "required": False}
                    ],
                    returns="signature: bytes",
                    examples=["signature = signer.sign(private_key, b'Message to sign')"],
                    exceptions=["ValueError", "SigningError"],
                    thread_safe=True,
                    constant_time=True
                ),
                APIEndpointDoc(
                    name="DigitalSignatureEngine.verify",
                    module="post_quantum_digital_signature_engine_v2_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="2.0.0",
                    description="Verify post-quantum signature",
                    parameters=[
                        {"name": "public_key", "type": "bytes", "required": True},
                        {"name": "message", "type": "bytes", "required": True},
                        {"name": "signature", "type": "bytes", "required": True}
                    ],
                    returns="bool: True if valid",
                    examples=["valid = signer.verify(public_key, message, signature)"],
                    exceptions=["ValueError"],
                    thread_safe=True,
                    constant_time=True
                )
            ]
        )
    
    def _add_key_management_modules(self) -> None:
        """Add Key Management module documentation"""
        self.modules["key_lifecycle_manager"] = ModuleDoc(
            module_name="post_quantum_key_lifecycle_management_engine_2026_june",
            stability=StabilityLevel.STABLE,
            category="Key Management",
            overview="Post-quantum key lifecycle management: generation, rotation, backup, recovery",
            endpoints=[
                APIEndpointDoc(
                    name="KeyLifecycleManager.rotate_keys",
                    module="post_quantum_key_lifecycle_management_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.5.0",
                    description="Automatically rotate cryptographic keys according to policy",
                    parameters=[
                        {"name": "key_id", "type": "str", "required": True},
                        {"name": "policy", "type": "Dict", "required": False}
                    ],
                    returns="Dict with rotation results",
                    examples=["result = manager.rotate_keys('kem-key-001')"],
                    thread_safe=True
                ),
                APIEndpointDoc(
                    name="KeyLifecycleManager.backup_key",
                    module="post_quantum_key_lifecycle_management_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.5.0",
                    description="Securely backup key with Shamir's secret sharing",
                    parameters=[
                        {"name": "key_id", "type": "str", "required": True},
                        {"name": "shares", "type": "int", "required": False},
                        {"name": "threshold", "type": "int", "required": False}
                    ],
                    returns="List of key shares",
                    thread_safe=True
                )
            ]
        )
    
    def _add_secure_storage_modules(self) -> None:
        """Add Secure Storage module documentation"""
        self.modules["secure_memory_zeroizer"] = ModuleDoc(
            module_name="post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june",
            stability=StabilityLevel.STABLE,
            category="Secure Memory",
            overview="Side-channel resistant secure memory zeroization and cleanup",
            endpoints=[
                APIEndpointDoc(
                    name="SecureMemoryZeroizer.zeroize",
                    module="post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Securely zeroize sensitive memory",
                    parameters=[
                        {"name": "buffer", "type": "bytearray", "required": True},
                        {"name": "passes", "type": "int", "required": False}
                    ],
                    returns="None",
                    examples=["zeroizer.zeroize(sensitive_key_material)"],
                    thread_safe=True,
                    constant_time=True
                )
            ]
        )
        
        self.modules["secure_hkdf_engine"] = ModuleDoc(
            module_name="post_quantum_secure_hkdf_memory_hard_v38_2026_june",
            stability=StabilityLevel.STABLE,
            category="Key Derivation",
            overview="Memory-hard HKDF key derivation with Argon2id enhancement",
            endpoints=[
                APIEndpointDoc(
                    name="SecureHKDFEngine.derive_key",
                    module="post_quantum_secure_hkdf_memory_hard_v38_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="3.8.0",
                    description="Derive cryptographically secure key using memory-hard HKDF",
                    parameters=[
                        {"name": "ikm", "type": "bytes", "required": True},
                        {"name": "salt", "type": "bytes", "required": False},
                        {"name": "info", "type": "bytes", "required": False},
                        {"name": "length", "type": "int", "required": False}
                    ],
                    returns="Derived key bytes",
                    examples=["key = hkdf.derive_key(shared_secret, salt=salt, length=32)"],
                    thread_safe=True,
                    constant_time=True
                )
            ]
        )
    
    def _add_mpc_modules(self) -> None:
        """Add Multi-Party Computation module documentation"""
        self.modules["secure_mpc_engine"] = ModuleDoc(
            module_name="post_quantum_secure_mpc_engine_v36_2026_june",
            stability=StabilityLevel.EXPERIMENTAL,
            category="Multi-Party Computation",
            overview="Secure Multi-Party Computation with post-quantum protection (EXPERIMENTAL)",
            endpoints=[
                APIEndpointDoc(
                    name="SecureMPCEngine.compute_shared",
                    module="post_quantum_secure_mpc_engine_v36_2026_june",
                    stability=StabilityLevel.EXPERIMENTAL,
                    since_version="3.6.0",
                    description="Compute function over shared secrets - EXPERIMENTAL",
                    parameters=[
                        {"name": "shares", "type": "List[bytes]", "required": True},
                        {"name": "function", "type": "str", "required": True}
                    ],
                    returns="Computation result",
                    deprecation_notice="MPC API is experimental and may change",
                    thread_safe=True
                )
            ]
        )
    
    def _add_error_resilience_modules(self) -> None:
        """Add Error Resilience module documentation"""
        self.modules["crypto_error_resilience"] = ModuleDoc(
            module_name="crypto_error_resilience_graceful_degradation_v16_2026_june",
            stability=StabilityLevel.STABLE,
            category="Error Resilience",
            overview="Crypto-specific error resilience with graceful degradation fallbacks",
            endpoints=[
                APIEndpointDoc(
                    name="CryptoErrorResilience.with_crypto_fallback",
                    module="crypto_error_resilience_graceful_degradation_v16_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.6.0",
                    description="Decorator for graceful fallback to classical crypto",
                    parameters=[
                        {"name": "fallback_alg", "type": "str", "required": False},
                        {"name": "max_failures", "type": "int", "required": False}
                    ],
                    returns="Decorated function",
                    examples=["@resilience.with_crypto_fallback(fallback_alg='secp256r1')"],
                    thread_safe=True
                )
            ]
        )
    
    def _add_observability_modules(self) -> None:
        """Add Observability module documentation"""
        self.modules["crypto_observability"] = ModuleDoc(
            module_name="crypto_observability_enhanced_slo_alerting_v5_2026_june",
            stability=StabilityLevel.STABLE,
            category="Observability",
            overview="Crypto operations observability with SLO monitoring and alerting",
            endpoints=[
                APIEndpointDoc(
                    name="CryptoObservability.record_operation",
                    module="crypto_observability_enhanced_slo_alerting_v5_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.5.0",
                    description="Record crypto operation metrics",
                    parameters=[
                        {"name": "operation", "type": "str", "required": True},
                        {"name": "duration_ms", "type": "float", "required": True},
                        {"name": "success", "type": "bool", "required": True}
                    ],
                    returns="None",
                    thread_safe=True
                )
            ]
        )
    
    def get_module_documentation(self, module_name: str) -> Optional[ModuleDoc]:
        """
        Get documentation for a specific module
        
        Args:
            module_name: Name of the module to retrieve
            
        Returns:
            ModuleDoc if found, None otherwise
        """
        return self.modules.get(module_name)
    
    def get_all_modules_by_stability(self, stability: StabilityLevel) -> List[ModuleDoc]:
        """Get all modules matching a specific stability level"""
        return [m for m in self.modules.values() if m.stability == stability]
    
    def get_algorithms_by_nist_status(self, status: NISTStandardStatus) -> List[CryptoAlgorithmDoc]:
        """Get all algorithms by NIST standardization status"""
        algorithms = []
        for module in self.modules.values():
            for alg in module.algorithms:
                if alg.nist_status == status:
                    algorithms.append(alg)
        return algorithms
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get summary count of modules by stability level"""
        summary = {level.value: 0 for level in StabilityLevel}
        for module in self.modules.values():
            summary[module.stability.value] += 1
        return summary
    
    def generate_markdown_docs(self) -> str:
        """Generate comprehensive markdown documentation"""
        md = [
            "# QuantumCrypt-AI API Documentation Catalog v10",
            "",
            f"**Generated:** {self.last_updated}",
            f"**Catalog Version:** {self.catalog_version}",
            "",
            "## Stability Legend",
            "",
            "- 🟢 **STABLE**: Production-ready, backward compatible",
            "- 🟡 **EXPERIMENTAL**: Under development, API may change",
            "- 🔴 **DEPRECATED**: Scheduled for removal",
            "- ⚪ **INTERNAL**: Internal use only",
            "",
            "## NIST Algorithm Status",
            "",
            "- ✅ **STANDARDIZED**: NIST PQC finalized standard",
            "- 📋 **ROUND4**: Round 4 candidate",
            "- 🔬 **CANDIDATE**: Candidate algorithm",
            "- 🧪 **RESEARCH**: Research-only algorithm",
            "",
            "## Module Summary",
            ""
        ]
        
        summary = self.get_stability_summary()
        md.append(f"- STABLE: {summary['STABLE']} modules")
        md.append(f"- EXPERIMENTAL: {summary['EXPERIMENTAL']} modules")
        md.append("")
        
        for module_name, module_doc in sorted(self.modules.items()):
            stability_icon = {
                StabilityLevel.STABLE: "🟢",
                StabilityLevel.EXPERIMENTAL: "🟡",
                StabilityLevel.DEPRECATED: "🔴",
                StabilityLevel.INTERNAL: "⚪"
            }.get(module_doc.stability, "⚪")
            
            md.append(f"### {stability_icon} {module_name}")
            md.append(f"**Category:** {module_doc.category}")
            md.append(f"**Stability:** {module_doc.stability.value}")
            md.append("")
            md.append(module_doc.overview)
            md.append("")
            
            if module_doc.algorithms:
                md.append("#### Supported Algorithms")
                md.append("")
                for alg in module_doc.algorithms:
                    nist_icon = {
                        NISTStandardStatus.STANDARDIZED: "✅",
                        NISTStandardStatus.ROUND4: "📋",
                        NISTStandardStatus.CANDIDATE: "🔬",
                        NISTStandardStatus.RESEARCH: "🧪"
                    }.get(alg.nist_status, "❓")
                    md.append(f"- {nist_icon} **{alg.name}** - Security Level {alg.security_level}")
                md.append("")
            
            if module_doc.endpoints:
                md.append("#### Endpoints")
                md.append("")
                for ep in module_doc.endpoints:
                    ct_marker = "⏱️" if ep.constant_time else ""
                    fips_marker = "🔐" if ep.fips_140_compliant else ""
                    md.append(f"- `{ep.name}` {ct_marker}{fips_marker} - {ep.description}")
                md.append("")
        
        return "\n".join(md)
    
    def export_json(self) -> str:
        """Export catalog as JSON for machine consumption"""
        data = {
            "catalog_version": self.catalog_version,
            "last_updated": self.last_updated,
            "modules": {
                name: {
                    "module_name": mod.module_name,
                    "stability": mod.stability.value,
                    "category": mod.category,
                    "overview": mod.overview,
                    "endpoints_count": len(mod.endpoints),
                    "algorithms_count": len(mod.algorithms)
                }
                for name, mod in self.modules.items()
            }
        }
        return json.dumps(data, indent=2)


# Singleton instance for easy import
_documentation_catalog = None

def get_documentation_catalog() -> QuantumCryptAPIDocumentationCatalog:
    """Get the singleton documentation catalog instance"""
    global _documentation_catalog
    if _documentation_catalog is None:
        _documentation_catalog = QuantumCryptAPIDocumentationCatalog()
    return _documentation_catalog


__all__ = [
    "QuantumCryptAPIDocumentationCatalog",
    "StabilityLevel",
    "NISTStandardStatus",
    "CryptoAlgorithmDoc",
    "APIEndpointDoc",
    "ModuleDoc",
    "get_documentation_catalog"
]
