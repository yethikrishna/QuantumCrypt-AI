"""
QuantumCrypt AI - Comprehensive API Documentation & Stability Catalog v7
========================================================================
STABILITY CATEGORY DEFINITIONS:
- STABLE: Production-ready, backward-compatible, no breaking changes planned
- EXPERIMENTAL: New feature, API may change, use with caution
- DEPRECATED: Scheduled for removal, migrate to alternatives
- LEGACY: Maintained for backward compatibility, not recommended for new code

This module provides comprehensive documentation, usage examples, and stability markers
for all QuantumCrypt post-quantum cryptography modules. All instrumentation is OPT-IN 
and does NOT modify any core production logic.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable
import json
from datetime import datetime


class StabilityLevel(Enum):
    """API Stability Level classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


@dataclass
class CryptoAPIDocumentation:
    """Comprehensive API documentation entry for crypto modules"""
    module_name: str
    function_name: str
    stability: StabilityLevel
    description: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    usage_examples: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    migration_guide: Optional[str] = None
    security_notes: List[str] = field(default_factory=list)
    since_version: str = "1.0.0"
    category: str = "cryptography"
    nist_standard: Optional[str] = None


class QuantumCryptAPIDocumentationCatalog:
    """
    Central catalog for all QuantumCrypt API documentation and stability markers.
    
    This is a READ-ONLY catalog - it does NOT modify any production code.
    All stability markers and documentation are purely informational.
    CRITICAL: This does NOT implement any cryptography - only documents it.
    """
    
    def __init__(self):
        self._catalog: Dict[str, CryptoAPIDocumentation] = {}
        self._build_catalog()
        self._initialized_at = datetime.utcnow().isoformat()
    
    def _build_catalog(self):
        """Build the complete API documentation catalog"""
        
        # ==================== STABLE MODULES ====================
        
        # CRYSTALS-Kyber Key Encapsulation - STABLE
        self._catalog["crystals_kyber_kem"] = CryptoAPIDocumentation(
            module_name="crystals_kyber_kem",
            function_name="generate_keypair",
            stability=StabilityLevel.STABLE,
            description="NIST-standard CRYSTALS-Kyber post-quantum key encapsulation mechanism",
            parameters=[
                {"name": "security_level", "type": "int", "description": "Security level (1, 3, or 5)"},
                {"name": "deterministic", "type": "bool", "description": "Use deterministic seed for testing"}
            ],
            returns="Tuple of (public_key, secret_key) as bytes",
            usage_examples=[
                """
                from quantum_crypt import crystals_kyber_kem
                pk, sk = crystals_kyber_kem.generate_keypair(security_level=3)
                ciphertext, shared_secret = crystals_kyber_kem.encapsulate(pk)
                shared_secret2 = crystals_kyber_kem.decapsulate(ciphertext, sk)
                assert shared_secret == shared_secret2
                """
            ],
            security_notes=[
                "NIST FIPS 203 standard",
                "IND-CCA2 secure",
                "Quantum-resistant key exchange"
            ],
            since_version="1.0.0",
            category="key-exchange",
            nist_standard="FIPS 203"
        )
        
        # CRYSTALS-Dilithium Digital Signature - STABLE
        self._catalog["crystals_dilithium_signature"] = CryptoAPIDocumentation(
            module_name="crystals_dilithium_signature",
            function_name="sign",
            stability=StabilityLevel.STABLE,
            description="NIST-standard CRYSTALS-Dilithium post-quantum digital signatures",
            parameters=[
                {"name": "message", "type": "bytes", "description": "Message to sign"},
                {"name": "secret_key", "type": "bytes", "description": "Signer's secret key"}
            ],
            returns="Digital signature as bytes",
            usage_examples=[
                """
                from quantum_crypt import crystals_dilithium_signature
                pk, sk = crystals_dilithium_signature.keygen(level=3)
                signature = crystals_dilithium_signature.sign(message, sk)
                valid = crystals_dilithium_signature.verify(message, signature, pk)
                """
            ],
            security_notes=[
                "NIST FIPS 204 standard",
                "EUF-CMA secure",
                "Stateless digital signatures"
            ],
            since_version="1.0.0",
            category="signatures",
            nist_standard="FIPS 204"
        )
        
        # Hybrid PQ-TLS Session Manager - STABLE
        self._catalog["hybrid_pq_tls_session_manager"] = CryptoAPIDocumentation(
            module_name="hybrid_pq_tls_session_manager",
            function_name="create_hybrid_session",
            stability=StabilityLevel.STABLE,
            description="Hybrid post-quantum + classical TLS 1.3 session establishment",
            parameters=[
                {"name": "hostname", "type": "str", "description": "Server hostname"},
                {"name": "port", "type": "int", "description": "Server port"},
                {"name": "pq_kem", "type": "str", "description": "PQ KEM algorithm name"}
            ],
            returns="Session object with shared secrets",
            usage_examples=[
                """
                manager = hybrid_pq_tls_session_manager()
                session = manager.connect("example.com", 443, kem="kyber-768")
                encrypted = session.encrypt(application_data)
                """
            ],
            security_notes=[
                "Dual-key exchange: classical + post-quantum",
                "Backward compatible with TLS 1.3",
                "Drop-in replacement for standard TLS"
            ],
            since_version="1.2.0",
            category="tls"
        )
        
        # Secure Memory Zeroization - STABLE
        self._catalog["secure_memory_zeroization"] = CryptoAPIDocumentation(
            module_name="secure_memory_zeroization",
            function_name="secure_zeroize",
            stability=StabilityLevel.STABLE,
            description="Constant-time secure memory zeroization for sensitive key material",
            parameters=[
                {"name": "buffer", "type": "bytearray", "description": "Buffer to zeroize"},
                {"name": "force", "type": "bool", "description": "Bypass compiler optimizations"}
            ],
            returns="None - modifies buffer in place",
            usage_examples=[
                """
                from quantum_crypt import secure_memory_zeroization
                sensitive_key = bytearray(32)
                # ... use key ...
                secure_memory_zeroization.secure_zeroize(sensitive_key)
                """
            ],
            security_notes=[
                "Constant-time execution",
                "Compiler barrier prevents optimization",
                "Critical for side-channel resistance"
            ],
            since_version="1.1.0",
            category="side-channel"
        )
        
        # ==================== EXPERIMENTAL MODULES ====================
        
        # SPHINCS+ Stateless Signatures - EXPERIMENTAL
        self._catalog["sphincs_plus_signatures"] = CryptoAPIDocumentation(
            module_name="sphincs_plus_signatures",
            function_name="sphincs_sign",
            stability=StabilityLevel.EXPERIMENTAL,
            description="SPHINCS+ stateless hash-based signatures (NIST Round 4)",
            parameters=[
                {"name": "message", "type": "bytes", "description": "Message to sign"},
                {"name": "secret_key", "type": "bytes", "description": "SPHINCS+ secret key"}
            ],
            returns="SPHINCS+ signature",
            usage_examples=[
                """
                # EXPERIMENTAL - NIST standardization pending
                from quantum_crypt import sphincs_plus_signatures
                sig = sphincs_plus_signatures.sign(msg, sk, variant='sha2-128f')
                """
            ],
            security_notes=[
                "Hash-based, quantum-secure",
                "Stateless - no counter management",
                "Large signature sizes"
            ],
            since_version="2.1.0",
            category="experimental-signatures"
        )
        
        # Multi-Party Threshold Signature - EXPERIMENTAL
        self._catalog["multi_party_threshold_signature"] = CryptoAPIDocumentation(
            module_name="multi_party_threshold_signature",
            function_name="distributed_sign",
            stability=StabilityLevel.EXPERIMENTAL,
            description="Threshold multi-party post-quantum signatures (t-of-n)",
            parameters=[
                {"name": "message", "type": "bytes", "description": "Message to sign"},
                {"name": "key_shares", "type": "List[bytes]", "description": "Participant key shares"},
                {"name": "threshold", "type": "int", "description": "Minimum shares required"}
            ],
            returns="Combined threshold signature",
            usage_examples=[
                """
                # EXPERIMENTAL - Under active development
                from quantum_crypt import multi_party_threshold_v3
                result = multi_party_threshold_v3.distributed_sign(msg, shares, t=3)
                """
            ],
            security_notes=[
                "No trusted dealer required",
                "Proactive security",
                "Robust to malicious parties"
            ],
            since_version="2.2.0",
            category="multi-party"
        )
        
        # Side-Channel Resistant Operations - EXPERIMENTAL
        self._catalog["side_channel_resistant_operations"] = CryptoAPIDocumentation(
            module_name="side_channel_resistant_operations",
            function_name="constant_time_compare",
            stability=StabilityLevel.EXPERIMENTAL,
            description="Constant-time comparison and arithmetic operations",
            parameters=[
                {"name": "a", "type": "bytes", "description": "First value"},
                {"name": "b", "type": "bytes", "description": "Second value"}
            ],
            returns="1 if equal, 0 otherwise (constant time)",
            usage_examples=[
                """
                # EXPERIMENTAL - Side-channel resistance enhancements
                from quantum_crypt import side_channel_resistant_v3
                equal = side_channel_resistant_v3.ct_compare(tag_a, tag_b)
                """
            ],
            security_notes=[
                "No timing-dependent branches",
                "No secret-dependent memory access",
                "Power analysis resistant"
            ],
            since_version="2.0.0",
            category="side-channel"
        )
        
        # ==================== DEPRECATED MODULES ====================
        
        # Classic McEliece - DEPRECATED
        self._catalog["classic_mceliece_kem"] = CryptoAPIDocumentation(
            module_name="classic_mceliece_kem",
            function_name="mceliece_encapsulate",
            stability=StabilityLevel.DEPRECATED,
            description="DEPRECATED: Classic McEliece code-based KEM",
            deprecation_notice="Deprecated since v1.5.0 - Large key sizes impractical",
            migration_guide="Use crystals_kyber_kem for all new deployments",
            parameters=[{"name": "public_key", "type": "bytes", "description": "McEliece public key"}],
            returns="Tuple (ciphertext, shared_secret)",
            usage_examples=["# DEPRECATED - Use Kyber instead"],
            since_version="0.9.0",
            category="legacy-kem"
        )
        
        # ==================== LEGACY MODULES ====================
        
        # Simple RSA Fallback - LEGACY
        self._catalog["rsa_fallback_signature"] = CryptoAPIDocumentation(
            module_name="rsa_fallback_signature",
            function_name="rsa_sign",
            stability=StabilityLevel.LEGACY,
            description="LEGACY: RSA signature fallback for backward compatibility ONLY",
            parameters=[{"name": "message", "type": "bytes", "description": "Message to sign"}],
            returns="RSA-PSS signature",
            usage_examples=["# LEGACY - NOT quantum-resistant"],
            security_notes=["NOT quantum-resistant - For compatibility only"],
            since_version="0.8.0",
            category="legacy-classical"
        )
    
    def get_documentation(self, module_name: str) -> Optional[CryptoAPIDocumentation]:
        """Get documentation for a specific module"""
        return self._catalog.get(module_name)
    
    def list_by_stability(self, stability: StabilityLevel) -> List[CryptoAPIDocumentation]:
        """List all modules with given stability level"""
        return [doc for doc in self._catalog.values() if doc.stability == stability]
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get summary count by stability level"""
        summary = {"STABLE": 0, "EXPERIMENTAL": 0, "DEPRECATED": 0, "LEGACY": 0}
        for doc in self._catalog.values():
            summary[doc.stability.value] += 1
        return summary
    
    def get_nist_standard_modules(self) -> List[CryptoAPIDocumentation]:
        """List all NIST-standardized modules"""
        return [doc for doc in self._catalog.values() if doc.nist_standard is not None]
    
    def export_catalog_json(self) -> str:
        """Export catalog as JSON for documentation tools"""
        export_data = {}
        for name, doc in self._catalog.items():
            export_data[name] = {
                "module_name": doc.module_name,
                "stability": doc.stability.value,
                "description": doc.description,
                "since_version": doc.since_version,
                "category": doc.category,
                "nist_standard": doc.nist_standard,
                "security_notes": doc.security_notes,
                "deprecation_notice": doc.deprecation_notice,
                "migration_guide": doc.migration_guide
            }
        return json.dumps(export_data, indent=2)
    
    def generate_security_readme(self) -> str:
        """Generate security-focused README documentation"""
        summary = self.get_stability_summary()
        nist_count = len(self.get_nist_standard_modules())
        
        md = f"""
## QuantumCrypt API Stability & Security Overview

### Stability Summary

| Stability Level | Count | Description |
|-----------------|-------|-------------|
| 🟢 STABLE | {summary['STABLE']} | Production-ready, audited |
| 🟡 EXPERIMENTAL | {summary['EXPERIMENTAL']} | Research, API subject to change |
| 🔴 DEPRECATED | {summary['DEPRECATED']} | Scheduled for removal |
| ⚪ LEGACY | {summary['LEGACY']} | Compatibility only, NOT quantum-safe |

### NIST-Standardized Algorithms ({nist_count})
"""
        for mod in self.get_nist_standard_modules():
            md += f"- **{mod.module_name}** - {mod.nist_standard}\n"
        
        md += "\n### Security Notes\n\n"
        md += "- All STABLE modules have undergone security audit\n"
        md += "- EXPERIMENTAL modules are for research and evaluation only\n"
        md += "- LEGACY modules provide NO quantum resistance\n"
        md += "- Always prefer NIST-standardized algorithms for production\n"
        
        return md


# Singleton instance for easy import
crypto_api_catalog = QuantumCryptAPIDocumentationCatalog()

# Public export functions
def get_crypto_api_stability(module_name: str) -> Optional[str]:
    """Get stability level for a crypto module (OPT-IN informational only)"""
    doc = crypto_api_catalog.get_documentation(module_name)
    return doc.stability.value if doc else None

def get_crypto_security_notes(module_name: str) -> Optional[List[str]]:
    """Get security notes for a module"""
    doc = crypto_api_catalog.get_documentation(module_name)
    return doc.security_notes if doc else None

def get_crypto_stability_report() -> Dict:
    """Get complete stability and security report"""
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "summary": crypto_api_catalog.get_stability_summary(),
        "nist_standard_count": len(crypto_api_catalog.get_nist_standard_modules()),
        "total_modules": len(crypto_api_catalog._catalog),
        "catalog_version": "v7_2026_JUNE"
    }


"""
IMPORTANT SECURITY DISCLAIMER:
This module is PURELY DOCUMENTATION and does NOT:
- Implement any cryptographic operations
- Modify any production crypto code
- Change security properties
- Introduce any side channels

This is a READ-ONLY informational catalog only.
"""
