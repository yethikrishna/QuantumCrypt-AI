"""
QuantumCrypt AI - Post-Quantum Crypto API Documentation & Stability Catalog v28
Session 137 - Dimension F: Documentation & API Stability
June 25, 2026

ADD-ONLY IMPLEMENTATION: No existing code modified.
This module provides comprehensive API documentation, usage examples,
and API stability markers for the QuantumCrypt post-quantum ecosystem.

API STABILITY MARKERS:
- STABLE: Production-ready, guaranteed backward compatible
- EXPERIMENTAL: New feature, subject to change
- DEPRECATED: Will be removed in future versions
- LEGACY: Maintained for backward compatibility only
"""

import typing
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import datetime


class PQAPIStability(Enum):
    """Post-Quantum API Stability Level Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


@dataclass
class PQAPIEndpointDoc:
    """Documentation for a single PQ API endpoint/function"""
    name: str
    module: str
    stability: PQAPIStability
    description: str
    signature: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    examples: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    security_level: str = "NIST Level 1"
    quantum_safe: bool = True
    since_version: str = "1.0.0"
    deprecation_version: Optional[str] = None
    removal_version: Optional[str] = None


@dataclass
class PQModuleDoc:
    """Documentation for an entire PQ module"""
    module_name: str
    category: str
    stability: PQAPIStability
    overview: str
    nist_standardized: bool = False
    endpoints: List[PQAPIEndpointDoc] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    usage_guide: str = ""


class QuantumCryptAPIDocumentationCatalog:
    """
    Comprehensive API Documentation Catalog for QuantumCrypt AI
    
    STABILITY: STABLE
    SINCE: v28.0.0
    
    This catalog provides:
    1. Complete PQ API reference with stability markers
    2. NIST security level information for each algorithm
    3. Usage examples for all major functions
    4. Quantum-safety guarantees and limitations
    5. Migration guides between versions
    """
    
    def __init__(self):
        self._modules: Dict[str, PQModuleDoc] = {}
        self._stability_stats: Dict[PQAPIStability, int] = {
            PQAPIStability.STABLE: 0,
            PQAPIStability.EXPERIMENTAL: 0,
            PQAPIStability.DEPRECATED: 0,
            PQAPIStability.LEGACY: 0
        }
        self._generated_at = datetime.datetime.now().isoformat()
        self._initialize_catalog()
    
    def _initialize_catalog(self) -> None:
        """Initialize the complete PQ API documentation catalog"""
        self._register_kem_encryption_module()
        self._register_digital_signature_module()
        self._register_key_management_module()
        self._register_security_hardening_module()
        self._register_observability_module()
        self._register_mpc_module()
    
    def _register_kem_encryption_module(self) -> None:
        """Register Post-Quantum KEM Encryption Module documentation"""
        module = PQModuleDoc(
            module_name="pq_kem_encryption",
            category="Key Encapsulation",
            stability=PQAPIStability.STABLE,
            overview="NIST-standardized Post-Quantum Key Encapsulation Mechanisms (CRYSTALS-Kyber)",
            nist_standardized=True
        )
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="hybrid_kem_generate_keypair",
            module="post_quantum_hybrid_kem_encryption_engine",
            stability=PQAPIStability.STABLE,
            description="Generate hybrid post-quantum + classical keypair (Kyber + ECC)",
            signature="hybrid_kem_generate_keypair(security_level: int = 3) -> Dict[str, Any]",
            parameters=[
                {"name": "security_level", "type": "int", "description": "NIST security level (1, 3, or 5)"}
            ],
            returns="Dictionary with 'public_key', 'secret_key', 'kem_type', 'security_level'",
            security_level="NIST Level 1/3/5",
            quantum_safe=True,
            examples=[
                """
# Generate Kyber-768 (NIST Level 3) hybrid keypair
keypair = hybrid_kem_generate_keypair(security_level=3)
pk = keypair['public_key']
sk = keypair['secret_key']
                """.strip()
            ],
            notes=["Hybrid mode: Kyber + X25519", "NIST FIPS 203 standardized"],
            since_version="v22.0.0"
        ))
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="hybrid_kem_encapsulate",
            module="post_quantum_hybrid_kem_encryption_engine",
            stability=PQAPIStability.STABLE,
            description="Encapsulate shared secret using recipient's public key",
            signature="hybrid_kem_encapsulate(public_key: bytes) -> Dict[str, Any]",
            parameters=[
                {"name": "public_key", "type": "bytes", "description": "Recipient's public key"}
            ],
            returns="Dictionary with 'ciphertext', 'shared_secret'",
            security_level="NIST Level 3",
            quantum_safe=True,
            examples=[
                """
ciphertext, shared_secret = hybrid_kem_encapsulate(recipient_pk)
send_to_recipient(ciphertext)
# Use shared_secret for symmetric encryption
                """.strip()
            ],
            notes=["IND-CCA2 secure", "Forward secrecy compatible"],
            since_version="v22.0.0"
        ))
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="hybrid_kem_decapsulate",
            module="post_quantum_hybrid_kem_encryption_engine",
            stability=PQAPIStability.STABLE,
            description="Decapsulate shared secret using secret key",
            signature="hybrid_kem_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes",
            parameters=[
                {"name": "ciphertext", "type": "bytes", "description": "Received ciphertext"},
                {"name": "secret_key", "type": "bytes", "description": "Recipient's secret key"}
            ],
            returns="Shared secret bytes",
            security_level="NIST Level 3",
            quantum_safe=True,
            examples=[
                """
shared_secret = hybrid_kem_decapsulate(received_ct, my_sk)
decrypt_message(encrypted_data, shared_secret)
                """.strip()
            ],
            since_version="v22.0.0"
        ))
        
        self._modules["pq_kem_encryption"] = module
        self._update_stability_stats(module)
    
    def _register_digital_signature_module(self) -> None:
        """Register Post-Quantum Digital Signature Module documentation"""
        module = PQModuleDoc(
            module_name="pq_digital_signature",
            category="Digital Signatures",
            stability=PQAPIStability.STABLE,
            overview="NIST-standardized Post-Quantum Digital Signatures (CRYSTALS-Dilithium)",
            nist_standardized=True
        )
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="pq_sign_generate_keypair",
            module="pqc_hybrid_signature_scheme",
            stability=PQAPIStability.STABLE,
            description="Generate post-quantum signature keypair (Dilithium)",
            signature="pq_sign_generate_keypair(mode: str = 'dilithium3') -> Dict[str, Any]",
            parameters=[
                {"name": "mode", "type": "str", "description": "Dilithium mode: dilithium2, dilithium3, dilithium5"}
            ],
            returns="Dictionary with 'public_key', 'secret_key', 'algorithm'",
            security_level="NIST Level 2/3/5",
            quantum_safe=True,
            examples=[
                """
# Generate Dilithium-3 keypair (NIST Level 3)
keypair = pq_sign_generate_keypair('dilithium3')
                """.strip()
            ],
            notes=["NIST FIPS 204 standardized", "Strongly unforgeable"],
            since_version="v28.0.0"
        ))
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="pq_sign_message",
            module="pqc_hybrid_signature_scheme",
            stability=PQAPIStability.STABLE,
            description="Sign message with post-quantum private key",
            signature="pq_sign_message(message: bytes, secret_key: bytes) -> bytes",
            parameters=[
                {"name": "message", "type": "bytes", "description": "Message to sign"},
                {"name": "secret_key", "type": "bytes", "description": "Signer's secret key"}
            ],
            returns="Signature bytes",
            security_level="NIST Level 3",
            quantum_safe=True,
            examples=[
                """
signature = pq_sign_message(document_bytes, signer_sk)
verify_signature(document_bytes, signature, signer_pk)
                """.strip()
            ],
            since_version="v28.0.0"
        ))
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="pq_composite_sign",
            module="post_quantum_composite_digital_signature_engine",
            stability=PQAPIStability.STABLE,
            description="Hybrid composite signature (PQ + classical)",
            signature="pq_composite_sign(message: bytes, pq_sk: bytes, classical_sk: bytes) -> Dict[str, bytes]",
            parameters=[
                {"name": "message", "type": "bytes", "description": "Message to sign"},
                {"name": "pq_sk", "type": "bytes", "description": "Post-quantum secret key"},
                {"name": "classical_sk", "type": "bytes", "description": "Classical (ECDSA/Ed25519) key"}
            ],
            returns="Dictionary with both signatures",
            security_level="NIST Level 3 + 128-bit classical",
            quantum_safe=True,
            examples=[
                """
# Dual verification - both must pass
result = pq_composite_sign(message, pq_sk, ed25519_sk)
                """.strip()
            ],
            notes=["Defense in depth - transition period protection"],
            since_version="v22.0.0"
        ))
        
        self._modules["pq_digital_signature"] = module
        self._update_stability_stats(module)
    
    def _register_key_management_module(self) -> None:
        """Register Post-Quantum Key Management Module documentation"""
        module = PQModuleDoc(
            module_name="pq_key_management",
            category="Key Management",
            stability=PQAPIStability.STABLE,
            overview="Post-quantum key rotation, diversification, and lifecycle management"
        )
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="KeyRotationEngine",
            module="post_quantum_key_management_rotation_engine",
            stability=PQAPIStability.STABLE,
            description="Automated post-quantum key rotation engine",
            signature="KeyRotationEngine(rotation_interval_days: int = 90)",
            parameters=[
                {"name": "rotation_interval_days", "type": "int", "description": "Automatic rotation interval"}
            ],
            returns="Key rotation engine instance",
            security_level="NIST Level 3",
            quantum_safe=True,
            examples=[
                """
rotator = KeyRotationEngine(rotation_interval_days=30)
rotator.register_key("root_kem", current_key)
if rotator.should_rotate("root_kem"):
    new_key = rotator.rotate_key("root_kem")
                """.strip()
            ],
            notes=["Zero-downtime key rotation", "Key history maintained for decryption"],
            since_version="v20.0.0"
        ))
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="derive_child_key",
            module="post_quantum_key_diversification_derivation_engine",
            stability=PQAPIStability.STABLE,
            description="HKDF-based post-quantum key derivation",
            signature="derive_child_key(master_key: bytes, context: bytes, length: int = 32) -> bytes",
            parameters=[
                {"name": "master_key", "type": "bytes", "description": "Root key material"},
                {"name": "context", "type": "bytes", "description": "Derivation context for domain separation"},
                {"name": "length", "type": "int", "description": "Output key length in bytes"}
            ],
            returns="Derived child key bytes",
            security_level="NIST Level 3",
            quantum_safe=True,
            examples=[
                """
# Derive per-user keys from master
user_key = derive_child_key(master, f"user_{user_id}".encode())
                """.strip()
            ],
            notes=["HKDF-SHA256 with domain separation", "Cryptographically secure derivation"],
            since_version="v20.0.0"
        ))
        
        self._modules["pq_key_management"] = module
        self._update_stability_stats(module)
    
    def _register_security_hardening_module(self) -> None:
        """Register PQ Security Hardening Module documentation"""
        module = PQModuleDoc(
            module_name="pq_security_hardening",
            category="Protection",
            stability=PQAPIStability.STABLE,
            overview="Side-channel resistant implementations and key material protection"
        )
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="SideChannelResistantWrapper",
            module="post_quantum_side_channel_resistant_encryption_engine",
            stability=PQAPIStability.STABLE,
            description="Timing and side-channel resistant wrapper for PQ operations",
            signature="SideChannelResistantWrapper(blinding_factor: int = 8)",
            returns="Side-channel protection wrapper instance",
            security_level="Implementation-dependent",
            quantum_safe=True,
            examples=[
                """
with SideChannelResistantWrapper():
    result = pq_private_key_operation(sk)
                """.strip()
            ],
            notes=["Masking and blinding applied", "Best-effort timing resistance"],
            since_version="v20.0.0"
        ))
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="SecurePQKeyMaterial",
            module="crypto_security_hardening_key_material_protection",
            stability=PQAPIStability.STABLE,
            description="Secure container for PQ private keys with auto-zeroization",
            signature="SecurePQKeyMaterial(key_bytes: bytes)",
            returns="Secure key container (context manager)",
            security_level="NIST Level 3",
            quantum_safe=True,
            examples=[
                """
with SecurePQKeyMaterial(private_key) as key:
    sign_with_key(key.access())
# Key automatically zeroized on exit
                """.strip()
            ],
            notes=["4-pass memory zeroization", "Cannot protect immutable Python objects"],
            since_version="v18.0.0"
        ))
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="pq_input_validation_wrapper",
            module="crypto_security_hardening_input_validation_injection_protection",
            stability=PQAPIStability.STABLE,
            description="Input validation for PQ cryptographic parameters",
            signature="pq_input_validation_wrapper(func: Callable) -> Callable",
            returns="Validated wrapper function",
            examples=[
                """
@pq_input_validation_wrapper
def secure_kem_encapsulate(pk: bytes) -> bytes:
    return kem_encapsulate(pk)
                """.strip()
            ],
            notes=["Validates key formats, lengths, and algorithm identifiers"],
            since_version="v17.0.0"
        ))
        
        self._modules["pq_security_hardening"] = module
        self._update_stability_stats(module)
    
    def _register_observability_module(self) -> None:
        """Register PQ Observability Module documentation"""
        module = PQModuleDoc(
            module_name="pq_observability",
            category="Monitoring",
            stability=PQAPIStability.STABLE,
            overview="Post-quantum crypto health monitoring and telemetry"
        )
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="PQCryptoHealthMonitor",
            module="post_quantum_cryptographic_randomness_health_monitor",
            stability=PQAPIStability.STABLE,
            description="Monitor entropy quality and randomness health",
            signature="PQCryptoHealthMonitor()",
            returns="Health monitor instance",
            examples=[
                """
monitor = PQCryptoHealthMonitor()
health = monitor.check_entropy_quality()
if health['score'] < 0.95:
    trigger_entropy_alert()
                """.strip()
            ],
            notes=["Monobit, runs, and chi-squared tests"],
            since_version="v20.0.0"
        ))
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="PQMetricsCollector",
            module="crypto_observability_instrumentation_pq_telemetry",
            stability=PQAPIStability.STABLE,
            description="PQ-specific metrics collection (OPT-IN)",
            signature="PQMetricsCollector(enabled: bool = False)",
            parameters=[
                {"name": "enabled", "type": "bool", "description": "OPT-IN - disabled by default"}
            ],
            returns="Metrics collector",
            examples=[
                """
# OPT-IN - must explicitly enable
metrics = PQMetricsCollector(enabled=True)
with metrics.timer("kem_encapsulate_latency"):
    result = kem_encapsulate(pk)
                """.strip()
            ],
            notes=["ZERO overhead when disabled"],
            since_version="v12.0.0"
        ))
        
        self._modules["pq_observability"] = module
        self._update_stability_stats(module)
    
    def _register_mpc_module(self) -> None:
        """Register MPC Module documentation"""
        module = PQModuleDoc(
            module_name="pq_secure_mpc",
            category="Multi-Party Computation",
            stability=PQAPIStability.EXPERIMENTAL,
            overview="Post-quantum secure multi-party computation (EXPERIMENTAL)"
        )
        
        module.endpoints.append(PQAPIEndpointDoc(
            name="PQSecureMPCEngine",
            module="post_quantum_secure_mpc_engine",
            stability=PQAPIStability.EXPERIMENTAL,
            description="Post-quantum secure MPC engine (under development)",
            signature="PQSecureMPCEngine(num_parties: int = 3)",
            parameters=[
                {"name": "num_parties", "type": "int", "description": "Number of compute parties"}
            ],
            returns="MPC engine instance",
            security_level="Research-grade",
            quantum_safe=True,
            examples=[
                """
# EXPERIMENTAL - API subject to change
mpc = PQSecureMPCEngine(num_parties=3)
result = mpc.compute_joint_signature(shares)
                """.strip()
            ],
            notes=["EXPERIMENTAL: Research implementation only", "Not for production use"],
            since_version="v36.0.0"
        ))
        
        self._modules["pq_secure_mpc"] = module
        self._update_stability_stats(module)
    
    def _update_stability_stats(self, module: PQModuleDoc) -> None:
        """Update stability statistics"""
        for endpoint in module.endpoints:
            self._stability_stats[endpoint.stability] += 1
    
    def get_module_documentation(self, module_name: str) -> Optional[PQModuleDoc]:
        """Get documentation for a specific module"""
        return self._modules.get(module_name)
    
    def get_all_modules(self) -> List[str]:
        """Get list of all documented modules"""
        return list(self._modules.keys())
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get summary of API stability distribution"""
        return {
            stability.value: count
            for stability, count in self._stability_stats.items()
        }
    
    def get_nist_standardized_modules(self) -> List[str]:
        """Get list of NIST-standardized modules"""
        return [name for name, mod in self._modules.items() if mod.nist_standardized]
    
    def generate_markdown_docs(self) -> str:
        """Generate comprehensive Markdown documentation"""
        lines = [
            "# QuantumCrypt AI - Post-Quantum API Documentation Catalog",
            f"**Generated:** {self._generated_at}",
            f"**Version:** v28",
            "",
            "## API Stability Summary",
            ""
        ]
        
        for stability, count in self._stability_stats.items():
            lines.append(f"- **{stability.value}**: {count} endpoints")
        
        lines.extend([
            "",
            "## NIST-Standardized Modules",
            ""
        ])
        
        for mod_name in self.get_nist_standardized_modules():
            mod = self._modules[mod_name]
            lines.append(f"- **{mod_name}**: {mod.overview}")
        
        lines.extend(["", "---", ""])
        
        for module_name, module in sorted(self._modules.items()):
            nist_badge = "✅ NIST Standardized" if module.nist_standardized else "⚠️ Non-Standardized"
            
            lines.extend([
                f"## Module: {module.module_name}",
                f"**Category:** {module.category}",
                f"**Stability:** {module.stability.value}",
                f"**NIST:** {nist_badge}",
                "",
                module.overview,
                ""
            ])
            
            for endpoint in module.endpoints:
                stability_badge = f"[{endpoint.stability.value}]"
                if endpoint.stability == PQAPIStability.EXPERIMENTAL:
                    stability_badge = "⚠️ [EXPERIMENTAL]"
                elif endpoint.stability == PQAPIStability.DEPRECATED:
                    stability_badge = "❌ [DEPRECATED]"
                
                quantum_badge = "🔒 Quantum-Safe" if endpoint.quantum_safe else "⚠️ Not Quantum-Safe"
                
                lines.extend([
                    f"### {endpoint.name} {stability_badge}",
                    "",
                    endpoint.description,
                    "",
                    f"**Signature:** `{endpoint.signature}`",
                    f"**Security Level:** {endpoint.security_level}",
                    f"**Quantum-Safe:** {quantum_badge}",
                    f"**Since:** {endpoint.since_version}",
                    "",
                    "**Parameters:**",
                    ""
                ])
                
                for param in endpoint.parameters:
                    lines.append(f"- `{param['name']}` ({param['type']}): {param['description']}")
                
                lines.extend([
                    "",
                    f"**Returns:** {endpoint.returns}",
                    ""
                ])
                
                if endpoint.examples:
                    lines.extend(["**Example:**", "", "```python"])
                    lines.append(endpoint.examples[0])
                    lines.extend(["```", ""])
                
                if endpoint.notes:
                    lines.append("**Notes:**")
                    for note in endpoint.notes:
                        lines.append(f"- {note}")
                    lines.append("")
                
                lines.append("---")
                lines.append("")
        
        return "\n".join(lines)
    
    def get_quick_reference(self) -> Dict[str, Any]:
        """Get quick reference guide for PQ crypto"""
        return {
            "getting_started": {
                "kem_encryption": "Use hybrid_kem_generate_keypair() for key exchange",
                "digital_signatures": "Use pq_composite_sign() for defense-in-depth",
                "key_management": "Use KeyRotationEngine for automated key rotation"
            },
            "nist_security_levels": {
                "Level 1": "128-bit security (Kyber-512, Dilithium-2)",
                "Level 3": "192-bit security (Kyber-768, Dilithium-3)",
                "Level 5": "256-bit security (Kyber-1024, Dilithium-5)"
            },
            "migration_guide": {
                "immediate": "Deploy hybrid mode today (PQ + classical)",
                "long_term": "Plan full PQ migration by 2030",
                "key_rotation": "Rotate keys every 90 days minimum"
            },
            "stability_guarantees": {
                "STABLE": "Production-ready, NIST-standardized",
                "EXPERIMENTAL": "Research, subject to change",
                "DEPRECATED": "Will be removed",
                "LEGACY": "Pre-NIST algorithms"
            }
        }


# Singleton instance for easy import
_pq_api_catalog = None


def get_pq_documentation_catalog() -> QuantumCryptAPIDocumentationCatalog:
    """Get the singleton PQ documentation catalog instance"""
    global _pq_api_catalog
    if _pq_api_catalog is None:
        _pq_api_catalog = QuantumCryptAPIDocumentationCatalog()
    return _pq_api_catalog


# Version information
__version__ = "28.0.0"
__api_stability__ = "STABLE"
__documentation_complete__ = True
__nist_compliant__ = True

if __name__ == "__main__":
    catalog = get_pq_documentation_catalog()
    print("QuantumCrypt PQ API Documentation Catalog v28")
    print("=" * 60)
    print(f"Modules documented: {len(catalog.get_all_modules())}")
    print(f"NIST-standardized: {len(catalog.get_nist_standardized_modules())}")
    print(f"Stability summary: {catalog.get_stability_summary()}")
    print("\nQuick Reference:")
    for key, value in catalog.get_quick_reference()["getting_started"].items():
        print(f"  {key}: {value}")
