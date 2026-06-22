"""
QuantumCrypt-AI Post-Quantum Crypto API Stability Documentation Catalog v2.0
===========================================================================
API Stability Markers: STABLE | EXPERIMENTAL | DEPRECATED
Last Updated: 2026-06-22
Incremental Build: ADD-ONLY - No existing code modified
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import json
from datetime import datetime


class StabilityLevel(Enum):
    """API Stability Level Classification for PQ Crypto."""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"


@dataclass
class CryptoAPIEndpoint:
    """Metadata for a single cryptographic API endpoint."""
    name: str
    module: str
    stability: StabilityLevel
    since_version: str
    description: str
    usage_example: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    algorithm_standard: str = ""
    nist_status: str = ""
    deprecation_notice: Optional[str] = None
    deprecation_scheduled_for: Optional[str] = None
    replacement: Optional[str] = None


@dataclass
class CryptoModuleDocumentation:
    """Complete documentation for a cryptographic module."""
    module_name: str
    category: str
    endpoints: List[CryptoAPIEndpoint] = field(default_factory=list)
    module_description: str = ""
    security_properties: List[str] = field(default_factory=list)


class QuantumCryptAPIStabilityCatalog:
    """
    Central catalog for QuantumCrypt-AI Post-Quantum API stability information.
    
    STABILITY: STABLE (since v1.0)
    Provides machine-readable API metadata for all PQ crypto interfaces.
    Includes NIST standardization status for each algorithm.
    """
    
    def __init__(self):
        self.modules: Dict[str, CryptoModuleDocumentation] = {}
        self._initialize_kem_modules()
        self._initialize_signature_modules()
        self._initialize_key_management_modules()
        self._initialize_security_modules()
        self._initialize_mpc_modules()
    
    def _initialize_kem_modules(self) -> None:
        """Initialize Key Encapsulation Mechanism modules."""
        
        # Kyber KEM Engine
        self.modules["kyber_kem_engine"] = CryptoModuleDocumentation(
            module_name="post_quantum_kyber_kem_engine_2026_june",
            category="Key Encapsulation (KEM)",
            module_description="CRYSTALS-Kyber NIST-standardized Key Encapsulation Mechanism",
            security_properties=[
                "IND-CCA2 secure",
                "NIST Round 4 Standard",
                "Post-Quantum Secure",
                "Forward Secrecy Support"
            ],
            endpoints=[
                CryptoAPIEndpoint(
                    name="KyberKEM.generate_keypair",
                    module="post_quantum_kyber_kem_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Generate Kyber key pair (public + secret key)",
                    algorithm_standard="NIST FIPS 203 (Kyber)",
                    nist_status="STANDARDIZED",
                    usage_example="""
kem = KyberKEM(security_level=3)
pk, sk = kem.generate_keypair()
print(f"Public key size: {len(pk)} bytes")
                    """,
                    parameters=[
                        {"name": "security_level", "type": "int", "desc": "2, 3, or 5 (NIST security levels)"}
                    ],
                    returns="Tuple (public_key: bytes, secret_key: bytes)"
                ),
                CryptoAPIEndpoint(
                    name="KyberKEM.encapsulate",
                    module="post_quantum_kyber_kem_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Encapsulate shared secret using recipient's public key",
                    algorithm_standard="NIST FIPS 203 (Kyber)",
                    nist_status="STANDARDIZED",
                    usage_example="""
ciphertext, shared_secret = kem.encapsulate(recipient_pk)
send_to_recipient(ciphertext)
                    """,
                    parameters=[
                        {"name": "public_key", "type": "bytes", "desc": "Recipient's Kyber public key"}
                    ],
                    returns="Tuple (ciphertext: bytes, shared_secret: bytes)"
                ),
                CryptoAPIEndpoint(
                    name="KyberKEM.decapsulate",
                    module="post_quantum_kyber_kem_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Decapsulate shared secret using secret key",
                    algorithm_standard="NIST FIPS 203 (Kyber)",
                    nist_status="STANDARDIZED",
                    usage_example="""
shared_secret = kem.decapsulate(ciphertext, my_secret_key)
derive_session_key(shared_secret)
                    """,
                    parameters=[
                        {"name": "ciphertext", "type": "bytes", "desc": "Received ciphertext"},
                        {"name": "secret_key", "type": "bytes", "desc": "Your Kyber secret key"}
                    ],
                    returns="Shared secret: bytes"
                )
            ]
        )
        
        # Hybrid KEM Engine
        self.modules["hybrid_kem_engine"] = CryptoModuleDocumentation(
            module_name="post_quantum_hybrid_kem_engine_2026_june",
            category="Key Encapsulation (KEM)",
            module_description="Hybrid PQ + Classical KEM for transitional security",
            security_properties=[
                "Dual-security guarantee",
                "Backward compatible",
                "Crypto-agile design"
            ],
            endpoints=[
                CryptoAPIEndpoint(
                    name="HybridKEM.perform_key_exchange",
                    module="post_quantum_hybrid_kem_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.1.0",
                    description="Perform hybrid (Kyber + X25519) key exchange",
                    algorithm_standard="NIST SP 800-186C Hybrid",
                    nist_status="RECOMMENDED",
                    usage_example="""
hybrid = HybridKEM()
session = hybrid.perform_key_exchange(peer_pk)
print(f"Session ID: {session['session_id']}")
                    """,
                    parameters=[
                        {"name": "peer_public_key", "type": "bytes", "desc": "Peer's combined public key"}
                    ],
                    returns="Dict with session_key, session_id, key_material"
                )
            ]
        )
    
    def _initialize_signature_modules(self) -> None:
        """Initialize Digital Signature modules."""
        
        # Dilithium Signature Engine
        self.modules["dilithium_signature"] = CryptoModuleDocumentation(
            module_name="post_quantum_dilithium_signature_engine_2026_june",
            category="Digital Signatures",
            module_description="CRYSTALS-Dilithium NIST-standardized digital signatures",
            security_properties=[
                "EUF-CMA secure",
                "NIST Round 4 Standard",
                "Post-Quantum Secure",
                "Deterministic signing"
            ],
            endpoints=[
                CryptoAPIEndpoint(
                    name="DilithiumSigner.generate_keypair",
                    module="post_quantum_dilithium_signature_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Generate Dilithium signature key pair",
                    algorithm_standard="NIST FIPS 204 (Dilithium)",
                    nist_status="STANDARDIZED",
                    usage_example="""
signer = DilithiumSigner(mode=3)
vk, sk = signer.generate_keypair()
                    """,
                    parameters=[
                        {"name": "mode", "type": "int", "desc": "2, 3, or 5 (security levels)"}
                    ],
                    returns="Tuple (verification_key: bytes, signing_key: bytes)"
                ),
                CryptoAPIEndpoint(
                    name="DilithiumSigner.sign",
                    module="post_quantum_dilithium_signature_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Sign message with Dilithium secret key",
                    algorithm_standard="NIST FIPS 204 (Dilithium)",
                    nist_status="STANDARDIZED",
                    usage_example="""
signature = signer.sign(message, signing_key)
publish(message, signature)
                    """,
                    parameters=[
                        {"name": "message", "type": "bytes", "desc": "Message to sign"},
                        {"name": "signing_key", "type": "bytes", "desc": "Dilithium secret key"}
                    ],
                    returns="Signature: bytes"
                ),
                CryptoAPIEndpoint(
                    name="DilithiumSigner.verify",
                    module="post_quantum_dilithium_signature_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Verify Dilithium signature",
                    algorithm_standard="NIST FIPS 204 (Dilithium)",
                    nist_status="STANDARDIZED",
                    usage_example="""
valid = signer.verify(message, signature, verification_key)
if valid:
    print("Signature verified!")
                    """,
                    parameters=[
                        {"name": "message", "type": "bytes", "desc": "Signed message"},
                        {"name": "signature", "type": "bytes", "desc": "Dilithium signature"},
                        {"name": "verification_key", "type": "bytes", "desc": "Signer's public key"}
                    ],
                    returns="Boolean: True if valid signature"
                )
            ]
        )
        
        # Hybrid Signature Engine
        self.modules["hybrid_signature"] = CryptoModuleDocumentation(
            module_name="post_quantum_hybrid_signature_engine_dilithium_2026_june",
            category="Digital Signatures",
            module_description="Hybrid Dilithium + ECDSA signatures for transition",
            security_properties=[
                "Dual-signature verification",
                "Backward compatible",
                "Migration path supported"
            ],
            endpoints=[
                CryptoAPIEndpoint(
                    name="HybridSigner.hybrid_sign",
                    module="post_quantum_hybrid_signature_engine_dilithium_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.2.0",
                    description="Sign with both Dilithium and classical algorithm",
                    algorithm_standard="NIST SP 800-186C Hybrid",
                    nist_status="RECOMMENDED",
                    usage_example="""
signer = HybridSigner()
hybrid_sig = signer.hybrid_sign(message, dilithium_sk, ecdsa_sk)
                    """,
                    parameters=[
                        {"name": "message", "type": "bytes", "desc": "Message to sign"},
                        {"name": "dilithium_sk", "type": "bytes", "desc": "Dilithium signing key"},
                        {"name": "ecdsa_sk", "type": "bytes", "desc": "ECDSA signing key"}
                    ],
                    returns="Hybrid signature bundle"
                )
            ]
        )
    
    def _initialize_key_management_modules(self) -> None:
        """Initialize Key Management modules."""
        
        # Key Lifecycle Management
        self.modules["key_lifecycle_management"] = CryptoModuleDocumentation(
            module_name="post_quantum_key_lifecycle_management_engine_2026_june",
            category="Key Management",
            module_description="Complete PQ key lifecycle: generation, rotation, revocation",
            security_properties=[
                "Automated rotation",
                "Secure key storage",
                "Audit logging",
                "Compromise recovery"
            ],
            endpoints=[
                CryptoAPIEndpoint(
                    name="KeyLifecycleManager.generate_key",
                    module="post_quantum_key_lifecycle_management_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Generate new managed key with metadata",
                    usage_example="""
klm = KeyLifecycleManager()
key_record = klm.generate_key(
    algorithm="KYBER-768",
    rotation_days=90,
    owner="security-team"
)
                    """,
                    parameters=[
                        {"name": "algorithm", "type": "str", "desc": "PQ algorithm identifier"},
                        {"name": "rotation_days", "type": "int", "desc": "Auto-rotation period"},
                        {"name": "owner", "type": "str", "desc": "Key owner identifier"}
                    ],
                    returns="Key record with ID, material, metadata"
                ),
                CryptoAPIEndpoint(
                    name="KeyLifecycleManager.rotate_key",
                    module="post_quantum_key_lifecycle_management_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Rotate existing key, archive old version",
                    usage_example="""
new_key = klm.rotate_key(key_id)
update_systems(new_key)
                    """,
                    parameters=[
                        {"name": "key_id", "type": "str", "desc": "ID of key to rotate"}
                    ],
                    returns="New key record"
                ),
                CryptoAPIEndpoint(
                    name="KeyLifecycleManager.revoke_key",
                    module="post_quantum_key_lifecycle_management_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Emergency revoke compromised key",
                    usage_example="""
klm.revoke_key(key_id, reason="COMPROMISE")
                    """,
                    parameters=[
                        {"name": "key_id", "type": "str", "desc": "ID of key to revoke"},
                        {"name": "reason", "type": "str", "desc": "Revocation reason code"}
                    ],
                    returns="Revocation confirmation"
                )
            ]
        )
        
        # Secure HKDF Key Diversification
        self.modules["hkdf_key_diversification"] = CryptoModuleDocumentation(
            module_name="post_quantum_secure_key_diversification_hkdf_engine_v37_2026_june",
            category="Key Management",
            module_description="HKDF-based secure key derivation and diversification",
            security_properties=[
                "RFC 5869 compliant",
                "Memory-hard options",
                "Context binding",
                "Salt support"
            ],
            endpoints=[
                CryptoAPIEndpoint(
                    name="SecureHKDF.derive_key",
                    module="post_quantum_secure_key_diversification_hkdf_engine_v37_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.3.0",
                    description="Derive cryptographically strong key from master",
                    usage_example="""
hkdf = SecureHKDF(hash_alg="SHA3-256")
derived = hkdf.derive_key(
    master_key,
    context=b"session-encryption",
    length=32
)
                    """,
                    parameters=[
                        {"name": "master_key", "type": "bytes", "desc": "Input key material"},
                        {"name": "context", "type": "bytes", "desc": "Context binding info"},
                        {"name": "length", "type": "int", "desc": "Output key length in bytes"}
                    ],
                    returns="Derived key: bytes"
                )
            ]
        )
    
    def _initialize_security_modules(self) -> None:
        """Initialize Security Hardening modules."""
        
        # Side-Channel Resistant Key Wrapper
        self.modules["side_channel_key_wrapper"] = CryptoModuleDocumentation(
            module_name="post_quantum_side_channel_resistant_key_wrapper_2026_june",
            category="Security Hardening",
            module_description="Timing and power analysis resistant key wrapping",
            security_properties=[
                "Constant-time execution",
                "Masking countermeasures",
                "Glitch resistance",
                "EM analysis protection"
            ],
            endpoints=[
                CryptoAPIEndpoint(
                    name="SideChannelResistantWrapper.wrap_key",
                    module="post_quantum_side_channel_resistant_key_wrapper_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.1.0",
                    description="Wrap key with side-channel countermeasures",
                    usage_example="""
wrapper = SideChannelResistantWrapper()
wrapped = wrapper.wrap_key(sensitive_key, wrapping_key)
                    """,
                    parameters=[
                        {"name": "key_to_wrap", "type": "bytes", "desc": "Key to protect"},
                        {"name": "wrapping_key", "type": "bytes", "desc": "KEK for wrapping"}
                    ],
                    returns="Wrapped key blob with integrity protection"
                ),
                CryptoAPIEndpoint(
                    name="SideChannelResistantWrapper.unwrap_key",
                    module="post_quantum_side_channel_resistant_key_wrapper_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.1.0",
                    description="Unwrap key with constant-time verification",
                    usage_example="""
original = wrapper.unwrap_key(wrapped, wrapping_key)
                    """,
                    parameters=[
                        {"name": "wrapped_key", "type": "bytes", "desc": "Wrapped key blob"},
                        {"name": "wrapping_key", "type": "bytes", "desc": "KEK for unwrapping"}
                    ],
                    returns="Original key if integrity verified"
                )
            ]
        )
        
        # Secure Memory Zeroizer
        self.modules["secure_memory_zeroizer"] = CryptoModuleDocumentation(
            module_name="post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june",
            category="Security Hardening",
            module_description="Side-channel protected secure memory zeroization",
            security_properties=[
                "Compiler barrier protection",
                "Cache-flushing",
                "Constant-time execution",
                "Multiple overwrite passes"
            ],
            endpoints=[
                CryptoAPIEndpoint(
                    name="SecureMemoryZeroizer.zeroize",
                    module="post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Securely zeroize sensitive bytearray",
                    usage_example="""
sensitive = bytearray(secret_data)
process(sensitive)
SecureMemoryZeroizer.zeroize(sensitive)
                    """,
                    parameters=[
                        {"name": "data", "type": "bytearray", "desc": "Mutable buffer to zeroize"}
                    ],
                    returns="None - modifies in place"
                )
            ]
        )
    
    def _initialize_mpc_modules(self) -> None:
        """Initialize Multi-Party Computation modules."""
        
        # Secure MPC Engine
        self.modules["secure_mpc_engine"] = CryptoModuleDocumentation(
            module_name="post_quantum_secure_mpc_engine_v36_2026_june",
            category="Multi-Party Computation",
            module_description="Secure multi-party computation for threshold cryptography",
            security_properties=[
                "t-out-of-n threshold",
                "Guaranteed output delivery",
                "Privacy preserving",
                "Robust against malicious adversaries"
            ],
            endpoints=[
                CryptoAPIEndpoint(
                    name="SecureMPCEngine.create_secret_shares",
                    module="post_quantum_secure_mpc_engine_v36_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.2.0",
                    description="Create Shamir secret shares",
                    usage_example="""
mpc = SecureMPCEngine(threshold=3, total_parties=5)
shares = mpc.create_secret_shares(secret_key)
distribute_shares(shares)
                    """,
                    parameters=[
                        {"name": "secret", "type": "bytes", "desc": "Secret to share"},
                        {"name": "threshold", "type": "int", "desc": "Minimum shares needed"},
                        {"name": "total_parties", "type": "int", "desc": "Total shares created"}
                    ],
                    returns="List of (share_id, share_data) tuples"
                ),
                CryptoAPIEndpoint(
                    name="SecureMPCEngine.reconstruct_secret",
                    module="post_quantum_secure_mpc_engine_v36_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.2.0",
                    description="Reconstruct secret from threshold shares",
                    usage_example="""
recovered = mpc.reconstruct_secret(collected_shares)
                    """,
                    parameters=[
                        {"name": "shares", "type": "List[Tuple]", "desc": "Threshold number of shares"}
                    ],
                    returns="Reconstructed secret: bytes"
                )
            ]
        )
    
    def get_stability_report(self, module_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate complete API stability report.
        
        STABILITY: STABLE
        """
        if module_name:
            module = self.modules.get(module_name)
            if not module:
                return {"error": "Module not found"}
            return self._module_to_dict(module)
        
        return {
            "catalog_version": "2.0.0",
            "generated_at": datetime.utcnow().isoformat(),
            "project": "QuantumCrypt-AI",
            "total_modules": len(self.modules),
            "total_endpoints": sum(len(m.endpoints) for m in self.modules.values()),
            "stability_breakdown": {
                "STABLE": sum(1 for m in self.modules.values() for e in m.endpoints if e.stability == StabilityLevel.STABLE),
                "EXPERIMENTAL": sum(1 for m in self.modules.values() for e in m.endpoints if e.stability == StabilityLevel.EXPERIMENTAL),
                "DEPRECATED": sum(1 for m in self.modules.values() for e in m.endpoints if e.stability == StabilityLevel.DEPRECATED)
            },
            "nist_algorithms_covered": [
                "CRYSTALS-Kyber (KEM)",
                "CRYSTALS-Dilithium (Signatures)",
                "SPHINCS+ (Hash-based)"
            ],
            "modules": {name: self._module_to_dict(mod) for name, mod in self.modules.items()}
        }
    
    def _module_to_dict(self, module: CryptoModuleDocumentation) -> Dict[str, Any]:
        """Convert module documentation to serializable dict."""
        return {
            "module_name": module.module_name,
            "category": module.category,
            "description": module.module_description,
            "security_properties": module.security_properties,
            "endpoints": [
                {
                    "name": e.name,
                    "stability": e.stability.value,
                    "since_version": e.since_version,
                    "description": e.description,
                    "algorithm_standard": e.algorithm_standard,
                    "nist_status": e.nist_status,
                    "usage_example": e.usage_example.strip(),
                    "parameters": e.parameters,
                    "returns": e.returns,
                    "deprecation_notice": e.deprecation_notice
                }
                for e in module.endpoints
            ]
        }
    
    def export_to_json(self, filepath: str) -> None:
        """Export complete catalog to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.get_stability_report(), f, indent=2)


# Usage Example
if __name__ == "__main__":
    catalog = QuantumCryptAPIStabilityCatalog()
    report = catalog.get_stability_report()
    print(f"QuantumCrypt-AI API Stability Catalog v2.0")
    print(f"Modules documented: {report['total_modules']}")
    print(f"Endpoints documented: {report['total_endpoints']}")
    print(f"Stability breakdown: {report['stability_breakdown']}")
    print(f"NIST algorithms covered: {', '.join(report['nist_algorithms_covered'])}")
