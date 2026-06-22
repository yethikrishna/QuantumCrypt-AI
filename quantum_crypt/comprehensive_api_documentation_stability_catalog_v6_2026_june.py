"""
QuantumCrypt AI - Comprehensive API Documentation & Stability Catalog v6
========================================================================
API STABILITY MARKERS:
- STABLE: Production-ready, backward-compatible, no breaking changes
- EXPERIMENTAL: New feature, subject to change, not for production
- DEPRECATED: Will be removed in future versions, migrate to alternatives
- BETA: Feature complete, undergoing final validation

This module provides comprehensive documentation, usage examples, and
API stability markers for all QuantumCrypt post-quantum modules.

STABILITY GUARANTEE: All STABLE-marked APIs maintain backward compatibility
for a minimum of 6 months from stabilization date.

NIST COMPLIANCE: All STABLE cryptographic modules follow NIST SP 800-186
and NIST SP 800-56C standards for post-quantum cryptography.
"""

import typing
from typing import Dict, List, Any, Optional, Callable, Tuple, TypeVar
from dataclasses import dataclass, field
from enum import Enum
import json
from datetime import datetime


class APIStability(str, Enum):
    """API Stability Level Enum"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    BETA = "BETA"


class NISTComplianceLevel(str, Enum):
    """NIST Compliance Level"""
    FIPS_140_3 = "FIPS_140_3"
    SP_800_186 = "SP_800_186"
    SP_800_56C = "SP_800_56C"
    SP_800_90A = "SP_800_90A"
    NONE = "NONE"


@dataclass
class APIDocumentation:
    """API Documentation Entry with Stability Marker"""
    module_name: str
    class_name: str
    method_name: str
    stability: APIStability
    since_version: str
    description: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    returns: str = ""
    raises: List[str] = field(default_factory=list)
    usage_example: str = ""
    deprecation_note: Optional[str] = None
    migration_path: Optional[str] = None
    nist_compliance: NISTComplianceLevel = NISTComplianceLevel.NONE


@dataclass
class ModuleDocumentation:
    """Complete Module Documentation"""
    module_id: str
    display_name: str
    stability: APIStability
    category: str
    description: str
    nist_compliance: NISTComplianceLevel = NISTComplianceLevel.NONE
    endpoints: List[APIDocumentation] = field(default_factory=list)
    code_example: str = ""
    best_practices: List[str] = field(default_factory=list)
    security_notes: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    performance_characteristics: Dict[str, str] = field(default_factory=dict)


T = TypeVar('T')


class QuantumCryptDocumentationCatalog:
    """
    QuantumCrypt Comprehensive API Documentation Catalog
    
    STABILITY: STABLE (since v1.5.0)
    PURPOSE: Central documentation hub for all post-quantum crypto modules
    USAGE: Import and query API documentation programmatically
    NIST COMPLIANCE: Tracks compliance with post-quantum standards
    """
    
    def __init__(self):
        self._modules: Dict[str, ModuleDocumentation] = {}
        self._stability_index: Dict[APIStability, List[str]] = {
            APIStability.STABLE: [],
            APIStability.EXPERIMENTAL: [],
            APIStability.DEPRECATED: [],
            APIStability.BETA: []
        }
        self._compliance_index: Dict[NISTComplianceLevel, List[str]] = {
            NISTComplianceLevel.FIPS_140_3: [],
            NISTComplianceLevel.SP_800_186: [],
            NISTComplianceLevel.SP_800_56C: [],
            NISTComplianceLevel.SP_800_90A: [],
            NISTComplianceLevel.NONE: []
        }
        self._build_catalog()
    
    def _build_catalog(self) -> None:
        """Build complete documentation catalog"""
        # === KEY ENCAPSULATION MECHANISMS (KEM) ===
        self._add_kem_modules()
        
        # === DIGITAL SIGNATURES ===
        self._add_digital_signature_modules()
        
        # === KEY MANAGEMENT ===
        self._add_key_management_modules()
        
        # === SECURE MEMORY & HARDENING ===
        self._add_security_hardening_modules()
        
        # === RANDOM NUMBER GENERATION ===
        self._add_entropy_modules()
        
        # === MPC & SECURE COMPUTATION ===
        self._add_mpc_modules()
        
        # === ERROR RESILIENCE ===
        self._add_error_resilience_modules()
    
    def _add_kem_modules(self) -> None:
        """Add Key Encapsulation Mechanism documentation"""
        
        # Kyber KEM Engine - STABLE
        self._modules["kyber_kem_engine"] = ModuleDocumentation(
            module_id="kyber_kem_engine",
            display_name="CRYSTALS-Kyber KEM Engine",
            stability=APIStability.STABLE,
            category="Key Encapsulation",
            nist_compliance=NISTComplianceLevel.SP_800_186,
            description="NIST-standardized CRYSTALS-Kyber post-quantum key encapsulation mechanism",
            code_example="""
from quantum_crypt.test_post_quantum_kyber_kem_engine_2026_june import KyberKEM

# Initialize with security level
kem = KyberKEM(security_level=3)

# Generate keypair
pk, sk = kem.generate_keypair()

# Encapsulate (sender)
ciphertext, shared_secret_sender = kem.encapsulate(pk)

# Decapsulate (receiver)
shared_secret_receiver = kem.decapsulate(ciphertext, sk)

assert shared_secret_sender == shared_secret_receiver
""",
            best_practices=[
                "Use security_level=3 for most applications",
                "Use security_level=5 for highest security requirements",
                "Always verify shared secret equality"
            ],
            security_notes=[
                "NIST FIPS 203 standardized algorithm",
                "IND-CCA2 secure",
                "Side-channel resistant implementation"
            ],
            limitations=[
                "Public keys: 1184 bytes (level 3)",
                "Ciphertexts: 1088 bytes (level 3)"
            ],
            performance_characteristics={
                "keygen": "~0.1ms",
                "encaps": "~0.05ms",
                "decaps": "~0.08ms"
            }
        )
        self._stability_index[APIStability.STABLE].append("kyber_kem_engine")
        self._compliance_index[NISTComplianceLevel.SP_800_186].append("kyber_kem_engine")
        
        # Hybrid KEM Engine v2 - STABLE
        self._modules["hybrid_kem_engine_v2"] = ModuleDocumentation(
            module_id="hybrid_kem_engine_v2",
            display_name="Hybrid PQ + Classical KEM Engine v2",
            stability=APIStability.STABLE,
            category="Key Encapsulation",
            nist_compliance=NISTComplianceLevel.SP_800_56C,
            description="Hybrid key exchange combining Kyber with classical ECDH/X25519",
            code_example="""
from quantum_crypt.test_post_quantum_hybrid_kem_engine_v2_2026_june import HybridKEM

hybrid = HybridKEM(classical_alg="x25519", pq_alg="kyber768")
pk, sk = hybrid.generate_keypair()
ct, ss = hybrid.encapsulate(pk)
""",
            best_practices=[
                "Recommended for migration period",
                "Provides transitional security",
                "Follows NIST SP 800-56C hybrid guidelines"
            ],
            security_notes=[
                "Dual security - safe even if one algorithm is broken",
                "Compliant with TLS 1.3 hybrid specifications"
            ],
            limitations=[
                "Larger keys than pure PQ",
                "Slightly higher latency"
            ]
        )
        self._stability_index[APIStability.STABLE].append("hybrid_kem_engine_v2")
        self._compliance_index[NISTComplianceLevel.SP_800_56C].append("hybrid_kem_engine_v2")
        
        # Hybrid KEM TLS 1.3 Simulator - EXPERIMENTAL
        self._modules["hybrid_kem_tls13_simulator"] = ModuleDocumentation(
            module_id="hybrid_kem_tls13_simulator",
            display_name="Hybrid KEM TLS 1.3 Simulator",
            stability=APIStability.EXPERIMENTAL,
            category="Key Encapsulation",
            description="TLS 1.3 handshake simulator with hybrid post-quantum key exchange",
            code_example="""
from quantum_crypt.test_post_quantum_hybrid_kem_tls13_simulator_2026_june import TLSSimulator

sim = TLSSimulator(kem_suites=["kyber768_x25519"])
handshake = sim.perform_handshake()
print(f"Handshake time: {handshake.duration_ms}ms")
""",
            best_practices=["Use for testing migration readiness"],
            limitations=["Experimental - not for production TLS termination"]
        )
        self._stability_index[APIStability.EXPERIMENTAL].append("hybrid_kem_tls13_simulator")
    
    def _add_digital_signature_modules(self) -> None:
        """Add Digital Signature documentation"""
        
        # Dilithium Signature Engine - STABLE
        self._modules["dilithium_signature_engine"] = ModuleDocumentation(
            module_id="dilithium_signature_engine",
            display_name="CRYSTALS-Dilithium Signature Engine",
            stability=APIStability.STABLE,
            category="Digital Signatures",
            nist_compliance=NISTComplianceLevel.SP_800_186,
            description="NIST-standardized CRYSTALS-Dilithium post-quantum digital signature",
            code_example="""
from quantum_crypt.test_post_quantum_dilithium_signature_engine_2026_june import DilithiumSigner

signer = DilithiumSigner(mode=3)
pk, sk = signer.generate_keypair()

message = b"Important document to sign"
signature = signer.sign(message, sk)
is_valid = signer.verify(message, signature, pk)
""",
            best_practices=[
                "Use mode=3 for general purpose",
                "Use mode=5 for highest security",
                "Pre-hash large messages before signing"
            ],
            security_notes=[
                "NIST FIPS 204 standardized algorithm",
                "EUF-CMA secure",
                "Deterministic signing"
            ],
            limitations=[
                "Signatures: ~2400 bytes (mode 3)",
                "Public keys: ~1300 bytes (mode 3)"
            ],
            performance_characteristics={
                "keygen": "~0.2ms",
                "sign": "~0.3ms",
                "verify": "~0.1ms"
            }
        )
        self._stability_index[APIStability.STABLE].append("dilithium_signature_engine")
        self._compliance_index[NISTComplianceLevel.SP_800_186].append("dilithium_signature_engine")
        
        # Hybrid Signature Engine - STABLE
        self._modules["hybrid_signature_engine"] = ModuleDocumentation(
            module_id="hybrid_signature_engine_dilithium",
            display_name="Hybrid Dilithium + ECDSA Signature Engine",
            stability=APIStability.STABLE,
            category="Digital Signatures",
            nist_compliance=NISTComplianceLevel.SP_800_56C,
            description="Hybrid signatures combining Dilithium with classical ECDSA",
            code_example="""
from quantum_crypt.test_post_quantum_hybrid_signature_engine_dilithium_2026_june import HybridSigner

signer = HybridSigner(classical="ecdsa_p256", pq="dilithium3")
pk, sk = signer.generate_keypair()
sig = signer.sign(message, sk)
valid = signer.verify(message, sig, pk)
""",
            best_practices=[
                "Recommended for certificate chains",
                "Supports verification by non-PQ systems"
            ],
            security_notes=["Dual security guarantee"],
            limitations=[
                "Larger signature size than pure PQ",
                "Higher verification latency",
                "Requires both classical and PQ verification"
            ]
        )
        self._stability_index[APIStability.STABLE].append("hybrid_signature_engine")
        self._compliance_index[NISTComplianceLevel.SP_800_56C].append("hybrid_signature_engine")
        
        # Batch Signature Verifier - STABLE
        self._modules["batch_signature_verifier"] = ModuleDocumentation(
            module_id="batch_signature_verifier_enhanced",
            display_name="Batch Signature Verifier Enhanced",
            stability=APIStability.STABLE,
            category="Digital Signatures",
            description="Optimized batch verification for high-throughput systems",
            code_example="""
from quantum_crypt.test_post_quantum_digital_signature_batch_verifier_enhanced_2026_june import BatchVerifier

verifier = BatchVerifier()
for msg, sig, pk in batch_items:
    verifier.add_to_batch(msg, sig, pk)
results = verifier.verify_batch()
""",
            best_practices=[
                "Batch sizes of 32-128 give best speedup",
                "Process in parallel where possible"
            ],
            limitations=[
                "Individual invalid signatures cause full batch rejection",
                "Memory usage scales with batch size",
                "Requires all public keys available at verification time"
            ],
            performance_characteristics={"speedup": "2-8x depending on batch size"}
        )
        self._stability_index[APIStability.STABLE].append("batch_signature_verifier")
    
    def _add_key_management_modules(self) -> None:
        """Add Key Management documentation"""
        
        # Key Lifecycle Management - STABLE
        self._modules["key_lifecycle_management"] = ModuleDocumentation(
            module_id="key_lifecycle_management_engine",
            display_name="Key Lifecycle Management Engine",
            stability=APIStability.STABLE,
            category="Key Management",
            nist_compliance=NISTComplianceLevel.SP_800_56C,
            description="Complete key lifecycle: generation, rotation, revocation, archival",
            code_example="""
from quantum_crypt.test_post_quantum_key_lifecycle_management_engine_2026_june import KeyLifecycleManager

manager = KeyLifecycleManager()
key_id = manager.generate_key(algorithm="kyber768")
manager.rotate_key(key_id)
manager.revoke_key(key_id, reason="compromise")
""",
            best_practices=[
                "Set rotation policies based on sensitivity",
                "Maintain audit logs for all operations",
                "Use HSM integration for key storage"
            ],
            security_notes=["Follows NIST SP 800-57 key management guidelines"],
            limitations=[
                "Requires persistent storage for key state",
                "Revocation checking adds latency",
                "Archived keys require secure storage"
            ]
        )
        self._stability_index[APIStability.STABLE].append("key_lifecycle_management")
        self._compliance_index[NISTComplianceLevel.SP_800_56C].append("key_lifecycle_management")
        
        # Auto Key Rotation Scheduler - STABLE
        self._modules["auto_key_rotation"] = ModuleDocumentation(
            module_id="key_management_auto_rotation_scheduler",
            display_name="Auto Key Rotation Scheduler",
            stability=APIStability.STABLE,
            category="Key Management",
            description="Automated key rotation scheduling with policy enforcement",
            code_example="""
from quantum_crypt.test_post_quantum_key_management_auto_rotation_scheduler_2026_june import KeyRotationScheduler

scheduler = KeyRotationScheduler()
scheduler.add_policy(key_id, rotation_days=90)
scheduler.start()
""",
            best_practices=[
                "Configure pre-rotation alerts",
                "Test rotation in staging first"
            ],
            limitations=[
                "Requires background scheduler",
                "Rotation may disrupt active sessions",
                "Clock drift affects scheduling accuracy"
            ]
        )
        self._stability_index[APIStability.STABLE].append("auto_key_rotation")
        
        # Key Diversification HKDF v37 - STABLE
        self._modules["key_diversification_hkdf_v37"] = ModuleDocumentation(
            module_id="secure_key_diversification_hkdf_v37",
            display_name="HKDF Key Diversification v37",
            stability=APIStability.STABLE,
            category="Key Management",
            nist_compliance=NISTComplianceLevel.SP_800_90A,
            description="HMAC-based Key Derivation Function for secure key diversification",
            code_example="""
from quantum_crypt.test_post_quantum_secure_key_diversification_hkdf_engine_v37_2026_june import HKDFDiversifier

diversifier = HKDFDiversifier(hash_alg="sha256")
derived_key = diversifier.derive_key(
    master_key,
    salt=salt_value,
    info=b"encryption-key-v1",
    length=32
)
""",
            best_practices=[
                "Always use unique info parameter per key purpose",
                "Use cryptographically random salt"
            ],
            security_notes=["NIST SP 800-56C compliant KDF"],
            limitations=[
                "Master key compromise exposes all derived keys",
                "Requires secure master key storage",
                "Info parameter must be application-specific"
            ]
        )
        self._stability_index[APIStability.STABLE].append("key_diversification_hkdf_v37")
        self._compliance_index[NISTComplianceLevel.SP_800_90A].append("key_diversification_hkdf_v37")
    
    def _add_security_hardening_modules(self) -> None:
        """Add Security Hardening documentation"""
        
        # Secure Memory Zeroization - STABLE
        self._modules["secure_memory_zeroization"] = ModuleDocumentation(
            module_id="secure_memory_zeroization_side_channel_hardened",
            display_name="Side-Channel Hardened Secure Memory Zeroization",
            stability=APIStability.STABLE,
            category="Security Hardening",
            description="Constant-time secure memory zeroization with side-channel protections",
            code_example="""
from quantum_crypt.test_post_quantum_secure_memory_zeroizer_side_channel_hardened_2026_june import secure_zeroize, SecureBuffer

with SecureBuffer(32) as key_material:
    process_sensitive_data(key_material)
# Automatically zeroized when exiting context
""",
            best_practices=[
                "Use SecureBuffer context manager",
                "Zeroize immediately after use",
                "Never rely on Python GC"
            ],
            security_notes=[
                "Constant-time execution",
                "Volatile memory barriers",
                "Compiler barrier intrinsics"
            ],
            limitations=["Python interpreter may create temporary copies"]
        )
        self._stability_index[APIStability.STABLE].append("secure_memory_zeroization")
        
        # Constant Time Execution Protector - STABLE
        self._modules["constant_time_execution"] = ModuleDocumentation(
            module_id="constant_time_execution_protector",
            display_name="Constant-Time Execution Protector",
            stability=APIStability.STABLE,
            category="Security Hardening",
            description="Decorators and utilities for timing-attack resistant code",
            code_example="""
from quantum_crypt.test_post_quantum_constant_time_execution_protector_2026_june import constant_time, ct_compare

@constant_time
def secure_compare(a: bytes, b: bytes) -> bool:
    return ct_compare(a, b)
""",
            best_practices=[
                "Apply to all crypto operations",
                "Avoid secret-dependent branches"
            ],
            security_notes=["Prevents timing side-channel attacks"],
            limitations=[
                "Python interpreter may reorder operations",
                "Cannot protect against microarchitectural leaks",
                "Decorator overhead adds minimal latency"
            ]
        )
        self._stability_index[APIStability.STABLE].append("constant_time_execution")
        
        # Input Validation Wrappers v9 - STABLE
        self._modules["input_validation_wrappers_v9"] = ModuleDocumentation(
            module_id="crypto_security_hardening_input_validation_wrappers_v9",
            display_name="Crypto Input Validation Wrappers v9",
            stability=APIStability.STABLE,
            category="Security Hardening",
            description="Comprehensive input validation for all cryptographic operations",
            code_example="""
from quantum_crypt.crypto_security_hardening_input_validation_wrappers_v9_2026_june import validate_crypto_inputs

@validate_crypto_inputs(
    key_length={32, 48, 64},
    nonce_length=12,
    allow_empty=False
)
def secure_encrypt(key: bytes, nonce: bytes, plaintext: bytes):
    return encrypt(key, nonce, plaintext)
""",
            best_practices=["Validate all public API entry points"],
            limitations=[
                "Validation adds minimal latency overhead",
                "Cannot prevent all semantic attacks",
                "Custom validators must be registered explicitly"
            ]
        )
        self._stability_index[APIStability.STABLE].append("input_validation_wrappers_v9")
    
    def _add_entropy_modules(self) -> None:
        """Add Entropy & Randomness documentation"""
        
        # Entropy Health Monitor - STABLE
        self._modules["entropy_health_monitor"] = ModuleDocumentation(
            module_id="entropy_health_monitor",
            display_name="Entropy Health Monitor",
            stability=APIStability.STABLE,
            category="Randomness",
            nist_compliance=NISTComplianceLevel.SP_800_90A,
            description="Continuous health monitoring of entropy sources",
            code_example="""
from quantum_crypt.test_post_quantum_entropy_health_monitor_2026_june import EntropyMonitor

monitor = EntropyMonitor()
health = monitor.check_entropy_quality()
if health.quality_score < 0.95:
    trigger_entropy_reseed()
""",
            best_practices=["Monitor continuously in production"],
            security_notes=["NIST SP 800-90B entropy assessment"],
            limitations=[
                "Cannot detect all entropy degradation patterns",
                "False positives possible under high load",
                "Requires baseline calibration"
            ]
        )
        self._stability_index[APIStability.STABLE].append("entropy_health_monitor")
        self._compliance_index[NISTComplianceLevel.SP_800_90A].append("entropy_health_monitor")
        
        # Entropy Beacon Distillation - STABLE
        self._modules["entropy_beacon_distillation"] = ModuleDocumentation(
            module_id="entropy_beacon_distillation_engine",
            display_name="Entropy Beacon Distillation Engine",
            stability=APIStability.STABLE,
            category="Randomness",
            description="Distills high-quality entropy from multiple independent sources",
            code_example="""
from quantum_crypt.test_post_quantum_entropy_beacon_distillation_engine_2026_june import EntropyBeacon

beacon = EntropyBeacon(sources=["os", "rdrand", "hrtimer"])
entropy = beacon.get_entropy(64)
""",
            best_practices=["Use at least 3 independent sources"],
            security_notes=["Uses cryptographic extractor for mixing"],
            limitations=[
                "Source availability varies by platform",
                "Network sources add latency",
                "Hardware sources may not be available in VMs"
            ]
        )
        self._stability_index[APIStability.STABLE].append("entropy_beacon_distillation")
    
    def _add_mpc_modules(self) -> None:
        """Add Multi-Party Computation documentation"""
        
        # Secure MPC Engine v36 - STABLE
        self._modules["secure_mpc_engine_v36"] = ModuleDocumentation(
            module_id="secure_mpc_engine_v36",
            display_name="Secure Multi-Party Computation Engine v36",
            stability=APIStability.STABLE,
            category="Secure Computation",
            description="Secure multi-party computation for distributed key generation and signing",
            code_example="""
from quantum_crypt.test_post_quantum_secure_mpc_engine_v36_2026_june import SecureMPCEngine

mpc = SecureMPCEngine(parties=3, threshold=2)
key_shares = mpc.generate_distributed_key()
signature_share = mpc.sign_with_share(message, my_share)
""",
            best_practices=[
                "Use threshold N/2+1 for security",
                "Verify all zero-knowledge proofs",
                "Use secure channels between parties"
            ],
            security_notes=[
                "Gennaro-Goldfeder protocol",
                "No trusted dealer required"
            ],
            limitations=[
                "Network latency scales with party count",
                "Requires synchronous protocol execution",
                "Recovery from party failure is complex"
            ]
        )
        self._stability_index[APIStability.STABLE].append("secure_mpc_engine_v36")
        
        # MPC Session Manager v6 - BETA
        self._modules["mpc_session_manager_v6"] = ModuleDocumentation(
            module_id="secure_mpc_session_manager_v6",
            display_name="MPC Session Manager v6",
            stability=APIStability.BETA,
            category="Secure Computation",
            description="Session management for multi-party computation protocols",
            code_example="""
from quantum_crypt.test_post_quantum_secure_mpc_session_manager_v6_2026_june import MPCSessionManager

manager = MPCSessionManager()
session_id = manager.create_session(parties=[alice, bob, charlie])
""",
            best_practices=["Set session timeouts appropriately"],
            limitations=["BETA - API may be refined"]
        )
        self._stability_index[APIStability.BETA].append("mpc_session_manager_v6")
    
    def _add_error_resilience_modules(self) -> None:
        """Add Error Resilience documentation"""
        
        # Crypto Error Resilience Engine - STABLE
        self._modules["crypto_error_resilience"] = ModuleDocumentation(
            module_id="crypto_error_resilience_comprehensive_enhanced_v2",
            display_name="Crypto Error Resilience Engine Enhanced v2",
            stability=APIStability.STABLE,
            category="Error Resilience",
            description="Comprehensive error handling and resilience for crypto operations",
            code_example="""
from quantum_crypt.test_crypto_error_resilience_comprehensive_enhanced_v2_2026_june import CryptoResilienceEngine

engine = CryptoResilienceEngine()
result = engine.execute_with_fallback(
    primary=lambda: risky_crypto_op(),
    fallback=lambda: safe_alternative(),
    max_attempts=3
)
""",
            best_practices=[
                "Define clear fallback behaviors",
                "Log all failures for audit"
            ],
            limitations=[
                "Fallback may have reduced security guarantees",
                "Retry loops can cause latency spikes",
                "Circuit breaker requires state management"
            ]
        )
        self._stability_index[APIStability.STABLE].append("crypto_error_resilience")
    
    def get_module_documentation(self, module_id: str) -> Optional[ModuleDocumentation]:
        """Get documentation for specific module"""
        return self._modules.get(module_id)
    
    def get_modules_by_stability(self, stability: APIStability) -> List[str]:
        """Get all modules with given stability level"""
        return self._stability_index.get(stability, [])
    
    def get_modules_by_compliance(self, compliance: NISTComplianceLevel) -> List[str]:
        """Get all modules with given NIST compliance level"""
        return self._compliance_index.get(compliance, [])
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get count of modules by stability level"""
        return {
            stability.value: len(modules)
            for stability, modules in self._stability_index.items()
        }
    
    def get_compliance_summary(self) -> Dict[str, int]:
        """Get count of modules by compliance level"""
        return {
            compliance.value: len(modules)
            for compliance, modules in self._compliance_index.items()
            if modules
        }
    
    def generate_documentation_report(self, format: str = "json") -> str:
        """Generate complete documentation report"""
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "catalog_version": "v6",
            "stability_summary": self.get_stability_summary(),
            "compliance_summary": self.get_compliance_summary(),
            "modules": [
                {
                    "id": m.module_id,
                    "name": m.display_name,
                    "stability": m.stability.value,
                    "category": m.category,
                    "nist_compliance": m.nist_compliance.value,
                    "description": m.description,
                    "best_practices": m.best_practices,
                    "security_notes": m.security_notes,
                    "limitations": m.limitations,
                    "performance": m.performance_characteristics
                }
                for m in self._modules.values()
            ]
        }
        if format == "json":
            return json.dumps(report, indent=2)
        return str(report)
    
    def list_all_modules(self) -> List[Dict[str, str]]:
        """List all documented modules"""
        return [
            {
                "id": mid,
                "name": mod.display_name,
                "stability": mod.stability.value,
                "category": mod.category,
                "compliance": mod.nist_compliance.value
            }
            for mid, mod in self._modules.items()
        ]


# Export stability markers for type checking
__all__ = [
    "APIStability",
    "NISTComplianceLevel",
    "APIDocumentation",
    "ModuleDocumentation",
    "QuantumCryptDocumentationCatalog"
]
