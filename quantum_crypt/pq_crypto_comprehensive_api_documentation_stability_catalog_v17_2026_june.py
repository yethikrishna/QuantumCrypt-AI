"""
QuantumCrypt-AI Comprehensive API Documentation & Stability Catalog v17
=======================================================================
API Stability Markers:
    STABLE:         Production-ready, backward-compatible, no breaking changes
    BETA:           Near-stable, minor changes possible, production-ready with caution
    EXPERIMENTAL:   Active development, breaking changes likely, NOT for production
    DEPRECATED:     Scheduled for removal, migrate to alternatives
    LEGACY:         Maintained for backward compatibility only

This module provides:
1. Complete post-quantum crypto API catalog with stability markers
2. Usage examples for every major crypto operation
3. NIST algorithm compliance documentation
4. Security boundary and FIPS considerations
5. Performance characteristics per algorithm
6. NEW v17: Key operation telemetry documentation
7. NEW v17: Side-channel resistance module documentation

ADD-ONLY MODULE - No existing code modified, pure documentation layer.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import json
from datetime import datetime


class StabilityLevel(Enum):
    STABLE = "STABLE"
    BETA = "BETA"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


class NISTStatus(Enum):
    STANDARDIZED = "NIST STANDARDIZED"
    ROUND_4 = "NIST ROUND 4"
    ROUND_3 = "NIST ROUND 3"
    CANDIDATE = "CANDIDATE"
    RESEARCH = "RESEARCH ONLY"


@dataclass
class CryptoAlgorithm:
    name: str
    nist_status: NISTStatus
    key_sizes: List[int]
    quantum_resistant: bool
    performance: Dict[str, str]


@dataclass
class APIEndpoint:
    name: str
    module_path: str
    stability: StabilityLevel
    description: str
    since_version: str
    algorithms: List[CryptoAlgorithm] = field(default_factory=list)
    deprecation_version: Optional[str] = None
    removal_version: Optional[str] = None
    performance_characteristics: Dict[str, str] = field(default_factory=dict)
    thread_safe: bool = True
    side_channel_resistant: bool = False
    fips_compliant: bool = False
    usage_examples: List[str] = field(default_factory=list)
    security_notes: List[str] = field(default_factory=list)


@dataclass
class MigrationGuide:
    from_version: str
    to_version: str
    breaking_changes: List[str]
    migration_steps: List[str]
    backward_compatible: bool = True


class QuantumCryptAPICatalog:
    """
    Comprehensive API documentation catalog for QuantumCrypt-AI v17.
    Pure documentation layer - 100% ADD-ONLY, no runtime impact.
    """
    
    def __init__(self):
        self._endpoints: Dict[str, APIEndpoint] = {}
        self._migration_guides: List[MigrationGuide] = []
        self._init_algorithms()
        self._init_catalog()
        self._init_migration_guides()
    
    def _init_algorithms(self):
        """Initialize reference algorithm data."""
        self._algorithms = {
            "CRYSTALS-Kyber": CryptoAlgorithm(
                name="CRYSTALS-Kyber",
                nist_status=NISTStatus.STANDARDIZED,
                key_sizes=[512, 768, 1024],
                quantum_resistant=True,
                performance={"keygen_ms": "0.1", "encap_ms": "0.15", "decap_ms": "0.12"}
            ),
            "CRYSTALS-Dilithium": CryptoAlgorithm(
                name="CRYSTALS-Dilithium",
                nist_status=NISTStatus.STANDARDIZED,
                key_sizes=[2, 3, 5],
                quantum_resistant=True,
                performance={"keygen_ms": "0.5", "sign_ms": "0.8", "verify_ms": "0.3"}
            ),
            "FALCON": CryptoAlgorithm(
                name="FALCON",
                nist_status=NISTStatus.STANDARDIZED,
                key_sizes=[512, 1024],
                quantum_resistant=True,
                performance={"keygen_ms": "15", "sign_ms": "2", "verify_ms": "0.2"}
            ),
            "SPHINCS+": CryptoAlgorithm(
                name="SPHINCS+",
                nist_status=NISTStatus.STANDARDIZED,
                key_sizes=[128, 192, 256],
                quantum_resistant=True,
                performance={"keygen_ms": "5", "sign_ms": "8", "verify_ms": "0.5"}
            ),
            "Classic-McEliece": CryptoAlgorithm(
                name="Classic-McEliece",
                nist_status=NISTStatus.ROUND_4,
                key_sizes=[348864, 460896, 6688128, 6960119],
                quantum_resistant=True,
                performance={"keygen_ms": "500", "encap_ms": "1", "decap_ms": "1"}
            ),
            "BIKE": CryptoAlgorithm(
                name="BIKE",
                nist_status=NISTStatus.ROUND_4,
                key_sizes=[128, 192, 256],
                quantum_resistant=True,
                performance={"keygen_ms": "2", "encap_ms": "0.5", "decap_ms": "0.5"}
            ),
            "HQC": CryptoAlgorithm(
                name="HQC",
                nist_status=NISTStatus.ROUND_4,
                key_sizes=[128, 192, 256],
                quantum_resistant=True,
                performance={"keygen_ms": "1", "encap_ms": "0.3", "decap_ms": "0.3"}
            )
        }
    
    def _init_catalog(self):
        """Initialize the complete API catalog with stability markers."""
        
        # ==================== v17 NEW: KEY OPERATION TELEMETRY ====================
        
        self._endpoints["crypto_telemetry_v14"] = APIEndpoint(
            name="CryptoKeyOperationTelemetry",
            module_path="quantum_crypt.crypto_observability_key_operation_telemetry_v14",
            stability=StabilityLevel.BETA,
            description="v14: Crypto key operation telemetry with security boundaries",
            since_version="v14",
            performance_characteristics={
                "avg_latency_ms": "<1 (disabled: 0 overhead)",
                "p99_latency_ms": "5",
                "memory_mb": "~20",
                "throughput": "10000+ ops/sec"
            },
            thread_safe=True,
            side_channel_resistant=True,
            fips_compliant=False,
            usage_examples=[
                """
                # STRICT OPT-IN - disabled by default (ZERO overhead)
                telemetry = CryptoKeyOperationTelemetry(enabled=False)
                # Pure NO-OP when disabled
                """,
                """
                # Explicit enable with security boundaries
                telemetry = CryptoKeyOperationTelemetry(
                    enabled=True,
                    enable_key_lifecycle_tracking=True,
                    enable_key_hashing=False  # EXPLICIT opt-in required
                )
                """
            ],
            security_notes=[
                "NEVER logs raw key material",
                "Automatic field filtering for 'key'/'secret'",
                "Key hashing DISABLED by default - explicit opt-in only",
                "100% backward compatible"
            ]
        )
        
        # ==================== v17 NEW: SIDE-CHANNEL RESISTANCE ====================
        
        self._endpoints["side_channel_key_protector_v17"] = APIEndpoint(
            name="KeyOperationProtector",
            module_path="quantum_crypt.post_quantum_side_channel_key_wrapper_v17",
            stability=StabilityLevel.BETA,
            description="v17: Side-channel resistant key operations with memory protection",
            since_version="v17",
            performance_characteristics={
                "avg_latency_ms": "1-3",
                "p99_latency_ms": "10",
                "memory_mb": "~15",
                "throughput": "5000+ ops/sec"
            },
            thread_safe=True,
            side_channel_resistant=True,
            fips_compliant=True,
            usage_examples=[
                """
                protector = KeyOperationProtector()
                with protector.protect_key_material(key_buffer):
                    # Key operations in protected scope
                    result = perform_key_operation()
                # Auto-zeroized on scope exit
                """,
                """
                # Constant-time comparison
                match = protector.constant_time_compare(a, b)
                """
            ],
            security_notes=[
                "Constant-time memory operations",
                "Automatic zeroization on scope exit",
                "Memory locking where available",
                "Timing attack resistant"
            ]
        )
        
        # ==================== KEY ENCAPSULATION MECHANISMS ====================
        
        self._endpoints["hybrid_kem_engine_v2"] = APIEndpoint(
            name="HybridKEMEngine",
            module_path="quantum_crypt.post_quantum_hybrid_kem_engine_v2",
            stability=StabilityLevel.STABLE,
            description="Hybrid post-quantum + classical key encapsulation mechanism",
            since_version="v2",
            algorithms=[self._algorithms["CRYSTALS-Kyber"]],
            performance_characteristics={
                "avg_keygen_ms": "0.5-1.0",
                "avg_encapsulate_ms": "0.3-0.8",
                "avg_decapsulate_ms": "0.3-0.8",
                "memory_mb": "~50"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False,
            usage_examples=[
                """
                kem = HybridKEMEngine(algorithm="Kyber-768")
                pk, sk = kem.keygen()
                ciphertext, shared_secret = kem.encapsulate(pk)
                recovered_secret = kem.decapsulate(ciphertext, sk)
                """,
                """
                # Hybrid mode (X25519 + Kyber-768)
                kem = HybridKEMEngine(enable_classical_hybrid=True)
                """
            ],
            security_notes=[
                "NIST FIPS 203 compliant (Kyber)",
                "Forward secrecy supported",
                "Classical fallback available"
            ]
        )
        
        self._endpoints["kem_session_manager"] = APIEndpoint(
            name="KEMSessionManager",
            module_path="quantum_crypt.hybrid_kem_signature_session_manager_v2",
            stability=StabilityLevel.STABLE,
            description="Authenticated KEM sessions with signature binding",
            since_version="v5",
            algorithms=[self._algorithms["CRYSTALS-Kyber"], self._algorithms["CRYSTALS-Dilithium"]],
            performance_characteristics={
                "avg_session_setup_ms": "2-5",
                "avg_key_rotation_ms": "1-3",
                "memory_mb": "~80"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False
        )
        
        # ==================== DIGITAL SIGNATURES ====================
        
        self._endpoints["pq_digital_signature_v2"] = APIEndpoint(
            name="PostQuantumDigitalSignature",
            module_path="quantum_crypt.post_quantum_digital_signature_engine_v2",
            stability=StabilityLevel.STABLE,
            description="Post-quantum digital signatures (Dilithium, Falcon, SPHINCS+)",
            since_version="v2",
            algorithms=[
                self._algorithms["CRYSTALS-Dilithium"],
                self._algorithms["FALCON"],
                self._algorithms["SPHINCS+"]
            ],
            performance_characteristics={
                "Dilithium3_sign_ms": "1-2",
                "Dilithium3_verify_ms": "0.3-0.5",
                "Falcon512_sign_ms": "5-10",
                "SPHINCS+_sign_ms": "15-25"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False,
            usage_examples=[
                """
                signer = PostQuantumDigitalSignature(algorithm="Dilithium3")
                pk, sk = signer.keygen()
                signature = signer.sign(message, sk)
                is_valid = signer.verify(message, signature, pk)
                """
            ]
        )
        
        self._endpoints["signature_batch_verifier"] = APIEndpoint(
            name="SignatureBatchVerifier",
            module_path="quantum_crypt.post_quantum_digital_signature_batch_verifier",
            stability=StabilityLevel.BETA,
            description="Batch signature verification for high-throughput scenarios",
            since_version="v8",
            algorithms=[self._algorithms["CRYSTALS-Dilithium"]],
            performance_characteristics={
                "batch_100_verify_ms": "15-25",
                "throughput_signatures_sec": "4000-6000"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False
        )
        
        # ==================== KEY MANAGEMENT ====================
        
        self._endpoints["key_rotation_manager_v17"] = APIEndpoint(
            name="KeyRotationManager",
            module_path="quantum_crypt.pq_key_rotation_manager_v17",
            stability=StabilityLevel.STABLE,
            description="v17: Automated key rotation with policy enforcement",
            since_version="v17",
            algorithms=[self._algorithms["CRYSTALS-Kyber"]],
            performance_characteristics={
                "rotation_latency_ms": "5-15",
                "memory_mb": "~40"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False,
            usage_examples=[
                """
                manager = KeyRotationManager()
                manager.set_rotation_policy(
                    max_age_hours=24,
                    max_operations=10000,
                    auto_rotate=True
                )
                """
            ]
        )
        
        self._endpoints["key_compromise_recovery"] = APIEndpoint(
            name="KeyCompromiseRecovery",
            module_path="quantum_crypt.post_quantum_key_compromise_recovery_emergency_rotation",
            stability=StabilityLevel.BETA,
            description="Emergency key rotation and compromise recovery",
            since_version="v10",
            algorithms=[self._algorithms["CRYSTALS-Kyber"]],
            performance_characteristics={
                "emergency_rotation_ms": "50-100"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False
        )
        
        self._endpoints["secure_key_derivation"] = APIEndpoint(
            name="SecureKeyDerivationFunction",
            module_path="quantum_crypt.post_quantum_secure_key_derivation_function_engine",
            stability=StabilityLevel.STABLE,
            description="Post-quantum secure HKDF with memory-hard KDF options",
            since_version="v7",
            performance_characteristics={
                "derive_ms": "1-5",
                "memory_mb": "~10-100 (configurable)"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False
        )
        
        # ==================== SECURE MULTI-PARTY COMPUTATION ====================
        
        self._endpoints["secure_mpc_v31"] = APIEndpoint(
            name="SecureMPCEngine",
            module_path="quantum_crypt.post_quantum_secure_mpc_engine_v31",
            stability=StabilityLevel.EXPERIMENTAL,
            description="v31: Post-quantum secure multi-party computation",
            since_version="v31",
            performance_characteristics={
                "2_party_ms": "100-500",
                "n_party_ms": "500-2000",
                "memory_mb": "~200"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False,
            security_notes=[
                "EXPERIMENTAL: Protocol under active development",
                "Honest-but-curious adversary model",
                "Not audited for production use"
            ]
        )
        
        # ==================== ZERO-KNOWLEDGE PROOFS ====================
        
        self._endpoints["zkp_engine_v1"] = APIEndpoint(
            name="ZeroKnowledgeProofEngine",
            module_path="quantum_crypt.post_quantum_zero_knowledge_proof_engine_v1",
            stability=StabilityLevel.EXPERIMENTAL,
            description="v1: Post-quantum zero-knowledge proof system",
            since_version="v1",
            performance_characteristics={
                "proof_gen_ms": "100-1000",
                "proof_verify_ms": "1-10",
                "proof_size_kb": "1-10"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False,
            security_notes=[
                "EXPERIMENTAL: Research prototype only",
                "Groth16-style SNARK construction",
                "NOT for production use"
            ]
        )
        
        # ==================== SECURITY HARDENING ====================
        
        self._endpoints["secure_memory_zeroizer"] = APIEndpoint(
            name="SecureMemoryZeroizer",
            module_path="quantum_crypt.post_quantum_secure_memory_zeroizer_side_channel_protected",
            stability=StabilityLevel.STABLE,
            description="Side-channel protected secure memory zeroization",
            since_version="v6",
            performance_characteristics={
                "zeroize_1kb_ms": "<1",
                "throughput": "10000+ ops/sec"
            },
            thread_safe=True,
            side_channel_resistant=True,
            fips_compliant=True,
            security_notes=[
                "Constant-time operations",
                "Compiler barrier protection",
                "Volatile memory access"
            ]
        )
        
        self._endpoints["secure_tokenization"] = APIEndpoint(
            name="SecureTokenizationEngine",
            module_path="quantum_crypt.post_quantum_secure_tokenization_engine",
            stability=StabilityLevel.BETA,
            description="Format-preserving encryption and tokenization",
            since_version="v9",
            performance_characteristics={
                "tokenize_ms": "0.5-2",
                "detokenize_ms": "0.5-2"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False
        )
        
        # ==================== ERROR RESILIENCE ====================
        
        self._endpoints["crypto_error_resilience_v15"] = APIEndpoint(
            name="CryptoErrorResilienceEngine",
            module_path="quantum_crypt.crypto_error_resilience_comprehensive_v15",
            stability=StabilityLevel.STABLE,
            description="v15: Crypto operation error resilience with fallbacks",
            since_version="v15",
            performance_characteristics={
                "overhead_pct": "<1% nominal",
                "fallback_switch_ms": "<10"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False
        )
        
        # ==================== OBSERVABILITY ====================
        
        self._endpoints["crypto_health_monitor"] = APIEndpoint(
            name="AlgorithmHealthMonitor",
            module_path="quantum_crypt.post_quantum_algorithm_health_monitor_rotation_advisor",
            stability=StabilityLevel.BETA,
            description="Crypto algorithm health monitoring and rotation advisory",
            since_version="v8",
            performance_characteristics={
                "health_check_ms": "1-5",
                "memory_mb": "~25"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False
        )
        
        self._endpoints["randomness_health_monitor"] = APIEndpoint(
            name="RandomnessHealthMonitor",
            module_path="quantum_crypt.post_quantum_randomness_health_monitor",
            stability=StabilityLevel.STABLE,
            description="Entropy quality monitoring and health checks",
            since_version="v9",
            performance_characteristics={
                "entropy_check_ms": "1-3"
            },
            thread_safe=True,
            side_channel_resistant=False,
            fips_compliant=False
        )
    
    def _init_migration_guides(self):
        """Initialize migration guides between major versions."""
        
        self._migration_guides.append(MigrationGuide(
            from_version="v16",
            to_version="v17",
            breaking_changes=[
                "No breaking changes - pure documentation update"
            ],
            migration_steps=[
                "No code changes required",
                "Import v17 catalog for updated algorithm docs"
            ],
            backward_compatible=True
        ))
        
        self._migration_guides.append(MigrationGuide(
            from_version="v1",
            to_version="v2",
            breaking_changes=[
                "KEMEngine API renamed to HybridKEMEngine",
                "SignatureEngine API renamed to PostQuantumDigitalSignature"
            ],
            migration_steps=[
                "Update imports from kem_engine to hybrid_kem_engine_v2",
                "Replace KEMEngine() with HybridKEMEngine()",
                "Update algorithm parameter names"
            ],
            backward_compatible=False
        ))
    
    def get_endpoint(self, name: str) -> Optional[APIEndpoint]:
        """Get API endpoint documentation by name."""
        return self._endpoints.get(name)
    
    def list_by_stability(self, stability: StabilityLevel) -> List[APIEndpoint]:
        """List all endpoints with specified stability level."""
        return [ep for ep in self._endpoints.values() if ep.stability == stability]
    
    def list_nist_algorithms(self, status: NISTStatus) -> List[CryptoAlgorithm]:
        """List algorithms by NIST standardization status."""
        return [alg for alg in self._algorithms.values() if alg.nist_status == status]
    
    def get_algorithm(self, name: str) -> Optional[CryptoAlgorithm]:
        """Get algorithm documentation by name."""
        return self._algorithms.get(name)
    
    def get_compliance_matrix(self) -> Dict[str, Any]:
        """Get compliance and security matrix."""
        return {
            "catalog_version": "v17",
            "nist_algorithms": {
                status.value: len(self.list_nist_algorithms(status))
                for status in NISTStatus
            },
            "fips_modules": len([ep for ep in self._endpoints.values() if ep.fips_compliant]),
            "side_channel_resistant": len([ep for ep in self._endpoints.values() if ep.side_channel_resistant]),
            "security_boundaries": {
                "key_material": "NEVER logged or exported",
                "telemetry": "OPT-IN ONLY, disabled by default",
                "memory": "Automatic zeroization available"
            },
            "recommended_production_algorithms": [
                "CRYSTALS-Kyber-768",
                "CRYSTALS-Dilithium3"
            ]
        }
    
    def generate_documentation(self, format: str = "json") -> str:
        """Generate complete API documentation in specified format."""
        docs = {
            "catalog_version": "v17",
            "generated_at": datetime.utcnow().isoformat(),
            "total_endpoints": len(self._endpoints),
            "stability_breakdown": {
                level.value: len(self.list_by_stability(level))
                for level in StabilityLevel
            },
            "nist_algorithm_breakdown": {
                status.value: len(self.list_nist_algorithms(status))
                for status in NISTStatus
            },
            "compliance_matrix": self.get_compliance_matrix()
        }
        
        if format == "json":
            return json.dumps(docs, indent=2)
        return str(docs)


# Singleton instance for easy import
api_catalog = QuantumCryptAPICatalog()


def get_api_stability(module_name: str) -> Optional[str]:
    """Get stability level for any crypto module."""
    endpoint = api_catalog.get_endpoint(module_name)
    return endpoint.stability.value if endpoint else None


def get_nist_status(algorithm_name: str) -> Optional[str]:
    """Get NIST standardization status for algorithm."""
    alg = api_catalog.get_algorithm(algorithm_name)
    return alg.nist_status.value if alg else None


def is_side_channel_resistant(module_name: str) -> Optional[bool]:
    """Check if module has side-channel resistance."""
    endpoint = api_catalog.get_endpoint(module_name)
    return endpoint.side_channel_resistant if endpoint else None


__all__ = [
    'QuantumCryptAPICatalog',
    'APIEndpoint',
    'CryptoAlgorithm',
    'StabilityLevel',
    'NISTStatus',
    'MigrationGuide',
    'api_catalog',
    'get_api_stability',
    'get_nist_status',
    'is_side_channel_resistant'
]
