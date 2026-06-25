"""
QuantumCrypt AI - Comprehensive API Documentation & Stability Catalog v32
=========================================================================
STABILITY LEVEL: STABLE
API VERSION: 2026.06.25
LAST UPDATED: 2026-06-25

This module provides comprehensive documentation, usage examples, and stability
markers for all QuantumCrypt post-quantum cryptography modules.

DOCUMENTATION PHILOSOPHY:
- CODE LOGIC IS SACRED - only docs and metadata
- All existing behavior 100% preserved
- Comprehensive docstrings with type hints
- Clear stability markers: STABLE / EXPERIMENTAL / DEPRECATED
- Working usage examples for every module
- NIST PQC standard compliance notes
"""

import typing
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import datetime


class StabilityLevel(Enum):
    """API Stability Level classification."""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    BETA = "BETA"


class NISTPQCStatus(Enum):
    """NIST Post-Quantum Cryptography standardization status."""
    STANDARDIZED = "STANDARDIZED"
    ROUND_4 = "ROUND_4"
    ROUND_3 = "ROUND_3"
    CANDIDATE = "CANDIDATE"
    RESEARCH = "RESEARCH"


@dataclass
class AlgorithmDocumentation:
    """Documentation metadata for a post-quantum cryptographic algorithm."""
    algorithm_name: str
    stability: StabilityLevel
    nist_status: NISTPQCStatus
    version: str
    description: str
    security_level: str
    key_sizes: Dict[str, int]
    author: str = "QuantumCrypt Team"
    last_updated: str = field(default_factory=lambda: datetime.date.today().isoformat())
    usage_examples: List[str] = field(default_factory=list)
    parameters: Dict[str, str] = field(default_factory=dict)
    returns: str = ""
    exceptions: List[str] = field(default_factory=list)
    see_also: List[str] = field(default_factory=list)
    compliance_notes: List[str] = field(default_factory=list)


class QuantumCryptDocumentationCatalog:
    """
    Comprehensive documentation catalog for all QuantumCrypt PQC modules.
    
    STABILITY LEVEL: STABLE
    
    Provides:
    - Algorithm stability classification
    - NIST PQC standardization status
    - Security level information
    - Comprehensive usage examples
    - Key size specifications
    - Compliance notes
    """
    
    def __init__(self):
        self._catalog: Dict[str, AlgorithmDocumentation] = {}
        self._init_catalog()
    
    def _init_catalog(self) -> None:
        """Initialize the documentation catalog with all PQC algorithms."""
        
        # ===== KEY ENCAPSULATION MECHANISMS (KEM) =====
        self._catalog["crystals_kyber"] = AlgorithmDocumentation(
            algorithm_name="CRYSTALS-Kyber",
            stability=StabilityLevel.STABLE,
            nist_status=NISTPQCStatus.STANDARDIZED,
            version="2026.06.25",
            description="NIST-standardized lattice-based Key Encapsulation Mechanism. "
                       "Primary recommendation for post-quantum key exchange.",
            security_level="NIST Security Level 1, 3, 5",
            key_sizes={"Kyber-512": 800, "Kyber-768": 1184, "Kyber-1024": 1568},
            usage_examples=[
                """
                from quantum_crypt.post_quantum_hybrid_kem_engine_v2_2026_june import KyberKEM
                
                # Initialize Kyber-768 (NIST Security Level 3)
                kem = KyberKEM(security_level=3)
                
                # Generate keypair
                public_key, secret_key = kem.keygen()
                
                # Encapsulate (sender)
                ciphertext, shared_secret = kem.encapsulate(public_key)
                
                # Decapsulate (receiver)
                recovered_secret = kem.decapsulate(ciphertext, secret_key)
                
                assert shared_secret == recovered_secret
                """,
                """
                # Hybrid mode with classical ECDHE (recommended for migration)
                hybrid_kem = HybridKEM(enable_classical_fallback=True)
                session_key = hybrid_kem.perform_hybrid_key_exchange()
                """
            ],
            parameters={
                "security_level": "int - 1, 3, or 5 corresponding to NIST security levels",
                "enable_hybrid_mode": "bool - Enable classical + post-quantum hybrid",
                "key_confirmation": "bool - Enable key confirmation protocol"
            },
            returns="Tuple[ciphertext, shared_secret] for encapsulation",
            exceptions=["KeyGenerationError", "DecapsulationError", "InvalidPublicKeyError"],
            see_also=["hybrid_kem_engine", "session_key_manager"],
            compliance_notes=[
                "NIST FIPS 203 standardized",
                "FIPS 140-3 compliant implementation",
                "Constant-time operations"
            ]
        )
        
        self._catalog["hybrid_kem_engine"] = AlgorithmDocumentation(
            algorithm_name="Hybrid KEM Engine",
            stability=StabilityLevel.STABLE,
            nist_status=NISTPQCStatus.STANDARDIZED,
            version="2026.06.25",
            description="Hybrid post-quantum + classical key exchange for smooth migration. "
                       "Combines Kyber with X25519 for transitional security.",
            security_level="Dual security: PQC + Classical",
            key_sizes={"Hybrid-768": 1184 + 32},
            usage_examples=[
                """
                from quantum_crypt.pq_hybrid_encryption_orchestrator_v23_2026_june import HybridEncryption
                
                orchestrator = HybridEncryption(
                    pqc_algorithm="kyber-768",
                    classical_algorithm="x25519",
                    require_both_secrets=True
                )
                
                # Both must succeed for session key derivation
                session_key = orchestrator.negotiate_session()
                """
            ],
            parameters={
                "pqc_algorithm": "str - Post-quantum algorithm name",
                "classical_algorithm": "str - Classical algorithm name",
                "require_both_secrets": "bool - Require both KEMs to succeed"
            },
            returns="bytes - 32-byte cryptographically secure session key",
            exceptions=["HybridNegotiationError", "ClassicalFallbackError"],
            see_also=["crystals_kyber", "session_key_manager_forward_secrecy"],
            compliance_notes=[
                "Migration-friendly hybrid approach",
                "Forward secrecy support",
                "Graceful degradation on failure"
            ]
        )
        
        # ===== DIGITAL SIGNATURES =====
        self._catalog["crystals_dilithium"] = AlgorithmDocumentation(
            algorithm_name="CRYSTALS-Dilithium",
            stability=StabilityLevel.STABLE,
            nist_status=NISTPQCStatus.STANDARDIZED,
            version="2026.06.25",
            description="NIST-standardized lattice-based digital signature algorithm. "
                       "Primary recommendation for post-quantum signatures.",
            security_level="NIST Security Level 2, 3, 5",
            key_sizes={"Dilithium-2": 1312, "Dilithium-3": 1952, "Dilithium-5": 2592},
            usage_examples=[
                """
                from quantum_crypt.post_quantum_digital_signature_batch_verifier_enhanced_2026_june import DilithiumSigner
                
                signer = DilithiumSigner(mode="dilithium3")
                pub_key, priv_key = signer.generate_keypair()
                
                # Sign message
                message = b"Important document to sign"
                signature = signer.sign(message, priv_key)
                
                # Verify signature
                is_valid = signer.verify(message, signature, pub_key)
                print(f"Signature valid: {is_valid}")
                """,
                """
                # Batch verification for performance
                verifier = BatchVerifier()
                results = verifier.verify_batch(messages, signatures, pub_keys)
                """
            ],
            parameters={
                "mode": "str - dilithium2, dilithium3, or dilithium5",
                "deterministic": "bool - Use deterministic signing (default: True)",
                "pre_hash": "bool - Pre-hash message before signing"
            },
            returns="bytes - Digital signature",
            exceptions=["SigningError", "VerificationError", "InvalidPrivateKeyError"],
            see_also=["falcon", "sphincs+"],
            compliance_notes=[
                "NIST FIPS 204 standardized",
                "FIPS 140-3 compliant",
                "Side-channel resistant implementation"
            ]
        )
        
        # ===== KEY MANAGEMENT =====
        self._catalog["session_key_manager_forward_secrecy"] = AlgorithmDocumentation(
            algorithm_name="Session Key Manager with Forward Secrecy",
            stability=StabilityLevel.STABLE,
            nist_status=NISTPQCStatus.STANDARDIZED,
            version="2026.06.25",
            description="Session key management with perfect forward secrecy (PFS). "
                       "Automatically rotates keys and provides compromise resilience.",
            security_level="Forward Secrecy + Post-Quantum",
            key_sizes={"Session Key": 32},
            usage_examples=[
                """
                from quantum_crypt.post_quantum_secure_session_key_manager_forward_secrecy_2026_june import SessionKeyManager
                
                key_manager = SessionKeyManager(
                    rotation_interval_seconds=3600,
                    enable_forward_secrecy=True,
                    pqc_algorithm="kyber-768"
                )
                
                # Get current session key
                session_key = key_manager.get_current_key()
                
                # Force rotation (e.g., after suspected compromise)
                key_manager.rotate_keys()
                new_key = key_manager.get_current_key()
                
                # Old keys are cryptographically erased
                """
            ],
            parameters={
                "rotation_interval_seconds": "int - Automatic key rotation interval",
                "enable_forward_secrecy": "bool - Enable forward secrecy guarantees",
                "pqc_algorithm": "str - Underlying KEM algorithm"
            },
            returns="bytes - Cryptographically secure session key",
            exceptions=["KeyRotationError", "ForwardSecrecyError"],
            see_also=["crystals_kyber", "hybrid_kem_engine"],
            compliance_notes=[
                "RFC 9180 (HPKE) inspired design",
                "Secure key zeroization on rotation",
                "Ephemeral key material never persisted"
            ]
        )
        
        # ===== SIDE-CHANNEL PROTECTION =====
        self._catalog["side_channel_resistant_key_wrapper"] = AlgorithmDocumentation(
            algorithm_name="Side-Channel Resistant Key Wrapper",
            stability=StabilityLevel.STABLE,
            nist_status=NISTPQCStatus.STANDARDIZED,
            version="2026.06.25",
            description="Key wrapping with timing and side-channel attack mitigations. "
                       "Constant-time operations and secure memory handling.",
            security_level="Side-Channel Resistant + Post-Quantum",
            key_sizes={"Wrapped Key": "Variable"},
            usage_examples=[
                """
                from quantum_crypt.post_quantum_side_channel_resistant_key_wrapper_v2_2026_june import SideChannelResistantWrapper
                
                wrapper = SideChannelResistantWrapper(
                    masking_order=2,
                    constant_time_only=True,
                    secure_zeroization=True
                )
                
                # Wrap key with side-channel protection
                wrapped_key = wrapper.wrap_key(
                    plaintext_key,
                    wrapping_key
                )
                
                # Unwrap with constant-time verification
                unwrapped_key = wrapper.unwrap_key(
                    wrapped_key,
                    wrapping_key
                )
                """
            ],
            parameters={
                "masking_order": "int - Order of boolean masking",
                "constant_time_only": "bool - Enforce constant-time operations",
                "secure_zeroization": "bool - Zeroize intermediate values"
            },
            returns="bytes - Wrapped key with authentication tag",
            exceptions=["UnwrapError", "AuthenticationFailedError"],
            see_also=["secure_memory_zeroization", "constant_time_comparison"],
            compliance_notes=[
                "First-order timing attack resistant",
                "Glitch attack mitigations",
                "Power analysis countermeasures"
            ]
        )
        
        # ===== PERFORMANCE & BENCHMARKING =====
        self._catalog["performance_benchmark_profiler"] = AlgorithmDocumentation(
            algorithm_name="Performance Benchmark Profiler",
            stability=StabilityLevel.BETA,
            nist_status=NISTPQCStatus.RESEARCH,
            version="2026.06.25",
            description="Performance benchmarking and profiling for PQC algorithms. "
                       "BETA stability - API may evolve based on usage.",
            security_level="N/A - Performance tooling",
            key_sizes={"N/A": 0},
            usage_examples=[
                """
                from quantum_crypt.post_quantum_performance_benchmark_profiler_2026_june import PQCBenchmarker
                
                benchmarker = PQCBenchmarker(
                    algorithms=["kyber-768", "dilithium3"],
                    iterations=1000,
                    warmup_cycles=100
                )
                
                results = benchmarker.run_benchmarks()
                print(f"Kyber-768 keygen: {results['kyber-768']['keygen_us']}µs")
                print(f"Dilithium3 sign: {results['dilithium3']['sign_us']}µs")
                """
            ],
            parameters={
                "algorithms": "List[str] - Algorithms to benchmark",
                "iterations": "int - Number of test iterations",
                "warmup_cycles": "int - Warmup iterations before timing"
            },
            returns="Dict - Benchmark results with microsecond timings",
            exceptions=["BenchmarkError", "AlgorithmNotFoundError"],
            see_also=["algorithm_compatibility_migration_advisor"],
            compliance_notes=[
                "Research tool - Not for production key operations",
                "Statistically significant sample sizes",
                "CPU frequency scaling aware"
            ]
        )
    
    def get_algorithm_documentation(self, algorithm_name: str) -> Optional[AlgorithmDocumentation]:
        """
        Get documentation for a specific algorithm.
        
        Args:
            algorithm_name: Name of the algorithm to look up
            
        Returns:
            AlgorithmDocumentation if found, None otherwise
        """
        return self._catalog.get(algorithm_name.lower())
    
    def list_algorithms_by_stability(self, stability: StabilityLevel) -> List[str]:
        """
        List all algorithms with a specific stability level.
        
        Args:
            stability: Stability level to filter by
            
        Returns:
            List of algorithm names matching the stability level
        """
        return [
            name for name, doc in self._catalog.items()
            if doc.stability == stability
        ]
    
    def list_algorithms_by_nist_status(self, nist_status: NISTPQCStatus) -> List[str]:
        """
        List all algorithms by NIST PQC standardization status.
        
        Args:
            nist_status: NIST status to filter by
            
        Returns:
            List of algorithm names matching the status
        """
        return [
            name for name, doc in self._catalog.items()
            if doc.nist_status == nist_status
        ]
    
    def get_stability_summary(self) -> Dict[str, int]:
        """
        Get summary count of algorithms by stability level.
        
        Returns:
            Dictionary with stability levels as keys and counts as values
        """
        summary: Dict[str, int] = {}
        for doc in self._catalog.values():
            key = doc.stability.value
            summary[key] = summary.get(key, 0) + 1
        return summary
    
    def get_nist_status_summary(self) -> Dict[str, int]:
        """
        Get summary count of algorithms by NIST PQC status.
        
        Returns:
            Dictionary with NIST status as keys and counts as values
        """
        summary: Dict[str, int] = {}
        for doc in self._catalog.values():
            key = doc.nist_status.value
            summary[key] = summary.get(key, 0) + 1
        return summary
    
    def generate_readme_section(self) -> str:
        """
        Generate a README-compatible documentation section.
        
        Returns:
            Markdown formatted documentation summary
        """
        stability_summary = self.get_stability_summary()
        nist_summary = self.get_nist_status_summary()
        
        readme = f"""
## QuantumCrypt API Stability Summary

Last Updated: {datetime.date.today().isoformat()}

### Stability Breakdown
"""
        for level, count in stability_summary.items():
            readme += f"- **{level}**: {count} algorithms\n"
        
        readme += """
### NIST PQC Standardization Status
"""
        for status, count in nist_summary.items():
            readme += f"- **{status}**: {count} algorithms\n"
        
        readme += """
### Algorithm Categories

#### 🔐 Key Encapsulation (STABLE, STANDARDIZED)
- **CRYSTALS-Kyber** - NIST FIPS 203 standardized KEM
- **Hybrid KEM Engine** - Classical + PQC hybrid key exchange

#### ✍️ Digital Signatures (STABLE, STANDARDIZED)
- **CRYSTALS-Dilithium** - NIST FIPS 204 standardized signatures
- Batch verification support for high-throughput scenarios

#### 🔑 Key Management (STABLE)
- **Session Key Manager (Forward Secrecy)** - Automatic key rotation
- Side-channel resistant key wrapping

#### ⚡ Performance Tools (BETA)
- **Performance Benchmark Profiler** - Algorithm timing and comparison

### Migration Recommendation
For production deployment:
1. **Start with Hybrid mode** - Combine PQC + classical algorithms
2. **Use Kyber-768** - NIST Security Level 3 (balanced security/performance)
3. **Enable Forward Secrecy** - Automatic key rotation enabled
4. **All instrumentation OPT-IN only** - Disabled by default
"""
        return readme


# Export singleton instance
documentation_catalog = QuantumCryptDocumentationCatalog()

__all__ = [
    "QuantumCryptDocumentationCatalog",
    "AlgorithmDocumentation",
    "StabilityLevel",
    "NISTPQCStatus",
    "documentation_catalog"
]
