"""
QuantumCrypt-AI: Comprehensive API Documentation & Stability Catalog v30
========================================================================
Date: 2026-06-25
Dimension: F - Documentation & API Stability

This module provides:
1. Comprehensive API documentation for all public crypto interfaces
2. API stability markers (STABLE/EXPERIMENTAL/DEPRECATED)
3. Usage examples and code snippets
4. Algorithm comparison and security level guidance
5. Migration guides and quantum readiness notes

API STABILITY LEVELS:
---------------------
STABLE:         API is frozen, backward compatible, safe for production
EXPERIMENTAL:   API may change, suitable for testing only
DEPRECATED:     Will be removed in future versions, migrate now
INTERNAL:       Not for public consumption, may change without notice

POST-QUANTUM READINESS:
-----------------------
NIST Security Levels: 1, 3, 5 (increasing security)
Migration Path: Classical → Hybrid → Post-Quantum Only
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union
from datetime import datetime
import inspect


class StabilityLevel(Enum):
    """API Stability Level Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    INTERNAL = "INTERNAL"
    
    def __str__(self) -> str:
        return self.value


class NISTSecurityLevel(Enum):
    """NIST Post-Quantum Security Levels"""
    LEVEL_1 = 1  # AES-128 equivalent
    LEVEL_3 = 3  # AES-192 equivalent
    LEVEL_5 = 5  # AES-256 equivalent
    
    def __str__(self) -> str:
        return f"LEVEL_{self.value}"


@dataclass
class AlgorithmInfo:
    """Cryptographic algorithm metadata"""
    name: str
    standard: str
    nist_level: NISTSecurityLevel
    type: str  # signature, key-exchange, encryption
    quantum_safe: bool
    recommended: bool
    key_sizes: Dict[str, int]
    performance_notes: str


@dataclass
class APIEndpoint:
    """Metadata for a documented API endpoint"""
    name: str
    module: str
    stability: StabilityLevel
    since_version: str
    description: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    examples: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    deprecation_scheduled: Optional[str] = None
    migration_guide: Optional[str] = None
    quantum_readiness: str = "CLASSICAL"  # CLASSICAL, HYBRID, PQ_ONLY


@dataclass
class ModuleDocumentation:
    """Complete documentation for a module"""
    module_name: str
    category: str
    stability: StabilityLevel
    endpoints: List[APIEndpoint] = field(default_factory=list)
    overview: str = ""
    getting_started: str = ""
    best_practices: List[str] = field(default_factory=list)
    common_pitfalls: List[str] = field(default_factory=list)
    quantum_migration_notes: str = ""


class DocumentationCatalog:
    """
    Central API Documentation and Stability Catalog for QuantumCrypt-AI
    
    Stability: STABLE (since v20)
    
    This is the single source of truth for all API documentation,
    stability information, and quantum readiness guidance.
    
    Usage:
        catalog = DocumentationCatalog()
        catalog.print_stability_report()
        catalog.print_quantum_readiness_guide()
        docs = catalog.get_module_docs("post_quantum")
    """
    
    def __init__(self) -> None:
        self._modules: Dict[str, ModuleDocumentation] = {}
        self._algorithms: Dict[str, AlgorithmInfo] = {}
        self._build_catalog()
        self._build_algorithm_catalog()
    
    def _build_catalog(self) -> None:
        """Build the complete documentation catalog"""
        # Core Crypto Modules
        self._add_post_quantum_docs()
        self._add_classical_crypto_docs()
        self._add_hybrid_signature_docs()
        
        # Key Management
        self._add_key_management_docs()
        
        # Security Modules
        self._add_security_hardening_docs()
        self._add_side_channel_protection_docs()
        
        # Error Resilience
        self._add_error_resilience_docs()
        
        # Observability
        self._add_observability_docs()
    
    def _build_algorithm_catalog(self) -> None:
        """Build cryptographic algorithm reference catalog"""
        # Post-Quantum Signature Algorithms (NIST FIPS 204, 205, 206)
        self._algorithms["CRYSTALS-Dilithium-2"] = AlgorithmInfo(
            name="CRYSTALS-Dilithium-2",
            standard="FIPS 204",
            nist_level=NISTSecurityLevel.LEVEL_1,
            type="signature",
            quantum_safe=True,
            recommended=True,
            key_sizes={"pk": 1312, "sk": 2528, "sig": 2420},
            performance_notes="Fastest PQ signature, recommended for general use"
        )
        self._algorithms["CRYSTALS-Dilithium-3"] = AlgorithmInfo(
            name="CRYSTALS-Dilithium-3",
            standard="FIPS 204",
            nist_level=NISTSecurityLevel.LEVEL_3,
            type="signature",
            quantum_safe=True,
            recommended=True,
            key_sizes={"pk": 1952, "sk": 4000, "sig": 3293},
            performance_notes="Balanced security/performance"
        )
        self._algorithms["CRYSTALS-Dilithium-5"] = AlgorithmInfo(
            name="CRYSTALS-Dilithium-5",
            standard="FIPS 204",
            nist_level=NISTSecurityLevel.LEVEL_5,
            type="signature",
            quantum_safe=True,
            recommended=True,
            key_sizes={"pk": 2592, "sk": 4864, "sig": 4595},
            performance_notes="Highest security, larger signatures"
        )
        self._algorithms["Falcon-512"] = AlgorithmInfo(
            name="Falcon-512",
            standard="FIPS 205",
            nist_level=NISTSecurityLevel.LEVEL_1,
            type="signature",
            quantum_safe=True,
            recommended=True,
            key_sizes={"pk": 897, "sk": 1281, "sig": 666},
            performance_notes="Small signatures, complex implementation"
        )
        self._algorithms["SPHINCS+-SHA2-128f"] = AlgorithmInfo(
            name="SPHINCS+-SHA2-128f",
            standard="FIPS 206",
            nist_level=NISTSecurityLevel.LEVEL_1,
            type="signature",
            quantum_safe=True,
            recommended=True,
            key_sizes={"pk": 32, "sk": 64, "sig": 17088},
            performance_notes="Stateless, very large signatures"
        )
        
        # Post-Quantum Key Exchange (NIST FIPS 203)
        self._algorithms["CRYSTALS-Kyber-512"] = AlgorithmInfo(
            name="CRYSTALS-Kyber-512",
            standard="FIPS 203",
            nist_level=NISTSecurityLevel.LEVEL_1,
            type="key-exchange",
            quantum_safe=True,
            recommended=True,
            key_sizes={"pk": 800, "sk": 1632, "ct": 768, "ss": 32},
            performance_notes="Fast KEM, recommended for TLS 1.3"
        )
        self._algorithms["CRYSTALS-Kyber-768"] = AlgorithmInfo(
            name="CRYSTALS-Kyber-768",
            standard="FIPS 203",
            nist_level=NISTSecurityLevel.LEVEL_3,
            type="key-exchange",
            quantum_safe=True,
            recommended=True,
            key_sizes={"pk": 1184, "sk": 2400, "ct": 1088, "ss": 32},
            performance_notes="Default recommended for most applications"
        )
        self._algorithms["CRYSTALS-Kyber-1024"] = AlgorithmInfo(
            name="CRYSTALS-Kyber-1024",
            standard="FIPS 203",
            nist_level=NISTSecurityLevel.LEVEL_5,
            type="key-exchange",
            quantum_safe=True,
            recommended=True,
            key_sizes={"pk": 1568, "sk": 3168, "ct": 1568, "ss": 32},
            performance_notes="Highest security KEM"
        )
        
        # Classical Algorithms
        self._algorithms["RSA-2048"] = AlgorithmInfo(
            name="RSA-2048",
            standard="PKCS #1",
            nist_level=NISTSecurityLevel.LEVEL_1,
            type="signature/encryption",
            quantum_safe=False,
            recommended=False,
            key_sizes={"pk": 256, "sk": 1152},
            performance_notes="NOT quantum-safe, migrate to hybrid"
        )
        self._algorithms["ECDSA-P256"] = AlgorithmInfo(
            name="ECDSA-P256",
            standard="FIPS 186-4",
            nist_level=NISTSecurityLevel.LEVEL_1,
            type="signature",
            quantum_safe=False,
            recommended=False,
            key_sizes={"pk": 64, "sk": 32, "sig": 64},
            performance_notes="NOT quantum-safe, use in hybrid mode"
        )
        self._algorithms["Ed25519"] = AlgorithmInfo(
            name="Ed25519",
            standard="RFC 8032",
            nist_level=NISTSecurityLevel.LEVEL_1,
            type="signature",
            quantum_safe=False,
            recommended=False,
            key_sizes={"pk": 32, "sk": 32, "sig": 64},
            performance_notes="NOT quantum-safe, use in hybrid mode"
        )
    
    def _add_post_quantum_docs(self) -> None:
        """Post-Quantum Cryptography Module Documentation"""
        module = ModuleDocumentation(
            module_name="post_quantum",
            category="Post-Quantum Crypto",
            stability=StabilityLevel.STABLE,
            overview="""
            Post-Quantum Cryptography module implements NIST-standardized
            post-quantum algorithms including CRYSTALS-Kyber (KEM) and
            CRYSTALS-Dilithium, Falcon, SPHINCS+ (signatures).
            
            All implementations follow FIPS 203, 204, 205, 206 standards.
            """,
            getting_started="""
            from quantum_crypt.pq_key_encapsulation_kyber_768_2026_june import (
                Kyber768KEM
            )
            
            kem = Kyber768KEM()
            pk, sk = kem.keygen()
            ct, ss = kem.encaps(pk)
            ss2 = kem.decaps(ct, sk)
            """,
            best_practices=[
                "Use Kyber-768 as default for key exchange",
                "Use Dilithium-3 as default for signatures",
                "Always validate ciphertext integrity",
                "Implement hybrid mode during migration"
            ],
            common_pitfalls=[
                "Using weak randomness for key generation",
                "Not validating public key format",
                "Timing side channels in decapsulation"
            ],
            quantum_migration_notes="""
            MIGRATION PATH:
            1. Start with hybrid (classical + PQ) mode
            2. Validate interoperability with peers
            3. Monitor for performance impact
            4. Phase out classical-only after full adoption
            """
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="Kyber768KEM.keygen",
                module="pq_key_encapsulation_kyber_768_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v20",
                description="Generate Kyber-768 key pair (NIST Level 3)",
                parameters=[
                    {"name": "seed", "type": "Optional[bytes]", "desc": "Deterministic seed (testing only)"}
                ],
                returns="Tuple[pk: bytes, sk: bytes]",
                examples=[
                    """
                    kem = Kyber768KEM()
                    public_key, secret_key = kem.keygen()
                    """
                ],
                notes=["NIST FIPS 203 compliant, 1184 byte pk, 2400 byte sk"],
                quantum_readiness="PQ_ONLY"
            ),
            APIEndpoint(
                name="Kyber768KEM.encaps",
                module="pq_key_encapsulation_kyber_768_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v20",
                description="Encapsulate shared secret using public key",
                parameters=[
                    {"name": "public_key", "type": "bytes", "desc": "Receiver's public key"}
                ],
                returns="Tuple[ciphertext: bytes, shared_secret: bytes]",
                notes=["1088 byte ciphertext, 32 byte shared secret"],
                quantum_readiness="PQ_ONLY"
            ),
            APIEndpoint(
                name="Kyber768KEM.decaps",
                module="pq_key_encapsulation_kyber_768_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v20",
                description="Decapsulate shared secret (constant-time)",
                parameters=[
                    {"name": "ciphertext", "type": "bytes", "desc": "Received ciphertext"},
                    {"name": "secret_key", "type": "bytes", "desc": "Receiver's secret key"}
                ],
                returns="shared_secret: bytes",
                notes=["Constant-time implementation resists timing attacks"],
                quantum_readiness="PQ_ONLY"
            ),
            APIEndpoint(
                name="Dilithium3Signer.keygen",
                module="pq_digital_signature_dilithium3_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v20",
                description="Generate Dilithium-3 signature key pair",
                parameters=[],
                returns="Tuple[pk: bytes, sk: bytes]",
                notes=["NIST FIPS 204 Level 3"],
                quantum_readiness="PQ_ONLY"
            ),
            APIEndpoint(
                name="Dilithium3Signer.sign",
                module="pq_digital_signature_dilithium3_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v20",
                description="Sign message with secret key",
                parameters=[
                    {"name": "message", "type": "bytes", "desc": "Message to sign"},
                    {"name": "secret_key", "type": "bytes", "desc": "Signer's secret key"}
                ],
                returns="signature: bytes",
                notes=["Deterministic signing (no randomness needed)"],
                quantum_readiness="PQ_ONLY"
            ),
            APIEndpoint(
                name="Dilithium3Signer.verify",
                module="pq_digital_signature_dilithium3_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v20",
                description="Verify signature (constant-time)",
                parameters=[
                    {"name": "message", "type": "bytes", "desc": "Signed message"},
                    {"name": "signature", "type": "bytes", "desc": "Signature to verify"},
                    {"name": "public_key", "type": "bytes", "desc": "Signer's public key"}
                ],
                returns="bool - True if valid",
                notes=["Constant-time verification"],
                quantum_readiness="PQ_ONLY"
            )
        ])
        
        self._modules["post_quantum"] = module
    
    def _add_classical_crypto_docs(self) -> None:
        """Classical Cryptography Module Documentation"""
        module = ModuleDocumentation(
            module_name="classical_crypto",
            category="Classical Crypto",
            stability=StabilityLevel.STABLE,
            overview="""
            Classical cryptography implementations for RSA, ECDSA, Ed25519,
            and AES. These are NOT quantum-safe but provided for hybrid
            migration and backward compatibility.
            
            USE IN HYBRID MODE ONLY for quantum readiness.
            """,
            getting_started="""
            from quantum_crypt.classical_signature_ed25519_2026_june import (
                Ed25519Signer
            )
            
            signer = Ed25519Signer()
            pk, sk = signer.keygen()
            sig = signer.sign(b"message", sk)
            valid = signer.verify(b"message", sig, pk)
            """,
            best_practices=[
                "Use only in hybrid mode with PQ algorithms",
                "Prefer Ed25519 over RSA and ECDSA",
                "Plan migration timeline to PQ-only",
                "Use 4096-bit RSA minimum if used"
            ],
            common_pitfalls=[
                "Assuming classical = quantum-safe (it's NOT)",
                "Using RSA-2048 (insufficient for long-term)",
                "No migration plan in place"
            ],
            quantum_migration_notes="""
            ALL classical algorithms are vulnerable to quantum computers.
            Start using hybrid (classical + PQ) mode immediately.
            Plan to phase out classical-only by 2030.
            """
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="Ed25519Signer.keygen",
                module="classical_signature_ed25519_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v15",
                description="Generate Ed25519 key pair (NOT quantum-safe)",
                parameters=[],
                returns="Tuple[pk: bytes, sk: bytes]",
                notes=["32 byte keys, 64 byte signatures"],
                quantum_readiness="CLASSICAL"
            ),
            APIEndpoint(
                name="Ed25519Signer.sign",
                module="classical_signature_ed25519_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v15",
                description="Sign message with Ed25519",
                parameters=[
                    {"name": "message", "type": "bytes", "desc": "Message"},
                    {"name": "secret_key", "type": "bytes", "desc": "Secret key"}
                ],
                returns="signature: bytes",
                notes=["NOT quantum-safe - use in hybrid mode only"],
                quantum_readiness="CLASSICAL"
            ),
            APIEndpoint(
                name="Ed25519Signer.verify",
                module="classical_signature_ed25519_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v15",
                description="Verify Ed25519 signature",
                parameters=[
                    {"name": "message", "type": "bytes", "desc": "Message"},
                    {"name": "signature", "type": "bytes", "desc": "Signature"},
                    {"name": "public_key", "type": "bytes", "desc": "Public key"}
                ],
                returns="bool",
                quantum_readiness="CLASSICAL"
            ),
            APIEndpoint(
                name="AESGCM.encrypt",
                module="classical_encryption_aes_gcm_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v15",
                description="AES-GCM authenticated encryption",
                parameters=[
                    {"name": "plaintext", "type": "bytes", "desc": "Data to encrypt"},
                    {"name": "key", "type": "bytes", "desc": "16/24/32 byte key"},
                    {"name": "associated_data", "type": "Optional[bytes]", "desc": "AEAD data"}
                ],
                returns="Tuple[nonce: bytes, ciphertext: bytes, tag: bytes]",
                notes=["AES is quantum-resistant (Grover only quadratic speedup)"],
                quantum_readiness="QUANTUM_RESISTANT"
            )
        ])
        
        self._modules["classical_crypto"] = module
    
    def _add_hybrid_signature_docs(self) -> None:
        """Hybrid Signature Module Documentation"""
        module = ModuleDocumentation(
            module_name="hybrid_signature",
            category="Hybrid Crypto",
            stability=StabilityLevel.STABLE,
            overview="""
            Hybrid signature verification combines classical and post-quantum
            algorithms for smooth migration. Provides AND, OR, MAJORITY,
            and priority-based verification modes.
            
            RECOMMENDED approach for quantum migration: start with AND mode
            requiring both classical AND PQ verification.
            """,
            getting_started="""
            from quantum_crypt.feature_expansion_pq_hybrid_signature_verifier_v81_2026_june import (
                HybridSignatureVerifier, VerificationMode
            )
            
            verifier = HybridSignatureVerifier(mode=VerificationMode.AND)
            result = verifier.verify(message, signatures, public_keys)
            """,
            best_practices=[
                "Use AND mode for strict verification (default)",
                "Start hybrid deployment immediately",
                "Monitor both classical and PQ verification separately",
                "Plan transition from AND to PQ_ONLY after adoption"
            ],
            common_pitfalls=[
                "Using OR mode reduces security to weakest link",
                "Not validating algorithm pairing compatibility",
                "Ignoring signature ordering requirements"
            ],
            quantum_migration_notes="""
            HYBRID MIGRATION TIMELINE:
            - Phase 1 (Now): AND mode (classical + PQ required)
            - Phase 2 (2027): PQ_FIRST mode (PQ sufficient)
            - Phase 3 (2028-2030): PQ_ONLY mode (classical optional)
            """
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="HybridSignatureVerifier.verify",
                module="feature_expansion_pq_hybrid_signature_verifier_v81",
                stability=StabilityLevel.STABLE,
                since_version="v81",
                description="Verify hybrid multi-algorithm signatures",
                parameters=[
                    {"name": "message", "type": "bytes", "desc": "Signed message"},
                    {"name": "signatures", "type": "List[bytes]", "desc": "Signatures per algorithm"},
                    {"name": "public_keys", "type": "List[bytes]", "desc": "Public keys per algorithm"}
                ],
                returns="HybridVerificationResult",
                examples=[
                    """
                    verifier = HybridSignatureVerifier(mode=VerificationMode.AND)
                    result = verifier.verify(
                        message=b"Important data",
                        signatures=[pq_sig, classical_sig],
                        public_keys=[pq_pk, classical_pk]
                    )
                    if result.verified:
                        print("Both PQ and classical verified!")
                    """
                ],
                notes=["AND mode: both must verify; OR mode: either suffices"],
                quantum_readiness="HYBRID"
            ),
            APIEndpoint(
                name="HybridSignatureVerifier.recommend_algorithms",
                module="feature_expansion_pq_hybrid_signature_verifier_v81",
                stability=StabilityLevel.STABLE,
                since_version="v81",
                description="Get algorithm pairing recommendations",
                parameters=[
                    {"name": "required_security_level", "type": "int", "desc": "NIST level 1/3/5"},
                    {"name": "performance_priority", "type": "str", "desc": "speed/security/balanced"}
                ],
                returns="AlgorithmRecommendation",
                quantum_readiness="HYBRID"
            )
        ])
        
        self._modules["hybrid_signature"] = module
    
    def _add_key_management_docs(self) -> None:
        """Key Management Module Documentation"""
        module = ModuleDocumentation(
            module_name="key_management",
            category="Key Management",
            stability=StabilityLevel.STABLE,
            overview="""
            Key management provides secure key generation, storage, rotation,
            and lifecycle management for both classical and post-quantum keys.
            
            Includes automated key rotation policies and emergency procedures.
            """,
            getting_started="""
            from quantum_crypt.pq_key_rotation_manager_2026_june import (
                PostQuantumKeyRotationManager
            )
            
            manager = PostQuantumKeyRotationManager()
            manager.set_rotation_policy(days=90, auto_rotate=True)
            """,
            best_practices=[
                "Rotate keys at least every 90 days",
                "Use separate keys for signing and encryption",
                "Implement emergency key revocation procedures",
                "Maintain offline backup of root keys"
            ],
            common_pitfalls=[
                "Hardcoding keys in source code",
                "No key rotation policy",
                "Single point of failure for root keys",
                "Not backing up keys securely"
            ],
            quantum_migration_notes="""
            Key storage requirements increase for PQ keys:
            - Kyber-768 sk: 2400 bytes (vs 32 for ECDSA)
            - Dilithium-3 sk: 4000 bytes (vs 32 for ECDSA)
            Plan HSM/storage capacity accordingly.
            """
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="PostQuantumKeyRotationManager.set_rotation_policy",
                module="pq_key_rotation_manager_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v81",
                description="Configure automatic key rotation policy",
                parameters=[
                    {"name": "days", "type": "int", "desc": "Rotation interval days"},
                    {"name": "auto_rotate", "type": "bool", "desc": "Enable auto-rotation"},
                    {"name": "overlap_hours", "type": "int", "desc": "Key overlap period"}
                ],
                returns="None",
                quantum_readiness="HYBRID"
            ),
            APIEndpoint(
                name="PostQuantumKeyRotationManager.rotate_keys",
                module="pq_key_rotation_manager_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v81",
                description="Manually trigger key rotation",
                parameters=[
                    {"name": "key_ids", "type": "Optional[List[str]]", "desc": "Specific keys to rotate"}
                ],
                returns="RotationResult with new key IDs",
                quantum_readiness="HYBRID"
            )
        ])
        
        self._modules["key_management"] = module
    
    def _add_security_hardening_docs(self) -> None:
        """Security Hardening Module Documentation"""
        module = ModuleDocumentation(
            module_name="security_hardening",
            category="Security",
            stability=StabilityLevel.STABLE,
            overview="""
            Security hardening provides constant-time operations, secure
            memory handling, side-channel protection, and secure key
            generation for cryptographic operations.
            
            CRITICAL: All crypto operations MUST use these protections.
            """,
            getting_started="""
            from quantum_crypt.security_hardening_pq_constant_time_key_v31_2026_june import (
                constant_time_compare, secure_zeroize
            )
            
            if constant_time_compare(received, expected):
                process_valid()
            secure_zeroize(sensitive_buffer)
            """,
            best_practices=[
                "Always use constant-time comparison for secrets",
                "Zeroize all sensitive memory after use",
                "Validate all key formats before use",
                "Use side-channel resistant implementations"
            ],
            common_pitfalls=[
                "Early exit in verification (timing leak)",
                "Sensitive data left in memory",
                "Not wiping stack/register contents",
                "Using non-cryptographic randomness"
            ]
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="constant_time_compare",
                module="security_hardening_pq_constant_time_key_v31",
                stability=StabilityLevel.STABLE,
                since_version="v31",
                description="Timing-attack resistant comparison",
                parameters=[
                    {"name": "a", "type": "bytes", "desc": "First value"},
                    {"name": "b", "type": "bytes", "desc": "Second value"}
                ],
                returns="bool - True if equal",
                notes=["Execution time depends only on length"],
                quantum_readiness="APPLICABLE"
            ),
            APIEndpoint(
                name="secure_zeroize",
                module="security_hardening_pq_constant_time_key_v31",
                stability=StabilityLevel.STABLE,
                since_version="v31",
                description="Securely overwrite sensitive memory",
                parameters=[
                    {"name": "buffer", "type": "bytearray", "desc": "Buffer to zeroize"},
                    {"name": "passes", "type": "int", "desc": "Overwrite passes (default 3)"}
                ],
                returns="None",
                notes=["Volatile writes prevent compiler optimization"],
                quantum_readiness="APPLICABLE"
            ),
            APIEndpoint(
                name="SideChannelProtectedDecapsulator.decapsulate",
                module="security_hardening_side_channel_cache_aware_protection_v31",
                stability=StabilityLevel.STABLE,
                since_version="v31",
                description="Side-channel protected Kyber decapsulation",
                parameters=[
                    {"name": "ct", "type": "bytes", "desc": "Ciphertext"},
                    {"name": "sk", "type": "bytes", "desc": "Secret key"}
                ],
                returns="shared_secret: bytes",
                notes=["Cache-aware, blinding, constant-time"],
                quantum_readiness="APPLICABLE"
            )
        ])
        
        self._modules["security_hardening"] = module
    
    def _add_side_channel_protection_docs(self) -> None:
        """Side-Channel Protection Module Documentation"""
        module = ModuleDocumentation(
            module_name="side_channel_protection",
            category="Advanced Security",
            stability=StabilityLevel.STABLE,
            overview="""
            Side-channel protection against timing, cache, power, and
            electromagnetic analysis attacks. Includes blinding, masking,
            and constant-time execution guarantees.
            """,
            getting_started="""
            from quantum_crypt.security_hardening_side_channel_timing_resistance_v21_2026_june import (
                TimingResistantOperation, blinding_mask
            )
            
            with TimingResistantOperation():
                result = sensitive_crypto_operation()
            """,
            best_practices=[
                "Apply first-order masking for all secret operations",
                "Use blinding for signature operations",
                "Avoid secret-dependent branching",
                "Validate constant-time behavior in testing"
            ],
            common_pitfalls=[
                "Compiler optimizations breaking constant-time",
                "Secret-dependent memory access patterns",
                "Not considering cache side channels"
            ]
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="first_order_mask",
                module="security_hardening_side_channel_timing_resistance_v21",
                stability=StabilityLevel.STABLE,
                since_version="v21",
                description="Apply first-order Boolean masking",
                parameters=[
                    {"name": "value", "type": "int", "desc": "Value to mask"},
                    {"name": "mask", "type": "Optional[int]", "desc": "Random mask"}
                ],
                returns="Tuple[masked_value: int, mask: int]",
                quantum_readiness="APPLICABLE"
            )
        ])
        
        self._modules["side_channel_protection"] = module
    
    def _add_error_resilience_docs(self) -> None:
        """Error Resilience Module Documentation"""
        module = ModuleDocumentation(
            module_name="error_resilience",
            category="Reliability",
            stability=StabilityLevel.STABLE,
            overview="""
            Error resilience for crypto operations including fallback chains,
            graceful degradation, and priority-based algorithm selection.
            
            Ensures crypto operations never fail catastrophically.
            """,
            getting_started="""
            from quantum_crypt.crypto_test_error_resilience_pq_key_operation_v34_2026_june import (
                PQKeyOperationResilience, FallbackPriority
            )
            
            resilient_ops = PQKeyOperationResilience()
            result = resilient_ops.execute_with_fallback(primary_op, fallbacks)
            """,
            best_practices=[
                "Always provide fallback algorithms",
                "Prioritize security over availability in fallback chain",
                "Log all fallback activations",
                "Set appropriate timeouts for HSM operations"
            ],
            common_pitfalls=[
                "Fallback to weaker security than necessary",
                "Silent failures without logging",
                "Infinite retry loops"
            ]
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="PQKeyOperationResilience.execute_with_fallback",
                module="crypto_test_error_resilience_pq_key_operation_v34",
                stability=StabilityLevel.STABLE,
                since_version="v34",
                description="Execute operation with fallback chain",
                parameters=[
                    {"name": "primary", "type": "Callable", "desc": "Primary operation"},
                    {"name": "fallbacks", "type": "List[Callable]", "desc": "Fallback operations"},
                    {"name": "priority", "type": "FallbackPriority", "desc": "SECURITY or AVAILABILITY"}
                ],
                returns="OperationResult",
                quantum_readiness="APPLICABLE"
            )
        ])
        
        self._modules["error_resilience"] = module
    
    def _add_observability_docs(self) -> None:
        """Observability Module Documentation"""
        module = ModuleDocumentation(
            module_name="observability",
            category="Observability",
            stability=StabilityLevel.STABLE,
            overview="""
            Observability for crypto operations including audit logging,
            metrics, tracing, and key usage monitoring.
            
            All instrumentation is OPT-IN and privacy-preserving.
            """,
            getting_started="""
            from quantum_crypt.crypto_test_observability_tracing_audit_v26_2026_june import (
                CryptoAuditLogger, CryptoMetrics
            )
            
            audit = CryptoAuditLogger()
            audit.log_key_usage(key_id, operation="sign", user_id="service")
            """,
            best_practices=[
                "Log all key operations for audit",
                "Monitor algorithm usage for migration tracking",
                "Never log key material in plaintext",
                "Use structured logging for SIEM integration"
            ],
            common_pitfalls=[
                "Logging sensitive key material",
                "High-cardinality dimensions in metrics",
                "Not sampling high-volume operations"
            ]
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="CryptoAuditLogger.log_key_usage",
                module="crypto_test_observability_tracing_audit_v26",
                stability=StabilityLevel.STABLE,
                since_version="v26",
                description="Log key usage for audit",
                parameters=[
                    {"name": "key_id", "type": "str", "desc": "Key identifier (hash)"},
                    {"name": "operation", "type": "str", "desc": "sign/encrypt/decaps"},
                    {"name": "context", "type": "Dict", "desc": "Operation context"}
                ],
                returns="None",
                notes=["Never logs actual key material"],
                quantum_readiness="APPLICABLE"
            ),
            APIEndpoint(
                name="CryptoMetrics.record_algorithm_usage",
                module="crypto_test_observability_tracing_audit_v26",
                stability=StabilityLevel.STABLE,
                since_version="v26",
                description="Record algorithm usage metrics",
                parameters=[
                    {"name": "algorithm", "type": "str", "desc": "Algorithm name"},
                    {"name": "operation", "type": "str", "desc": "Operation type"},
                    {"name": "duration_ms", "type": "float", "desc": "Execution time"}
                ],
                returns="None",
                quantum_readiness="APPLICABLE"
            )
        ])
        
        self._modules["observability"] = module
    
    def get_module_docs(self, module_name: str) -> Optional[ModuleDocumentation]:
        """Get documentation for a specific module"""
        return self._modules.get(module_name)
    
    def get_all_modules(self) -> List[str]:
        """Get list of all documented modules"""
        return list(self._modules.keys())
    
    def get_algorithm_info(self, algo_name: str) -> Optional[AlgorithmInfo]:
        """Get information about a cryptographic algorithm"""
        return self._algorithms.get(algo_name)
    
    def get_all_algorithms(self) -> List[str]:
        """Get list of all documented algorithms"""
        return list(self._algorithms.keys())
    
    def get_recommended_algorithms(self, quantum_safe_only: bool = True) -> List[AlgorithmInfo]:
        """Get list of recommended algorithms"""
        return [
            algo for algo in self._algorithms.values()
            if algo.recommended and (not quantum_safe_only or algo.quantum_safe)
        ]
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get count of endpoints by stability level"""
        summary = {level: 0 for level in StabilityLevel}
        for module in self._modules.values():
            for endpoint in module.endpoints:
                summary[endpoint.stability] += 1
        return {str(k): v for k, v in summary.items()}
    
    def print_stability_report(self) -> None:
        """Print human-readable stability report"""
        print("=" * 70)
        print("QUANTUMCRYPT-AI API STABILITY REPORT v30")
        print("=" * 70)
        print(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
        print(f"Modules Documented: {len(self._modules)}")
        print(f"Algorithms Documented: {len(self._algorithms)}")
        
        total_endpoints = sum(len(m.endpoints) for m in self._modules.values())
        print(f"Total Documented Endpoints: {total_endpoints}")
        print()
        
        print("STABILITY BREAKDOWN:")
        for level, count in self.get_stability_summary().items():
            pct = (count / total_endpoints * 100) if total_endpoints > 0 else 0
            print(f"  {level:15} {count:3d} endpoints ({pct:5.1f}%)")
        
        print()
        print("MODULES:")
        for name, module in sorted(self._modules.items()):
            print(f"  {name:25} [{module.stability.value:12}] "
                  f"{len(module.endpoints)} endpoints")
        
        print()
        print("QUANTUM-SAFE ALGORITHMS:")
        for algo in sorted(self.get_recommended_algorithms(quantum_safe_only=True),
                          key=lambda a: a.nist_level.value):
            print(f"  {algo.name:30} NIST-{algo.nist_level.value}  "
                  f"pk={algo.key_sizes.get('pk', 0):4d} bytes")
        
        print()
        print("=" * 70)
        print("QUANTUM READINESS GUIDANCE:")
        print("  ✅ Use hybrid (classical + PQ) mode immediately")
        print("  ✅ Prefer Kyber-768 / Dilithium-3 for new deployments")
        print("  ⚠️  Classical algorithms (RSA, ECDSA) are NOT quantum-safe")
        print("  📅 Plan full PQ migration by 2030")
        print("=" * 70)
    
    def print_quantum_readiness_guide(self) -> None:
        """Print quantum migration readiness guide"""
        print("\n" + "=" * 70)
        print("POST-QUANTUM MIGRATION READINESS GUIDE")
        print("=" * 70)
        print("\nMIGRATION PATH:")
        print("  PHASE 1: HYBRID MODE (NOW)")
        print("    - Sign/encrypt with BOTH classical AND PQ algorithms")
        print("    - Verify requires BOTH to pass (AND mode)")
        print("    - Maintains backward compatibility")
        print()
        print("  PHASE 2: PQ-PRIORITY (2027)")
        print("    - PQ verification sufficient, classical optional")
        print("    - Begin deprecating classical-only peers")
        print()
        print("  PHASE 3: PQ-ONLY (2028-2030)")
        print("    - Remove classical algorithms entirely")
        print("    - Full quantum-safe deployment")
        print()
        print("RECOMMENDED ALGORITHMS:")
        print("  Key Exchange:  CRYSTALS-Kyber-768  (NIST Level 3)")
        print("  Signatures:    CRYSTALS-Dilithium-3 (NIST Level 3)")
        print("  Encryption:    AES-256-GCM (quantum-resistant)")
        print()
        print("=" * 70 + "\n")


# Global catalog instance
_catalog_instance: Optional[DocumentationCatalog] = None


def get_documentation_catalog() -> DocumentationCatalog:
    """Get the global documentation catalog instance (singleton)"""
    global _catalog_instance
    if _catalog_instance is None:
        _catalog_instance = DocumentationCatalog()
    return _catalog_instance


def print_api_stability_report() -> None:
    """Convenience function to print the full stability report"""
    catalog = get_documentation_catalog()
    catalog.print_stability_report()


def print_quantum_readiness_guide() -> None:
    """Convenience function to print quantum readiness guide"""
    catalog = get_documentation_catalog()
    catalog.print_quantum_readiness_guide()


# Export public API
__all__ = [
    'StabilityLevel',
    'NISTSecurityLevel',
    'AlgorithmInfo',
    'APIEndpoint',
    'ModuleDocumentation',
    'DocumentationCatalog',
    'get_documentation_catalog',
    'print_api_stability_report',
    'print_quantum_readiness_guide',
]

# API Stability Markers for exports
__api_stability__ = {
    'StabilityLevel': 'STABLE',
    'NISTSecurityLevel': 'STABLE',
    'AlgorithmInfo': 'STABLE',
    'APIEndpoint': 'STABLE',
    'ModuleDocumentation': 'STABLE',
    'DocumentationCatalog': 'STABLE',
    'get_documentation_catalog': 'STABLE',
    'print_api_stability_report': 'STABLE',
    'print_quantum_readiness_guide': 'STABLE',
}
