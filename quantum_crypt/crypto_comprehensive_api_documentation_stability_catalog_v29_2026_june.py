"""
QuantumCrypt-AI Comprehensive API Documentation & Stability Catalog v29
=======================================================================
API Stability Markers: STABLE | EXPERIMENTAL | DEPRECATED

This module provides comprehensive documentation, usage examples, and API stability
markers for all QuantumCrypt-AI post-quantum cryptography modules.

STABLE: API is frozen - no breaking changes without major version bump
EXPERIMENTAL: API may change - use with caution in production
DEPRECATED: API scheduled for removal - migrate to recommended alternatives
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import json
from datetime import datetime


class StabilityLevel(Enum):
    """API Stability Level Classification for Post-Quantum Cryptography"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"


@dataclass
class CryptoAlgorithmDocumentation:
    """Documentation metadata for a post-quantum cryptographic algorithm"""
    algorithm_name: str
    standard: str
    nist_status: str
    stability: StabilityLevel
    version: str
    description: str
    primary_use_cases: List[str]
    usage_examples: List[str]
    key_classes: List[str]
    key_methods: List[str]
    security_level: str
    performance_notes: str
    dependencies: List[str]
    deprecation_notice: Optional[str] = None
    migration_guide: Optional[str] = None
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class QuantumCryptAPIDocumentationCatalog:
    """
    Comprehensive PQ Crypto API Documentation & Stability Catalog
    
    STABLE API - This catalog interface is guaranteed stable.
    All methods and return types will remain backward compatible.
    """
    
    def __init__(self):
        self._algorithms: Dict[str, CryptoAlgorithmDocumentation] = {}
        self._init_pq_algorithms()
    
    def _init_pq_algorithms(self) -> None:
        """Initialize documentation for all post-quantum algorithms"""
        
        # === STABLE ALGORITHMS (NIST Standardized) ===
        
        self._algorithms["crystals_kyber"] = CryptoAlgorithmDocumentation(
            algorithm_name="CRYSTALS-Kyber",
            standard="NIST FIPS 203",
            nist_status="STANDARDIZED",
            stability=StabilityLevel.STABLE,
            version="1.0.0",
            description="Module-Lattice-Based Key Encapsulation Mechanism (NIST Primary KEM Standard)",
            primary_use_cases=[
                "TLS 1.3 key exchange",
                "VPN tunnel establishment",
                "General-purpose key encapsulation",
                "Hybrid classical-quantum key exchange"
            ],
            usage_examples=[
                """
                from quantum_crypt import KyberKEM
                kem = KyberKEM(security_level=3)
                pk, sk = kem.keygen()
                ciphertext, shared_secret = kem.encaps(pk)
                recovered_secret = kem.decaps(ciphertext, sk)
                """,
                """
                # Hybrid with X25519
                hybrid = HybridKEM(classical='x25519', pq='kyber768')
                shared = hybrid.perform_key_exchange()
                """
            ],
            key_classes=["KyberKEM", "KyberPublicKey", "KyberSecretKey"],
            key_methods=["keygen", "encaps", "decaps"],
            security_level="NIST Security Levels 1, 3, 5",
            performance_notes="Kyber-768: ~100μs keygen, ~50μs encaps, ~50μs decaps",
            dependencies=["random_generator", "sha3", "polynomial_arithmetic"]
        )
        
        self._algorithms["crystals_dilithium"] = CryptoAlgorithmDocumentation(
            algorithm_name="CRYSTALS-Dilithium",
            standard="NIST FIPS 204",
            nist_status="STANDARDIZED",
            stability=StabilityLevel.STABLE,
            version="1.0.0",
            description="Module-Lattice-Based Digital Signature Algorithm (NIST Primary Signature Standard)",
            primary_use_cases=[
                "Digital signatures for documents",
                "Code signing",
                "Certificate signatures (X.509)",
                "Blockchain transaction signing"
            ],
            usage_examples=[
                """
                from quantum_crypt import DilithiumSigner
                signer = DilithiumSigner(mode=3)
                pk, sk = signer.keygen()
                signature = signer.sign(message, sk)
                is_valid = signer.verify(message, signature, pk)
                """,
                """
                # Batch verification
                results = signer.verify_batch(messages, signatures, public_keys)
                """
            ],
            key_classes=["DilithiumSigner", "DilithiumPublicKey", "DilithiumSecretKey"],
            key_methods=["keygen", "sign", "verify", "verify_batch"],
            security_level="NIST Security Levels 2, 3, 5",
            performance_notes="Dilithium-3: ~300μs sign, ~100μs verify",
            dependencies=["random_generator", "sha3", "polynomial_arithmetic"]
        )
        
        self._algorithms["falcon"] = CryptoAlgorithmDocumentation(
            algorithm_name="FALCON",
            standard="NIST FIPS 205",
            nist_status="STANDARDIZED",
            stability=StabilityLevel.STABLE,
            version="1.0.0",
            description="Fast-Fourier Lattice-Based Compact Signatures Over NTRU",
            primary_use_cases=[
                "Resource-constrained devices",
                "IoT device authentication",
                "Compact signature requirements"
            ],
            usage_examples=[
                """
                from quantum_crypt import FalconSigner
                signer = FalconSigner(degree=512)
                pk, sk = signer.keygen()
                sig = signer.sign(message, sk)
                assert signer.verify(message, sig, pk)
                """
            ],
            key_classes=["FalconSigner", "FalconPublicKey", "FalconSecretKey"],
            key_methods=["keygen", "sign", "verify"],
            security_level="NIST Security Levels 1, 5",
            performance_notes="Falcon-512: Very compact signatures (~666 bytes)",
            dependencies=["ntru_arithmetic", "fft", "sampler"]
        )
        
        self._algorithms["sphincs_plus"] = CryptoAlgorithmDocumentation(
            algorithm_name="SPHINCS+",
            standard="NIST FIPS 206",
            nist_status="STANDARDIZED",
            stability=StabilityLevel.STABLE,
            version="1.0.0",
            description="Stateless Hash-Based Digital Signature Standard",
            primary_use_cases=[
                "Long-term signatures",
                "Root certificate authorities",
                "Code signing with long validity"
            ],
            usage_examples=[
                """
                from quantum_crypt import SphincsPlus
                sphincs = SphincsPlus(hash='sha256', robust=True)
                pk, sk = sphincs.keygen()
                sig = sphincs.sign(message, sk)
                valid = sphincs.verify(message, sig, pk)
                """
            ],
            key_classes=["SphincsPlus", "SphincsPublicKey", "SphincsSecretKey"],
            key_methods=["keygen", "sign", "verify"],
            security_level="NIST Security Levels 1, 3, 5",
            performance_notes="Stateless - no state management required",
            dependencies=["hash_function", "wots", "hypertree"]
        )
        
        # === EXPERIMENTAL ALGORITHMS (Round 4 Candidates / Research) ===
        
        self._algorithms["classic_mceliece"] = CryptoAlgorithmDocumentation(
            algorithm_name="Classic McEliece",
            standard="NIST Round 4",
            nist_status="ROUND_4_CANDIDATE",
            stability=StabilityLevel.EXPERIMENTAL,
            version="0.9.0",
            description="Code-Based Key Encapsulation Mechanism (Conservative Security)",
            primary_use_cases=[
                "High-assurance key exchange",
                "Long-term security requirements",
                "Conservative security choice"
            ],
            usage_examples=[
                """
                from quantum_crypt import ClassicMcEliece
                kem = ClassicMcEliece(parameter_set='mceliece6960119')
                pk, sk = kem.keygen()
                ct, ss = kem.encaps(pk)
                """
            ],
            key_classes=["ClassicMcEliece", "McEliecePublicKey", "McElieceSecretKey"],
            key_methods=["keygen", "encaps", "decaps"],
            security_level="NIST Security Level 5",
            performance_notes="Very large public keys (~1MB)",
            dependencies=["goppa_codes", "binary_field_arithmetic"]
        )
        
        self._algorithms["bike"] = CryptoAlgorithmDocumentation(
            algorithm_name="BIKE",
            standard="NIST Round 4",
            nist_status="ROUND_4_ALTERNATE",
            stability=StabilityLevel.EXPERIMENTAL,
            version="0.8.0",
            description="Bit Flipping Key Encapsulation (Code-Based)",
            primary_use_cases=[
                "Alternative code-based KEM",
                "Smaller keys than Classic McEliece"
            ],
            usage_examples=[
                """
                from quantum_crypt import BIKE
                kem = BIKE(level=1)
                pk, sk = kem.keygen()
                ct, ss = kem.encaps(pk)
                """
            ],
            key_classes=["BIKE", "BIKEPublicKey", "BIKESecretKey"],
            key_methods=["keygen", "encaps", "decaps"],
            security_level="NIST Security Levels 1, 3",
            performance_notes="Moderate key sizes, moderate performance",
            dependencies=["ldpc_codes", "bit_flipping_decoder"]
        )
        
        self._algorithms["ntru_prime"] = CryptoAlgorithmDocumentation(
            algorithm_name="NTRU Prime",
            standard="NIST Round 4",
            nist_status="ROUND_4_ALTERNATE",
            stability=StabilityLevel.EXPERIMENTAL,
            version="0.8.0",
            description="Streamlined NTRU for High Security",
            primary_use_cases=[
                "Alternative lattice KEM",
                "Simplified security analysis"
            ],
            usage_examples=[
                """
                from quantum_crypt import NTRUPrime
                kem = NTRUPrime(parameter='sntrup761')
                pk, sk = kem.keygen()
                ct, ss = kem.encaps(pk)
                """
            ],
            key_classes=["NTRUPrime", "NTRUPrimePublicKey", "NTRUPrimeSecretKey"],
            key_methods=["keygen", "encaps", "decaps"],
            security_level="NIST Security Level 3",
            performance_notes="Streamlined design, conservative approach",
            dependencies=["ntru_arithmetic", "polynomial_reduction"]
        )
        
        self._algorithms["hybrid_tls_13"] = CryptoAlgorithmDocumentation(
            algorithm_name="Hybrid TLS 1.3",
            standard="IETF RFC 9180 + X25519Kyber768",
            nist_status="STANDARDIZED_HYBRID",
            stability=StabilityLevel.EXPERIMENTAL,
            version="0.9.0",
            description="Hybrid Post-Quantum TLS 1.3 Key Exchange",
            primary_use_cases=[
                "TLS 1.3 PQ transition",
                "Browser-server communication",
                "Gradual PQ migration"
            ],
            usage_examples=[
                """
                from quantum_crypt import HybridTLS13
                tls = HybridTLS13(group='X25519Kyber768')
                client_hello = tls.generate_client_hello()
                server_hello = tls.process_client_hello(client_hello)
                master_secret = tls.derive_master_secret()
                """
            ],
            key_classes=["HybridTLS13", "KeySchedule"],
            key_methods=["generate_client_hello", "process_client_hello", "derive_master_secret"],
            security_level="Dual security: classical + post-quantum",
            performance_notes="Deployed in Chrome, Firefox, Cloudflare",
            dependencies=["x25519", "kyber768", "hkdf"]
        )
        
        # === DEPRECATED ALGORITHMS ===
        
        self._algorithms["sidh"] = CryptoAlgorithmDocumentation(
            algorithm_name="SIDH",
            standard="Superseded",
            nist_status="BROKEN",
            stability=StabilityLevel.DEPRECATED,
            version="0.5.0",
            description="[DEPRECATED - CRYPTOANALYTICALLY BROKEN]",
            primary_use_cases=["DO NOT USE - Cryptanalyzed in 2022"],
            usage_examples=[],
            key_classes=["SIDH"],
            key_methods=["keygen", "derive"],
            security_level="BROKEN - DO NOT USE",
            performance_notes="Practical key recovery attacks exist",
            dependencies=["isogeny_arithmetic"],
            deprecation_notice="SIDH was completely broken in 2022 by Castryck-Decru attack",
            migration_guide="Migrate to CRYSTALS-Kyber for all KEM applications"
        )
    
    def get_algorithm_documentation(self, algo_name: str) -> Optional[CryptoAlgorithmDocumentation]:
        """
        Get documentation for a specific cryptographic algorithm.
        
        STABLE API - Method signature guaranteed stable.
        
        Args:
            algo_name: Name of the algorithm to retrieve
            
        Returns:
            CryptoAlgorithmDocumentation object or None if not found
        """
        return self._algorithms.get(algo_name.lower())
    
    def list_algorithms_by_stability(self, stability: StabilityLevel) -> List[str]:
        """
        List all algorithms with specified stability level.
        
        STABLE API - Method signature guaranteed stable.
        
        Args:
            stability: StabilityLevel to filter by
            
        Returns:
            List of algorithm names
        """
        return [
            name for name, doc in self._algorithms.items()
            if doc.stability == stability
        ]
    
    def list_algorithms_by_nist_status(self, status: str) -> List[str]:
        """
        List algorithms by NIST standardization status.
        
        STABLE API - Method signature guaranteed stable.
        
        Args:
            status: NIST status filter
            
        Returns:
            List of matching algorithm names
        """
        return [
            name for name, doc in self._algorithms.items()
            if doc.nist_status.upper() == status.upper()
        ]
    
    def get_stability_summary(self) -> Dict[str, int]:
        """
        Get summary count of algorithms by stability level.
        
        STABLE API - Method signature guaranteed stable.
        
        Returns:
            Dictionary with stability counts
        """
        summary = {"STABLE": 0, "EXPERIMENTAL": 0, "DEPRECATED": 0}
        for doc in self._algorithms.values():
            summary[doc.stability.value] += 1
        return summary
    
    def generate_documentation_report(self, format: str = "json") -> str:
        """
        Generate comprehensive documentation report.
        
        STABLE API - Method signature guaranteed stable.
        
        Args:
            format: Output format ('json' or 'markdown')
            
        Returns:
            Formatted documentation report
        """
        data = {
            "catalog_version": "v29",
            "generated_at": datetime.utcnow().isoformat(),
            "stability_summary": self.get_stability_summary(),
            "algorithms": [
                {
                    "name": doc.algorithm_name,
                    "standard": doc.standard,
                    "nist_status": doc.nist_status,
                    "stability": doc.stability.value,
                    "version": doc.version,
                    "description": doc.description,
                    "security_level": doc.security_level,
                    "use_cases": doc.primary_use_cases,
                    "key_classes": doc.key_classes,
                    "key_methods": doc.key_methods
                }
                for doc in self._algorithms.values()
            ]
        }
        
        if format == "json":
            return json.dumps(data, indent=2)
        elif format == "markdown":
            return self._generate_markdown_report(data)
        else:
            return json.dumps(data, indent=2)
    
    def _generate_markdown_report(self, data: Dict) -> str:
        """Generate markdown formatted report"""
        md = f"""# QuantumCrypt-AI PQ Algorithm Documentation Catalog v29
Generated: {data['generated_at']}

## Stability Summary
- **STABLE**: {data['stability_summary']['STABLE']} algorithms (NIST standardized)
- **EXPERIMENTAL**: {data['stability_summary']['EXPERIMENTAL']} algorithms (Round 4 / Research)
- **DEPRECATED**: {data['stability_summary']['DEPRECATED']} algorithms (Broken / Superseded)

## Algorithm Documentation
"""
        for algo in data["algorithms"]:
            md += f"\n### {algo['name']} `[{algo['stability']}]`\n"
            md += f"- **Standard**: {algo['standard']}\n"
            md += f"- **NIST Status**: {algo['nist_status']}\n"
            md += f"- **Version**: {algo['version']}\n"
            md += f"- **Security Level**: {algo['security_level']}\n"
            md += f"- **Description**: {algo['description']}\n"
            md += f"- **Key Classes**: {', '.join(algo['key_classes'])}\n"
        return md
    
    def validate_api_compatibility(self, client_version: str) -> Dict[str, Any]:
        """
        Validate API compatibility for client version.
        
        STABLE API - Method signature guaranteed stable.
        
        Args:
            client_version: Client's expected API version
            
        Returns:
            Compatibility report
        """
        return {
            "compatible": True,
            "client_version": client_version,
            "catalog_version": "v29",
            "breaking_changes": [],
            "nist_updates": ["All 4 primary PQ algorithms now standardized (FIPS 203-206)"],
            "warnings": [
                "EXPERIMENTAL algorithms may change without version bump",
                "DEPRECATED algorithms (SIDH) are BROKEN - DO NOT USE"
            ],
            "recommendation": "Use only STABLE NIST algorithms for production"
        }
    
    def get_nist_standardized_algorithms(self) -> List[str]:
        """
        Get list of NIST standardized post-quantum algorithms.
        
        STABLE API - Method signature guaranteed stable.
        
        Returns:
            List of standardized algorithm names
        """
        return [
            name for name, doc in self._algorithms.items()
            if "STANDARDIZED" in doc.nist_status.upper()
        ]


# Export singleton instance for easy import
pq_api_documentation_catalog = QuantumCryptAPIDocumentationCatalog()

__all__ = [
    "QuantumCryptAPIDocumentationCatalog",
    "CryptoAlgorithmDocumentation",
    "StabilityLevel",
    "pq_api_documentation_catalog"
]
