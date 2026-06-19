"""
Post-Quantum Cryptography Algorithm Recommendation & Selection Engine
June 19, 2026 - Production Grade Implementation

Provides intelligent algorithm selection and recommendation for post-quantum cryptography.
Core capabilities:
- Use case analysis and algorithm matching
- NIST standardization status tracking (Round 4, Standardized, Finalists)
- Security level assessment (NIST Security Levels 1-5)
- Performance profiling and optimization recommendations
- Migration path planning and transition guidance
- Compatibility assessment with existing infrastructure
- Risk assessment for algorithm selection
- Regulatory and compliance alignment

Enables organizations to make informed decisions about PQC adoption
based on their specific requirements, constraints, and risk profiles.
"""
import re
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict
from statistics import mean


class NISTSecurityLevel(Enum):
    LEVEL_1 = 1  # AES-128 equivalent
    LEVEL_2 = 2  # SHA-256 equivalent
    LEVEL_3 = 3  # AES-192 equivalent
    LEVEL_4 = 4  # SHA-384 equivalent
    LEVEL_5 = 5  # AES-256 equivalent


class NISTStatus(Enum):
    STANDARDIZED = "standardized"
    FINALIST = "finalist"
    ROUND_4 = "round_4"
    CANDIDATE = "candidate"
    RESEARCH = "research"


class UseCaseCategory(Enum):
    TLS_HANDSHAKE = "tls_handshake"
    CODE_SIGNING = "code_signing"
    DOCUMENT_SIGNING = "document_signing"
    EMAIL_ENCRYPTION = "email_encryption"
    VPN = "vpn"
    SSH = "ssh"
    KEM = "key_encapsulation"
    DIGITAL_SIGNATURE = "digital_signature"
    DATA_AT_REST = "data_at_rest"
    BLOCKCHAIN = "blockchain"
    IOT = "iot"
    CLOUD_API = "cloud_api"


class AlgorithmType(Enum):
    KEM = "key_encapsulation_mechanism"
    SIGNATURE = "digital_signature"
    HYBRID = "hybrid_scheme"
    HASH_BASED = "hash_based"
    CODE_BASED = "code_based"
    LATTICE_BASED = "lattice_based"
    MULTIVARIATE = "multivariate"
    ISOGENY = "isogeny_based"


@dataclass
class AlgorithmProfile:
    name: str
    algorithm_type: AlgorithmType
    nist_security_level: NISTSecurityLevel
    nist_status: NISTStatus
    public_key_size_bytes: int
    private_key_size_bytes: int
    signature_size_bytes: Optional[int] = None
    ciphertext_size_bytes: Optional[int] = None
    keygen_latency_ms: float = 0.0
    sign_latency_ms: float = 0.0
    verify_latency_ms: float = 0.0
    encaps_latency_ms: float = 0.0
    decaps_latency_ms: float = 0.0
    memory_usage_mb: float = 0.0
    supported_platforms: Set[str] = field(default_factory=set)
    known_vulnerabilities: List[str] = field(default_factory=list)
    implementation_maturity: str = "beta"
    patent_status: str = "unknown"
    year_standardized: Optional[int] = None


@dataclass
class RecommendationResult:
    algorithm_name: str
    match_score: float
    suitability_rating: str
    security_assessment: Dict[str, Any]
    performance_assessment: Dict[str, Any]
    compatibility_notes: List[str]
    migration_complexity: str
    risk_factors: List[str]
    implementation_recommendations: List[str]


@dataclass
class SelectionCriteria:
    use_case: UseCaseCategory
    required_security_level: NISTSecurityLevel
    performance_requirements: Dict[str, float]
    platform_constraints: Set[str]
    compliance_requirements: Set[str]
    migration_timeline_months: int
    risk_tolerance: str  # "conservative", "moderate", "aggressive"
    resource_constraints: Dict[str, Any]


class PostQuantumAlgorithmSelector:
    """
    Production-grade post-quantum algorithm recommendation and selection engine.
    Provides data-driven algorithm selection based on organizational requirements.
    """

    def __init__(self):
        self.algorithm_profiles: Dict[str, AlgorithmProfile] = {}
        self._initialize_standard_algorithms()
        self.use_case_requirements = self._initialize_use_case_requirements()

    def _initialize_standard_algorithms(self):
        """Initialize profiles for NIST-standardized and selected PQC algorithms."""
        
        # CRYSTALS-Kyber (NIST Standardized KEM)
        self.algorithm_profiles["CRYSTALS-Kyber-512"] = AlgorithmProfile(
            name="CRYSTALS-Kyber-512",
            algorithm_type=AlgorithmType.KEM,
            nist_security_level=NISTSecurityLevel.LEVEL_1,
            nist_status=NISTStatus.STANDARDIZED,
            public_key_size_bytes=800,
            private_key_size_bytes=1632,
            ciphertext_size_bytes=768,
            keygen_latency_ms=0.05,
            encaps_latency_ms=0.08,
            decaps_latency_ms=0.07,
            memory_usage_mb=1.2,
            supported_platforms={"x86", "x86_64", "ARM", "ARM64", "WebAssembly"},
            implementation_maturity="production",
            patent_status="royalty_free",
            year_standardized=2024
        )

        self.algorithm_profiles["CRYSTALS-Kyber-768"] = AlgorithmProfile(
            name="CRYSTALS-Kyber-768",
            algorithm_type=AlgorithmType.KEM,
            nist_security_level=NISTSecurityLevel.LEVEL_3,
            nist_status=NISTStatus.STANDARDIZED,
            public_key_size_bytes=1184,
            private_key_size_bytes=2400,
            ciphertext_size_bytes=1088,
            keygen_latency_ms=0.08,
            encaps_latency_ms=0.12,
            decaps_latency_ms=0.10,
            memory_usage_mb=1.8,
            supported_platforms={"x86", "x86_64", "ARM", "ARM64", "WebAssembly"},
            implementation_maturity="production",
            patent_status="royalty_free",
            year_standardized=2024
        )

        self.algorithm_profiles["CRYSTALS-Kyber-1024"] = AlgorithmProfile(
            name="CRYSTALS-Kyber-1024",
            algorithm_type=AlgorithmType.KEM,
            nist_security_level=NISTSecurityLevel.LEVEL_5,
            nist_status=NISTStatus.STANDARDIZED,
            public_key_size_bytes=1568,
            private_key_size_bytes=3168,
            ciphertext_size_bytes=1568,
            keygen_latency_ms=0.12,
            encaps_latency_ms=0.18,
            decaps_latency_ms=0.15,
            memory_usage_mb=2.5,
            supported_platforms={"x86", "x86_64", "ARM", "ARM64"},
            implementation_maturity="production",
            patent_status="royalty_free",
            year_standardized=2024
        )

        # CRYSTALS-Dilithium (NIST Standardized Signature)
        self.algorithm_profiles["CRYSTALS-Dilithium-2"] = AlgorithmProfile(
            name="CRYSTALS-Dilithium-2",
            algorithm_type=AlgorithmType.SIGNATURE,
            nist_security_level=NISTSecurityLevel.LEVEL_2,
            nist_status=NISTStatus.STANDARDIZED,
            public_key_size_bytes=1312,
            private_key_size_bytes=2528,
            signature_size_bytes=2420,
            keygen_latency_ms=0.15,
            sign_latency_ms=0.30,
            verify_latency_ms=0.10,
            memory_usage_mb=2.0,
            supported_platforms={"x86", "x86_64", "ARM", "ARM64", "WebAssembly"},
            implementation_maturity="production",
            patent_status="royalty_free",
            year_standardized=2024
        )

        self.algorithm_profiles["CRYSTALS-Dilithium-3"] = AlgorithmProfile(
            name="CRYSTALS-Dilithium-3",
            algorithm_type=AlgorithmType.SIGNATURE,
            nist_security_level=NISTSecurityLevel.LEVEL_3,
            nist_status=NISTStatus.STANDARDIZED,
            public_key_size_bytes=1952,
            private_key_size_bytes=4000,
            signature_size_bytes=3293,
            keygen_latency_ms=0.25,
            sign_latency_ms=0.50,
            verify_latency_ms=0.15,
            memory_usage_mb=3.0,
            supported_platforms={"x86", "x86_64", "ARM", "ARM64"},
            implementation_maturity="production",
            patent_status="royalty_free",
            year_standardized=2024
        )

        self.algorithm_profiles["CRYSTALS-Dilithium-5"] = AlgorithmProfile(
            name="CRYSTALS-Dilithium-5",
            algorithm_type=AlgorithmType.SIGNATURE,
            nist_security_level=NISTSecurityLevel.LEVEL_5,
            nist_status=NISTStatus.STANDARDIZED,
            public_key_size_bytes=2592,
            private_key_size_bytes=4864,
            signature_size_bytes=4595,
            keygen_latency_ms=0.40,
            sign_latency_ms=0.80,
            verify_latency_ms=0.25,
            memory_usage_mb=4.5,
            supported_platforms={"x86", "x86_64"},
            implementation_maturity="production",
            patent_status="royalty_free",
            year_standardized=2024
        )

        # SPHINCS+ (NIST Standardized Hash-Based Signature)
        self.algorithm_profiles["SPHINCS+-SHA2-128f"] = AlgorithmProfile(
            name="SPHINCS+-SHA2-128f",
            algorithm_type=AlgorithmType.HASH_BASED,
            nist_security_level=NISTSecurityLevel.LEVEL_1,
            nist_status=NISTStatus.STANDARDIZED,
            public_key_size_bytes=32,
            private_key_size_bytes=64,
            signature_size_bytes=17088,
            keygen_latency_ms=0.50,
            sign_latency_ms=15.0,
            verify_latency_ms=0.20,
            memory_usage_mb=0.5,
            supported_platforms={"x86", "x86_64", "ARM", "ARM64", "embedded"},
            implementation_maturity="production",
            patent_status="royalty_free",
            year_standardized=2024
        )

        # Falcon (NIST Round 4 Signature)
        self.algorithm_profiles["Falcon-512"] = AlgorithmProfile(
            name="Falcon-512",
            algorithm_type=AlgorithmType.SIGNATURE,
            nist_security_level=NISTSecurityLevel.LEVEL_1,
            nist_status=NISTStatus.ROUND_4,
            public_key_size_bytes=897,
            private_key_size_bytes=1281,
            signature_size_bytes=666,
            keygen_latency_ms=50.0,
            sign_latency_ms=1.5,
            verify_latency_ms=0.05,
            memory_usage_mb=15.0,
            supported_platforms={"x86", "x86_64", "ARM", "ARM64"},
            implementation_maturity="beta",
            patent_status="royalty_free",
            known_vulnerabilities=["Floating-point timing side channel concerns"]
        )

        # Classic McEliece (NIST Round 4 Code-Based KEM)
        self.algorithm_profiles["Classic-McEliece-460896"] = AlgorithmProfile(
            name="Classic-McEliece-460896",
            algorithm_type=AlgorithmType.CODE_BASED,
            nist_security_level=NISTSecurityLevel.LEVEL_1,
            nist_status=NISTStatus.ROUND_4,
            public_key_size_bytes=524160,
            private_key_size_bytes=13608,
            ciphertext_size_bytes=188,
            keygen_latency_ms=5000.0,
            encaps_latency_ms=0.10,
            decaps_latency_ms=0.50,
            memory_usage_mb=8.0,
            supported_platforms={"x86", "x86_64"},
            implementation_maturity="beta",
            patent_status="royalty_free",
            known_vulnerabilities=["Very large public keys"]
        )

        # BIKE (NIST Round 4 Code-Based KEM)
        self.algorithm_profiles["BIKE-L1"] = AlgorithmProfile(
            name="BIKE-L1",
            algorithm_type=AlgorithmType.CODE_BASED,
            nist_security_level=NISTSecurityLevel.LEVEL_1,
            nist_status=NISTStatus.ROUND_4,
            public_key_size_bytes=1543,
            private_key_size_bytes=3074,
            ciphertext_size_bytes=1543,
            keygen_latency_ms=1.0,
            encaps_latency_ms=0.50,
            decaps_latency_ms=0.80,
            memory_usage_mb=2.0,
            supported_platforms={"x86", "x86_64", "ARM"},
            implementation_maturity="beta",
            patent_status="royalty_free"
        )

        # HQC (NIST Round 4 Code-Based KEM)
        self.algorithm_profiles["HQC-128"] = AlgorithmProfile(
            name="HQC-128",
            algorithm_type=AlgorithmType.CODE_BASED,
            nist_security_level=NISTSecurityLevel.LEVEL_1,
            nist_status=NISTStatus.ROUND_4,
            public_key_size_bytes=2249,
            private_key_size_bytes=2289,
            ciphertext_size_bytes=4481,
            keygen_latency_ms=0.50,
            encaps_latency_ms=0.80,
            decaps_latency_ms=1.20,
            memory_usage_mb=1.5,
            supported_platforms={"x86", "x86_64", "ARM"},
            implementation_maturity="beta",
            patent_status="royalty_free"
        )

    def _initialize_use_case_requirements(self) -> Dict[UseCaseCategory, Dict[str, Any]]:
        """Initialize performance and security requirements per use case."""
        return {
            UseCaseCategory.TLS_HANDSHAKE: {
                "algorithm_type": [AlgorithmType.KEM, AlgorithmType.HYBRID],
                "max_latency_ms": 1.0,
                "max_key_size_bytes": 2048,
                "min_nist_status": NISTStatus.STANDARDIZED,
                "platforms": {"x86", "x86_64", "ARM", "ARM64"},
                "description": "TLS 1.3 handshake requires low latency and moderate key sizes"
            },
            UseCaseCategory.CODE_SIGNING: {
                "algorithm_type": [AlgorithmType.SIGNATURE, AlgorithmType.HASH_BASED],
                "max_sign_latency_ms": 100.0,
                "max_verify_latency_ms": 1.0,
                "max_signature_size_bytes": 10000,
                "min_nist_status": NISTStatus.STANDARDIZED,
                "description": "Code signing requires fast verification and standardized algorithms"
            },
            UseCaseCategory.DOCUMENT_SIGNING: {
                "algorithm_type": [AlgorithmType.SIGNATURE, AlgorithmType.HASH_BASED],
                "max_sign_latency_ms": 500.0,
                "max_verify_latency_ms": 50.0,
                "min_nist_status": NISTStatus.FINALIST,
                "description": "Document signing prioritizes security and long-term validity"
            },
            UseCaseCategory.IOT: {
                "algorithm_type": [AlgorithmType.KEM, AlgorithmType.SIGNATURE],
                "max_latency_ms": 50.0,
                "max_memory_mb": 2.0,
                "max_key_size_bytes": 1500,
                "min_nist_status": NISTStatus.STANDARDIZED,
                "platforms": {"ARM", "ARM64", "embedded"},
                "description": "IoT requires small memory footprint and constrained resource operation"
            },
            UseCaseCategory.DATA_AT_REST: {
                "algorithm_type": [AlgorithmType.KEM, AlgorithmType.HYBRID],
                "max_latency_ms": 100.0,
                "min_nist_status": NISTStatus.FINALIST,
                "description": "Data at rest encryption prioritizes long-term security"
            },
            UseCaseCategory.VPN: {
                "algorithm_type": [AlgorithmType.KEM, AlgorithmType.HYBRID],
                "max_latency_ms": 5.0,
                "max_key_size_bytes": 3000,
                "min_nist_status": NISTStatus.STANDARDIZED,
                "description": "VPN requires low latency for tunnel establishment"
            },
            UseCaseCategory.SSH: {
                "algorithm_type": [AlgorithmType.KEM, AlgorithmType.SIGNATURE],
                "max_latency_ms": 10.0,
                "min_nist_status": NISTStatus.STANDARDIZED,
                "description": "SSH requires standardized algorithms for interoperability"
            },
            UseCaseCategory.BLOCKCHAIN: {
                "algorithm_type": [AlgorithmType.SIGNATURE],
                "max_signature_size_bytes": 1000,
                "max_verify_latency_ms": 0.5,
                "min_nist_status": NISTStatus.FINALIST,
                "description": "Blockchain requires small signatures and fast verification"
            },
            UseCaseCategory.CLOUD_API: {
                "algorithm_type": [AlgorithmType.SIGNATURE, AlgorithmType.KEM],
                "max_latency_ms": 2.0,
                "min_nist_status": NISTStatus.STANDARDIZED,
                "description": "Cloud APIs require low latency and broad compatibility"
            }
        }

    def get_algorithm_profile(self, algorithm_name: str) -> Optional[AlgorithmProfile]:
        """Get the profile for a specific algorithm."""
        return self.algorithm_profiles.get(algorithm_name)

    def list_available_algorithms(self, algorithm_type: Optional[AlgorithmType] = None) -> List[str]:
        """List all available algorithms, optionally filtered by type."""
        if algorithm_type:
            return [
                name for name, profile in self.algorithm_profiles.items()
                if profile.algorithm_type == algorithm_type
            ]
        return list(self.algorithm_profiles.keys())

    def calculate_security_match_score(
        self,
        profile: AlgorithmProfile,
        criteria: SelectionCriteria
    ) -> Tuple[float, List[str]]:
        """Calculate security match score (0-100) based on requirements."""
        score = 100.0
        notes = []

        # Security level check
        if profile.nist_security_level.value < criteria.required_security_level.value:
            score -= 50
            notes.append(f"Security level insufficient: {profile.nist_security_level.name} < {criteria.required_security_level.name}")
        elif profile.nist_security_level.value > criteria.required_security_level.value:
            score += 10  # Bonus for higher security
            notes.append(f"Security level exceeds requirement: {profile.nist_security_level.name}")

        # NIST status check based on risk tolerance
        status_penalties = {
            "conservative": {
                NISTStatus.STANDARDIZED: 0,
                NISTStatus.FINALIST: 30,
                NISTStatus.ROUND_4: 50,
                NISTStatus.CANDIDATE: 70,
                NISTStatus.RESEARCH: 90
            },
            "moderate": {
                NISTStatus.STANDARDIZED: 0,
                NISTStatus.FINALIST: 15,
                NISTStatus.ROUND_4: 30,
                NISTStatus.CANDIDATE: 50,
                NISTStatus.RESEARCH: 75
            },
            "aggressive": {
                NISTStatus.STANDARDIZED: 0,
                NISTStatus.FINALIST: 5,
                NISTStatus.ROUND_4: 15,
                NISTStatus.CANDIDATE: 30,
                NISTStatus.RESEARCH: 50
            }
        }
        
        penalty = status_penalties.get(criteria.risk_tolerance, {}).get(profile.nist_status, 50)
        score -= penalty
        if penalty > 0:
            notes.append(f"NIST status penalty ({criteria.risk_tolerance}): -{penalty} for {profile.nist_status.value}")

        # Known vulnerabilities penalty
        if profile.known_vulnerabilities:
            vuln_penalty = len(profile.known_vulnerabilities) * 15
            score -= vuln_penalty
            notes.append(f"Known vulnerabilities penalty: -{vuln_penalty}")

        return max(0.0, score), notes

    def calculate_performance_match_score(
        self,
        profile: AlgorithmProfile,
        criteria: SelectionCriteria
    ) -> Tuple[float, List[str]]:
        """Calculate performance match score (0-100)."""
        score = 100.0
        notes = []

        use_case_reqs = self.use_case_requirements.get(criteria.use_case, {})
        
        # Latency checks
        if profile.algorithm_type == AlgorithmType.KEM:
            max_latency = use_case_reqs.get("max_latency_ms", 100.0)
            total_latency = profile.keygen_latency_ms + profile.encaps_latency_ms + profile.decaps_latency_ms
            if total_latency > max_latency:
                penalty = min(40, (total_latency / max_latency - 1) * 20)
                score -= penalty
                notes.append(f"Latency exceeds requirement: {total_latency:.3f}ms > {max_latency}ms")
        elif profile.algorithm_type in [AlgorithmType.SIGNATURE, AlgorithmType.HASH_BASED]:
            max_sign = use_case_reqs.get("max_sign_latency_ms", 100.0)
            max_verify = use_case_reqs.get("max_verify_latency_ms", 10.0)
            if profile.sign_latency_ms > max_sign:
                score -= min(30, (profile.sign_latency_ms / max_sign - 1) * 15)
                notes.append(f"Sign latency high: {profile.sign_latency_ms}ms")
            if profile.verify_latency_ms > max_verify:
                score -= min(20, (profile.verify_latency_ms / max_verify - 1) * 10)
                notes.append(f"Verify latency high: {profile.verify_latency_ms}ms")

        # Key size penalty
        max_key_size = use_case_reqs.get("max_key_size_bytes", 10000)
        if profile.public_key_size_bytes > max_key_size:
            penalty = min(40, (profile.public_key_size_bytes / max_key_size - 1) * 20)
            score -= penalty
            notes.append(f"Public key size large: {profile.public_key_size_bytes} bytes")

        # Memory constraints
        if "max_memory_mb" in criteria.resource_constraints:
            max_mem = criteria.resource_constraints["max_memory_mb"]
            if profile.memory_usage_mb > max_mem:
                score -= 30
                notes.append(f"Memory usage exceeds constraint: {profile.memory_usage_mb}MB")

        # Platform compatibility
        if criteria.platform_constraints:
            platform_match = criteria.platform_constraints.intersection(profile.supported_platforms)
            if not platform_match:
                score -= 50
                notes.append("No platform overlap with requirements")
            elif len(platform_match) < len(criteria.platform_constraints):
                score -= 15
                notes.append(f"Partial platform support: {platform_match}")

        return max(0.0, score), notes

    def calculate_migration_score(
        self,
        profile: AlgorithmProfile,
        criteria: SelectionCriteria
    ) -> Tuple[float, List[str]]:
        """Calculate migration ease score (0-100)."""
        score = 100.0
        notes = []

        # Implementation maturity
        maturity_scores = {
            "production": 0,
            "beta": 15,
            "alpha": 30,
            "research": 50
        }
        penalty = maturity_scores.get(profile.implementation_maturity, 25)
        score -= penalty
        if penalty > 0:
            notes.append(f"Implementation maturity penalty: -{penalty} ({profile.implementation_maturity})")

        # Timeline urgency
        if criteria.migration_timeline_months < 3:
            if profile.nist_status != NISTStatus.STANDARDIZED:
                score -= 30
                notes.append("Urgent timeline requires standardized algorithms")
        elif criteria.migration_timeline_months < 6:
            if profile.nist_status not in [NISTStatus.STANDARDIZED, NISTStatus.FINALIST]:
                score -= 15
                notes.append("Short timeline prefers mature algorithms")

        # Patent status
        if profile.patent_status != "royalty_free":
            score -= 20
            notes.append(f"Patent status consideration: {profile.patent_status}")

        return max(0.0, score), notes

    def recommend_algorithms(
        self,
        criteria: SelectionCriteria,
        top_n: int = 5
    ) -> List[RecommendationResult]:
        """
        Generate ranked algorithm recommendations based on selection criteria.
        Returns top N recommendations with detailed assessments.
        """
        recommendations = []
        
        use_case_reqs = self.use_case_requirements.get(criteria.use_case, {})
        allowed_types = use_case_reqs.get("algorithm_type", list(AlgorithmType))

        for name, profile in self.algorithm_profiles.items():
            # Filter by algorithm type
            if profile.algorithm_type not in allowed_types:
                continue

            # Calculate component scores
            security_score, security_notes = self.calculate_security_match_score(profile, criteria)
            performance_score, performance_notes = self.calculate_performance_match_score(profile, criteria)
            migration_score, migration_notes = self.calculate_migration_score(profile, criteria)

            # Weighted overall score
            weights = {
                'security': 0.45,
                'performance': 0.35,
                'migration': 0.20
            }
            
            overall_score = (
                security_score * weights['security'] +
                performance_score * weights['performance'] +
                migration_score * weights['migration']
            )

            # Determine suitability rating
            if overall_score >= 85:
                suitability = "EXCELLENT_MATCH"
            elif overall_score >= 70:
                suitability = "GOOD_MATCH"
            elif overall_score >= 55:
                suitability = "FAIR_MATCH"
            elif overall_score >= 40:
                suitability = "POOR_MATCH"
            else:
                suitability = "NOT_RECOMMENDED"

            # Compile risk factors
            risk_factors = []
            if profile.nist_status != NISTStatus.STANDARDIZED:
                risk_factors.append(f"Not NIST standardized yet: {profile.nist_status.value}")
            risk_factors.extend(profile.known_vulnerabilities)
            if profile.implementation_maturity != "production":
                risk_factors.append(f"Implementation maturity: {profile.implementation_maturity}")

            recommendations.append(RecommendationResult(
                algorithm_name=name,
                match_score=round(overall_score, 2),
                suitability_rating=suitability,
                security_assessment={
                    'score': security_score,
                    'notes': security_notes,
                    'security_level': profile.nist_security_level.name,
                    'nist_status': profile.nist_status.value
                },
                performance_assessment={
                    'score': performance_score,
                    'notes': performance_notes,
                    'public_key_size': profile.public_key_size_bytes,
                    'signature_size': profile.signature_size_bytes,
                    'ciphertext_size': profile.ciphertext_size_bytes
                },
                compatibility_notes=[
                    f"Supported platforms: {', '.join(profile.supported_platforms)}",
                    f"Implementation maturity: {profile.implementation_maturity}",
                    f"Patent status: {profile.patent_status}"
                ],
                migration_complexity="LOW" if migration_score >= 70 else "MEDIUM" if migration_score >= 40 else "HIGH",
                risk_factors=risk_factors,
                implementation_recommendations=[
                    "Start with hybrid deployment alongside classical algorithms",
                    "Conduct performance testing in target environment",
                    "Review NIST documentation and implementation guides",
                    "Plan for key management infrastructure updates"
                ]
            ))

        # Sort by match score and return top N
        recommendations.sort(key=lambda x: x.match_score, reverse=True)
        return recommendations[:top_n]

    def generate_migration_plan(
        self,
        selected_algorithm: str,
        timeline_months: int = 12
    ) -> Dict[str, Any]:
        """Generate a detailed migration plan for the selected algorithm."""
        profile = self.algorithm_profiles.get(selected_algorithm)
        if not profile:
            raise ValueError(f"Algorithm {selected_algorithm} not found")

        phases = []
        
        if timeline_months >= 12:
            phases.append({
                'phase': 'Assessment & Planning',
                'duration': 'Months 1-3',
                'activities': [
                    'Inventory existing cryptographic infrastructure',
                    'Assess performance requirements and constraints',
                    'Select library and implementation',
                    'Create test environment',
                    'Develop migration rollback plan'
                ]
            })
            phases.append({
                'phase': 'Development & Testing',
                'duration': 'Months 4-6',
                'activities': [
                    'Implement hybrid mode (classical + PQC)',
                    'Conduct performance benchmarking',
                    'Perform interoperability testing',
                    'Security audit and penetration testing',
                    'Key management system integration'
                ]
            })
            phases.append({
                'phase': 'Pilot Deployment',
                'duration': 'Months 7-9',
                'activities': [
                    'Deploy to non-production environment',
                    'Monitor performance and stability',
                    'Gather operational metrics',
                    'Train operations team',
                    'Refine deployment procedures'
                ]
            })
            phases.append({
                'phase': 'Production Rollout',
                'duration': 'Months 10-12',
                'activities': [
                    'Gradual production deployment',
                    'Phased cutover with monitoring',
                    'Full production deployment',
                    'Post-deployment audit',
                    'Ongoing monitoring established'
                ]
            })
        else:
            phases.append({
                'phase': 'Accelerated Migration',
                'duration': f'Months 1-{timeline_months}',
                'activities': [
                    'Rapid assessment and library selection',
                    'Hybrid mode implementation',
                    'Accelerated testing',
                    'Phased production deployment',
                    'Continuous monitoring'
                ]
            })

        return {
            'algorithm': selected_algorithm,
            'algorithm_type': profile.algorithm_type.value,
            'nist_status': profile.nist_status.value,
            'security_level': profile.nist_security_level.name,
            'timeline_months': timeline_months,
            'migration_phases': phases,
            'key_considerations': [
                'Always deploy in hybrid mode initially',
                'Maintain backward compatibility during transition',
                'Ensure proper key ceremony procedures',
                'Monitor for cryptanalytic developments',
                'Plan for algorithm agility for future updates'
            ],
            'recommended_libraries': [
                'liboqs (Open Quantum Safe)',
                'BoringSSL with PQC extensions',
                'OpenSSL 3.0+ providers',
                'Botan PQC modules'
            ]
        }
