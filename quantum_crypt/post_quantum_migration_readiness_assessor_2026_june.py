"""
Post-Quantum Migration Readiness Assessor
Production-grade PQC migration readiness evaluation system

Evaluates:
- Algorithm compatibility and quantum resistance
- Key inventory and management capabilities
- Infrastructure readiness
- Interoperability assessment
- Performance impact analysis
- Compliance verification
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import threading


class ReadinessLevel(Enum):
    NOT_READY = "not_ready"
    PARTIALLY_READY = "partially_ready"
    READY = "ready"
    FULLY_MIGRATED = "fully_migrated"


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class AlgorithmCategory(Enum):
    CLASSICAL_VULNERABLE = "classical_vulnerable"
    CLASSICAL_AT_RISK = "classical_at_risk"
    POST_QUANTUM_STANDARD = "post_quantum_standard"
    POST_QUANTUM_CANDIDATE = "post_quantum_candidate"
    HYBRID = "hybrid"


class MigrationPriority(Enum):
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    DEFERRED = "deferred"


@dataclass
class AlgorithmAssessment:
    algorithm_name: str
    category: AlgorithmCategory
    quantum_resistance_score: float  # 0-100
    nist_standardized: bool
    usage_count: int
    key_sizes_supported: List[int]
    recommended_replacement: Optional[str]
    risk_level: RiskLevel
    migration_priority: MigrationPriority

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value
        data["risk_level"] = self.risk_level.value
        data["migration_priority"] = self.migration_priority.value
        return data


@dataclass
class KeyInventoryAssessment:
    total_keys: int
    classical_keys: int
    post_quantum_keys: int
    hybrid_keys: int
    keys_with_rotation_enabled: int
    keys_in_hardware_security_module: int
    key_rotation_frequency_days: float
    average_key_age_days: float
    expired_keys: int
    weak_keys: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InfrastructureAssessment:
    tls_version_supported: str
    tls_13_enabled: bool
    certificate_chain_pqc_compatible: bool
    hsm_pqc_support: bool
    library_versions: Dict[str, str]
    network_device_support: bool
    cloud_provider_support: bool
    api_gateway_support: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InteroperabilityAssessment:
    internal_system_compatibility: float  # 0-1
    external_partner_compatibility: float  # 0-1
    protocol_support_coverage: float  # 0-1
    fallback_mechanisms_exist: bool
    hybrid_mode_supported: bool
    certificate_interoperability: float  # 0-1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PerformanceAssessment:
    signature_throughput_impact_percent: float
    verification_throughput_impact_percent: float
    key_generation_impact_percent: float
    memory_overhead_percent: float
    latency_impact_ms: float
    hardware_acceleration_available: bool
    overall_performance_score: float  # 0-100

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ComplianceAssessment:
    nist_sp_800_186_compliant: bool
    nist_sp_800_56c_compliant: bool
    cnsa_2_0_compliant: bool
    quantum_safe_mandate_timeline_met: bool
    industry_regulatory_compliance: Dict[str, bool]
    documentation_complete: bool
    audit_trail_exists: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MigrationGap:
    gap_id: str
    description: str
    category: str
    risk_level: RiskLevel
    priority: MigrationPriority
    effort_estimate_hours: int
    recommended_action: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["risk_level"] = self.risk_level.value
        data["priority"] = self.priority.value
        return data


@dataclass
class ReadinessReport:
    overall_readiness_score: float  # 0-100
    overall_readiness_level: ReadinessLevel
    algorithm_assessment: AlgorithmAssessment
    key_inventory: KeyInventoryAssessment
    infrastructure: InfrastructureAssessment
    interoperability: InteroperabilityAssessment
    performance: PerformanceAssessment
    compliance: ComplianceAssessment
    migration_gaps: List[MigrationGap]
    migration_timeline_months: float
    estimated_cost_usd: float
    recommendations: List[str]
    assessment_timestamp: datetime

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "overall_readiness_score": self.overall_readiness_score,
            "overall_readiness_level": self.overall_readiness_level.value,
            "algorithm_assessment": self.algorithm_assessment.to_dict(),
            "key_inventory": self.key_inventory.to_dict(),
            "infrastructure": self.infrastructure.to_dict(),
            "interoperability": self.interoperability.to_dict(),
            "performance": self.performance.to_dict(),
            "compliance": self.compliance.to_dict(),
            "migration_gaps": [gap.to_dict() for gap in self.migration_gaps],
            "migration_timeline_months": self.migration_timeline_months,
            "estimated_cost_usd": self.estimated_cost_usd,
            "recommendations": self.recommendations,
            "assessment_timestamp": self.assessment_timestamp.isoformat()
        }
        return data


class PostQuantumMigrationReadinessAssessor:
    """
    Production-grade Post-Quantum Cryptography migration readiness assessor.
    
    Provides comprehensive evaluation of an organization's readiness to migrate
    to post-quantum cryptographic algorithms, including algorithm analysis,
    key inventory assessment, infrastructure evaluation, and compliance checking.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.logger = self._setup_logger()
        self.assessments: Dict[str, ReadinessReport] = {}
        self.lock = threading.Lock()
        self._initialize_algorithm_database()

    def _default_config(self) -> Dict:
        return {
            "nist_standardized_algorithms": [
                "CRYSTALS-Kyber",
                "CRYSTALS-Dilithium",
                "FALCON",
                "SPHINCS+"
            ],
            "vulnerable_classical_algorithms": [
                "RSA",
                "ECC",
                "ECDSA",
                "ECDH",
                "DH",
                "DSA"
            ],
            "minimum_key_rotation_days": 90,
            "maximum_key_age_days": 365,
            "performance_impact_threshold_percent": 20,
            "target_migration_date": "2030-01-01",
            "cnsa_2_0_deadline": "2030-01-01"
        }

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("PQCMigrationReadinessAssessor")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def _initialize_algorithm_database(self):
        """Initialize quantum resistance scores for common algorithms."""
        self.algorithm_quantum_scores = {
            # Classical vulnerable algorithms
            "RSA-2048": 0,
            "RSA-3072": 5,
            "RSA-4096": 10,
            "ECC-P256": 0,
            "ECC-P384": 5,
            "ECDSA-P256": 0,
            "ECDSA-P384": 5,
            "ECDH-P256": 0,
            "ECDH-P384": 5,
            "SHA-256": 80,
            "SHA-384": 90,
            "SHA-512": 95,
            "AES-128": 85,
            "AES-256": 95,
            # NIST standardized PQC algorithms
            "CRYSTALS-Kyber-512": 100,
            "CRYSTALS-Kyber-768": 100,
            "CRYSTALS-Kyber-1024": 100,
            "CRYSTALS-Dilithium-2": 100,
            "CRYSTALS-Dilithium-3": 100,
            "CRYSTALS-Dilithium-5": 100,
            "FALCON-512": 100,
            "FALCON-1024": 100,
            "SPHINCS+-128f": 100,
            "SPHINCS+-128s": 100,
            "SPHINCS+-192f": 100,
            "SPHINCS+-192s": 100,
            "SPHINCS+-256f": 100,
            "SPHINCS+-256s": 100,
            # Hybrid modes
            "Kyber+X25519": 95,
            "Kyber+P256": 90,
            "Dilithium+ECDSA": 90
        }
        
        self.algorithm_replacements = {
            "RSA-2048": "CRYSTALS-Kyber-768",
            "RSA-3072": "CRYSTALS-Kyber-768",
            "RSA-4096": "CRYSTALS-Kyber-1024",
            "ECC-P256": "CRYSTALS-Kyber-512",
            "ECC-P384": "CRYSTALS-Kyber-768",
            "ECDSA-P256": "CRYSTALS-Dilithium-3",
            "ECDSA-P384": "CRYSTALS-Dilithium-5",
            "ECDH-P256": "CRYSTALS-Kyber-512",
            "ECDH-P384": "CRYSTALS-Kyber-768"
        }

    def assess_algorithm_readiness(
        self,
        algorithm_inventory: Dict[str, int],
        organization_name: str = "default"
    ) -> AlgorithmAssessment:
        """Assess algorithm quantum resistance and migration readiness."""
        total_usage = sum(algorithm_inventory.values())
        
        if total_usage == 0:
            return AlgorithmAssessment(
                algorithm_name="none",
                category=AlgorithmCategory.POST_QUANTUM_STANDARD,
                quantum_resistance_score=100,
                nist_standardized=True,
                usage_count=0,
                key_sizes_supported=[],
                recommended_replacement=None,
                risk_level=RiskLevel.NONE,
                migration_priority=MigrationPriority.DEFERRED
            )
        
        # Calculate weighted quantum resistance score
        weighted_score = 0.0
        vulnerable_count = 0
        pqc_count = 0
        
        for algo, count in algorithm_inventory.items():
            score = self.algorithm_quantum_scores.get(algo, 50)
            weighted_score += score * count
            
            if score < 20:
                vulnerable_count += count
            elif score >= 90:
                pqc_count += count
        
        avg_score = weighted_score / total_usage
        
        # Determine primary algorithm category
        vulnerable_ratio = vulnerable_count / total_usage
        pqc_ratio = pqc_count / total_usage
        
        if pqc_ratio >= 0.9:
            category = AlgorithmCategory.POST_QUANTUM_STANDARD
            risk_level = RiskLevel.NONE
            priority = MigrationPriority.DEFERRED
        elif pqc_ratio >= 0.5:
            category = AlgorithmCategory.HYBRID
            risk_level = RiskLevel.LOW
            priority = MigrationPriority.LOW
        elif vulnerable_ratio > 0.5:
            category = AlgorithmCategory.CLASSICAL_VULNERABLE
            risk_level = RiskLevel.CRITICAL
            priority = MigrationPriority.IMMEDIATE
        else:
            category = AlgorithmCategory.CLASSICAL_AT_RISK
            risk_level = RiskLevel.HIGH
            priority = MigrationPriority.HIGH
        
        # Find most used vulnerable algorithm for recommendation
        most_used_vulnerable = None
        max_vulnerable_count = 0
        for algo, count in algorithm_inventory.items():
            score = self.algorithm_quantum_scores.get(algo, 50)
            if score < 20 and count > max_vulnerable_count:
                max_vulnerable_count = count
                most_used_vulnerable = algo
        
        recommended_replacement = None
        if most_used_vulnerable:
            recommended_replacement = self.algorithm_replacements.get(
                most_used_vulnerable, "CRYSTALS-Kyber-768"
            )
        
        return AlgorithmAssessment(
            algorithm_name="mixed" if len(algorithm_inventory) > 1 else next(iter(algorithm_inventory.keys())),
            category=category,
            quantum_resistance_score=avg_score,
            nist_standardized=(pqc_ratio >= 0.9),
            usage_count=total_usage,
            key_sizes_supported=list(algorithm_inventory.keys()),
            recommended_replacement=recommended_replacement,
            risk_level=risk_level,
            migration_priority=priority
        )

    def assess_key_inventory(
        self,
        key_metrics: Dict[str, Any]
    ) -> KeyInventoryAssessment:
        """Assess key management and inventory readiness."""
        total_keys = key_metrics.get("total_keys", 0)
        classical_keys = key_metrics.get("classical_keys", 0)
        pq_keys = key_metrics.get("post_quantum_keys", 0)
        hybrid_keys = key_metrics.get("hybrid_keys", 0)
        
        return KeyInventoryAssessment(
            total_keys=total_keys,
            classical_keys=classical_keys,
            post_quantum_keys=pq_keys,
            hybrid_keys=hybrid_keys,
            keys_with_rotation_enabled=key_metrics.get("keys_with_rotation_enabled", 0),
            keys_in_hardware_security_module=key_metrics.get("keys_in_hsm", 0),
            key_rotation_frequency_days=key_metrics.get("rotation_frequency_days", 365),
            average_key_age_days=key_metrics.get("avg_key_age_days", 180),
            expired_keys=key_metrics.get("expired_keys", 0),
            weak_keys=key_metrics.get("weak_keys", 0)
        )

    def assess_infrastructure(
        self,
        infra_metrics: Dict[str, Any]
    ) -> InfrastructureAssessment:
        """Assess infrastructure readiness for PQC migration."""
        return InfrastructureAssessment(
            tls_version_supported=infra_metrics.get("tls_version", "1.2"),
            tls_13_enabled=infra_metrics.get("tls_13_enabled", False),
            certificate_chain_pqc_compatible=infra_metrics.get("cert_chain_pqc", False),
            hsm_pqc_support=infra_metrics.get("hsm_pqc_support", False),
            library_versions=infra_metrics.get("library_versions", {}),
            network_device_support=infra_metrics.get("network_device_support", False),
            cloud_provider_support=infra_metrics.get("cloud_provider_support", False),
            api_gateway_support=infra_metrics.get("api_gateway_support", False)
        )

    def assess_interoperability(
        self,
        interop_metrics: Dict[str, Any]
    ) -> InteroperabilityAssessment:
        """Assess interoperability readiness."""
        return InteroperabilityAssessment(
            internal_system_compatibility=interop_metrics.get("internal_compat", 0.5),
            external_partner_compatibility=interop_metrics.get("external_compat", 0.3),
            protocol_support_coverage=interop_metrics.get("protocol_coverage", 0.4),
            fallback_mechanisms_exist=interop_metrics.get("fallback_exists", False),
            hybrid_mode_supported=interop_metrics.get("hybrid_supported", False),
            certificate_interoperability=interop_metrics.get("cert_interop", 0.5)
        )

    def assess_performance(
        self,
        perf_metrics: Dict[str, Any]
    ) -> PerformanceAssessment:
        """Assess performance impact of PQC migration."""
        sig_impact = perf_metrics.get("signature_impact", 15)
        ver_impact = perf_metrics.get("verification_impact", 10)
        keygen_impact = perf_metrics.get("keygen_impact", 25)
        mem_overhead = perf_metrics.get("memory_overhead", 20)
        latency = perf_metrics.get("latency_ms", 2)
        
        # Calculate overall performance score
        # Lower impact = higher score
        impact_scores = [
            max(0, 100 - sig_impact * 2),
            max(0, 100 - ver_impact * 2),
            max(0, 100 - keygen_impact * 2),
            max(0, 100 - mem_overhead * 2),
            max(0, 100 - latency * 10)
        ]
        overall_score = sum(impact_scores) / len(impact_scores)
        
        return PerformanceAssessment(
            signature_throughput_impact_percent=sig_impact,
            verification_throughput_impact_percent=ver_impact,
            key_generation_impact_percent=keygen_impact,
            memory_overhead_percent=mem_overhead,
            latency_impact_ms=latency,
            hardware_acceleration_available=perf_metrics.get("hw_accel", False),
            overall_performance_score=overall_score
        )

    def assess_compliance(
        self,
        compliance_metrics: Dict[str, Any]
    ) -> ComplianceAssessment:
        """Assess compliance with PQC standards and regulations."""
        return ComplianceAssessment(
            nist_sp_800_186_compliant=compliance_metrics.get("nist_186", False),
            nist_sp_800_56c_compliant=compliance_metrics.get("nist_56c", False),
            cnsa_2_0_compliant=compliance_metrics.get("cnsa_20", False),
            quantum_safe_mandate_timeline_met=compliance_metrics.get("timeline_met", False),
            industry_regulatory_compliance=compliance_metrics.get("industry_compliance", {}),
            documentation_complete=compliance_metrics.get("docs_complete", False),
            audit_trail_exists=compliance_metrics.get("audit_trail", False)
        )

    def identify_migration_gaps(
        self,
        algo_assessment: AlgorithmAssessment,
        key_assessment: KeyInventoryAssessment,
        infra_assessment: InfrastructureAssessment,
        interop_assessment: InteroperabilityAssessment,
        perf_assessment: PerformanceAssessment,
        compliance_assessment: ComplianceAssessment
    ) -> List[MigrationGap]:
        """Identify migration gaps and recommendations."""
        gaps = []
        
        # Algorithm gaps
        if algo_assessment.quantum_resistance_score < 50:
            gaps.append(MigrationGap(
                gap_id="GAP-ALG-001",
                description=f"High quantum vulnerability detected. Average quantum resistance score: {algo_assessment.quantum_resistance_score:.1f}/100",
                category="algorithms",
                risk_level=algo_assessment.risk_level,
                priority=algo_assessment.migration_priority,
                effort_estimate_hours=80,
                recommended_action=f"Migrate vulnerable algorithms to {algo_assessment.recommended_replacement}"
            ))
        
        # Key management gaps
        if key_assessment.classical_keys > 0:
            gaps.append(MigrationGap(
                gap_id="GAP-KEY-001",
                description=f"{key_assessment.classical_keys} classical keys vulnerable to quantum attacks",
                category="keys",
                risk_level=RiskLevel.HIGH,
                priority=MigrationPriority.HIGH,
                effort_estimate_hours=40,
                recommended_action="Generate post-quantum key counterparts and implement hybrid mode"
            ))
        
        if key_assessment.key_rotation_frequency_days > self.config["minimum_key_rotation_days"]:
            gaps.append(MigrationGap(
                gap_id="GAP-KEY-002",
                description=f"Key rotation frequency ({key_assessment.key_rotation_frequency_days} days) exceeds recommended maximum",
                category="keys",
                risk_level=RiskLevel.MEDIUM,
                priority=MigrationPriority.MEDIUM,
                effort_estimate_hours=16,
                recommended_action="Implement automated key rotation with 90-day maximum period"
            ))
        
        # Infrastructure gaps
        if not infra_assessment.tls_13_enabled:
            gaps.append(MigrationGap(
                gap_id="GAP-INFRA-001",
                description="TLS 1.3 not enabled - required for PQC cipher suites",
                category="infrastructure",
                risk_level=RiskLevel.HIGH,
                priority=MigrationPriority.HIGH,
                effort_estimate_hours=24,
                recommended_action="Upgrade all endpoints to TLS 1.3"
            ))
        
        if not infra_assessment.hsm_pqc_support:
            gaps.append(MigrationGap(
                gap_id="GAP-INFRA-002",
                description="Hardware Security Module does not support PQC algorithms",
                category="infrastructure",
                risk_level=RiskLevel.MEDIUM,
                priority=MigrationPriority.MEDIUM,
                effort_estimate_hours=40,
                recommended_action="Upgrade HSM firmware or migrate to PQC-capable HSM"
            ))
        
        # Interoperability gaps
        if not interop_assessment.hybrid_mode_supported:
            gaps.append(MigrationGap(
                gap_id="GAP-INTEROP-001",
                description="Hybrid mode not supported - critical for gradual migration",
                category="interoperability",
                risk_level=RiskLevel.HIGH,
                priority=MigrationPriority.HIGH,
                effort_estimate_hours=32,
                recommended_action="Implement hybrid classical-quantum mode for all connections"
            ))
        
        # Performance gaps
        if perf_assessment.overall_performance_score < 70:
            gaps.append(MigrationGap(
                gap_id="GAP-PERF-001",
                description=f"Performance impact exceeds acceptable thresholds. Score: {perf_assessment.overall_performance_score:.1f}/100",
                category="performance",
                risk_level=RiskLevel.MEDIUM,
                priority=MigrationPriority.MEDIUM,
                effort_estimate_hours=24,
                recommended_action="Implement hardware acceleration and performance optimization"
            ))
        
        # Compliance gaps
        if not compliance_assessment.cnsa_2_0_compliant:
            gaps.append(MigrationGap(
                gap_id="GAP-COMP-001",
                description="Not compliant with CNSA 2.0 quantum-safe requirements",
                category="compliance",
                risk_level=RiskLevel.CRITICAL,
                priority=MigrationPriority.IMMEDIATE,
                effort_estimate_hours=120,
                recommended_action="Initiate CNSA 2.0 compliance program immediately"
            ))
        
        return gaps

    def calculate_overall_readiness_score(
        self,
        algo_assessment: AlgorithmAssessment,
        key_assessment: KeyInventoryAssessment,
        infra_assessment: InfrastructureAssessment,
        interop_assessment: InteroperabilityAssessment,
        perf_assessment: PerformanceAssessment,
        compliance_assessment: ComplianceAssessment
    ) -> Tuple[float, ReadinessLevel]:
        """Calculate overall readiness score and level."""
        # Algorithm score (weight: 30%)
        algo_score = algo_assessment.quantum_resistance_score * 0.30
        
        # Key management score (weight: 20%)
        pq_key_ratio = (
            key_assessment.post_quantum_keys / max(1, key_assessment.total_keys)
        )
        key_score = pq_key_ratio * 100 * 0.20
        
        # Infrastructure score (weight: 20%)
        infra_items = [
            infra_assessment.tls_13_enabled,
            infra_assessment.certificate_chain_pqc_compatible,
            infra_assessment.hsm_pqc_support,
            infra_assessment.cloud_provider_support,
            infra_assessment.api_gateway_support
        ]
        infra_score = (sum(1 for x in infra_items if x) / len(infra_items)) * 100 * 0.20
        
        # Interoperability score (weight: 15%)
        interop_score = (
            (interop_assessment.internal_system_compatibility * 0.4 +
             interop_assessment.external_partner_compatibility * 0.3 +
             interop_assessment.protocol_support_coverage * 0.3) * 100
        ) * 0.15
        
        # Performance score (weight: 10%)
        perf_score = perf_assessment.overall_performance_score * 0.10
        
        # Compliance score (weight: 5%)
        compliance_items = [
            compliance_assessment.nist_sp_800_186_compliant,
            compliance_assessment.nist_sp_800_56c_compliant,
            compliance_assessment.cnsa_2_0_compliant,
            compliance_assessment.documentation_complete,
            compliance_assessment.audit_trail_exists
        ]
        compliance_score = (sum(1 for x in compliance_items if x) / len(compliance_items)) * 100 * 0.05
        
        total_score = algo_score + key_score + infra_score + interop_score + perf_score + compliance_score
        
        # Determine readiness level
        if total_score >= 90:
            level = ReadinessLevel.FULLY_MIGRATED
        elif total_score >= 70:
            level = ReadinessLevel.READY
        elif total_score >= 40:
            level = ReadinessLevel.PARTIALLY_READY
        else:
            level = ReadinessLevel.NOT_READY
        
        return total_score, level

    def generate_recommendations(
        self,
        gaps: List[MigrationGap],
        readiness_level: ReadinessLevel
    ) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []
        
        immediate_gaps = [g for g in gaps if g.priority == MigrationPriority.IMMEDIATE]
        high_gaps = [g for g in gaps if g.priority == MigrationPriority.HIGH]
        
        if readiness_level == ReadinessLevel.NOT_READY:
            recommendations.append("PHASE 1 (URGENT): Initiate emergency quantum risk assessment program")
            recommendations.append("  - Deploy hybrid mode immediately for all critical connections")
            recommendations.append("  - Create PQC migration steering committee")
            recommendations.append("  - Conduct full cryptographic inventory audit")
        elif readiness_level == ReadinessLevel.PARTIALLY_READY:
            recommendations.append("PHASE 1: Complete hybrid mode deployment for high-risk systems")
            recommendations.append("PHASE 2: Upgrade infrastructure to TLS 1.3")
            recommendations.append("PHASE 3: Begin full PQC migration for non-critical systems")
        elif readiness_level == ReadinessLevel.READY:
            recommendations.append("PHASE 1: Complete migration of remaining classical systems")
            recommendations.append("PHASE 2: Optimize performance with hardware acceleration")
            recommendations.append("PHASE 3: Achieve CNSA 2.0 compliance")
        else:
            recommendations.append("Maintain: Continue monitoring for new PQC standards")
            recommendations.append("Maintain: Perform quarterly PQC health assessments")
            recommendations.append("Maintain: Update cryptographic inventory continuously")
        
        # Add specific gap recommendations
        for gap in immediate_gaps[:3]:
            recommendations.append(f"IMMEDIATE: {gap.recommended_action}")
        for gap in high_gaps[:3]:
            recommendations.append(f"HIGH PRIORITY: {gap.recommended_action}")
        
        return recommendations

    def estimate_migration_timeline_and_cost(
        self,
        gaps: List[MigrationGap]
    ) -> Tuple[float, float]:
        """Estimate migration timeline in months and cost in USD."""
        total_effort_hours = sum(g.effort_estimate_hours for g in gaps)
        
        # Assume 40 hours per week per FTE, 2 FTEs
        timeline_months = (total_effort_hours / 40 / 4 / 2)
        
        # $150 per hour for specialized cryptography consulting
        estimated_cost = total_effort_hours * 150
        
        return max(1, timeline_months), max(10000, estimated_cost)

    def perform_full_assessment(
        self,
        organization_id: str,
        algorithm_inventory: Dict[str, int],
        key_metrics: Dict[str, Any],
        infra_metrics: Dict[str, Any],
        interop_metrics: Dict[str, Any],
        perf_metrics: Dict[str, Any],
        compliance_metrics: Dict[str, Any]
    ) -> ReadinessReport:
        """Perform complete PQC migration readiness assessment."""
        self.logger.info(f"Starting PQC migration readiness assessment for: {organization_id}")
        
        # Perform individual assessments
        algo_assessment = self.assess_algorithm_readiness(algorithm_inventory)
        key_assessment = self.assess_key_inventory(key_metrics)
        infra_assessment = self.assess_infrastructure(infra_metrics)
        interop_assessment = self.assess_interoperability(interop_metrics)
        perf_assessment = self.assess_performance(perf_metrics)
        compliance_assessment = self.assess_compliance(compliance_metrics)
        
        # Identify gaps
        gaps = self.identify_migration_gaps(
            algo_assessment, key_assessment, infra_assessment,
            interop_assessment, perf_assessment, compliance_assessment
        )
        
        # Calculate overall score
        overall_score, readiness_level = self.calculate_overall_readiness_score(
            algo_assessment, key_assessment, infra_assessment,
            interop_assessment, perf_assessment, compliance_assessment
        )
        
        # Generate recommendations
        recommendations = self.generate_recommendations(gaps, readiness_level)
        
        # Estimate timeline and cost
        timeline, cost = self.estimate_migration_timeline_and_cost(gaps)
        
        report = ReadinessReport(
            overall_readiness_score=overall_score,
            overall_readiness_level=readiness_level,
            algorithm_assessment=algo_assessment,
            key_inventory=key_assessment,
            infrastructure=infra_assessment,
            interoperability=interop_assessment,
            performance=perf_assessment,
            compliance=compliance_assessment,
            migration_gaps=gaps,
            migration_timeline_months=timeline,
            estimated_cost_usd=cost,
            recommendations=recommendations,
            assessment_timestamp=datetime.utcnow()
        )
        
        with self.lock:
            self.assessments[organization_id] = report
        
        self.logger.info(
            f"Assessment complete for {organization_id}: "
            f"Score={overall_score:.1f}/100, Level={readiness_level.value}"
        )
        
        return report

    def get_assessment_report(
        self, organization_id: str
    ) -> Optional[ReadinessReport]:
        """Get assessment report for an organization."""
        with self.lock:
            return self.assessments.get(organization_id)

    def export_assessment_json(
        self, organization_id: str
    ) -> Optional[str]:
        """Export assessment as JSON string."""
        report = self.get_assessment_report(organization_id)
        if report:
            return json.dumps(report.to_dict(), indent=2)
        return None
