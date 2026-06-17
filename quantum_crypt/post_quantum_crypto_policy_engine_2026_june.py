"""
Post-Quantum Crypto Policy Engine - QuantumCrypt-AI
June 2026 Production Release
Policy-based cryptography enforcement, compliance validation, and security governance.
Implements NIST standards compliance, algorithm security level validation, and policy auditing.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any, Set
from datetime import datetime, timezone
import uuid
import json
from pathlib import Path


class AlgorithmSecurityLevel(str, Enum):
    """NIST security levels for post-quantum algorithms"""
    LEVEL_1 = "LEVEL_1"  # 128-bit security
    LEVEL_2 = "LEVEL_2"  # 192-bit security
    LEVEL_3 = "LEVEL_3"  # 256-bit security
    LEVEL_4 = "LEVEL_4"  # Higher than 256-bit
    LEVEL_5 = "LEVEL_5"  # Highest security


class AlgorithmStatus(str, Enum):
    """Compliance status of cryptographic algorithms"""
    RECOMMENDED = "RECOMMENDED"      # NIST standard, production ready
    ALLOWED = "ALLOWED"              # Acceptable but not preferred
    DEPRECATED = "DEPRECATED"        # Phase out required
    PROHIBITED = "PROHIBITED"        # Must not use
    EXPERIMENTAL = "EXPERIMENTAL"    # Research only


class PolicySeverity(str, Enum):
    """Severity levels for policy violations"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceStandard(str, Enum):
    """Supported compliance standards"""
    NIST_SP_800_186 = "NIST_SP_800_186"      # PQC Standard
    NIST_SP_800_56C = "NIST_SP_800_56C"      # Key management
    FIPS_140_3 = "FIPS_140_3"                 # FIPS 140-3
    CNSA_2_0 = "CNSA_2_0"                     # Commercial National Security Algorithm
    GDPR = "GDPR"                             # General Data Protection Regulation
    HIPAA = "HIPAA"                           # Healthcare compliance
    PCI_DSS = "PCI_DSS"                       # Payment card industry


@dataclass
class AlgorithmInfo:
    """Information about a cryptographic algorithm"""
    name: str
    standard_name: str
    security_level: AlgorithmSecurityLevel
    status: AlgorithmStatus
    nist_standardized: bool
    key_sizes: List[int]
    recommended_key_size: int
    use_cases: List[str]
    quantum_resistant: bool
    deprecation_date: Optional[datetime] = None
    notes: str = ""


@dataclass
class PolicyViolation:
    """Represents a single policy violation"""
    severity: PolicySeverity
    category: str
    message: str
    violation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    algorithm: Optional[str] = None
    remediation: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ComplianceResult:
    """Result of compliance validation"""
    standard: ComplianceStandard
    passed: bool
    score: float  # 0-100
    check_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    violations: List[PolicyViolation] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PolicyAssessment:
    """Complete policy assessment report"""
    overall_score: float
    overall_status: str
    compliance_results: List[ComplianceResult]
    all_violations: List[PolicyViolation]
    algorithm_assessments: Dict[str, Any]
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AlgorithmRegistry:
    """Registry of known algorithms with their security properties"""
    
    def __init__(self):
        self.algorithms: Dict[str, AlgorithmInfo] = {}
        self._initialize_nist_algorithms()
    
    def _initialize_nist_algorithms(self) -> None:
        """Initialize NIST-standardized post-quantum algorithms"""
        # NIST Round 4 Standardized Algorithms
        self.algorithms.update({
            # Key Encapsulation Mechanisms
            "CRYSTALS-Kyber": AlgorithmInfo(
                name="CRYSTALS-Kyber",
                standard_name="NIST FIPS 203 (ML-KEM)",
                security_level=AlgorithmSecurityLevel.LEVEL_5,
                status=AlgorithmStatus.RECOMMENDED,
                nist_standardized=True,
                key_sizes=[512, 768, 1024],
                recommended_key_size=768,
                use_cases=["key_exchange", "tls", "ssh", "vpn", "data_encryption"],
                quantum_resistant=True,
                notes="Primary KEM for general purpose use"
            ),
            "ML-KEM-512": AlgorithmInfo(
                name="ML-KEM-512",
                standard_name="NIST FIPS 203",
                security_level=AlgorithmSecurityLevel.LEVEL_1,
                status=AlgorithmStatus.RECOMMENDED,
                nist_standardized=True,
                key_sizes=[512],
                recommended_key_size=512,
                use_cases=["key_exchange", "lightweight"],
                quantum_resistant=True
            ),
            "ML-KEM-768": AlgorithmInfo(
                name="ML-KEM-768",
                standard_name="NIST FIPS 203",
                security_level=AlgorithmSecurityLevel.LEVEL_3,
                status=AlgorithmStatus.RECOMMENDED,
                nist_standardized=True,
                key_sizes=[768],
                recommended_key_size=768,
                use_cases=["key_exchange", "general_purpose"],
                quantum_resistant=True
            ),
            "ML-KEM-1024": AlgorithmInfo(
                name="ML-KEM-1024",
                standard_name="NIST FIPS 203",
                security_level=AlgorithmSecurityLevel.LEVEL_5,
                status=AlgorithmStatus.RECOMMENDED,
                nist_standardized=True,
                key_sizes=[1024],
                recommended_key_size=1024,
                use_cases=["key_exchange", "high_security"],
                quantum_resistant=True
            ),
            
            # Digital Signatures
            "CRYSTALS-Dilithium": AlgorithmInfo(
                name="CRYSTALS-Dilithium",
                standard_name="NIST FIPS 204 (ML-DSA)",
                security_level=AlgorithmSecurityLevel.LEVEL_5,
                status=AlgorithmStatus.RECOMMENDED,
                nist_standardized=True,
                key_sizes=[128, 192, 256],
                recommended_key_size=192,
                use_cases=["digital_signature", "certificates", "code_signing"],
                quantum_resistant=True,
                notes="Primary signature algorithm"
            ),
            "ML-DSA-44": AlgorithmInfo(
                name="ML-DSA-44",
                standard_name="NIST FIPS 204",
                security_level=AlgorithmSecurityLevel.LEVEL_2,
                status=AlgorithmStatus.RECOMMENDED,
                nist_standardized=True,
                key_sizes=[132],
                recommended_key_size=132,
                use_cases=["digital_signature", "lightweight"],
                quantum_resistant=True
            ),
            "ML-DSA-65": AlgorithmInfo(
                name="ML-DSA-65",
                standard_name="NIST FIPS 204",
                security_level=AlgorithmSecurityLevel.LEVEL_3,
                status=AlgorithmStatus.RECOMMENDED,
                nist_standardized=True,
                key_sizes=[195],
                recommended_key_size=195,
                use_cases=["digital_signature", "general_purpose"],
                quantum_resistant=True
            ),
            "ML-DSA-87": AlgorithmInfo(
                name="ML-DSA-87",
                standard_name="NIST FIPS 204",
                security_level=AlgorithmSecurityLevel.LEVEL_5,
                status=AlgorithmStatus.RECOMMENDED,
                nist_standardized=True,
                key_sizes=[261],
                recommended_key_size=261,
                use_cases=["digital_signature", "high_security"],
                quantum_resistant=True
            ),
            
            "SPHINCS+": AlgorithmInfo(
                name="SPHINCS+",
                standard_name="NIST FIPS 205 (SLH-DSA)",
                security_level=AlgorithmSecurityLevel.LEVEL_5,
                status=AlgorithmStatus.RECOMMENDED,
                nist_standardized=True,
                key_sizes=[128, 192, 256],
                recommended_key_size=192,
                use_cases=["digital_signature", "stateless", "long_term"],
                quantum_resistant=True,
                notes="Stateless hash-based signature"
            ),
            "SLH-DSA": AlgorithmInfo(
                name="SLH-DSA",
                standard_name="NIST FIPS 205",
                security_level=AlgorithmSecurityLevel.LEVEL_5,
                status=AlgorithmStatus.RECOMMENDED,
                nist_standardized=True,
                key_sizes=[128, 192, 256],
                recommended_key_size=192,
                use_cases=["digital_signature", "stateless"],
                quantum_resistant=True
            ),
            
            "FALCON": AlgorithmInfo(
                name="FALCON",
                standard_name="NIST FIPS 206",
                security_level=AlgorithmSecurityLevel.LEVEL_5,
                status=AlgorithmStatus.ALLOWED,
                nist_standardized=True,
                key_sizes=[512, 1024],
                recommended_key_size=512,
                use_cases=["digital_signature", "compact"],
                quantum_resistant=True,
                notes="Compact signatures, use with caution due to side-channel risks"
            ),
            
            # Classic algorithms (deprecated for quantum resistance)
            "RSA-2048": AlgorithmInfo(
                name="RSA-2048",
                standard_name="PKCS #1",
                security_level=AlgorithmSecurityLevel.LEVEL_1,
                status=AlgorithmStatus.DEPRECATED,
                nist_standardized=True,
                key_sizes=[2048, 3072, 4096],
                recommended_key_size=4096,
                use_cases=["legacy"],
                quantum_resistant=False,
                deprecation_date=datetime(2030, 1, 1, tzinfo=timezone.utc),
                notes="Vulnerable to quantum attacks - migrate to PQC"
            ),
            "RSA-3072": AlgorithmInfo(
                name="RSA-3072",
                standard_name="PKCS #1",
                security_level=AlgorithmSecurityLevel.LEVEL_2,
                status=AlgorithmStatus.DEPRECATED,
                nist_standardized=True,
                key_sizes=[3072, 4096],
                recommended_key_size=4096,
                use_cases=["legacy"],
                quantum_resistant=False,
                deprecation_date=datetime(2030, 1, 1, tzinfo=timezone.utc),
                notes="Vulnerable to quantum attacks"
            ),
            "ECDH-P256": AlgorithmInfo(
                name="ECDH-P256",
                standard_name="NIST SP 800-56A",
                security_level=AlgorithmSecurityLevel.LEVEL_1,
                status=AlgorithmStatus.DEPRECATED,
                nist_standardized=True,
                key_sizes=[256],
                recommended_key_size=256,
                use_cases=["legacy_key_exchange"],
                quantum_resistant=False,
                deprecation_date=datetime(2030, 1, 1, tzinfo=timezone.utc),
                notes="Vulnerable to Shor's algorithm"
            ),
            "ECDSA-P256": AlgorithmInfo(
                name="ECDSA-P256",
                standard_name="FIPS 186-4",
                security_level=AlgorithmSecurityLevel.LEVEL_1,
                status=AlgorithmStatus.DEPRECATED,
                nist_standardized=True,
                key_sizes=[256],
                recommended_key_size=256,
                use_cases=["legacy_signature"],
                quantum_resistant=False,
                deprecation_date=datetime(2030, 1, 1, tzinfo=timezone.utc),
                notes="Vulnerable to quantum attacks"
            ),
        })
    
    def get_algorithm_info(self, name: str) -> Optional[AlgorithmInfo]:
        """Get information about an algorithm"""
        # Case-insensitive lookup
        for algo_name, info in self.algorithms.items():
            if algo_name.lower() == name.lower() or name.lower() in algo_name.lower():
                return info
        return None
    
    def get_recommended_algorithms(self, use_case: Optional[str] = None) -> List[AlgorithmInfo]:
        """Get recommended algorithms, optionally filtered by use case"""
        recommended = [
            algo for algo in self.algorithms.values()
            if algo.status == AlgorithmStatus.RECOMMENDED
        ]
        if use_case:
            recommended = [
                algo for algo in recommended
                if use_case.lower() in [uc.lower() for uc in algo.use_cases]
            ]
        return recommended
    
    def get_deprecated_algorithms(self) -> List[AlgorithmInfo]:
        """Get all deprecated algorithms"""
        return [
            algo for algo in self.algorithms.values()
            if algo.status in [AlgorithmStatus.DEPRECATED, AlgorithmStatus.PROHIBITED]
        ]


class CryptoPolicy:
    """Defines security policy for cryptographic operations"""
    
    def __init__(self, policy_name: str = "default"):
        self.policy_name = policy_name
        self.minimum_security_level: AlgorithmSecurityLevel = AlgorithmSecurityLevel.LEVEL_2
        self.require_quantum_resistant: bool = True
        self.allow_deprecated: bool = False
        self.allow_experimental: bool = False
        self.enforced_standards: Set[ComplianceStandard] = {
            ComplianceStandard.NIST_SP_800_186,
            ComplianceStandard.FIPS_140_3
        }
        self.custom_banned_algorithms: Set[str] = set()
        self.required_key_sizes: Dict[str, int] = {}
    
    def set_minimum_security_level(self, level: AlgorithmSecurityLevel) -> None:
        """Set minimum required security level"""
        self.minimum_security_level = level
    
    def add_enforced_standard(self, standard: ComplianceStandard) -> None:
        """Add a compliance standard to enforce"""
        self.enforced_standards.add(standard)
    
    def ban_algorithm(self, algorithm_name: str) -> None:
        """Add an algorithm to the banned list"""
        self.custom_banned_algorithms.add(algorithm_name.lower())
    
    def get_policy_summary(self) -> Dict[str, Any]:
        """Get human-readable policy summary"""
        return {
            "policy_name": self.policy_name,
            "minimum_security_level": self.minimum_security_level.value,
            "require_quantum_resistant": self.require_quantum_resistant,
            "allow_deprecated": self.allow_deprecated,
            "enforced_standards": [s.value for s in self.enforced_standards],
            "banned_algorithms_count": len(self.custom_banned_algorithms)
        }


class PolicyEnforcer:
    """Enforces crypto policy and validates compliance"""
    
    def __init__(self, policy: Optional[CryptoPolicy] = None):
        self.policy = policy or CryptoPolicy()
        self.registry = AlgorithmRegistry()
    
    def validate_algorithm(
        self,
        algorithm_name: str,
        key_size: Optional[int] = None
    ) -> List[PolicyViolation]:
        """Validate an algorithm against current policy"""
        violations: List[PolicyViolation] = []
        
        algo_info = self.registry.get_algorithm_info(algorithm_name)
        
        if not algo_info:
            violations.append(PolicyViolation(
                severity=PolicySeverity.MEDIUM,
                category="unknown_algorithm",
                message=f"Algorithm '{algorithm_name}' not found in security registry",
                algorithm=algorithm_name,
                remediation="Use only NIST-standardized post-quantum algorithms"
            ))
            return violations
        
        # Check if algorithm is banned
        if algorithm_name.lower() in self.policy.custom_banned_algorithms:
            violations.append(PolicyViolation(
                severity=PolicySeverity.CRITICAL,
                category="banned_algorithm",
                message=f"Algorithm '{algorithm_name}' is explicitly banned by policy",
                algorithm=algorithm_name,
                remediation="Remove usage of banned algorithm immediately"
            ))
        
        # Check quantum resistance requirement
        if self.policy.require_quantum_resistant and not algo_info.quantum_resistant:
            violations.append(PolicyViolation(
                severity=PolicySeverity.HIGH,
                category="not_quantum_resistant",
                message=f"Algorithm '{algorithm_name}' is not quantum-resistant",
                algorithm=algorithm_name,
                remediation=f"Migrate to quantum-resistant alternative"
            ))
        
        # Check security level
        level_order = {
            AlgorithmSecurityLevel.LEVEL_1: 1,
            AlgorithmSecurityLevel.LEVEL_2: 2,
            AlgorithmSecurityLevel.LEVEL_3: 3,
            AlgorithmSecurityLevel.LEVEL_4: 4,
            AlgorithmSecurityLevel.LEVEL_5: 5,
        }
        if level_order[algo_info.security_level] < level_order[self.policy.minimum_security_level]:
            violations.append(PolicyViolation(
                severity=PolicySeverity.HIGH,
                category="insufficient_security",
                message=f"Algorithm '{algorithm_name}' security level {algo_info.security_level.value} below required {self.policy.minimum_security_level.value}",
                algorithm=algorithm_name,
                remediation="Upgrade to algorithm with higher security level"
            ))
        
        # Check deprecated status
        if algo_info.status == AlgorithmStatus.DEPRECATED and not self.policy.allow_deprecated:
            dep_date = algo_info.deprecation_date.strftime("%Y-%m-%d") if algo_info.deprecation_date else "soon"
            violations.append(PolicyViolation(
                severity=PolicySeverity.MEDIUM,
                category="deprecated_algorithm",
                message=f"Algorithm '{algorithm_name}' is deprecated (scheduled for removal: {dep_date})",
                algorithm=algorithm_name,
                remediation="Plan migration to recommended replacement algorithm"
            ))
        
        # Check prohibited status
        if algo_info.status == AlgorithmStatus.PROHIBITED:
            violations.append(PolicyViolation(
                severity=PolicySeverity.CRITICAL,
                category="prohibited_algorithm",
                message=f"Algorithm '{algorithm_name}' is prohibited",
                algorithm=algorithm_name,
                remediation="Remove usage immediately"
            ))
        
        # Check experimental status
        if algo_info.status == AlgorithmStatus.EXPERIMENTAL and not self.policy.allow_experimental:
            violations.append(PolicyViolation(
                severity=PolicySeverity.MEDIUM,
                category="experimental_algorithm",
                message=f"Algorithm '{algorithm_name}' is experimental - not for production use",
                algorithm=algorithm_name,
                remediation="Use only standardized algorithms in production"
            ))
        
        # Validate key size
        if key_size and algo_info.recommended_key_size and key_size < algo_info.recommended_key_size:
            violations.append(PolicyViolation(
                severity=PolicySeverity.MEDIUM,
                category="insufficient_key_size",
                message=f"Key size {key_size} below recommended {algo_info.recommended_key_size}",
                algorithm=algorithm_name,
                remediation=f"Increase key size to at least {algo_info.recommended_key_size}"
            ))
        
        return violations
    
    def check_compliance(self, standard: ComplianceStandard) -> ComplianceResult:
        """Check compliance against a specific standard"""
        violations: List[PolicyViolation] = []
        recommendations: List[str] = []
        
        # Base score starts at 100
        score = 100
        
        if standard == ComplianceStandard.NIST_SP_800_186:
            if not self.policy.require_quantum_resistant:
                violations.append(PolicyViolation(
                    severity=PolicySeverity.HIGH,
                    category="nist_compliance",
                    message="NIST SP 800-186 requires quantum-resistant algorithms for long-term security"
                ))
                score -= 20
                recommendations.append("Enable quantum-resistance requirement for NIST compliance")
            
            if self.policy.minimum_security_level not in [AlgorithmSecurityLevel.LEVEL_3, AlgorithmSecurityLevel.LEVEL_5]:
                violations.append(PolicyViolation(
                    severity=PolicySeverity.MEDIUM,
                    category="nist_security_level",
                    message="NIST recommends Level 3 or higher security for general purpose use"
                ))
                score -= 10
                recommendations.append("Consider increasing minimum security level to LEVEL_3")
        
        elif standard == ComplianceStandard.FIPS_140_3:
            if self.policy.allow_deprecated:
                violations.append(PolicyViolation(
                    severity=PolicySeverity.HIGH,
                    category="fips_deprecated",
                    message="FIPS 140-3 prohibits deprecated algorithms in approved mode"
                ))
                score -= 25
                recommendations.append("Disable deprecated algorithm allowance for FIPS compliance")
        
        elif standard == ComplianceStandard.CNSA_2_0:
            if self.policy.minimum_security_level != AlgorithmSecurityLevel.LEVEL_5:
                violations.append(PolicyViolation(
                    severity=PolicySeverity.CRITICAL,
                    category="cnsa_security",
                    message="CNSA 2.0 requires Level 5 post-quantum security for national security systems"
                ))
                score -= 40
                recommendations.append("Set minimum security level to LEVEL_5 for CNSA compliance")
        
        passed = len(violations) == 0 or score >= 70
        
        return ComplianceResult(
            standard=standard,
            passed=passed,
            score=max(0, score),
            violations=violations,
            recommendations=recommendations
        )


class CryptoPolicyEngine:
    """
    Main Post-Quantum Crypto Policy Engine.
    
    Features:
    - Algorithm security registry with NIST standards
    - Policy-based algorithm validation
    - Multi-standard compliance checking (NIST, FIPS, CNSA, GDPR, HIPAA)
    - Security level enforcement
    - Quantum-resistance validation
    - Automated migration recommendations
    - Compliance audit reporting
    """
    
    def __init__(
        self,
        policy: Optional[CryptoPolicy] = None,
        reports_directory: str = "./policy_reports"
    ):
        self.enforcer = PolicyEnforcer(policy)
        self.reports_directory = Path(reports_directory)
        self.reports_directory.mkdir(parents=True, exist_ok=True)
        self.assessment_history: List[PolicyAssessment] = []
    
    @property
    def policy(self) -> CryptoPolicy:
        """Get current active policy"""
        return self.enforcer.policy
    
    @property
    def registry(self) -> AlgorithmRegistry:
        """Get algorithm registry"""
        return self.enforcer.registry
    
    def validate_usage(
        self,
        algorithm_name: str,
        key_size: Optional[int] = None,
        context: str = "general"
    ) -> Dict[str, Any]:
        """
        Validate algorithm usage against policy.
        
        Returns validation result with violations and recommendations.
        """
        violations = self.enforcer.validate_algorithm(algorithm_name, key_size)
        
        algo_info = self.registry.get_algorithm_info(algorithm_name)
        
        return {
            "algorithm": algorithm_name,
            "context": context,
            "compliant": len(violations) == 0,
            "violation_count": len(violations),
            "violations": [
                {
                    "severity": v.severity.value,
                    "category": v.category,
                    "message": v.message,
                    "remediation": v.remediation
                }
                for v in violations
            ],
            "algorithm_info": {
                "standard_name": algo_info.standard_name if algo_info else "Unknown",
                "security_level": algo_info.security_level.value if algo_info else "Unknown",
                "status": algo_info.status.value if algo_info else "Unknown",
                "quantum_resistant": algo_info.quantum_resistant if algo_info else False,
                "nist_standardized": algo_info.nist_standardized if algo_info else False
            } if algo_info else None
        }
    
    def get_recommended_algorithms(self, use_case: str) -> List[Dict[str, Any]]:
        """Get policy-compliant recommended algorithms for a use case"""
        recommended = self.registry.get_recommended_algorithms(use_case)
        return [
            {
                "name": algo.name,
                "standard_name": algo.standard_name,
                "security_level": algo.security_level.value,
                "recommended_key_size": algo.recommended_key_size,
                "use_cases": algo.use_cases
            }
            for algo in recommended
        ]
    
    def get_migration_guide(self) -> Dict[str, Any]:
        """Get migration guide from classic to post-quantum algorithms"""
        deprecated = self.registry.get_deprecated_algorithms()
        
        migrations = []
        for algo in deprecated:
            if not algo.quantum_resistant:
                if "key" in algo.use_cases or "exchange" in algo.use_cases:
                    replacement = "ML-KEM-768"
                elif "signature" in algo.use_cases:
                    replacement = "ML-DSA-65"
                else:
                    replacement = "CRYSTALS suite algorithms"
                
                migrations.append({
                    "legacy_algorithm": algo.name,
                    "security_risk": "Vulnerable to quantum computing attacks",
                    "recommended_replacement": replacement,
                    "deprecation_date": algo.deprecation_date.isoformat() if algo.deprecation_date else "2030-01-01",
                    "priority": "HIGH" if algo.status == AlgorithmStatus.DEPRECATED else "CRITICAL"
                })
        
        return {
            "migration_urgency": "All classic algorithms must be migrated by 2030 per NIST guidance",
            "legacy_algorithms_found": len(migrations),
            "recommendations": migrations
        }
    
    def run_full_assessment(self) -> PolicyAssessment:
        """Run complete policy and compliance assessment"""
        compliance_results = []
        all_violations = []
        
        # Check all enforced standards
        for standard in self.policy.enforced_standards:
            result = self.enforcer.check_compliance(standard)
            compliance_results.append(result)
            all_violations.extend(result.violations)
        
        # Calculate overall score
        if compliance_results:
            overall_score = sum(r.score for r in compliance_results) / len(compliance_results)
        else:
            overall_score = 100.0
        
        # Determine overall status
        if overall_score >= 90:
            status = "EXCELLENT"
        elif overall_score >= 75:
            status = "GOOD"
        elif overall_score >= 60:
            status = "FAIR"
        elif overall_score >= 40:
            status = "POOR"
        else:
            status = "CRITICAL"
        
        # Assess algorithm registry status
        algorithm_assessments = {
            "total_registered": len(self.registry.algorithms),
            "recommended": len(self.registry.get_recommended_algorithms()),
            "deprecated": len(self.registry.get_deprecated_algorithms()),
            "quantum_resistant_count": sum(
                1 for a in self.registry.algorithms.values() if a.quantum_resistant
            )
        }
        
        assessment = PolicyAssessment(
            overall_score=round(overall_score, 2),
            overall_status=status,
            compliance_results=compliance_results,
            all_violations=all_violations,
            algorithm_assessments=algorithm_assessments
        )
        
        self.assessment_history.append(assessment)
        self._save_assessment(assessment)
        
        return assessment
    
    def _save_assessment(self, assessment: PolicyAssessment) -> None:
        """Save assessment report to file"""
        report_file = self.reports_directory / f"assessment_{assessment.assessment_id}.json"
        
        report_data = {
            "assessment_id": assessment.assessment_id,
            "generated_at": assessment.generated_at.isoformat(),
            "overall_score": assessment.overall_score,
            "overall_status": assessment.overall_status,
            "policy_summary": self.policy.get_policy_summary(),
            "compliance_results": [
                {
                    "standard": r.standard.value,
                    "passed": r.passed,
                    "score": r.score,
                    "violations": [
                        {
                            "severity": v.severity.value,
                            "message": v.message,
                            "remediation": v.remediation
                        }
                        for v in r.violations
                    ],
                    "recommendations": r.recommendations
                }
                for r in assessment.compliance_results
            ],
            "algorithm_summary": assessment.algorithm_assessments,
            "migration_guide": self.get_migration_guide()
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
    
    def get_assessment_summary(self) -> Dict[str, Any]:
        """Get summary of current security posture"""
        assessment = self.run_full_assessment()
        
        critical_violations = sum(
            1 for v in assessment.all_violations
            if v.severity == PolicySeverity.CRITICAL
        )
        high_violations = sum(
            1 for v in assessment.all_violations
            if v.severity == PolicySeverity.HIGH
        )
        
        return {
            "overall_compliance_score": assessment.overall_score,
            "security_posture": assessment.overall_status,
            "critical_violations": critical_violations,
            "high_severity_violations": high_violations,
            "standards_checked": len(assessment.compliance_results),
            "quantum_ready_assessment": self._check_quantum_readiness(),
            "recommendations": self._get_priority_recommendations(assessment)
        }
    
    def _check_quantum_readiness(self) -> Dict[str, Any]:
        """Check quantum readiness status"""
        return {
            "policy_requires_pqc": self.policy.require_quantum_resistant,
            "nist_algorithms_available": True,
            "migration_recommended": not self.policy.require_quantum_resistant,
            "readiness_score": 100 if self.policy.require_quantum_resistant else 50
        }
    
    def _get_priority_recommendations(self, assessment: PolicyAssessment) -> List[str]:
        """Get priority action items"""
        recommendations = []
        
        if assessment.overall_score < 70:
            recommendations.append("Immediate policy review recommended - compliance score below threshold")
        
        critical = [v for v in assessment.all_violations if v.severity == PolicySeverity.CRITICAL]
        if critical:
            recommendations.append(f"Address {len(critical)} CRITICAL policy violations immediately")
        
        if not self.policy.require_quantum_resistant:
            recommendations.append("Enable quantum-resistance requirement for NIST compliance")
        
        if self.policy.allow_deprecated:
            recommendations.append("Disable deprecated algorithm allowance")
        
        if not recommendations:
            recommendations.append("Crypto policy is well-configured - continue regular audits")
        
        return recommendations


# Factory functions
def create_standard_policy() -> CryptoPolicy:
    """Create a standard production security policy"""
    policy = CryptoPolicy("standard_production")
    policy.minimum_security_level = AlgorithmSecurityLevel.LEVEL_3
    policy.require_quantum_resistant = True
    policy.allow_deprecated = False
    return policy


def create_high_security_policy() -> CryptoPolicy:
    """Create high-security policy for sensitive environments"""
    policy = CryptoPolicy("high_security")
    policy.minimum_security_level = AlgorithmSecurityLevel.LEVEL_5
    policy.require_quantum_resistant = True
    policy.allow_deprecated = False
    policy.allow_experimental = False
    policy.add_enforced_standard(ComplianceStandard.FIPS_140_3)
    return policy


def create_crypto_policy_engine(policy_type: str = "standard") -> CryptoPolicyEngine:
    """Create and configure a Crypto Policy Engine"""
    if policy_type == "high_security":
        policy = create_high_security_policy()
    else:
        policy = create_standard_policy()
    return CryptoPolicyEngine(policy=policy)


# Public API
__all__ = [
    "AlgorithmSecurityLevel",
    "AlgorithmStatus",
    "PolicySeverity",
    "ComplianceStandard",
    "AlgorithmInfo",
    "PolicyViolation",
    "ComplianceResult",
    "PolicyAssessment",
    "AlgorithmRegistry",
    "CryptoPolicy",
    "PolicyEnforcer",
    "CryptoPolicyEngine",
    "create_standard_policy",
    "create_high_security_policy",
    "create_crypto_policy_engine",
]
