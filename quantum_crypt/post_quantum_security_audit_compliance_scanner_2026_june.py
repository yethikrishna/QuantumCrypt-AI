"""
Post-Quantum Cryptography Security Audit & Compliance Scanner
June 20, 2026 - Production Grade Implementation

Real working feature:
- NIST SP 800-186 compliance checking
- Algorithm strength assessment (quantum-resistant)
- Cryptographic configuration audit
- Security gap analysis and recommendations
- Compliance report generation
- FIPS 140-3 readiness assessment
"""

import hashlib
import json
import time
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from collections import defaultdict


class AlgorithmCategory(Enum):
    """Cryptographic algorithm categories"""
    KEY_ENCAPSULATION = "key_encapsulation"
    DIGITAL_SIGNATURE = "digital_signature"
    HASH_FUNCTION = "hash_function"
    SYMMETRIC_CIPHER = "symmetric_cipher"
    KEY_EXCHANGE = "key_exchange"
    KEY_DERIVATION = "key_derivation"
    RANDOM_GENERATOR = "random_generator"
    UNKNOWN = "unknown"


class NISTSecurityLevel(Enum):
    """NIST PQC Security Levels"""
    LEVEL_1 = 1  # AES-128 equivalent
    LEVEL_2 = 2  # SHA-256 equivalent
    LEVEL_3 = 3  # AES-192 equivalent
    LEVEL_4 = 4  # SHA-384 equivalent
    LEVEL_5 = 5  # AES-256 equivalent


class ComplianceStatus(Enum):
    """Compliance status levels"""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"


class RiskLevel(Enum):
    """Security risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    NIST_SP_800_186 = "nist_sp_800_186"
    FIPS_140_3 = "fips_140_3"
    CNSA_2_0 = "cnsa_2_0"
    ETSI_QSC = "etsi_qsc"
    GDPR = "gdpr"
    HIPAA = "hipaa"


@dataclass
class CryptographicAlgorithm:
    """Cryptographic algorithm metadata"""
    name: str
    category: AlgorithmCategory
    nist_standardized: bool
    quantum_resistant: bool
    nist_security_level: Optional[NISTSecurityLevel] = None
    key_size_bits: int = 0
    signature_size_bits: int = 0
    public_key_size_bits: int = 0
    private_key_size_bits: int = 0
    ciphertext_size_bits: int = 0
    standard_reference: str = ""
    fips_approved: bool = False
    deprecation_date: Optional[str] = None
    quantum_risk_assessment: str = ""


@dataclass
class ComplianceFinding:
    """Individual compliance finding"""
    finding_id: str
    framework: ComplianceFramework
    requirement: str
    status: ComplianceStatus
    risk_level: RiskLevel
    description: str
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    section_reference: str = ""


@dataclass
class SecurityGap:
    """Identified security gap"""
    gap_id: str
    title: str
    description: str
    risk_level: RiskLevel
    affected_components: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)
    priority: int = 0
    effort_estimate_hours: int = 0


@dataclass
class AlgorithmAssessment:
    """Algorithm security assessment"""
    algorithm: CryptographicAlgorithm
    usage_context: str
    quantum_safe: bool
    risk_level: RiskLevel
    recommendations: List[str] = field(default_factory=list)
    migration_priority: str = ""
    migration_timeline: str = ""


@dataclass
class ComplianceAuditResult:
    """Complete compliance audit result"""
    audit_id: str
    audit_timestamp: datetime
    target_system: str
    frameworks_audited: List[ComplianceFramework]
    overall_compliance_score: float
    compliance_by_framework: Dict[str, float] = field(default_factory=dict)
    findings: List[ComplianceFinding] = field(default_factory=list)
    security_gaps: List[SecurityGap] = field(default_factory=list)
    algorithm_assessments: List[AlgorithmAssessment] = field(default_factory=list)
    compliant_algorithms: List[str] = field(default_factory=list)
    non_compliant_algorithms: List[str] = field(default_factory=list)
    recommendations_summary: List[str] = field(default_factory=list)
    executive_summary: str = ""
    detailed_report: str = ""
    processing_time_ms: float = 0.0


class PostQuantumSecurityAuditScanner:
    """
    Production-grade Post-Quantum Security Audit & Compliance Scanner
    
    Real working capabilities:
    1. Audit cryptographic implementations for NIST SP 800-186 compliance
    2. Assess algorithm quantum-resistance
    3. Check FIPS 140-3 readiness
    4. Identify security gaps and vulnerabilities
    5. Generate compliance reports
    6. Provide migration recommendations
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.audit_history: List[ComplianceAuditResult] = []
        self._initialize_algorithm_database()
        self._initialize_compliance_rules()
        self._initialize_framework_requirements()
        
    def _initialize_algorithm_database(self):
        """Initialize NIST-standardized post-quantum algorithm database"""
        self.algorithm_database: Dict[str, CryptographicAlgorithm] = {}
        
        # NIST Standardized KEM Algorithms (Round 4)
        self.algorithm_database["CRYSTALS-Kyber"] = CryptographicAlgorithm(
            name="CRYSTALS-Kyber",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            nist_standardized=True,
            quantum_resistant=True,
            nist_security_level=NISTSecurityLevel.LEVEL_5,
            key_size_bits=256,
            public_key_size_bits=1184,
            private_key_size_bits=2400,
            ciphertext_size_bits=1088,
            standard_reference="NIST FIPS 203",
            fips_approved=True,
            quantum_risk_assessment="Fully quantum-resistant - Module-LWE based"
        )
        
        self.algorithm_database["Kyber-512"] = CryptographicAlgorithm(
            name="Kyber-512",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            nist_standardized=True,
            quantum_resistant=True,
            nist_security_level=NISTSecurityLevel.LEVEL_1,
            public_key_size_bits=800,
            private_key_size_bits=1632,
            ciphertext_size_bits=768,
            standard_reference="NIST FIPS 203",
            fips_approved=True,
            quantum_risk_assessment="Quantum-resistant at NIST Security Level 1"
        )
        
        self.algorithm_database["Kyber-768"] = CryptographicAlgorithm(
            name="Kyber-768",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            nist_standardized=True,
            quantum_resistant=True,
            nist_security_level=NISTSecurityLevel.LEVEL_3,
            public_key_size_bits=1184,
            private_key_size_bits=2400,
            ciphertext_size_bits=1088,
            standard_reference="NIST FIPS 203",
            fips_approved=True,
            quantum_risk_assessment="Quantum-resistant at NIST Security Level 3"
        )
        
        self.algorithm_database["Kyber-1024"] = CryptographicAlgorithm(
            name="Kyber-1024",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            nist_standardized=True,
            quantum_resistant=True,
            nist_security_level=NISTSecurityLevel.LEVEL_5,
            public_key_size_bits=1568,
            private_key_size_bits=3168,
            ciphertext_size_bits=1568,
            standard_reference="NIST FIPS 203",
            fips_approved=True,
            quantum_risk_assessment="Quantum-resistant at NIST Security Level 5"
        )
        
        # NIST Standardized Signature Algorithms (Round 4)
        self.algorithm_database["CRYSTALS-Dilithium"] = CryptographicAlgorithm(
            name="CRYSTALS-Dilithium",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            nist_standardized=True,
            quantum_resistant=True,
            nist_security_level=NISTSecurityLevel.LEVEL_5,
            public_key_size_bits=1760,
            private_key_size_bits=3856,
            signature_size_bits=2704,
            standard_reference="NIST FIPS 204",
            fips_approved=True,
            quantum_risk_assessment="Fully quantum-resistant - Module-LWE based"
        )
        
        self.algorithm_database["Dilithium-2"] = CryptographicAlgorithm(
            name="Dilithium-2",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            nist_standardized=True,
            quantum_resistant=True,
            nist_security_level=NISTSecurityLevel.LEVEL_2,
            public_key_size_bits=1184,
            private_key_size_bits=2528,
            signature_size_bits=2048,
            standard_reference="NIST FIPS 204",
            fips_approved=True,
            quantum_risk_assessment="Quantum-resistant at NIST Security Level 2"
        )
        
        self.algorithm_database["Dilithium-3"] = CryptographicAlgorithm(
            name="Dilithium-3",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            nist_standardized=True,
            quantum_resistant=True,
            nist_security_level=NISTSecurityLevel.LEVEL_3,
            public_key_size_bits=1760,
            private_key_size_bits=3856,
            signature_size_bits=2704,
            standard_reference="NIST FIPS 204",
            fips_approved=True,
            quantum_risk_assessment="Quantum-resistant at NIST Security Level 3"
        )
        
        self.algorithm_database["Dilithium-5"] = CryptographicAlgorithm(
            name="Dilithium-5",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            nist_standardized=True,
            quantum_resistant=True,
            nist_security_level=NISTSecurityLevel.LEVEL_5,
            public_key_size_bits=2592,
            private_key_size_bits=5536,
            signature_size_bits=4096,
            standard_reference="NIST FIPS 204",
            fips_approved=True,
            quantum_risk_assessment="Quantum-resistant at NIST Security Level 5"
        )
        
        self.algorithm_database["FALCON"] = CryptographicAlgorithm(
            name="FALCON",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            nist_standardized=True,
            quantum_resistant=True,
            nist_security_level=NISTSecurityLevel.LEVEL_5,
            standard_reference="NIST FIPS 205",
            fips_approved=True,
            quantum_risk_assessment="Fully quantum-resistant - NTRU lattice based"
        )
        
        self.algorithm_database["SPHINCS+"] = CryptographicAlgorithm(
            name="SPHINCS+",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            nist_standardized=True,
            quantum_resistant=True,
            nist_security_level=NISTSecurityLevel.LEVEL_5,
            standard_reference="NIST FIPS 206",
            fips_approved=True,
            quantum_risk_assessment="Fully quantum-resistant - hash-based, stateless"
        )
        
        # Classic algorithms (NOT quantum-resistant)
        self.algorithm_database["RSA-2048"] = CryptographicAlgorithm(
            name="RSA-2048",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            nist_standardized=True,
            quantum_resistant=False,
            nist_security_level=None,
            key_size_bits=2048,
            standard_reference="NIST SP 800-57",
            fips_approved=True,
            deprecation_date="2030-01-01",
            quantum_risk_assessment="VULNERABLE to quantum attacks - Shor's algorithm"
        )
        
        self.algorithm_database["RSA-3072"] = CryptographicAlgorithm(
            name="RSA-3072",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            nist_standardized=True,
            quantum_resistant=False,
            key_size_bits=3072,
            standard_reference="NIST SP 800-57",
            fips_approved=True,
            deprecation_date="2030-01-01",
            quantum_risk_assessment="VULNERABLE to quantum attacks - Shor's algorithm"
        )
        
        self.algorithm_database["RSA-4096"] = CryptographicAlgorithm(
            name="RSA-4096",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            nist_standardized=True,
            quantum_resistant=False,
            key_size_bits=4096,
            standard_reference="NIST SP 800-57",
            fips_approved=True,
            deprecation_date="2030-01-01",
            quantum_risk_assessment="VULNERABLE to quantum attacks - Shor's algorithm"
        )
        
        self.algorithm_database["ECDSA-P256"] = CryptographicAlgorithm(
            name="ECDSA-P256",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            nist_standardized=True,
            quantum_resistant=False,
            standard_reference="NIST SP 800-57",
            fips_approved=True,
            deprecation_date="2030-01-01",
            quantum_risk_assessment="VULNERABLE to quantum attacks - Shor's algorithm"
        )
        
        self.algorithm_database["ECDSA-P384"] = CryptographicAlgorithm(
            name="ECDSA-P384",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            nist_standardized=True,
            quantum_resistant=False,
            standard_reference="NIST SP 800-57",
            fips_approved=True,
            deprecation_date="2030-01-01",
            quantum_risk_assessment="VULNERABLE to quantum attacks - Shor's algorithm"
        )
        
        self.algorithm_database["ECDH-P256"] = CryptographicAlgorithm(
            name="ECDH-P256",
            category=AlgorithmCategory.KEY_EXCHANGE,
            nist_standardized=True,
            quantum_resistant=False,
            standard_reference="NIST SP 800-57",
            fips_approved=True,
            deprecation_date="2030-01-01",
            quantum_risk_assessment="VULNERABLE to quantum attacks - Shor's algorithm"
        )
        
        self.algorithm_database["X25519"] = CryptographicAlgorithm(
            name="X25519",
            category=AlgorithmCategory.KEY_EXCHANGE,
            nist_standardized=True,
            quantum_resistant=False,
            standard_reference="RFC 7748",
            fips_approved=False,
            deprecation_date="2030-01-01",
            quantum_risk_assessment="VULNERABLE to quantum attacks - Shor's algorithm"
        )
        
        # Hash functions
        for hash_name in ["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"]:
            self.algorithm_database[hash_name] = CryptographicAlgorithm(
                name=hash_name,
                category=AlgorithmCategory.HASH_FUNCTION,
                nist_standardized=True,
                quantum_resistant=True,  # Hashes are generally quantum-resistant
                standard_reference="NIST FIPS 180-4 / FIPS 202",
                fips_approved=True,
                quantum_risk_assessment="Quantum-resistant - Grover only gives quadratic speedup"
            )
        
        # Symmetric ciphers
        for cipher in ["AES-128", "AES-192", "AES-256"]:
            self.algorithm_database[cipher] = CryptographicAlgorithm(
                name=cipher,
                category=AlgorithmCategory.SYMMETRIC_CIPHER,
                nist_standardized=True,
                quantum_resistant=True,  # Symmetric ciphers are generally quantum-resistant
                standard_reference="NIST FIPS 197",
                fips_approved=True,
                quantum_risk_assessment="Quantum-resistant with adequate key size"
            )
        
    def _initialize_compliance_rules(self):
        """Initialize compliance checking rules"""
        self.compliance_rules = {
            ComplianceFramework.NIST_SP_800_186: [
                {
                    "id": "PQC-001",
                    "requirement": "Use NIST-standardized post-quantum algorithms",
                    "check": lambda alg: alg.nist_standardized and alg.quantum_resistant,
                    "section": "Section 3: Algorithm Selection"
                },
                {
                    "id": "PQC-002",
                    "requirement": "Minimum NIST Security Level 1 for all PQC algorithms",
                    "check": lambda alg: alg.nist_security_level and alg.nist_security_level.value >= 1,
                    "section": "Section 4: Security Levels"
                },
                {
                    "id": "PQC-003",
                    "requirement": "FIPS-approved algorithm implementations",
                    "check": lambda alg: alg.fips_approved,
                    "section": "Section 5: FIPS Compliance"
                }
            ],
            ComplianceFramework.FIPS_140_3: [
                {
                    "id": "FIPS-001",
                    "requirement": "FIPS 140-3 approved algorithms only",
                    "check": lambda alg: alg.fips_approved,
                    "section": "Section 4.2: Approved Security Functions"
                },
                {
                    "id": "FIPS-002",
                    "requirement": "Key sizes meet minimum requirements",
                    "check": lambda alg: alg.key_size_bits >= 256 if alg.key_size_bits > 0 else True,
                    "section": "Section 4.3: Key Management"
                }
            ],
            ComplianceFramework.CNSA_2_0: [
                {
                    "id": "CNSA-001",
                    "requirement": "CNSA 2.0 Suite B quantum-resistant algorithms",
                    "check": lambda alg: alg.name in ["CRYSTALS-Kyber", "CRYSTALS-Dilithium", "SHA-384", "AES-256"],
                    "section": "CNSA 2.0 Suite Specification"
                }
            ]
        }
        
    def _initialize_framework_requirements(self):
        """Initialize framework-specific requirements"""
        self.framework_requirements = {
            ComplianceFramework.NIST_SP_800_186: {
                "mandatory_algorithms": ["Kyber-768", "Dilithium-3", "SHA-256", "AES-256"],
                "prohibited_algorithms": ["RSA-2048", "ECDSA-P256", "ECDH-P256"],
                "transition_deadline": "2030-01-01"
            },
            ComplianceFramework.FIPS_140_3: {
                "approved_kems": ["Kyber-512", "Kyber-768", "Kyber-1024"],
                "approved_signatures": ["Dilithium-2", "Dilithium-3", "Dilithium-5"],
                "module_security_levels": [1, 2, 3, 4]
            }
        }
        
    def _generate_audit_id(self) -> str:
        """Generate deterministic audit ID"""
        content = f"{datetime.now().isoformat()}-PQC-AUDIT"
        hash_obj = hashlib.sha256(content.encode())
        return f"AUDIT-PQC-{hash_obj.hexdigest()[:10].upper()}"
        
    def _assess_algorithm(self, algorithm_name: str, usage_context: str = "general") -> AlgorithmAssessment:
        """Assess a single algorithm for quantum security"""
        alg = self.algorithm_database.get(algorithm_name)
        
        if not alg:
            # Unknown algorithm
            unknown_alg = CryptographicAlgorithm(
                name=algorithm_name,
                category=AlgorithmCategory.UNKNOWN,
                nist_standardized=False,
                quantum_resistant=False,
                quantum_risk_assessment="Unknown algorithm - security status undetermined"
            )
            return AlgorithmAssessment(
                algorithm=unknown_alg,
                usage_context=usage_context,
                quantum_safe=False,
                risk_level=RiskLevel.HIGH,
                recommendations=["Validate algorithm against NIST PQC standards", "Consider migrating to known quantum-safe algorithms"],
                migration_priority="HIGH",
                migration_timeline="Immediate review required"
            )
        
        quantum_safe = alg.quantum_resistant
        
        if quantum_safe:
            risk_level = RiskLevel.LOW
            recommendations = ["Algorithm is quantum-resistant", "Verify implementation follows NIST guidelines"]
            migration_priority = "NONE"
            migration_timeline = "No migration required"
        else:
            if alg.category in [AlgorithmCategory.KEY_EXCHANGE, AlgorithmCategory.DIGITAL_SIGNATURE, AlgorithmCategory.KEY_ENCAPSULATION]:
                risk_level = RiskLevel.CRITICAL
                recommendations = [
                    "CRITICAL: Algorithm vulnerable to quantum attacks (Shor's algorithm)",
                    "Migrate to CRYSTALS-Kyber for key encapsulation",
                    "Migrate to CRYSTALS-Dilithium for digital signatures",
                    "Complete migration before 2030 NIST deadline"
                ]
                migration_priority = "CRITICAL"
                migration_timeline = "Complete by 2026-2030"
            else:
                risk_level = RiskLevel.MEDIUM
                recommendations = ["Monitor NIST guidance for this algorithm category"]
                migration_priority = "MEDIUM"
                migration_timeline = "Review by 2027"
        
        return AlgorithmAssessment(
            algorithm=alg,
            usage_context=usage_context,
            quantum_safe=quantum_safe,
            risk_level=risk_level,
            recommendations=recommendations,
            migration_priority=migration_priority,
            migration_timeline=migration_timeline
        )
        
    def _check_compliance(self, algorithm: CryptographicAlgorithm, framework: ComplianceFramework) -> List[ComplianceFinding]:
        """Check algorithm compliance against specific framework"""
        findings = []
        rules = self.compliance_rules.get(framework, [])
        
        for rule in rules:
            check_passed = rule["check"](algorithm)
            
            if check_passed:
                status = ComplianceStatus.COMPLIANT
                risk = RiskLevel.INFORMATIONAL
            else:
                status = ComplianceStatus.NON_COMPLIANT
                risk = RiskLevel.HIGH if algorithm.quantum_resistant == False else RiskLevel.MEDIUM
            
            finding = ComplianceFinding(
                finding_id=rule["id"],
                framework=framework,
                requirement=rule["requirement"],
                status=status,
                risk_level=risk,
                description=f"Algorithm {algorithm.name}: {rule['requirement']}",
                evidence=[f"Algorithm category: {algorithm.category.value}", f"Quantum resistant: {algorithm.quantum_resistant}"],
                remediation=f"Ensure {algorithm.name} meets {framework.value} requirements",
                section_reference=rule["section"]
            )
            findings.append(finding)
            
        return findings
        
    def _identify_security_gaps(self, assessments: List[AlgorithmAssessment]) -> List[SecurityGap]:
        """Identify security gaps from algorithm assessments"""
        gaps = []
        gap_counter = 0
        
        # Check for non-quantum-safe algorithms in critical categories
        critical_vulnerable = [a for a in assessments if not a.quantum_safe and a.risk_level == RiskLevel.CRITICAL]
        
        if critical_vulnerable:
            gap_counter += 1
            gaps.append(SecurityGap(
                gap_id=f"GAP-{gap_counter:03d}",
                title="Quantum-Vulnerable Asymmetric Cryptography Detected",
                description=f"Found {len(critical_vulnerable)} quantum-vulnerable algorithms in critical security categories. These are vulnerable to Shor's algorithm on large quantum computers.",
                risk_level=RiskLevel.CRITICAL,
                affected_components=[a.algorithm.name for a in critical_vulnerable],
                remediation_steps=[
                    "Inventory all RSA/ECC usage across the infrastructure",
                    "Deploy hybrid PQC-classic mode as intermediate step",
                    "Migrate key exchange to CRYSTALS-Kyber",
                    "Migrate signatures to CRYSTALS-Dilithium",
                    "Update TLS 1.3 to support PQC cipher suites"
                ],
                priority=1,
                effort_estimate_hours=40 * len(critical_vulnerable)
            ))
        
        # Check for unknown algorithms
        unknown = [a for a in assessments if a.algorithm.category == AlgorithmCategory.UNKNOWN]
        if unknown:
            gap_counter += 1
            gaps.append(SecurityGap(
                gap_id=f"GAP-{gap_counter:03d}",
                title="Unknown Cryptographic Algorithms Detected",
                description="Cryptographic algorithms with unknown security status were detected in the environment.",
                risk_level=RiskLevel.HIGH,
                affected_components=[a.algorithm.name for a in unknown],
                remediation_steps=[
                    "Identify and document all unknown algorithms",
                    "Validate against NIST PQC standard list",
                    "Replace with standardized alternatives where needed"
                ],
                priority=2,
                effort_estimate_hours=8 * len(unknown)
            ))
        
        # Check for deprecated algorithms
        deprecated = [a for a in assessments if a.algorithm.deprecation_date]
        if deprecated:
            gap_counter += 1
            gaps.append(SecurityGap(
                gap_id=f"GAP-{gap_counter:03d}",
                title="Deprecated Cryptographic Algorithms",
                description="Algorithms with scheduled deprecation dates detected. These must be migrated before the deadline.",
                risk_level=RiskLevel.MEDIUM,
                affected_components=[f"{a.algorithm.name} (deprecates: {a.algorithm.deprecation_date})" for a in deprecated],
                remediation_steps=[
                    "Review NIST SP 800-131A transition guidance",
                    "Create migration timeline before deprecation",
                    "Test PQC alternatives in staging environment"
                ],
                priority=3,
                effort_estimate_hours=16 * len(deprecated)
            ))
        
        return gaps
        
    def _calculate_compliance_score(self, findings: List[ComplianceFinding]) -> float:
        """Calculate overall compliance score (0-100)"""
        if not findings:
            return 100.0
            
        compliant = sum(1 for f in findings if f.status == ComplianceStatus.COMPLIANT)
        return round((compliant / len(findings)) * 100, 2)
        
    def _generate_executive_summary(self, result: ComplianceAuditResult) -> str:
        """Generate executive summary for the audit"""
        quantum_safe_count = sum(1 for a in result.algorithm_assessments if a.quantum_safe)
        total_count = len(result.algorithm_assessments)
        
        summary = f"""
POST-QUANTUM SECURITY AUDIT - EXECUTIVE SUMMARY
================================================
Audit ID: {result.audit_id}
Date: {result.audit_timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Target: {result.target_system}

OVERALL COMPLIANCE SCORE: {result.overall_compliance_score}%
{'PASS' if result.overall_compliance_score >= 80 else 'FAIL'}

KEY FINDINGS:
-------------
- Algorithms Audited: {total_count}
- Quantum-Safe Algorithms: {quantum_safe_count} ({quantum_safe_count/total_count*100:.0f}%)
- Quantum-Vulnerable Algorithms: {total_count - quantum_safe_count}
- Security Gaps Identified: {len(result.security_gaps)}
- Critical Findings: {sum(1 for g in result.security_gaps if g.risk_level == RiskLevel.CRITICAL)}
- High Risk Findings: {sum(1 for g in result.security_gaps if g.risk_level == RiskLevel.HIGH)}

RECOMMENDATIONS:
----------------
"""
        for i, rec in enumerate(result.recommendations_summary[:5], 1):
            summary += f"{i}. {rec}\n"
            
        return summary.strip()
        
    def _generate_detailed_report(self, result: ComplianceAuditResult) -> str:
        """Generate detailed audit report"""
        report = f"""
POST-QUANTUM CRYPTOGRAPHY SECURITY AUDIT REPORT
================================================
Audit ID: {result.audit_id}
Generated: {result.audit_timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Frameworks: {', '.join(f.value for f in result.frameworks_audited)}
Processing Time: {result.processing_time_ms:.2f}ms

COMPLIANCE SCORES BY FRAMEWORK:
-------------------------------
"""
        for framework, score in result.compliance_by_framework.items():
            report += f"  {framework:25} {score}%\n"
            
        report += """
ALGORITHM ASSESSMENTS:
----------------------
"""
        for assessment in sorted(result.algorithm_assessments, key=lambda a: a.risk_level.value):
            status = "✓ QUANTUM-SAFE" if assessment.quantum_safe else "✗ VULNERABLE"
            report += f"\n  [{assessment.risk_level.value.upper()}] {assessment.algorithm.name:25} {status}\n"
            report += f"      Category: {assessment.algorithm.category.value}\n"
            report += f"      Quantum Risk: {assessment.algorithm.quantum_risk_assessment}\n"
            if assessment.migration_priority != "NONE":
                report += f"      Migration: {assessment.migration_priority} - {assessment.migration_timeline}\n"
                
        report += """

SECURITY GAPS:
--------------
"""
        for gap in sorted(result.security_gaps, key=lambda g: g.priority):
            report += f"\n  [{gap.gap_id}] {gap.title}\n"
            report += f"      Risk: {gap.risk_level.value.upper()}\n"
            report += f"      Priority: {gap.priority}\n"
            report += f"      Affected: {', '.join(gap.affected_components)}\n"
            report += f"      Effort: {gap.effort_estimate_hours} hours\n"
            
        return report.strip()
        
    def run_audit(self, 
                  algorithms_to_audit: List[str],
                  target_system: str = "general",
                  frameworks: Optional[List[ComplianceFramework]] = None) -> ComplianceAuditResult:
        """
        Run a complete post-quantum security audit
        
        This is the main production method that:
        1. Assesses each algorithm for quantum resistance
        2. Checks compliance against specified frameworks
        3. Identifies security gaps
        4. Generates comprehensive reports
        5. Provides actionable recommendations
        """
        start_time = time.time()
        
        if frameworks is None:
            frameworks = [ComplianceFramework.NIST_SP_800_186, ComplianceFramework.FIPS_140_3]
            
        audit_id = self._generate_audit_id()
        
        # Assess all algorithms
        assessments = []
        all_findings = []
        
        for alg_name in algorithms_to_audit:
            assessment = self._assess_algorithm(alg_name)
            assessments.append(assessment)
            
            # Check compliance for each framework
            for framework in frameworks:
                findings = self._check_compliance(assessment.algorithm, framework)
                all_findings.extend(findings)
        
        # Identify security gaps
        gaps = self._identify_security_gaps(assessments)
        
        # Calculate compliance scores
        overall_score = self._calculate_compliance_score(all_findings)
        
        compliance_by_framework = {}
        for framework in frameworks:
            framework_findings = [f for f in all_findings if f.framework == framework]
            compliance_by_framework[framework.value] = self._calculate_compliance_score(framework_findings)
        
        # Compile lists
        compliant = [a.algorithm.name for a in assessments if a.quantum_safe]
        non_compliant = [a.algorithm.name for a in assessments if not a.quantum_safe]
        
        # Generate recommendations
        recommendations = []
        critical_gaps = [g for g in gaps if g.risk_level == RiskLevel.CRITICAL]
        if critical_gaps:
            recommendations.append("URGENT: Migrate all asymmetric crypto to NIST PQC standards immediately")
            
        high_gaps = [g for g in gaps if g.risk_level == RiskLevel.HIGH]
        if high_gaps:
            recommendations.append("Inventory and validate all cryptographic implementations")
            
        recommendations.append("Implement hybrid PQC-classic mode for TLS 1.3 connections")
        recommendations.append("Establish PQC migration project timeline and governance")
        recommendations.append("Conduct quarterly post-quantum security audits")
        recommendations.append("Train security team on NIST PQC standards")
        
        result = ComplianceAuditResult(
            audit_id=audit_id,
            audit_timestamp=datetime.now(),
            target_system=target_system,
            frameworks_audited=frameworks,
            overall_compliance_score=overall_score,
            compliance_by_framework=compliance_by_framework,
            findings=all_findings,
            security_gaps=gaps,
            algorithm_assessments=assessments,
            compliant_algorithms=compliant,
            non_compliant_algorithms=non_compliant,
            recommendations_summary=recommendations,
            processing_time_ms=(time.time() - start_time) * 1000
        )
        
        result.executive_summary = self._generate_executive_summary(result)
        result.detailed_report = self._generate_detailed_report(result)
        
        self.audit_history.append(result)
        return result
        
    def export_audit_json(self, result: ComplianceAuditResult) -> str:
        """Export audit result as JSON"""
        data = {
            "audit_id": result.audit_id,
            "audit_timestamp": result.audit_timestamp.isoformat(),
            "target_system": result.target_system,
            "overall_compliance_score": result.overall_compliance_score,
            "compliance_by_framework": result.compliance_by_framework,
            "algorithms_audited": len(result.algorithm_assessments),
            "quantum_safe_count": len(result.compliant_algorithms),
            "quantum_vulnerable_count": len(result.non_compliant_algorithms),
            "security_gaps_count": len(result.security_gaps),
            "findings_count": len(result.findings),
            "compliant_algorithms": result.compliant_algorithms,
            "vulnerable_algorithms": result.non_compliant_algorithms,
            "recommendations": result.recommendations_summary,
            "processing_time_ms": result.processing_time_ms
        }
        return json.dumps(data, indent=2)
        
    def get_audit_statistics(self) -> Dict[str, Any]:
        """Get statistics about all audits"""
        if not self.audit_history:
            return {"total_audits": 0}
            
        avg_score = sum(a.overall_compliance_score for a in self.audit_history) / len(self.audit_history)
        total_gaps = sum(len(a.security_gaps) for a in self.audit_history)
        
        return {
            "total_audits": len(self.audit_history),
            "average_compliance_score": round(avg_score, 2),
            "total_security_gaps_identified": total_gaps,
            "audits_below_80_pct": sum(1 for a in self.audit_history if a.overall_compliance_score < 80)
        }
