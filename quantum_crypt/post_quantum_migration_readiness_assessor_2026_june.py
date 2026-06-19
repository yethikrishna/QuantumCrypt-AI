"""
Post-Quantum Cryptography Migration Readiness Assessor
Production-grade PQC migration assessment and planning

Features:
- Crypto algorithm inventory scanning
- Quantum vulnerability assessment
- Migration priority scoring
- Risk classification
- Migration roadmap generation
- Compliance gap analysis
"""

import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import json
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CryptoAlgorithmCategory(Enum):
    KEY_EXCHANGE = "key_exchange"
    SIGNATURE = "signature"
    HASH = "hash"
    SYMMETRIC_ENCRYPTION = "symmetric_encryption"
    MAC = "message_authentication_code"
    RANDOM_GENERATOR = "random_generator"


class QuantumRiskLevel(Enum):
    CRITICAL = "critical"      # Broken by Shor's algorithm - immediate migration needed
    HIGH = "high"              # Theoretical quantum vulnerability
    MEDIUM = "medium"          # Partial vulnerability / large quantum computer needed
    LOW = "low"                # Quantum-resistant or post-quantum secure
    UNKNOWN = "unknown"        # Risk not yet assessed


class MigrationPriority(Enum):
    IMMEDIATE = "immediate"    # Migrate within 0-3 months
    HIGH = "high"              # Migrate within 3-6 months
    MEDIUM = "medium"          # Migrate within 6-12 months
    LOW = "low"                # Migrate within 12-24 months
    NONE = "none"              # No migration needed


@dataclass
class CryptoAlgorithmInfo:
    name: str
    category: CryptoAlgorithmCategory
    quantum_risk: QuantumRiskLevel
    migration_priority: MigrationPriority
    nist_standardized: bool = False
    recommended_replacement: Optional[str] = None
    key_size_bits: Optional[int] = None
    security_strength_bits: int = 0
    deprecation_date: Optional[str] = None
    notes: str = ""


@dataclass
class CryptoUsageFinding:
    algorithm_name: str
    category: CryptoAlgorithmCategory
    location: str
    line_number: Optional[int] = None
    context: str = ""
    quantum_risk: QuantumRiskLevel = QuantumRiskLevel.UNKNOWN
    migration_priority: MigrationPriority = MigrationPriority.MEDIUM


@dataclass
class MigrationReadinessScore:
    overall_score: float  # 0-100, higher = more ready
    critical_risk_count: int = 0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    pqc_adoption_percentage: float = 0.0
    inventory_coverage: float = 0.0


@dataclass
class MigrationRecommendation:
    algorithm: str
    risk_level: QuantumRiskLevel
    priority: MigrationPriority
    recommended_action: str
    replacement_algorithm: Optional[str] = None
    estimated_effort_hours: int = 0
    timeline_months: str = ""
    dependencies: List[str] = field(default_factory=list)


# Known algorithm quantum risk database
ALGORITHM_RISK_DATABASE: Dict[str, CryptoAlgorithmInfo] = {
    # RSA - CRITICAL risk from Shor's algorithm
    "RSA": CryptoAlgorithmInfo(
        name="RSA",
        category=CryptoAlgorithmCategory.KEY_EXCHANGE,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        migration_priority=MigrationPriority.IMMEDIATE,
        nist_standardized=True,
        recommended_replacement="CRYSTALS-Kyber",
        security_strength_bits=112,
        notes="Completely broken by Shor's algorithm for factoring"
    ),
    "RSA-2048": CryptoAlgorithmInfo(
        name="RSA-2048",
        category=CryptoAlgorithmCategory.KEY_EXCHANGE,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommended_replacement="CRYSTALS-Kyber-768",
        key_size_bits=2048,
        security_strength_bits=112
    ),
    "RSA-3072": CryptoAlgorithmInfo(
        name="RSA-3072",
        category=CryptoAlgorithmCategory.KEY_EXCHANGE,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommended_replacement="CRYSTALS-Kyber-1024",
        key_size_bits=3072,
        security_strength_bits=128
    ),
    "RSA-4096": CryptoAlgorithmInfo(
        name="RSA-4096",
        category=CryptoAlgorithmCategory.KEY_EXCHANGE,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        migration_priority=MigrationPriority.HIGH,
        recommended_replacement="CRYSTALS-Kyber-1024",
        key_size_bits=4096,
        security_strength_bits=192
    ),
    
    # ECC / ECDH / ECDSA - CRITICAL risk
    "ECDH": CryptoAlgorithmInfo(
        name="ECDH",
        category=CryptoAlgorithmCategory.KEY_EXCHANGE,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommended_replacement="CRYSTALS-Kyber",
        notes="Broken by Shor's algorithm for discrete logarithm"
    ),
    "ECDSA": CryptoAlgorithmInfo(
        name="ECDSA",
        category=CryptoAlgorithmCategory.SIGNATURE,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommended_replacement="CRYSTALS-Dilithium"
    ),
    "secp256r1": CryptoAlgorithmInfo(
        name="secp256r1 (NIST P-256)",
        category=CryptoAlgorithmCategory.KEY_EXCHANGE,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommended_replacement="CRYSTALS-Kyber-768"
    ),
    "secp384r1": CryptoAlgorithmInfo(
        name="secp384r1 (NIST P-384)",
        category=CryptoAlgorithmCategory.KEY_EXCHANGE,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommended_replacement="CRYSTALS-Kyber-1024"
    ),
    "X25519": CryptoAlgorithmInfo(
        name="X25519 (Curve25519)",
        category=CryptoAlgorithmCategory.KEY_EXCHANGE,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommended_replacement="CRYSTALS-Kyber-768"
    ),
    "Ed25519": CryptoAlgorithmInfo(
        name="Ed25519 (EdDSA)",
        category=CryptoAlgorithmCategory.SIGNATURE,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommended_replacement="CRYSTALS-Dilithium"
    ),
    
    # Diffie-Hellman - CRITICAL risk
    "DH": CryptoAlgorithmInfo(
        name="Diffie-Hellman",
        category=CryptoAlgorithmCategory.KEY_EXCHANGE,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommended_replacement="CRYSTALS-Kyber"
    ),
    "DHE": CryptoAlgorithmInfo(
        name="DHE",
        category=CryptoAlgorithmCategory.KEY_EXCHANGE,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommended_replacement="CRYSTALS-Kyber"
    ),
    
    # NIST PQC Algorithms - LOW risk (quantum-resistant)
    "CRYSTALS-Kyber": CryptoAlgorithmInfo(
        name="CRYSTALS-Kyber",
        category=CryptoAlgorithmCategory.KEY_EXCHANGE,
        quantum_risk=QuantumRiskLevel.LOW,
        migration_priority=MigrationPriority.NONE,
        nist_standardized=True,
        security_strength_bits=128,
        notes="NIST PQC standard for key encapsulation"
    ),
    "CRYSTALS-Dilithium": CryptoAlgorithmInfo(
        name="CRYSTALS-Dilithium",
        category=CryptoAlgorithmCategory.SIGNATURE,
        quantum_risk=QuantumRiskLevel.LOW,
        migration_priority=MigrationPriority.NONE,
        nist_standardized=True,
        security_strength_bits=128,
        notes="NIST PQC standard for digital signatures"
    ),
    "FALCON": CryptoAlgorithmInfo(
        name="FALCON",
        category=CryptoAlgorithmCategory.SIGNATURE,
        quantum_risk=QuantumRiskLevel.LOW,
        migration_priority=MigrationPriority.NONE,
        nist_standardized=True,
        security_strength_bits=128
    ),
    "SPHINCS+": CryptoAlgorithmInfo(
        name="SPHINCS+",
        category=CryptoAlgorithmCategory.SIGNATURE,
        quantum_risk=QuantumRiskLevel.LOW,
        migration_priority=MigrationPriority.NONE,
        nist_standardized=True,
        security_strength_bits=128,
        notes="Hash-based signature, stateless"
    ),
    
    # Symmetric algorithms - generally LOW risk
    "AES": CryptoAlgorithmInfo(
        name="AES",
        category=CryptoAlgorithmCategory.SYMMETRIC_ENCRYPTION,
        quantum_risk=QuantumRiskLevel.LOW,
        migration_priority=MigrationPriority.LOW,
        nist_standardized=True,
        security_strength_bits=128,
        notes="Grover's algorithm halves effective security; double key size recommended"
    ),
    "AES-128": CryptoAlgorithmInfo(
        name="AES-128",
        category=CryptoAlgorithmCategory.SYMMETRIC_ENCRYPTION,
        quantum_risk=QuantumRiskLevel.MEDIUM,
        migration_priority=MigrationPriority.MEDIUM,
        recommended_replacement="AES-256",
        security_strength_bits=64,  # After Grover
        notes="Upgrade to AES-256 for post-quantum security"
    ),
    "AES-256": CryptoAlgorithmInfo(
        name="AES-256",
        category=CryptoAlgorithmCategory.SYMMETRIC_ENCRYPTION,
        quantum_risk=QuantumRiskLevel.LOW,
        migration_priority=MigrationPriority.NONE,
        security_strength_bits=128,  # After Grover
        notes="Post-quantum secure with 256-bit key"
    ),
    
    # Hash functions - generally LOW risk
    "SHA-2": CryptoAlgorithmInfo(
        name="SHA-2",
        category=CryptoAlgorithmCategory.HASH,
        quantum_risk=QuantumRiskLevel.LOW,
        migration_priority=MigrationPriority.LOW,
        security_strength_bits=128
    ),
    "SHA-256": CryptoAlgorithmInfo(
        name="SHA-256",
        category=CryptoAlgorithmCategory.HASH,
        quantum_risk=QuantumRiskLevel.MEDIUM,
        migration_priority=MigrationPriority.MEDIUM,
        recommended_replacement="SHA-512",
        security_strength_bits=128,
        notes="Grover's reduces pre-image resistance"
    ),
    "SHA-512": CryptoAlgorithmInfo(
        name="SHA-512",
        category=CryptoAlgorithmCategory.HASH,
        quantum_risk=QuantumRiskLevel.LOW,
        migration_priority=MigrationPriority.NONE,
        security_strength_bits=256
    ),
    "SHA-3": CryptoAlgorithmInfo(
        name="SHA-3",
        category=CryptoAlgorithmCategory.HASH,
        quantum_risk=QuantumRiskLevel.LOW,
        migration_priority=MigrationPriority.NONE,
        nist_standardized=True,
        security_strength_bits=256
    ),
}


class PQCMigrationReadinessAssessor:
    """
    Production-grade Post-Quantum Cryptography migration readiness assessor.
    
    Scans code and configurations for crypto usage, assesses quantum vulnerability,
    and generates prioritized migration recommendations.
    """

    def __init__(self):
        self.findings: List[CryptoUsageFinding] = []
        self.algorithm_database = ALGORITHM_RISK_DATABASE
        self._patterns = self._build_detection_patterns()

    def _build_detection_patterns(self) -> Dict[str, re.Pattern]:
        """Build regex patterns for algorithm detection."""
        patterns = {}
        
        # Algorithm name patterns
        for algo_name in self.algorithm_database.keys():
            # Create word-boundary pattern for exact matches
            escaped = re.escape(algo_name)
            patterns[algo_name] = re.compile(
                r'\b(' + escaped + r'|' + escaped.replace('-', '_') + r')\b',
                re.IGNORECASE
            )
        
        # Common crypto library patterns
        patterns["crypto_libs"] = re.compile(
            r'(cryptography|pycryptodome|openssl|javax\.crypto|bcrypt|hashlib|hmac)',
            re.IGNORECASE
        )
        
        return patterns

    def scan_code_content(
        self, 
        content: str, 
        file_path: str = "unknown"
    ) -> List[CryptoUsageFinding]:
        """
        Scan source code content for cryptographic algorithm usage.
        
        Args:
            content: Source code text
            file_path: File path for reference
            
        Returns:
            List of crypto usage findings
        """
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith(('#', '//', '/*', '*')):
                continue
                
            # Check for each algorithm
            for algo_name, pattern in self._patterns.items():
                if algo_name == "crypto_libs":
                    continue
                    
                if pattern.search(line):
                    algo_info = self.algorithm_database.get(algo_name)
                    if algo_info:
                        finding = CryptoUsageFinding(
                            algorithm_name=algo_name,
                            category=algo_info.category,
                            location=f"{file_path}:{line_num}",
                            line_number=line_num,
                            context=stripped[:100],
                            quantum_risk=algo_info.quantum_risk,
                            migration_priority=algo_info.migration_priority
                        )
                        findings.append(finding)
                        logger.debug(f"Found {algo_name} at {file_path}:{line_num}")
        
        self.findings.extend(findings)
        return findings

    def scan_file(self, file_path: str) -> List[CryptoUsageFinding]:
        """Scan a single file for crypto usage."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self.scan_code_content(content, file_path)
        except Exception as e:
            logger.warning(f"Failed to scan {file_path}: {e}")
            return []

    def get_algorithm_info(self, algorithm_name: str) -> Optional[CryptoAlgorithmInfo]:
        """Get risk information for a specific algorithm."""
        return self.algorithm_database.get(algorithm_name)

    def calculate_readiness_score(self) -> MigrationReadinessScore:
        """
        Calculate overall PQC migration readiness score.
        
        Returns:
            Readiness score (0-100) with breakdown
        """
        if not self.findings:
            return MigrationReadinessScore(
                overall_score=50.0,
                pqc_adoption_percentage=0.0,
                inventory_coverage=0.0
            )

        risk_counts = defaultdict(int)
        pqc_count = 0
        total_count = len(self.findings)

        for finding in self.findings:
            risk_counts[finding.quantum_risk.value] += 1
            if finding.quantum_risk == QuantumRiskLevel.LOW:
                pqc_count += 1

        # Calculate score components
        critical_penalty = risk_counts[QuantumRiskLevel.CRITICAL.value] * 10
        high_penalty = risk_counts[QuantumRiskLevel.HIGH.value] * 5
        medium_penalty = risk_counts[QuantumRiskLevel.MEDIUM.value] * 2
        
        base_score = 100
        total_penalty = min(critical_penalty + high_penalty + medium_penalty, 80)
        overall_score = max(base_score - total_penalty, 0)
        
        pqc_adoption = (pqc_count / total_count * 100) if total_count > 0 else 0

        return MigrationReadinessScore(
            overall_score=overall_score,
            critical_risk_count=risk_counts[QuantumRiskLevel.CRITICAL.value],
            high_risk_count=risk_counts[QuantumRiskLevel.HIGH.value],
            medium_risk_count=risk_counts[QuantumRiskLevel.MEDIUM.value],
            low_risk_count=risk_counts[QuantumRiskLevel.LOW.value],
            pqc_adoption_percentage=pqc_adoption,
            inventory_coverage=100.0  # We scanned all findings
        )

    def generate_migration_recommendations(self) -> List[MigrationRecommendation]:
        """
        Generate prioritized migration recommendations.
        
        Returns:
            List of recommendations sorted by priority
        """
        # Group findings by algorithm
        algo_findings = defaultdict(list)
        for finding in self.findings:
            algo_findings[finding.algorithm_name].append(finding)

        recommendations = []
        
        for algo_name, findings in algo_findings.items():
            algo_info = self.algorithm_database.get(algo_name)
            
            if not algo_info:
                continue
                
            # Skip if already PQC secure
            if algo_info.quantum_risk == QuantumRiskLevel.LOW:
                continue
                
            # Determine effort estimate
            usage_count = len(findings)
            if algo_info.migration_priority == MigrationPriority.IMMEDIATE:
                effort = usage_count * 8
                timeline = "0-3 months"
            elif algo_info.migration_priority == MigrationPriority.HIGH:
                effort = usage_count * 4
                timeline = "3-6 months"
            elif algo_info.migration_priority == MigrationPriority.MEDIUM:
                effort = usage_count * 2
                timeline = "6-12 months"
            else:
                effort = usage_count
                timeline = "12-24 months"

            action = f"Migrate {usage_count} instance(s) of {algo_name}"
            if algo_info.recommended_replacement:
                action += f" to {algo_info.recommended_replacement}"

            recommendation = MigrationRecommendation(
                algorithm=algo_name,
                risk_level=algo_info.quantum_risk,
                priority=algo_info.migration_priority,
                recommended_action=action,
                replacement_algorithm=algo_info.recommended_replacement,
                estimated_effort_hours=effort,
                timeline_months=timeline
            )
            recommendations.append(recommendation)

        # Sort by priority
        priority_order = {
            MigrationPriority.IMMEDIATE: 0,
            MigrationPriority.HIGH: 1,
            MigrationPriority.MEDIUM: 2,
            MigrationPriority.LOW: 3,
            MigrationPriority.NONE: 4
        }
        recommendations.sort(key=lambda r: priority_order[r.priority])
        
        return recommendations

    def generate_migration_roadmap(self) -> Dict[str, Any]:
        """
        Generate a complete migration roadmap.
        
        Returns:
            Structured roadmap with phases and timelines
        """
        readiness = self.calculate_readiness_score()
        recommendations = self.generate_migration_recommendations()
        
        # Group by timeline
        phases = defaultdict(list)
        total_effort = 0
        
        for rec in recommendations:
            phases[rec.timeline_months].append({
                "algorithm": rec.algorithm,
                "action": rec.recommended_action,
                "replacement": rec.replacement_algorithm,
                "risk": rec.risk_level.value
            })
            total_effort += rec.estimated_effort_hours

        return {
            "assessment_date": datetime.utcnow().isoformat(),
            "readiness_score": readiness.overall_score,
            "risk_summary": {
                "critical": readiness.critical_risk_count,
                "high": readiness.high_risk_count,
                "medium": readiness.medium_risk_count,
                "low": readiness.low_risk_count
            },
            "pqc_adoption": readiness.pqc_adoption_percentage,
            "total_effort_estimate_hours": total_effort,
            "migration_phases": dict(phases),
            "recommendations": [
                {
                    "algorithm": r.algorithm,
                    "priority": r.priority.value,
                    "action": r.recommended_action,
                    "replacement": r.replacement_algorithm,
                    "timeline": r.timeline_months
                }
                for r in recommendations
            ]
        }

    def generate_readiness_report(self) -> str:
        """Generate human-readable migration readiness report."""
        readiness = self.calculate_readiness_score()
        roadmap = self.generate_migration_roadmap()
        
        lines = [
            "=" * 70,
            "POST-QUANTUM CRYPTOGRAPHY MIGRATION READINESS REPORT",
            "=" * 70,
            f"Generated: {roadmap['assessment_date']}",
            "",
            f"OVERALL READINESS SCORE: {readiness.overall_score:.1f} / 100",
            "",
        ]

        # Interpret score
        if readiness.overall_score >= 80:
            readiness_level = "EXCELLENT - Well prepared for PQC migration"
        elif readiness.overall_score >= 60:
            readiness_level = "GOOD - Moderate preparation, some critical items"
        elif readiness.overall_score >= 40:
            readiness_level = "FAIR - Significant work needed"
        else:
            readiness_level = "CRITICAL - Immediate action required"
            
        lines.extend([
            f"Readiness Level: {readiness_level}",
            f"PQC Algorithm Adoption: {readiness.pqc_adoption_percentage:.1f}%",
            "",
            "RISK SUMMARY:",
            f"  CRITICAL (Shor-vulnerable): {readiness.critical_risk_count} instances",
            f"  HIGH: {readiness.high_risk_count} instances",
            f"  MEDIUM: {readiness.medium_risk_count} instances",
            f"  LOW (PQC-secure): {readiness.low_risk_count} instances",
            "",
            f"Total Estimated Migration Effort: {roadmap['total_effort_estimate_hours']} hours",
            "",
            "-" * 70,
            "MIGRATION RECOMMENDATIONS (PRIORITIZED):",
            "-" * 70,
        ])

        for rec in roadmap["recommendations"][:10]:  # Top 10
            lines.append(f"\n[{rec['priority'].upper()}] {rec['algorithm']}")
            lines.append(f"  Action: {rec['action']}")
            if rec['replacement']:
                lines.append(f"  Recommended: {rec['replacement']}")
            lines.append(f"  Timeline: {rec['timeline']}")

        lines.extend([
            "",
            "=" * 70,
            "QUANTUM SECURITY NOTE:",
            "RSA, ECC, DH, and related algorithms are completely vulnerable to",
            "Shor's algorithm. Migrate to NIST PQC standards (CRYSTALS-Kyber,",
            "CRYSTALS-Dilithium, SPHINCS+, FALCON) immediately.",
            "=" * 70
        ])

        return "\n".join(lines)
