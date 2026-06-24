"""
Post-Quantum Readiness Assessment - QuantumCrypt AI
Dimension A: Feature Expansion (V25 - June 2026)

Evaluates cryptographic infrastructure against NIST Post-Quantum Cryptography
standards and provides migration guidance, risk scoring, and roadmap generation.

API Stability: STABLE
Backward Compatible: YES
Dependencies: None (pure Python)
"""

import json
import hashlib
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


class CryptoAlgorithm(str, Enum):
    """Cryptographic algorithms with quantum resistance classification"""
    # Traditional (vulnerable to quantum)
    RSA_2048 = "RSA-2048"
    RSA_3072 = "RSA-3072"
    RSA_4096 = "RSA-4096"
    ECC_SECP256R1 = "ECC-secp256r1"
    ECC_SECP384R1 = "ECC-secp384r1"
    AES_128 = "AES-128"
    AES_256 = "AES-256"
    SHA_256 = "SHA-256"
    SHA_512 = "SHA-512"
    
    # NIST PQC Standardized (CRQC-resistant)
    CRYSTALS_KYBER = "CRYSTALS-Kyber"
    CRYSTALS_DILITHIUM = "CRYSTALS-Dilithium"
    FALCON = "FALCON"
    SPHINCS = "SPHINCS+"
    
    # NIST PQC Round 4 Candidates
    BIKE = "BIKE"
    HQC = "HQC"
    CLASSIC_MCELIECE = "Classic-McEliece"


class QuantumRiskLevel(str, Enum):
    """Quantum vulnerability risk levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    SECURE = "SECURE"


class MigrationPriority(str, Enum):
    """Migration priority levels"""
    IMMEDIATE = "IMMEDIATE"
    SOON = "SOON"
    SCHEDULED = "SCHEDULED"
    MONITOR = "MONITOR"
    NONE = "NONE"


@dataclass
class AlgorithmAssessment:
    """Assessment result for a single cryptographic algorithm"""
    algorithm: str
    quantum_resistant: bool
    risk_level: str
    nist_status: str
    key_strength_bits: int
    equivalent_quantum_strength: int
    recommended_replacement: str
    migration_priority: str
    implementation_complexity: str
    estimated_effort_hours: int


@dataclass
class ReadinessSummary:
    """Executive summary of post-quantum readiness"""
    assessment_date: str
    overall_readiness_score: float
    quantum_risk_rating: str
    algorithms_assessed: int
    quantum_resistant_count: int
    vulnerable_count: int
    critical_migrations_needed: int
    estimated_migration_effort_hours: int
    migration_readiness_grade: str


class PostQuantumReadinessAssessor:
    """
    Post-Quantum Cryptography Readiness Assessment Engine.
    
    Features:
    - NIST PQC standards alignment verification
    - Algorithm quantum vulnerability scoring
    - Migration roadmap generation
    - Risk assessment by use case
    - Effort estimation for migration
    - Executive-ready reporting
    
    Usage:
        assessor = PostQuantumReadinessAssessor()
        assessor.add_algorithm("RSA-2048", "TLS", "production")
        report = assessor.generate_readiness_report()
    """
    
    # Algorithm vulnerability database
    ALGORITHM_RISK = {
        # Traditional algorithms (quantum vulnerable)
        "RSA-2048": {
            "quantum_resistant": False,
            "risk_level": QuantumRiskLevel.CRITICAL,
            "nist_status": "Vulnerable to CRQC",
            "key_strength": 112,
            "quantum_strength": 0,
            "replacement": "CRYSTALS-Kyber-768",
            "priority": MigrationPriority.IMMEDIATE,
            "complexity": "MEDIUM",
            "effort_hours": 40
        },
        "RSA-3072": {
            "quantum_resistant": False,
            "risk_level": QuantumRiskLevel.HIGH,
            "nist_status": "Vulnerable to CRQC",
            "key_strength": 128,
            "quantum_strength": 0,
            "replacement": "CRYSTALS-Kyber-768",
            "priority": MigrationPriority.SOON,
            "complexity": "MEDIUM",
            "effort_hours": 40
        },
        "RSA-4096": {
            "quantum_resistant": False,
            "risk_level": QuantumRiskLevel.MODERATE,
            "nist_status": "Vulnerable to CRQC",
            "key_strength": 156,
            "quantum_strength": 0,
            "replacement": "CRYSTALS-Kyber-1024",
            "priority": MigrationPriority.SCHEDULED,
            "complexity": "MEDIUM",
            "effort_hours": 40
        },
        "ECC-secp256r1": {
            "quantum_resistant": False,
            "risk_level": QuantumRiskLevel.CRITICAL,
            "nist_status": "Vulnerable to CRQC",
            "key_strength": 128,
            "quantum_strength": 0,
            "replacement": "CRYSTALS-Dilithium-2",
            "priority": MigrationPriority.IMMEDIATE,
            "complexity": "HIGH",
            "effort_hours": 80
        },
        "ECC-secp384r1": {
            "quantum_resistant": False,
            "risk_level": QuantumRiskLevel.HIGH,
            "nist_status": "Vulnerable to CRQC",
            "key_strength": 192,
            "quantum_strength": 0,
            "replacement": "CRYSTALS-Dilithium-3",
            "priority": MigrationPriority.SOON,
            "complexity": "HIGH",
            "effort_hours": 80
        },
        "AES-128": {
            "quantum_resistant": True,
            "risk_level": QuantumRiskLevel.LOW,
            "nist_status": "Grover-resistant with proper key size",
            "key_strength": 128,
            "quantum_strength": 64,
            "replacement": "AES-256",
            "priority": MigrationPriority.MONITOR,
            "complexity": "LOW",
            "effort_hours": 8
        },
        "AES-256": {
            "quantum_resistant": True,
            "risk_level": QuantumRiskLevel.SECURE,
            "nist_status": "Grover-resistant",
            "key_strength": 256,
            "quantum_strength": 128,
            "replacement": "None (secure)",
            "priority": MigrationPriority.NONE,
            "complexity": "NONE",
            "effort_hours": 0
        },
        "SHA-256": {
            "quantum_resistant": True,
            "risk_level": QuantumRiskLevel.LOW,
            "nist_status": "Grover-resistant",
            "key_strength": 256,
            "quantum_strength": 128,
            "replacement": "SHA-512 for long-term",
            "priority": MigrationPriority.MONITOR,
            "complexity": "LOW",
            "effort_hours": 4
        },
        "SHA-512": {
            "quantum_resistant": True,
            "risk_level": QuantumRiskLevel.SECURE,
            "nist_status": "Grover-resistant",
            "key_strength": 512,
            "quantum_strength": 256,
            "replacement": "None (secure)",
            "priority": MigrationPriority.NONE,
            "complexity": "NONE",
            "effort_hours": 0
        },
        # NIST PQC Standardized
        "CRYSTALS-Kyber": {
            "quantum_resistant": True,
            "risk_level": QuantumRiskLevel.SECURE,
            "nist_status": "NIST PQC Standard (KEM)",
            "key_strength": 256,
            "quantum_strength": 256,
            "replacement": "None (PQC standard)",
            "priority": MigrationPriority.NONE,
            "complexity": "NONE",
            "effort_hours": 0
        },
        "CRYSTALS-Dilithium": {
            "quantum_resistant": True,
            "risk_level": QuantumRiskLevel.SECURE,
            "nist_status": "NIST PQC Standard (Signature)",
            "key_strength": 256,
            "quantum_strength": 256,
            "replacement": "None (PQC standard)",
            "priority": MigrationPriority.NONE,
            "complexity": "NONE",
            "effort_hours": 0
        },
        "FALCON": {
            "quantum_resistant": True,
            "risk_level": QuantumRiskLevel.SECURE,
            "nist_status": "NIST PQC Standard (Signature)",
            "key_strength": 256,
            "quantum_strength": 256,
            "replacement": "None (PQC standard)",
            "priority": MigrationPriority.NONE,
            "complexity": "NONE",
            "effort_hours": 0
        },
        "SPHINCS+": {
            "quantum_resistant": True,
            "risk_level": QuantumRiskLevel.SECURE,
            "nist_status": "NIST PQC Standard (Signature)",
            "key_strength": 256,
            "quantum_strength": 256,
            "replacement": "None (PQC standard)",
            "priority": MigrationPriority.NONE,
            "complexity": "NONE",
            "effort_hours": 0
        },
    }
    
    def __init__(self, organization_name: str = "QuantumCrypt AI"):
        self.organization_name = organization_name
        self.deployed_algorithms: List[Dict[str, Any]] = []
        self.version = "25.0.0"
        self.assessment_id = hashlib.sha256(
            f"{time.time()}{organization_name}".encode()
        ).hexdigest()[:12]
    
    def add_algorithm(
        self,
        algorithm_name: str,
        use_case: str,
        environment: str = "production",
        deployment_count: int = 1,
        business_criticality: str = "medium"
    ) -> bool:
        """
        Add a deployed cryptographic algorithm for assessment.
        
        Args:
            algorithm_name: Name of the algorithm (e.g., "RSA-2048")
            use_case: Usage context (e.g., "TLS", "code-signing", "database")
            environment: deployment environment
            deployment_count: Number of deployments
            business_criticality: low/medium/high/critical
            
        Returns:
            True if algorithm is recognized, False otherwise
        """
        if algorithm_name not in self.ALGORITHM_RISK:
            return False
        
        self.deployed_algorithms.append({
            "algorithm": algorithm_name,
            "use_case": use_case,
            "environment": environment,
            "deployment_count": deployment_count,
            "business_criticality": business_criticality,
            "added_at": datetime.utcnow().isoformat()
        })
        return True
    
    def assess_algorithm(self, algorithm_name: str) -> Optional[AlgorithmAssessment]:
        """
        Get detailed assessment for a specific algorithm.
        
        Args:
            algorithm_name: Name of algorithm to assess
            
        Returns:
            AlgorithmAssessment or None if unknown
        """
        if algorithm_name not in self.ALGORITHM_RISK:
            return None
        
        data = self.ALGORITHM_RISK[algorithm_name]
        return AlgorithmAssessment(
            algorithm=algorithm_name,
            quantum_resistant=data["quantum_resistant"],
            risk_level=data["risk_level"].value,
            nist_status=data["nist_status"],
            key_strength_bits=data["key_strength"],
            equivalent_quantum_strength=data["quantum_strength"],
            recommended_replacement=data["replacement"],
            migration_priority=data["priority"].value,
            implementation_complexity=data["complexity"],
            estimated_effort_hours=data["effort_hours"]
        )
    
    def generate_readiness_summary(self) -> ReadinessSummary:
        """
        Generate executive-level post-quantum readiness summary.
        
        Returns:
            ReadinessSummary with overall metrics
        """
        if not self.deployed_algorithms:
            return ReadinessSummary(
                assessment_date=datetime.utcnow().strftime("%Y-%m-%d"),
                overall_readiness_score=0.0,
                quantum_risk_rating="UNKNOWN",
                algorithms_assessed=0,
                quantum_resistant_count=0,
                vulnerable_count=0,
                critical_migrations_needed=0,
                estimated_migration_effort_hours=0,
                migration_readiness_grade="F"
            )
        
        # Count metrics
        quantum_resistant = 0
        vulnerable = 0
        critical_migrations = 0
        total_effort = 0
        total_score = 0
        
        for deployed in self.deployed_algorithms:
            algo = deployed["algorithm"]
            assessment = self.ALGORITHM_RISK[algo]
            
            if assessment["quantum_resistant"]:
                quantum_resistant += 1
                total_score += 100
            else:
                vulnerable += 1
                # Score based on risk level
                risk_scores = {
                    QuantumRiskLevel.CRITICAL: 10,
                    QuantumRiskLevel.HIGH: 30,
                    QuantumRiskLevel.MODERATE: 50,
                    QuantumRiskLevel.LOW: 70,
                }
                total_score += risk_scores.get(assessment["risk_level"], 25)
                
                if assessment["priority"] in [MigrationPriority.IMMEDIATE, MigrationPriority.SOON]:
                    critical_migrations += 1
            
            total_effort += assessment["effort_hours"] * deployed["deployment_count"]
        
        avg_score = total_score / len(self.deployed_algorithms)
        
        # Determine grade
        if avg_score >= 90:
            grade = "A"
        elif avg_score >= 75:
            grade = "B"
        elif avg_score >= 60:
            grade = "C"
        elif avg_score >= 40:
            grade = "D"
        else:
            grade = "F"
        
        # Overall risk rating
        if vulnerable == 0:
            risk_rating = "SECURE"
        elif critical_migrations > len(self.deployed_algorithms) * 0.5:
            risk_rating = "CRITICAL"
        elif vulnerable > len(self.deployed_algorithms) * 0.3:
            risk_rating = "HIGH"
        else:
            risk_rating = "MODERATE"
        
        return ReadinessSummary(
            assessment_date=datetime.utcnow().strftime("%Y-%m-%d"),
            overall_readiness_score=round(avg_score, 1),
            quantum_risk_rating=risk_rating,
            algorithms_assessed=len(self.deployed_algorithms),
            quantum_resistant_count=quantum_resistant,
            vulnerable_count=vulnerable,
            critical_migrations_needed=critical_migrations,
            estimated_migration_effort_hours=total_effort,
            migration_readiness_grade=grade
        )
    
    def generate_migration_roadmap(self) -> Dict[str, Any]:
        """
        Generate prioritized migration roadmap.
        
        Returns:
            Roadmap with phases and recommendations
        """
        immediate_migrations = []
        soon_migrations = []
        scheduled_migrations = []
        monitor_items = []
        
        for deployed in self.deployed_algorithms:
            algo = deployed["algorithm"]
            assessment = self.ALGORITHM_RISK[algo]
            priority = assessment["priority"]
            
            migration_item = {
                "algorithm": algo,
                "use_case": deployed["use_case"],
                "environment": deployed["environment"],
                "current_risk": assessment["risk_level"].value,
                "replacement": assessment["replacement"],
                "effort_hours": assessment["effort_hours"] * deployed["deployment_count"],
                "complexity": assessment["complexity"],
                "business_criticality": deployed["business_criticality"]
            }
            
            if priority == MigrationPriority.IMMEDIATE:
                immediate_migrations.append(migration_item)
            elif priority == MigrationPriority.SOON:
                soon_migrations.append(migration_item)
            elif priority == MigrationPriority.SCHEDULED:
                scheduled_migrations.append(migration_item)
            elif priority == MigrationPriority.MONITOR:
                monitor_items.append(migration_item)
        
        return {
            "roadmap_id": f"PQ-MIGRATION-{self.assessment_id}",
            "generated_at": datetime.utcnow().isoformat(),
            "organization": self.organization_name,
            "phases": {
                "phase_0_immediate": {
                    "timeframe": "0-30 days",
                    "description": "Critical vulnerabilities requiring immediate action",
                    "items": immediate_migrations,
                    "total_effort_hours": sum(i["effort_hours"] for i in immediate_migrations)
                },
                "phase_1_soon": {
                    "timeframe": "30-90 days",
                    "description": "High priority items for near-term migration",
                    "items": soon_migrations,
                    "total_effort_hours": sum(i["effort_hours"] for i in soon_migrations)
                },
                "phase_2_scheduled": {
                    "timeframe": "90-180 days",
                    "description": "Scheduled upgrades during normal maintenance windows",
                    "items": scheduled_migrations,
                    "total_effort_hours": sum(i["effort_hours"] for i in scheduled_migrations)
                },
                "phase_3_monitor": {
                    "timeframe": "Ongoing",
                    "description": "Items to monitor and reassess periodically",
                    "items": monitor_items,
                    "total_effort_hours": sum(i["effort_hours"] for i in monitor_items)
                }
            },
            "summary": {
                "total_migrations_needed": len(immediate_migrations) + len(soon_migrations) + len(scheduled_migrations),
                "total_effort_hours": sum(i["effort_hours"] for i in immediate_migrations + soon_migrations + scheduled_migrations),
                "immediate_actions_count": len(immediate_migrations)
            }
        }
    
    def generate_detailed_report(self) -> Dict[str, Any]:
        """Generate complete post-quantum readiness report"""
        return {
            "report_id": f"PQ-REPORT-{self.assessment_id}",
            "version": self.version,
            "organization": self.organization_name,
            "generated_at": datetime.utcnow().isoformat(),
            "nist_pqc_alignment": {
                "standardized_algorithms": ["CRYSTALS-Kyber", "CRYSTALS-Dilithium", "FALCON", "SPHINCS+"],
                "assessment_basis": "NIST PQC Standardization Final (2024)"
            },
            "executive_summary": asdict(self.generate_readiness_summary()),
            "algorithm_assessments": [
                asdict(self.assess_algorithm(d["algorithm"]))
                for d in self.deployed_algorithms
            ],
            "migration_roadmap": self.generate_migration_roadmap(),
            "nist_cryptographic_standards": {
                "key_encapsulation": "CRYSTALS-Kyber (FIPS 203)",
                "digital_signatures": "CRYSTALS-Dilithium (FIPS 204), FALCON (FIPS 205), SPHINCS+ (FIPS 206)"
            }
        }
    
    def export_json_report(self, filepath: str) -> bool:
        """Export full assessment report to JSON file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.generate_detailed_report(), f, indent=2)
            return True
        except Exception:
            return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get assessor health and operational status"""
        return {
            "status": "healthy",
            "version": self.version,
            "assessment_id": self.assessment_id,
            "algorithms_tracked": len(self.ALGORITHM_RISK),
            "algorithms_assessed": len(self.deployed_algorithms),
            "api_stability": "STABLE",
            "nist_alignment": "FIPS 203/204/205/206"
        }
