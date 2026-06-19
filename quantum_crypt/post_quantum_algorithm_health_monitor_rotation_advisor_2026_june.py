"""
QuantumCrypt AI - Post-Quantum Algorithm Health Monitor & Rotation Advisor
Production-Grade Implementation

This module provides continuous monitoring and automated rotation advisory for
post-quantum cryptographic algorithms, ensuring quantum-resistant security posture.

Features:
1. Algorithm health monitoring (NIST status, cryptanalysis updates)
2. Key usage tracking and age monitoring
3. Quantum resistance scoring (NIST security levels 1-5)
4. Automated rotation recommendations
5. Compliance reporting (FIPS 140-3, CNSA 2.0)
6. Health dashboard generation

Author: QuantumCrypt AI Team
Version: 1.0.0
Date: June 2026
"""

import json
import hashlib
import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, asdict
from enum import Enum
from abc import ABC, abstractmethod


class AlgorithmStatus(str, Enum):
    """NIST Standardization Status"""
    STANDARDIZED = "STANDARDIZED"          # NIST final standard
    FINALIST = "FINALIST"                  # NIST finalist
    CANDIDATE = "CANDIDATE"                # Round 3+ candidate
    DEPRECATED = "DEPRECATED"              # Marked for removal
    BROKEN = "BROKEN"                      # Cryptanalytic breaks found
    EXPERIMENTAL = "EXPERIMENTAL"          # Research/experimental


class SecurityLevel(int, Enum):
    """NIST Security Levels (quantum resistance)"""
    LEVEL_1 = 1    # AES-128 equivalent
    LEVEL_2 = 2    # SHA-256 equivalent
    LEVEL_3 = 3    # AES-192 equivalent
    LEVEL_4 = 4    # SHA-384 equivalent
    LEVEL_5 = 5    # AES-256 equivalent


class RotationUrgency(str, Enum):
    """Rotation recommendation urgency levels"""
    IMMEDIATE = "IMMEDIATE"    # Within 24 hours
    URGENT = "URGENT"          # Within 7 days
    SCHEDULED = "SCHEDULED"    # Within 30 days
    MONITOR = "MONITOR"        # Regular monitoring only
    NONE = "NONE"              # No rotation needed


class AlgorithmType(str, Enum):
    KEM = "KEY_ENCAPSULATION_MECHANISM"
    SIGNATURE = "DIGITAL_SIGNATURE"
    HASH = "HASH_FUNCTION"
    SYMMETRIC = "SYMMETRIC_CIPHER"


@dataclass
class AlgorithmHealth:
    """Health status for a post-quantum algorithm"""
    algorithm_name: str
    algorithm_type: str
    nist_status: str
    security_level: int
    quantum_resistance_score: float  # 0.0 - 10.0
    cryptanalysis_risk: float        # 0.0 - 10.0 (lower is better)
    last_updated: str
    known_issues: List[str]
    recommended: bool
    rotation_days_recommended: int


@dataclass
class KeyMetadata:
    """Metadata for tracked cryptographic keys"""
    key_id: str
    algorithm: str
    created_timestamp: str
    last_rotation: str
    usage_count: int
    encryption_operations: int
    signature_operations: int
    key_age_days: float
    is_active: bool


@dataclass
class RotationRecommendation:
    """Individual key rotation recommendation"""
    key_id: str
    algorithm: str
    current_age_days: float
    max_allowed_age_days: int
    urgency: str
    reason: str
    recommended_algorithm: str
    estimated_quantum_risk: float


@dataclass
class HealthDashboard:
    """Complete algorithm health dashboard"""
    report_generated: str
    overall_security_score: float
    algorithms_monitored: int
    keys_tracked: int
    algorithm_health_summary: Dict[str, Any]
    rotation_recommendations: List[Dict[str, Any]]
    compliance_status: Dict[str, Any]
    risk_assessment: Dict[str, Any]


class PostQuantumAlgorithmRegistry:
    """
    Registry of post-quantum algorithms with current health status
    Based on NIST PQ Standardization (as of June 2026)
    """
    
    ALGORITHM_DATABASE = {
        # CRYSTALS-Kyber (NIST Standardized KEM)
        "KYBER-512": AlgorithmHealth(
            algorithm_name="CRYSTALS-Kyber-512",
            algorithm_type=AlgorithmType.KEM,
            nist_status=AlgorithmStatus.STANDARDIZED,
            security_level=SecurityLevel.LEVEL_1,
            quantum_resistance_score=9.5,
            cryptanalysis_risk=1.0,
            last_updated="2026-06-01",
            known_issues=[],
            recommended=True,
            rotation_days_recommended=90,
        ),
        "KYBER-768": AlgorithmHealth(
            algorithm_name="CRYSTALS-Kyber-768",
            algorithm_type=AlgorithmType.KEM,
            nist_status=AlgorithmStatus.STANDARDIZED,
            security_level=SecurityLevel.LEVEL_3,
            quantum_resistance_score=9.8,
            cryptanalysis_risk=0.5,
            last_updated="2026-06-01",
            known_issues=[],
            recommended=True,
            rotation_days_recommended=90,
        ),
        "KYBER-1024": AlgorithmHealth(
            algorithm_name="CRYSTALS-Kyber-1024",
            algorithm_type=AlgorithmType.KEM,
            nist_status=AlgorithmStatus.STANDARDIZED,
            security_level=SecurityLevel.LEVEL_5,
            quantum_resistance_score=10.0,
            cryptanalysis_risk=0.3,
            last_updated="2026-06-01",
            known_issues=[],
            recommended=True,
            rotation_days_recommended=90,
        ),
        
        # CRYSTALS-Dilithium (NIST Standardized Signature)
        "DILITHIUM-2": AlgorithmHealth(
            algorithm_name="CRYSTALS-Dilithium-2",
            algorithm_type=AlgorithmType.SIGNATURE,
            nist_status=AlgorithmStatus.STANDARDIZED,
            security_level=SecurityLevel.LEVEL_2,
            quantum_resistance_score=9.2,
            cryptanalysis_risk=1.2,
            last_updated="2026-06-01",
            known_issues=["Side-channel resistance improvements recommended"],
            recommended=True,
            rotation_days_recommended=180,
        ),
        "DILITHIUM-3": AlgorithmHealth(
            algorithm_name="CRYSTALS-Dilithium-3",
            algorithm_type=AlgorithmType.SIGNATURE,
            nist_status=AlgorithmStatus.STANDARDIZED,
            security_level=SecurityLevel.LEVEL_3,
            quantum_resistance_score=9.5,
            cryptanalysis_risk=0.8,
            last_updated="2026-06-01",
            known_issues=[],
            recommended=True,
            rotation_days_recommended=180,
        ),
        "DILITHIUM-5": AlgorithmHealth(
            algorithm_name="CRYSTALS-Dilithium-5",
            algorithm_type=AlgorithmType.SIGNATURE,
            nist_status=AlgorithmStatus.STANDARDIZED,
            security_level=SecurityLevel.LEVEL_5,
            quantum_resistance_score=9.7,
            cryptanalysis_risk=0.5,
            last_updated="2026-06-01",
            known_issues=[],
            recommended=True,
            rotation_days_recommended=180,
        ),
        
        # Falcon (NIST Standardized Signature)
        "FALCON-512": AlgorithmHealth(
            algorithm_name="Falcon-512",
            algorithm_type=AlgorithmType.SIGNATURE,
            nist_status=AlgorithmStatus.STANDARDIZED,
            security_level=SecurityLevel.LEVEL_1,
            quantum_resistance_score=8.8,
            cryptanalysis_risk=2.0,
            last_updated="2026-06-01",
            known_issues=["Floating-point timing concerns", "Implementation complexity"],
            recommended=True,
            rotation_days_recommended=180,
        ),
        
        # SPHINCS+ (NIST Standardized Hash-based Signature)
        "SPHINCS+-SHA2-128F": AlgorithmHealth(
            algorithm_name="SPHINCS+-SHA2-128F",
            algorithm_type=AlgorithmType.SIGNATURE,
            nist_status=AlgorithmStatus.STANDARDIZED,
            security_level=SecurityLevel.LEVEL_1,
            quantum_resistance_score=10.0,
            cryptanalysis_risk=0.1,
            last_updated="2026-06-01",
            known_issues=["Large signature size", "Slow verification"],
            recommended=True,
            rotation_days_recommended=365,
        ),
        
        # Classic McEliece (NIST Selected - Code-based)
        "CLASSIC-MCELIECE-460896": AlgorithmHealth(
            algorithm_name="Classic-McEliece-460896",
            algorithm_type=AlgorithmType.KEM,
            nist_status=AlgorithmStatus.FINALIST,
            security_level=SecurityLevel.LEVEL_5,
            quantum_resistance_score=10.0,
            cryptanalysis_risk=0.1,
            last_updated="2026-06-01",
            known_issues=["Extremely large public keys"],
            recommended=False,
            rotation_days_recommended=90,
        ),
        
        # Legacy/Deprecated (for comparison)
        "RSA-2048": AlgorithmHealth(
            algorithm_name="RSA-2048",
            algorithm_type=AlgorithmType.SIGNATURE,
            nist_status=AlgorithmStatus.DEPRECATED,
            security_level=0,
            quantum_resistance_score=0.0,
            cryptanalysis_risk=10.0,
            last_updated="2026-06-01",
            known_issues=["Quantum-vulnerable (Shor's algorithm)"],
            recommended=False,
            rotation_days_recommended=1,  # Immediate rotation
        ),
        "ECC-P256": AlgorithmHealth(
            algorithm_name="ECC-P256",
            algorithm_type=AlgorithmType.SIGNATURE,
            nist_status=AlgorithmStatus.DEPRECATED,
            security_level=0,
            quantum_resistance_score=0.0,
            cryptanalysis_risk=10.0,
            last_updated="2026-06-01",
            known_issues=["Quantum-vulnerable (Shor's algorithm)"],
            recommended=False,
            rotation_days_recommended=1,
        ),
    }
    
    @classmethod
    def get_algorithm_health(cls, algorithm_name: str) -> Optional[AlgorithmHealth]:
        """Get health status for a specific algorithm"""
        return cls.ALGORITHM_DATABASE.get(algorithm_name.upper())
    
    @classmethod
    def get_all_algorithms(cls) -> List[AlgorithmHealth]:
        """Get all monitored algorithms"""
        return list(cls.ALGORITHM_DATABASE.values())
    
    @classmethod
    def get_recommended_algorithms(cls, alg_type: Optional[AlgorithmType] = None) -> List[AlgorithmHealth]:
        """Get recommended algorithms by type"""
        return [
            alg for alg in cls.ALGORITHM_DATABASE.values()
            if alg.recommended and (alg_type is None or alg.algorithm_type == alg_type)
        ]


class AlgorithmHealthMonitor:
    """
    Production-grade Post-Quantum Algorithm Health Monitor
    
    Monitors:
    - Algorithm security status (NIST updates)
    - Cryptanalysis developments
    - Key usage and age
    - Quantum resistance levels
    
    Provides:
    - Health scoring
    - Rotation recommendations
    - Compliance reporting
    """
    
    # Default rotation policies (production-grade)
    ROTATION_POLICIES = {
        AlgorithmType.KEM: {
            SecurityLevel.LEVEL_1: 90,
            SecurityLevel.LEVEL_3: 90,
            SecurityLevel.LEVEL_5: 90,
        },
        AlgorithmType.SIGNATURE: {
            SecurityLevel.LEVEL_1: 180,
            SecurityLevel.LEVEL_2: 180,
            SecurityLevel.LEVEL_3: 180,
            SecurityLevel.LEVEL_5: 180,
        },
    }
    
    QUANTUM_RISK_THRESHOLDS = {
        "CRITICAL": 8.0,
        "HIGH": 5.0,
        "MEDIUM": 3.0,
        "LOW": 0.0,
    }
    
    def __init__(self):
        self.key_registry: Dict[str, KeyMetadata] = {}
        self.usage_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {
            "encryptions": 0, "signatures": 0, "decryptions": 0, "verifications": 0
        })
        self.alert_history: List[Dict[str, Any]] = []
        
    def register_key(self, key_data: Dict[str, Any]) -> bool:
        """
        Register a cryptographic key for monitoring
        
        Args:
            key_data: Dictionary with key_id, algorithm, created timestamp
            
        Returns:
            bool: Registration success
        """
        try:
            required_fields = ["key_id", "algorithm", "created_timestamp"]
            if not all(field in key_data for field in required_fields):
                return False
                
            key_id = key_data["key_id"]
            algorithm = key_data["algorithm"].upper()
            
            # Calculate key age
            created = datetime.datetime.fromisoformat(
                key_data["created_timestamp"].replace("Z", "+00:00")
            )
            now = datetime.datetime.now(datetime.timezone.utc)
            age_days = (now - created).total_seconds() / 86400.0
            
            key_meta = KeyMetadata(
                key_id=key_id,
                algorithm=algorithm,
                created_timestamp=key_data["created_timestamp"],
                last_rotation=key_data.get("last_rotation", key_data["created_timestamp"]),
                usage_count=0,
                encryption_operations=0,
                signature_operations=0,
                key_age_days=round(age_days, 2),
                is_active=key_data.get("is_active", True),
            )
            
            self.key_registry[key_id] = key_meta
            return True
            
        except Exception:
            return False
            
    def record_key_usage(self, key_id: str, operation_type: str) -> bool:
        """Record key usage for monitoring"""
        if key_id not in self.key_registry:
            return False
            
        key = self.key_registry[key_id]
        key.usage_count += 1
        
        if operation_type == "ENCRYPT":
            key.encryption_operations += 1
            self.usage_stats[key.algorithm]["encryptions"] += 1
        elif operation_type == "SIGN":
            key.signature_operations += 1
            self.usage_stats[key.algorithm]["signatures"] += 1
        elif operation_type == "DECRYPT":
            self.usage_stats[key.algorithm]["decryptions"] += 1
        elif operation_type == "VERIFY":
            self.usage_stats[key.algorithm]["verifications"] += 1
            
        return True
        
    def calculate_quantum_risk(self, algorithm: str, key_age_days: float) -> Tuple[float, str]:
        """
        Calculate quantum vulnerability risk score (0.0 - 10.0)
        Higher = more risky
        """
        alg_health = PostQuantumAlgorithmRegistry.get_algorithm_health(algorithm)
        
        if alg_health is None:
            # Unknown algorithm - high risk
            return 8.0, "CRITICAL"
            
        # Base risk from quantum resistance (inverted)
        base_risk = 10.0 - alg_health.quantum_resistance_score
        
        # Age factor (older keys = more risk)
        age_factor = min(key_age_days / 365.0, 2.0)  # Cap at 2x multiplier
        
        # Cryptanalysis risk
        crypto_risk = alg_health.cryptanalysis_risk / 2.0
        
        total_risk = round(base_risk + (age_factor * 1.5) + crypto_risk, 2)
        total_risk = min(total_risk, 10.0)  # Cap at 10
        
        # Determine level
        if total_risk >= self.QUANTUM_RISK_THRESHOLDS["CRITICAL"]:
            level = "CRITICAL"
        elif total_risk >= self.QUANTUM_RISK_THRESHOLDS["HIGH"]:
            level = "HIGH"
        elif total_risk >= self.QUANTUM_RISK_THRESHOLDS["MEDIUM"]:
            level = "MEDIUM"
        else:
            level = "LOW"
            
        return total_risk, level
        
    def evaluate_rotation_need(self, key_id: str) -> Optional[RotationRecommendation]:
        """Evaluate if a key needs rotation"""
        if key_id not in self.key_registry:
            return None
            
        key = self.key_registry[key_id]
        alg_health = PostQuantumAlgorithmRegistry.get_algorithm_health(key.algorithm)
        
        if alg_health is None:
            # Unknown algorithm - immediate rotation
            return RotationRecommendation(
                key_id=key_id,
                algorithm=key.algorithm,
                current_age_days=key.key_age_days,
                max_allowed_age_days=7,
                urgency=RotationUrgency.IMMEDIATE,
                reason="Unknown algorithm - security risk",
                recommended_algorithm="KYBER-768",
                estimated_quantum_risk=9.0,
            )
        
        # Get max allowed age
        max_age = alg_health.rotation_days_recommended
        
        # Check algorithm status
        if alg_health.nist_status == AlgorithmStatus.BROKEN:
            urgency = RotationUrgency.IMMEDIATE
            reason = "Algorithm cryptanalytically broken"
        elif alg_health.nist_status == AlgorithmStatus.DEPRECATED:
            urgency = RotationUrgency.IMMEDIATE
            reason = "Algorithm deprecated/quantum-vulnerable"
        elif not alg_health.recommended:
            urgency = RotationUrgency.URGENT
            reason = "Algorithm not recommended for production"
        elif key.key_age_days > max_age * 2:
            urgency = RotationUrgency.URGENT
            reason = f"Key age ({key.key_age_days:.1f}d) exceeds 2x policy limit ({max_age}d)"
        elif key.key_age_days > max_age:
            urgency = RotationUrgency.SCHEDULED
            reason = f"Key age ({key.key_age_days:.1f}d) exceeds policy limit ({max_age}d)"
        elif alg_health.cryptanalysis_risk > 5.0:
            urgency = RotationUrgency.MONITOR
            reason = "Elevated cryptanalysis risk detected"
        else:
            return None  # No rotation needed
            
        # Find recommended replacement
        recommended = PostQuantumAlgorithmRegistry.get_recommended_algorithms(alg_health.algorithm_type)
        recommended_alg = recommended[0].algorithm_name if recommended else "KYBER-768"
        
        risk_score, _ = self.calculate_quantum_risk(key.algorithm, key.key_age_days)
        
        return RotationRecommendation(
            key_id=key_id,
            algorithm=key.algorithm,
            current_age_days=key.key_age_days,
            max_allowed_age_days=max_age,
            urgency=urgency,
            reason=reason,
            recommended_algorithm=recommended_alg,
            estimated_quantum_risk=risk_score,
        )
        
    def get_all_rotation_recommendations(self) -> List[RotationRecommendation]:
        """Get rotation recommendations for all tracked keys"""
        recommendations = []
        for key_id in self.key_registry:
            rec = self.evaluate_rotation_need(key_id)
            if rec:
                recommendations.append(rec)
        return recommendations
        
    def generate_health_dashboard(self) -> HealthDashboard:
        """Generate complete health dashboard"""
        all_algs = PostQuantumAlgorithmRegistry.get_all_algorithms()
        recommendations = self.get_all_rotation_recommendations()
        
        # Calculate overall security score
        total_score = sum(
            alg.quantum_resistance_score 
            for alg in PostQuantumAlgorithmRegistry.get_recommended_algorithms()
        )
        avg_score = total_score / max(len(PostQuantumAlgorithmRegistry.get_recommended_algorithms()), 1)
        
        # Algorithm summary
        alg_summary = {
            "standardized": sum(1 for a in all_algs if a.nist_status == AlgorithmStatus.STANDARDIZED),
            "finalists": sum(1 for a in all_algs if a.nist_status == AlgorithmStatus.FINALIST),
            "deprecated": sum(1 for a in all_algs if a.nist_status == AlgorithmStatus.DEPRECATED),
            "recommended_count": len(PostQuantumAlgorithmRegistry.get_recommended_algorithms()),
        }
        
        # Compliance check
        quantum_vulnerable = sum(
            1 for key in self.key_registry.values()
            if PostQuantumAlgorithmRegistry.get_algorithm_health(key.algorithm)
            and PostQuantumAlgorithmRegistry.get_algorithm_health(key.algorithm).nist_status == AlgorithmStatus.DEPRECATED
        )
        
        compliance = {
            "fips_140_3_compliant": quantum_vulnerable == 0,
            "cnsa_2_0_ready": all(
                key.algorithm.startswith(("KYBER", "DILITHIUM"))
                for key in self.key_registry.values()
            ),
            "quantum_vulnerable_keys": quantum_vulnerable,
            "compliance_percentage": round(
                (len(self.key_registry) - quantum_vulnerable) / max(len(self.key_registry), 1) * 100, 2
            ),
        }
        
        # Risk assessment
        risk_levels = [
            self.calculate_quantum_risk(key.algorithm, key.key_age_days)
            for key in self.key_registry.values()
        ]
        
        risk_assessment = {
            "average_quantum_risk": round(sum(r[0] for r in risk_levels) / max(len(risk_levels), 1), 2),
            "critical_risk_keys": sum(1 for r in risk_levels if r[1] == "CRITICAL"),
            "high_risk_keys": sum(1 for r in risk_levels if r[1] == "HIGH"),
            "medium_risk_keys": sum(1 for r in risk_levels if r[1] == "MEDIUM"),
            "low_risk_keys": sum(1 for r in risk_levels if r[1] == "LOW"),
        }
        
        return HealthDashboard(
            report_generated=datetime.datetime.utcnow().isoformat() + "Z",
            overall_security_score=round(avg_score, 2),
            algorithms_monitored=len(all_algs),
            keys_tracked=len(self.key_registry),
            algorithm_health_summary=alg_summary,
            rotation_recommendations=[asdict(r) for r in recommendations],
            compliance_status=compliance,
            risk_assessment=risk_assessment,
        )
        
    def export_dashboard_json(self, filepath: str) -> bool:
        """Export dashboard to JSON"""
        try:
            dashboard = self.generate_health_dashboard()
            with open(filepath, "w") as f:
                json.dump(asdict(dashboard), f, indent=2)
            return True
        except Exception:
            return False
            
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        return {
            "keys_tracked": len(self.key_registry),
            "algorithms_monitored": len(PostQuantumAlgorithmRegistry.ALGORITHM_DATABASE),
            "total_operations": {
                alg: sum(stats.values()) for alg, stats in self.usage_stats.items()
            },
            "recommendations_pending": len(self.get_all_rotation_recommendations()),
        }


# Production entry point
def create_sample_monitor() -> Dict[str, Any]:
    """Create sample monitor with test data"""
    monitor = AlgorithmHealthMonitor()
    
    # Register sample keys
    sample_keys = [
        {"key_id": "KEY-KEM-001", "algorithm": "KYBER-768", 
         "created_timestamp": "2026-03-01T00:00:00Z"},
        {"key_id": "KEY-KEM-002", "algorithm": "KYBER-1024", 
         "created_timestamp": "2026-01-15T00:00:00Z"},
        {"key_id": "KEY-SIG-001", "algorithm": "DILITHIUM-3", 
         "created_timestamp": "2026-02-01T00:00:00Z"},
        {"key_id": "KEY-LEGACY-001", "algorithm": "RSA-2048", 
         "created_timestamp": "2025-06-01T00:00:00Z"},
        {"key_id": "KEY-SIG-002", "algorithm": "SPHINCS+-SHA2-128F", 
         "created_timestamp": "2026-05-01T00:00:00Z"},
    ]
    
    for key in sample_keys:
        monitor.register_key(key)
    
    # Record some usage
    for _ in range(150):
        monitor.record_key_usage("KEY-KEM-001", "ENCRYPT")
    for _ in range(75):
        monitor.record_key_usage("KEY-SIG-001", "SIGN")
    
    dashboard = monitor.generate_health_dashboard()
    stats = monitor.get_statistics()
    
    return {
        "monitor_stats": stats,
        "dashboard": asdict(dashboard),
        "recommendations_count": len(dashboard.rotation_recommendations),
    }


if __name__ == "__main__":
    result = create_sample_monitor()
    print(json.dumps(result, indent=2))
