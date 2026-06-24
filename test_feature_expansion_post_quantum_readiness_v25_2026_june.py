"""
Test Suite for Post-Quantum Readiness Assessment
Dimension A: Feature Expansion (V25 - June 2026)

Comprehensive tests covering all assessment functionality.
All tests are ADD-ONLY - no existing code modified.
"""

import json
import os
import tempfile
import pytest

from quantum_crypt.post_quantum_readiness_assessment_v25_2026_june import (
    PostQuantumReadinessAssessor,
    CryptoAlgorithm,
    QuantumRiskLevel,
    MigrationPriority,
    AlgorithmAssessment,
    ReadinessSummary
)


class TestPostQuantumReadinessAssessor:
    """Test suite for Post-Quantum Readiness Assessor"""
    
    def test_assessor_initialization(self):
        """Test assessor initializes correctly"""
        assessor = PostQuantumReadinessAssessor(organization_name="Test Corp")
        
        assert assessor.organization_name == "Test Corp"
        assert len(assessor.deployed_algorithms) == 0
        assert assessor.version == "25.0.0"
        assert len(assessor.assessment_id) == 12
    
    def test_default_organization_name(self):
        """Test default organization name"""
        assessor = PostQuantumReadinessAssessor()
        assert assessor.organization_name == "QuantumCrypt AI"
    
    def test_add_valid_algorithm(self):
        """Test adding a valid algorithm returns True"""
        assessor = PostQuantumReadinessAssessor()
        
        result = assessor.add_algorithm(
            algorithm_name="RSA-2048",
            use_case="TLS",
            environment="production"
        )
        
        assert result == True
        assert len(assessor.deployed_algorithms) == 1
    
    def test_add_invalid_algorithm(self):
        """Test adding an invalid algorithm returns False"""
        assessor = PostQuantumReadinessAssessor()
        
        result = assessor.add_algorithm(
            algorithm_name="INVALID-ALG-123",
            use_case="test"
        )
        
        assert result == False
        assert len(assessor.deployed_algorithms) == 0
    
    def test_add_algorithm_with_deployment_count(self):
        """Test adding algorithm with deployment count"""
        assessor = PostQuantumReadinessAssessor()
        
        assessor.add_algorithm(
            algorithm_name="RSA-2048",
            use_case="TLS",
            deployment_count=5,
            business_criticality="critical"
        )
        
        deployed = assessor.deployed_algorithms[0]
        assert deployed["deployment_count"] == 5
        assert deployed["business_criticality"] == "critical"
    
    def test_assess_known_algorithm(self):
        """Test assessment of known algorithm"""
        assessor = PostQuantumReadinessAssessor()
        
        assessment = assessor.assess_algorithm("RSA-2048")
        
        assert assessment is not None
        assert assessment.algorithm == "RSA-2048"
        assert assessment.quantum_resistant == False
        assert assessment.risk_level == "CRITICAL"
    
    def test_assess_unknown_algorithm(self):
        """Test assessment of unknown algorithm returns None"""
        assessor = PostQuantumReadinessAssessor()
        
        assessment = assessor.assess_algorithm("UNKNOWN-ALG")
        assert assessment is None
    
    def test_rsa_2048_is_vulnerable(self):
        """Test RSA-2048 is marked as quantum vulnerable"""
        assessor = PostQuantumReadinessAssessor()
        
        assessment = assessor.assess_algorithm("RSA-2048")
        
        assert assessment.quantum_resistant == False
        assert assessment.risk_level == "CRITICAL"
        assert assessment.migration_priority == "IMMEDIATE"
    
    def test_aes_256_is_secure(self):
        """Test AES-256 is marked as quantum secure"""
        assessor = PostQuantumReadinessAssessor()
        
        assessment = assessor.assess_algorithm("AES-256")
        
        assert assessment.quantum_resistant == True
        assert assessment.risk_level == "SECURE"
        assert assessment.migration_priority == "NONE"
    
    def test_kyber_is_quantum_resistant(self):
        """Test CRYSTALS-Kyber is NIST PQC standard"""
        assessor = PostQuantumReadinessAssessor()
        
        assessment = assessor.assess_algorithm("CRYSTALS-Kyber")
        
        assert assessment.quantum_resistant == True
        assert assessment.risk_level == "SECURE"
        assert "NIST PQC Standard" in assessment.nist_status
    
    def test_generate_readiness_summary_empty(self):
        """Test readiness summary with no algorithms"""
        assessor = PostQuantumReadinessAssessor()
        
        summary = assessor.generate_readiness_summary()
        
        assert summary.algorithms_assessed == 0
        assert summary.quantum_resistant_count == 0
        assert summary.vulnerable_count == 0
        assert summary.overall_readiness_score == 0.0
        assert summary.migration_readiness_grade == "F"
    
    def test_generate_readiness_summary_all_secure(self):
        """Test readiness summary with all secure algorithms"""
        assessor = PostQuantumReadinessAssessor()
        
        assessor.add_algorithm("AES-256", "database")
        assessor.add_algorithm("SHA-512", "hashing")
        assessor.add_algorithm("CRYSTALS-Kyber", "key-exchange")
        
        summary = assessor.generate_readiness_summary()
        
        assert summary.algorithms_assessed == 3
        assert summary.quantum_resistant_count == 3
        assert summary.vulnerable_count == 0
        assert summary.overall_readiness_score == 100.0
        assert summary.migration_readiness_grade == "A"
        assert summary.quantum_risk_rating == "SECURE"
    
    def test_generate_readiness_summary_mixed(self):
        """Test readiness summary with mixed algorithms"""
        assessor = PostQuantumReadinessAssessor()
        
        assessor.add_algorithm("RSA-2048", "TLS")  # CRITICAL
        assessor.add_algorithm("AES-256", "database")  # SECURE
        
        summary = assessor.generate_readiness_summary()
        
        assert summary.algorithms_assessed == 2
        assert summary.quantum_resistant_count == 1
        assert summary.vulnerable_count == 1
        assert summary.overall_readiness_score > 0
        assert summary.overall_readiness_score < 100
    
    def test_generate_readiness_summary_critical_risk(self):
        """Test critical risk rating calculation"""
        assessor = PostQuantumReadinessAssessor()
        
        # Majority critical vulnerable
        assessor.add_algorithm("RSA-2048", "TLS")
        assessor.add_algorithm("ECC-secp256r1", "signing")
        assessor.add_algorithm("AES-256", "database")
        
        summary = assessor.generate_readiness_summary()
        
        assert summary.quantum_risk_rating in ["CRITICAL", "HIGH", "MODERATE"]
    
    def test_generate_migration_roadmap(self):
        """Test migration roadmap generation"""
        assessor = PostQuantumReadinessAssessor()
        
        assessor.add_algorithm("RSA-2048", "TLS")  # IMMEDIATE
        assessor.add_algorithm("RSA-3072", "code-signing")  # SOON
        assessor.add_algorithm("AES-256", "database")  # NONE
        
        roadmap = assessor.generate_migration_roadmap()
        
        assert "roadmap_id" in roadmap
        assert "phases" in roadmap
        assert len(roadmap["phases"]["phase_0_immediate"]["items"]) >= 1
        assert len(roadmap["phases"]["phase_1_soon"]["items"]) >= 1
    
    def test_migration_roadmap_effort_calculation(self):
        """Test effort calculation in roadmap"""
        assessor = PostQuantumReadinessAssessor()
        
        # RSA-2048 = 40 hours, 2 deployments = 80 hours
        assessor.add_algorithm("RSA-2048", "TLS", deployment_count=2)
        
        roadmap = assessor.generate_migration_roadmap()
        
        assert roadmap["phases"]["phase_0_immediate"]["total_effort_hours"] == 80
    
    def test_generate_detailed_report(self):
        """Test detailed report generation"""
        assessor = PostQuantumReadinessAssessor()
        
        assessor.add_algorithm("RSA-2048", "TLS")
        assessor.add_algorithm("AES-256", "database")
        
        report = assessor.generate_detailed_report()
        
        assert "report_id" in report
        assert "version" in report
        assert "executive_summary" in report
        assert "algorithm_assessments" in report
        assert "migration_roadmap" in report
        assert "nist_pqc_alignment" in report
    
    def test_detailed_report_nist_alignment(self):
        """Test NIST alignment info in report"""
        assessor = PostQuantumReadinessAssessor()
        
        report = assessor.generate_detailed_report()
        
        assert "standardized_algorithms" in report["nist_pqc_alignment"]
        assert "CRYSTALS-Kyber" in report["nist_pqc_alignment"]["standardized_algorithms"]
        assert "CRYSTALS-Dilithium" in report["nist_pqc_alignment"]["standardized_algorithms"]
    
    def test_export_json_report(self):
        """Test JSON report export"""
        assessor = PostQuantumReadinessAssessor()
        
        assessor.add_algorithm("RSA-2048", "TLS")
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            filepath = f.name
        
        try:
            result = assessor.export_json_report(filepath)
            assert result == True
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            assert "report_id" in data
            assert "executive_summary" in data
        finally:
            os.unlink(filepath)
    
    def test_export_json_invalid_path_returns_false(self):
        """Test JSON export handles invalid paths"""
        assessor = PostQuantumReadinessAssessor()
        
        result = assessor.export_json_report("/nonexistent/path/report.json")
        assert result == False
    
    def test_get_health_status(self):
        """Test health status reporting"""
        assessor = PostQuantumReadinessAssessor()
        
        health = assessor.get_health_status()
        
        assert health["status"] == "healthy"
        assert health["version"] == "25.0.0"
        assert health["algorithms_tracked"] > 0
        assert health["api_stability"] == "STABLE"
        assert "FIPS" in health["nist_alignment"]
    
    def test_health_status_after_adding_algorithms(self):
        """Test health status updates with algorithms"""
        assessor = PostQuantumReadinessAssessor()
        
        assessor.add_algorithm("RSA-2048", "TLS")
        assessor.add_algorithm("AES-256", "database")
        
        health = assessor.get_health_status()
        
        assert health["algorithms_assessed"] == 2
    
    def test_crypto_algorithm_enum(self):
        """Test CryptoAlgorithm enum values"""
        assert CryptoAlgorithm.RSA_2048.value == "RSA-2048"
        assert CryptoAlgorithm.AES_256.value == "AES-256"
        assert CryptoAlgorithm.CRYSTALS_KYBER.value == "CRYSTALS-Kyber"
        assert CryptoAlgorithm.CRYSTALS_DILITHIUM.value == "CRYSTALS-Dilithium"
    
    def test_quantum_risk_level_enum(self):
        """Test QuantumRiskLevel enum"""
        assert QuantumRiskLevel.CRITICAL.value == "CRITICAL"
        assert QuantumRiskLevel.HIGH.value == "HIGH"
        assert QuantumRiskLevel.SECURE.value == "SECURE"
    
    def test_migration_priority_enum(self):
        """Test MigrationPriority enum"""
        assert MigrationPriority.IMMEDIATE.value == "IMMEDIATE"
        assert MigrationPriority.SOON.value == "SOON"
        assert MigrationPriority.NONE.value == "NONE"
    
    def test_algorithm_assessment_dataclass(self):
        """Test AlgorithmAssessment dataclass"""
        assessment = AlgorithmAssessment(
            algorithm="Test-ALG",
            quantum_resistant=False,
            risk_level="HIGH",
            nist_status="Test status",
            key_strength_bits=128,
            equivalent_quantum_strength=0,
            recommended_replacement="New-Alg",
            migration_priority="IMMEDIATE",
            implementation_complexity="HIGH",
            estimated_effort_hours=40
        )
        
        assert assessment.algorithm == "Test-ALG"
        assert assessment.quantum_resistant == False
        assert assessment.estimated_effort_hours == 40
    
    def test_ecc_is_critical_risk(self):
        """Test ECC algorithms have critical risk"""
        assessor = PostQuantumReadinessAssessor()
        
        assessment = assessor.assess_algorithm("ECC-secp256r1")
        
        assert assessment.risk_level == "CRITICAL"
        assert assessment.migration_priority == "IMMEDIATE"
        assert assessment.implementation_complexity == "HIGH"
    
    def test_sha256_monitor_priority(self):
        """Test SHA-256 has monitor priority"""
        assessor = PostQuantumReadinessAssessor()
        
        assessment = assessor.assess_algorithm("SHA-256")
        
        assert assessment.quantum_resistant == True
        assert assessment.migration_priority == "MONITOR"
    
    def test_multiple_algorithms_same_type(self):
        """Test multiple deployments of same algorithm"""
        assessor = PostQuantumReadinessAssessor()
        
        assessor.add_algorithm("RSA-2048", "TLS", deployment_count=10)
        assessor.add_algorithm("RSA-2048", "VPN", deployment_count=5)
        
        assert len(assessor.deployed_algorithms) == 2
        
        summary = assessor.generate_readiness_summary()
        assert summary.estimated_migration_effort_hours == (10 + 5) * 40
    
    def test_readiness_grade_f_calculation(self):
        """Test F grade for very poor readiness"""
        assessor = PostQuantumReadinessAssessor()
        
        # All critical vulnerable
        assessor.add_algorithm("RSA-2048", "TLS")
        assessor.add_algorithm("ECC-secp256r1", "signing")
        
        summary = assessor.generate_readiness_summary()
        
        # Both CRITICAL = score 10 each, avg = 10 = F
        assert summary.migration_readiness_grade in ["D", "F"]
    
    def test_sphincs_plus_is_secure(self):
        """Test SPHINCS+ is marked as secure"""
        assessor = PostQuantumReadinessAssessor()
        
        assessment = assessor.assess_algorithm("SPHINCS+")
        
        assert assessment.quantum_resistant == True
        assert assessment.risk_level == "SECURE"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
