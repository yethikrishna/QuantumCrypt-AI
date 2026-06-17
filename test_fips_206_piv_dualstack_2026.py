"""
Test suite for FIPS 206 and PIV Dual-Stack Implementation - June 2026
"""

import pytest
import sys
from datetime import datetime
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.fips_206_piv_dualstack_2026 import (
    FIPS206BIKE,
    PIVDualStackManager,
    HybridKeyMigrationFramework,
    PQCAlgorithm,
    ClassicalAlgorithm,
    PIVKeyType,
    DualStackKey,
    MigrationStatus
)


class TestFIPS206BIKE:
    """Test FIPS 206 BIKE implementation"""

    def test_bike_l1_initialization(self):
        """Test BIKE Level 1 (128-bit security)"""
        bike = FIPS206BIKE(security_level=128)
        assert bike.algorithm == PQCAlgorithm.BIKE_L1
        assert bike.security_level == 128
        assert bike.n == 12323

    def test_bike_l3_initialization(self):
        """Test BIKE Level 3 (192-bit security)"""
        bike = FIPS206BIKE(security_level=192)
        assert bike.algorithm == PQCAlgorithm.BIKE_L3
        assert bike.security_level == 192

    def test_bike_l5_initialization(self):
        """Test BIKE Level 5 (256-bit security)"""
        bike = FIPS206BIKE(security_level=256)
        assert bike.algorithm == PQCAlgorithm.BIKE_L5
        assert bike.security_level == 256

    def test_keypair_generation(self):
        """Test BIKE keypair generation"""
        bike = FIPS206BIKE()
        priv, pub = bike.generate_keypair()
        assert len(priv) == 64
        assert len(pub) == 64
        assert bike.key_pair is not None

    def test_encapsulation_decapsulation(self):
        """Test KEM encapsulation/decapsulation flow"""
        bike = FIPS206BIKE()
        priv, pub = bike.generate_keypair()
        
        ciphertext, shared_secret1 = bike.encapsulate(pub)
        assert len(ciphertext) == 32
        assert len(shared_secret1) == 32
        
        shared_secret2 = bike.decapsulate(priv, ciphertext)
        assert len(shared_secret2) == 32

    def test_security_properties(self):
        """Test security properties report"""
        bike = FIPS206BIKE()
        props = bike.get_security_properties()
        assert props["fips_206_compliant"] is True
        assert props["quantum_resistant"] is True
        assert "security_level" in props
        assert props["standard"] == "NIST IR 8610 Round 3"


class TestPIVDualStackManager:
    """Test NIST PIV Dual-Stack Manager"""

    def setup_method(self):
        self.manager = PIVDualStackManager()

    def test_manager_initialization(self):
        """Test manager initializes correctly"""
        assert self.manager.version == "PIV Draft 2026-06-12"
        assert isinstance(self.manager.keys, dict)
        assert isinstance(self.manager.certificate_chain, list)

    def test_create_dual_stack_key(self):
        """Test dual-stack key creation"""
        key = self.manager.create_dual_stack_key(
            classical_algo=ClassicalAlgorithm.ECDSA_P384,
            pqc_algo=PQCAlgorithm.ML_KEM_768,
            key_type=PIVKeyType.DUAL_STACK
        )
        
        assert isinstance(key, DualStackKey)
        assert key.key_type == PIVKeyType.DUAL_STACK
        assert key.classical_algorithm == ClassicalAlgorithm.ECDSA_P384
        assert key.pqc_algorithm == PQCAlgorithm.ML_KEM_768
        assert key.key_id in self.manager.keys

    def test_create_pqc_only_key(self):
        """Test pure PQC key (no classical)"""
        key = self.manager.create_dual_stack_key(
            classical_algo=None,
            pqc_algo=PQCAlgorithm.ML_DSA_65,
            key_type=PIVKeyType.PQC_ONLY
        )
        
        assert key.key_type == PIVKeyType.PQC_ONLY
        assert key.classical_algorithm is None
        assert key.classical_public_key is None

    def test_create_hybrid_certificate(self):
        """Test hybrid certificate creation"""
        key = self.manager.create_dual_stack_key(
            ClassicalAlgorithm.RSA_3072,
            PQCAlgorithm.ML_KEM_768
        )
        cert = self.manager.create_hybrid_certificate(key.key_id)
        
        assert cert["version"] == "PIV Dual-Stack 2026"
        assert cert["pqc_algorithm"] == PQCAlgorithm.ML_KEM_768.value
        assert cert["fips_203_compliant"] is True
        assert cert["nist_piv_draft_compliant"] is True
        assert "public_keys" in cert

    def test_migration_recommendation(self):
        """Test migration status recommendation"""
        status = self.manager.get_migration_recommendation()
        assert isinstance(status, MigrationStatus)
        assert status.phase == 3  # Implementation phase
        assert status.dual_stack_deployed is True
        assert status.classical_deprecation_date is not None

    def test_compliance_report(self):
        """Test NIST compliance report"""
        report = self.manager.get_compliance_report()
        
        assert "fips_standards" in report
        assert report["fips_standards"]["FIPS 203"] == "Final (ML-KEM)"
        assert report["fips_standards"]["FIPS 206"] == "Draft (BIKE/HQC)"
        assert "browser_support" in report
        assert "enterprise_migration_timeline" in report
        assert "compliance_deadlines" in report
        assert report["compliance_deadlines"]["US Federal"] == "2033 (NSM-10)"


class TestHybridKeyMigrationFramework:
    """Test Enterprise Migration Framework"""

    def setup_method(self):
        self.framework = HybridKeyMigrationFramework()

    def test_inventory_crypto_assets(self):
        """Test crypto asset inventory"""
        assessment = self.framework.inventory_crypto_assets("Enterprise VPN")
        
        assert assessment["system"] == "Enterprise VPN"
        assert len(assessment["classical_algorithms_found"]) > 0
        assert "RSA-2048" in assessment["classical_algorithms_found"]
        assert assessment["priority"] == "HIGH"
        assert "Harvest Now, Decrypt Later" in assessment["risk_level"]

    def test_generate_migration_plan(self):
        """Test 15-year migration plan generation"""
        plan = self.framework.generate_migration_plan("Global Enterprise Inc")
        
        assert plan["enterprise"] == "Global Enterprise Inc"
        assert plan["total_duration_years"] == 15
        assert len(plan["phases"]) == 3
        assert plan["phases"][0]["phase"] == 1
        assert plan["phases"][0]["name"] == "Dual-Stack Deployment"
        assert plan["phases"][0]["timeframe"] == "2026-2027"
        assert plan["nist_compliant"] is True
        assert plan["csa_recommended"] is True


class TestEnums:
    """Test all enumerations"""

    def test_pqc_algorithm_enum(self):
        """Test PQC algorithm enum has all FIPS standards"""
        algorithms = list(PQCAlgorithm)
        # FIPS 203
        assert PQCAlgorithm.ML_KEM_512 is not None
        assert PQCAlgorithm.ML_KEM_768 is not None
        # FIPS 204
        assert PQCAlgorithm.ML_DSA_44 is not None
        assert PQCAlgorithm.ML_DSA_65 is not None
        # FIPS 205
        assert PQCAlgorithm.SLH_DSA_128S is not None
        # FIPS 206
        assert PQCAlgorithm.BIKE_L1 is not None
        assert PQCAlgorithm.HQC_L1 is not None

    def test_classical_algorithm_enum(self):
        """Test classical algorithm enum"""
        assert ClassicalAlgorithm.RSA_2048 is not None
        assert ClassicalAlgorithm.RSA_3072 is not None
        assert ClassicalAlgorithm.ECDSA_P256 is not None
        assert ClassicalAlgorithm.X25519 is not None

    def test_piv_key_type_enum(self):
        """Test PIV key type enum"""
        assert PIVKeyType.DUAL_STACK is not None
        assert PIVKeyType.PQC_ONLY is not None
        assert PIVKeyType.CLASSICAL_ONLY is not None
        assert PIVKeyType.MIGRATION is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
