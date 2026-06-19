#!/usr/bin/env python3
"""
Test suite for Post-Quantum Cryptography Migration Readiness Assessor
Production-grade testing with real assertions
"""

import sys
import json
sys.path.insert(0, 'quantum_crypt')

from post_quantum_migration_readiness_assessor_2026_june import (
    PQCMigrationReadinessAssessor,
    ALGORITHM_RISK_DATABASE,
    QuantumRiskLevel,
    MigrationPriority,
    CryptoAlgorithmCategory
)


def run_tests():
    print("=" * 60)
    print("PQC MIGRATION READINESS ASSESSOR - TEST SUITE")
    print("=" * 60)
    
    test_results = {
        "passed": 0,
        "failed": 0,
        "tests": []
    }

    # Test 1: Basic initialization
    print("\n[TEST 1] Basic Initialization")
    try:
        assessor = PQCMigrationReadinessAssessor()
        assert assessor is not None
        assert len(assessor.findings) == 0
        assert len(assessor.algorithm_database) > 0
        print("  ✓ Assessor initialized correctly")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "initialization", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "initialization", "status": "failed", "error": str(e)})

    # Test 2: Algorithm risk database
    print("\n[TEST 2] Algorithm Risk Database")
    try:
        # RSA should be CRITICAL risk
        rsa_info = ALGORITHM_RISK_DATABASE["RSA"]
        assert rsa_info.quantum_risk == QuantumRiskLevel.CRITICAL
        assert rsa_info.migration_priority == MigrationPriority.IMMEDIATE
        
        # Kyber should be LOW risk
        kyber_info = ALGORITHM_RISK_DATABASE["CRYSTALS-Kyber"]
        assert kyber_info.quantum_risk == QuantumRiskLevel.LOW
        assert kyber_info.migration_priority == MigrationPriority.NONE
        
        print(f"  ✓ Database has {len(ALGORITHM_RISK_DATABASE)} algorithms")
        print("  ✓ RSA = CRITICAL risk, CRYSTALS-Kyber = LOW risk")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "risk_database", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "risk_database", "status": "failed", "error": str(e)})

    # Test 3: Code scanning - RSA detection
    print("\n[TEST 3] Code Scanning - RSA Detection")
    try:
        assessor = PQCMigrationReadinessAssessor()
        code = """
        from cryptography.hazmat.primitives.asymmetric import rsa
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        """
        findings = assessor.scan_code_content(code, "test_rsa.py")
        assert len(findings) >= 1
        assert findings[0].quantum_risk == QuantumRiskLevel.CRITICAL
        print(f"  ✓ Found {len(findings)} RSA instance(s) with CRITICAL risk")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "rsa_detection", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "rsa_detection", "status": "failed", "error": str(e)})

    # Test 4: Code scanning - ECC detection
    print("\n[TEST 4] Code Scanning - ECC Detection")
    try:
        assessor = PQCMigrationReadinessAssessor()
        code = """
        from cryptography.hazmat.primitives.asymmetric import ec
        private_key = ec.generate_private_key(ec.SECP256R1())
        """
        findings = assessor.scan_code_content(code, "test_ecc.py")
        secp_findings = [f for f in findings if "secp256r1" in f.algorithm_name.lower()]
        assert len(findings) >= 1
        print(f"  ✓ Found ECC algorithm(s) with quantum vulnerability")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "ecc_detection", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "ecc_detection", "status": "failed", "error": str(e)})

    # Test 5: Readiness score calculation
    print("\n[TEST 5] Readiness Score Calculation")
    try:
        assessor = PQCMigrationReadinessAssessor()
        # Simulate vulnerable code
        code = """
        import rsa
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP256R1())
        """
        assessor.scan_code_content(code, "vulnerable.py")
        readiness = assessor.calculate_readiness_score()
        
        assert readiness.overall_score < 100  # Should be penalized
        assert readiness.critical_risk_count > 0
        print(f"  ✓ Readiness score: {readiness.overall_score:.1f}/100")
        print(f"  ✓ Critical risks found: {readiness.critical_risk_count}")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "readiness_score", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "readiness_score", "status": "failed", "error": str(e)})

    # Test 6: Migration recommendations
    print("\n[TEST 6] Migration Recommendations Generation")
    try:
        assessor = PQCMigrationReadinessAssessor()
        code = """
        # Vulnerable RSA usage
        import rsa
        (pubkey, privkey) = rsa.newkeys(2048)
        """
        assessor.scan_code_content(code, "rsa_test.py")
        recommendations = assessor.generate_migration_recommendations()
        
        assert len(recommendations) >= 1
        assert recommendations[0].priority == MigrationPriority.IMMEDIATE
        assert "Kyber" in (recommendations[0].replacement_algorithm or "")
        print(f"  ✓ Generated {len(recommendations)} recommendation(s)")
        print(f"  ✓ Top priority: {recommendations[0].priority.value}")
        print(f"  ✓ Recommended: {recommendations[0].replacement_algorithm}")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "recommendations", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "recommendations", "status": "failed", "error": str(e)})

    # Test 7: PQC secure algorithm detection
    print("\n[TEST 7] PQC-Secure Algorithm Recognition")
    try:
        assessor = PQCMigrationReadinessAssessor()
        code = """
        # Using NIST PQC standard
        algorithm = "CRYSTALS-Kyber"
        signature = "CRYSTALS-Dilithium"
        """
        assessor.scan_code_content(code, "pqc_secure.py")
        readiness = assessor.calculate_readiness_score()
        
        # Should have low risk count
        assert readiness.low_risk_count > 0
        print(f"  ✓ PQC algorithms detected: LOW risk count = {readiness.low_risk_count}")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "pqc_detection", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "pqc_detection", "status": "failed", "error": str(e)})

    # Test 8: Migration roadmap
    print("\n[TEST 8] Migration Roadmap Generation")
    try:
        assessor = PQCMigrationReadinessAssessor()
        code = """
        import rsa
        from cryptography.hazmat.primitives.asymmetric import ec
        """
        assessor.scan_code_content(code, "mixed.py")
        roadmap = assessor.generate_migration_roadmap()
        
        assert "readiness_score" in roadmap
        assert "risk_summary" in roadmap
        assert "migration_phases" in roadmap
        assert "recommendations" in roadmap
        print("  ✓ Roadmap contains all required fields")
        print(f"  ✓ Migration phases: {list(roadmap['migration_phases'].keys())}")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "roadmap", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "roadmap", "status": "failed", "error": str(e)})

    # Test 9: Readiness report
    print("\n[TEST 9] Human-Readable Report")
    try:
        assessor = PQCMigrationReadinessAssessor()
        code = "import rsa"
        assessor.scan_code_content(code, "simple.py")
        report = assessor.generate_readiness_report()
        
        assert isinstance(report, str)
        assert len(report) > 0
        assert "POST-QUANTUM CRYPTOGRAPHY" in report
        assert "READINESS SCORE" in report
        print("  ✓ Full readiness report generated")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "report", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "report", "status": "failed", "error": str(e)})

    # Test 10: AES-128 vs AES-256 risk difference
    print("\n[TEST 10] AES Security Level Differentiation")
    try:
        aes128 = ALGORITHM_RISK_DATABASE["AES-128"]
        aes256 = ALGORITHM_RISK_DATABASE["AES-256"]
        
        assert aes128.quantum_risk == QuantumRiskLevel.MEDIUM
        assert aes256.quantum_risk == QuantumRiskLevel.LOW
        assert aes128.migration_priority == MigrationPriority.MEDIUM
        assert aes256.migration_priority == MigrationPriority.NONE
        print("  ✓ AES-128 = MEDIUM risk (upgrade to AES-256)")
        print("  ✓ AES-256 = LOW risk (post-quantum secure)")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "aes_differentiation", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "aes_differentiation", "status": "failed", "error": str(e)})

    # Print final results
    print("\n" + "=" * 60)
    print("TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"Passed: {test_results['passed']}")
    print(f"Failed: {test_results['failed']}")
    print(f"Total:  {test_results['passed'] + test_results['failed']}")
    print(f"Success Rate: {(test_results['passed']/(test_results['passed']+test_results['failed'])*100):.1f}%")
    
    # Save results
    with open("test_results_pqc_migration_readiness.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print("\nTest results saved to test_results_pqc_migration_readiness.json")
    
    return test_results["failed"] == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
