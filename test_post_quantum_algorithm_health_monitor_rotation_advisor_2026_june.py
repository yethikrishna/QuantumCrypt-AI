#!/usr/bin/env python3
"""
Test Suite for QuantumCrypt Algorithm Health Monitor & Rotation Advisor
Production-Grade Testing

This test suite validates all core functionality:
- Algorithm registry and health status
- Key registration and tracking
- Quantum risk calculation
- Rotation recommendation engine
- Health dashboard generation
- Compliance reporting

Author: QuantumCrypt AI Team
Version: 1.0.0
Date: June 2026
"""

import json
import os
import sys
import tempfile
from typing import Dict, List, Any

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "quantum_crypt"))

from post_quantum_algorithm_health_monitor_rotation_advisor_2026_june import (
    AlgorithmHealthMonitor,
    PostQuantumAlgorithmRegistry,
    AlgorithmStatus,
    SecurityLevel,
    RotationUrgency,
    AlgorithmType,
    create_sample_monitor,
)


def run_test(test_name: str, test_func) -> Dict[str, Any]:
    """Run a single test and return results"""
    try:
        result = test_func()
        return {
            "test": test_name,
            "passed": True,
            "result": result,
            "error": None,
        }
    except Exception as e:
        return {
            "test": test_name,
            "passed": False,
            "result": None,
            "error": str(e),
        }


def test_algorithm_registry_initialization() -> bool:
    """Test algorithm registry has proper data"""
    algs = PostQuantumAlgorithmRegistry.get_all_algorithms()
    assert len(algs) > 0
    
    # Check NIST standardized algorithms exist
    kyber = PostQuantumAlgorithmRegistry.get_algorithm_health("KYBER-768")
    assert kyber is not None
    assert kyber.nist_status == AlgorithmStatus.STANDARDIZED
    assert kyber.recommended is True
    return True


def test_algorithm_health_scoring() -> bool:
    """Test algorithm health and quantum resistance scoring"""
    kyber = PostQuantumAlgorithmRegistry.get_algorithm_health("KYBER-768")
    rsa = PostQuantumAlgorithmRegistry.get_algorithm_health("RSA-2048")
    
    # Kyber should have high quantum resistance
    assert kyber.quantum_resistance_score > 9.0
    assert kyber.cryptanalysis_risk < 2.0
    
    # RSA should be quantum-vulnerable
    assert rsa.quantum_resistance_score == 0.0
    assert rsa.nist_status == AlgorithmStatus.DEPRECATED
    assert rsa.recommended is False
    return True


def test_recommended_algorithms_filtering() -> bool:
    """Test filtering recommended algorithms by type"""
    all_recommended = PostQuantumAlgorithmRegistry.get_recommended_algorithms()
    kem_recommended = PostQuantumAlgorithmRegistry.get_recommended_algorithms(AlgorithmType.KEM)
    sig_recommended = PostQuantumAlgorithmRegistry.get_recommended_algorithms(AlgorithmType.SIGNATURE)
    
    assert len(all_recommended) > 0
    assert len(kem_recommended) > 0
    assert len(sig_recommended) > 0
    
    # All KEM algorithms should be type KEM
    for alg in kem_recommended:
        assert alg.algorithm_type == AlgorithmType.KEM
    
    return True


def test_monitor_initialization() -> bool:
    """Test monitor initialization"""
    monitor = AlgorithmHealthMonitor()
    assert monitor.key_registry == {}
    assert len(monitor.usage_stats) == 0
    return True


def test_key_registration() -> bool:
    """Test key registration functionality"""
    monitor = AlgorithmHealthMonitor()
    
    key_data = {
        "key_id": "TEST-KEY-001",
        "algorithm": "KYBER-768",
        "created_timestamp": "2026-06-01T00:00:00Z",
    }
    
    result = monitor.register_key(key_data)
    assert result is True
    assert "TEST-KEY-001" in monitor.key_registry
    
    key = monitor.key_registry["TEST-KEY-001"]
    assert key.algorithm == "KYBER-768"
    assert key.key_age_days >= 0
    return True


def test_invalid_key_registration_rejection() -> bool:
    """Test invalid key data is rejected"""
    monitor = AlgorithmHealthMonitor()
    
    # Missing required fields
    invalid_key = {
        "key_id": "TEST-KEY-001",
        # Missing algorithm and timestamp
    }
    result = monitor.register_key(invalid_key)
    assert result is False
    return True


def test_key_usage_tracking() -> bool:
    """Test key usage tracking"""
    monitor = AlgorithmHealthMonitor()
    
    monitor.register_key({
        "key_id": "TEST-KEY-001",
        "algorithm": "KYBER-768",
        "created_timestamp": "2026-06-01T00:00:00Z",
    })
    
    # Record operations
    for _ in range(10):
        monitor.record_key_usage("TEST-KEY-001", "ENCRYPT")
    for _ in range(5):
        monitor.record_key_usage("TEST-KEY-001", "DECRYPT")
    
    key = monitor.key_registry["TEST-KEY-001"]
    assert key.usage_count == 15
    assert key.encryption_operations == 10
    return True


def test_unknown_key_usage_rejection() -> bool:
    """Test usage tracking rejects unknown keys"""
    monitor = AlgorithmHealthMonitor()
    result = monitor.record_key_usage("NONEXISTENT-KEY", "ENCRYPT")
    assert result is False
    return True


def test_quantum_risk_calculation() -> bool:
    """Test quantum risk calculation"""
    monitor = AlgorithmHealthMonitor()
    
    # Modern PQ algorithm - low risk
    risk_score, risk_level = monitor.calculate_quantum_risk("KYBER-768", 30.0)
    assert risk_score >= 0
    assert risk_score <= 10.0
    assert risk_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    
    # Legacy quantum-vulnerable algorithm - high risk
    risk_score2, risk_level2 = monitor.calculate_quantum_risk("RSA-2048", 365.0)
    assert risk_score2 > risk_score  # RSA should be riskier
    
    # Older keys should be riskier
    risk_score_old, _ = monitor.calculate_quantum_risk("KYBER-768", 365.0)
    risk_score_new, _ = monitor.calculate_quantum_risk("KYBER-768", 1.0)
    assert risk_score_old >= risk_score_new
    
    return True


def test_rotation_recommendation_for_deprecated_algorithm() -> bool:
    """Test deprecated algorithms get IMMEDIATE rotation recommendation"""
    monitor = AlgorithmHealthMonitor()
    
    monitor.register_key({
        "key_id": "LEGACY-KEY-001",
        "algorithm": "RSA-2048",
        "created_timestamp": "2026-01-01T00:00:00Z",
    })
    
    recommendation = monitor.evaluate_rotation_need("LEGACY-KEY-001")
    assert recommendation is not None
    assert recommendation.urgency == RotationUrgency.IMMEDIATE
    assert "quantum-vulnerable" in recommendation.reason.lower()
    return True


def test_rotation_recommendation_for_old_key() -> bool:
    """Test old keys get rotation recommendations"""
    monitor = AlgorithmHealthMonitor()
    
    # Very old key (simulate by using old date)
    monitor.register_key({
        "key_id": "OLD-KEY-001",
        "algorithm": "KYBER-768",
        "created_timestamp": "2025-01-01T00:00:00Z",  # > 1 year old
    })
    
    recommendation = monitor.evaluate_rotation_need("OLD-KEY-001")
    assert recommendation is not None
    assert recommendation.urgency in [RotationUrgency.URGENT, RotationUrgency.SCHEDULED]
    return True


def test_no_recommendation_for_good_key() -> bool:
    """Test fresh, good keys don't need rotation"""
    monitor = AlgorithmHealthMonitor()
    
    # Fresh key (today)
    monitor.register_key({
        "key_id": "FRESH-KEY-001",
        "algorithm": "KYBER-768",
        "created_timestamp": "2026-06-19T00:00:00Z",  # Today
    })
    
    recommendation = monitor.evaluate_rotation_need("FRESH-KEY-001")
    # Fresh key with good algorithm should not need rotation
    # (or None if within policy limits)
    assert recommendation is None or recommendation.urgency == RotationUrgency.NONE
    return True


def test_all_rotation_recommendations() -> bool:
    """Test bulk recommendation generation"""
    monitor = AlgorithmHealthMonitor()
    
    # Mix of good and bad keys
    keys = [
        {"key_id": "KEY-001", "algorithm": "RSA-2048", "created_timestamp": "2025-01-01T00:00:00Z"},
        {"key_id": "KEY-002", "algorithm": "KYBER-768", "created_timestamp": "2026-06-19T00:00:00Z"},
        {"key_id": "KEY-003", "algorithm": "ECC-P256", "created_timestamp": "2025-06-01T00:00:00Z"},
    ]
    
    for key in keys:
        monitor.register_key(key)
    
    recommendations = monitor.get_all_rotation_recommendations()
    # Should have at least 2 recommendations (RSA and ECC)
    assert len(recommendations) >= 2
    return True


def test_health_dashboard_generation() -> bool:
    """Test complete health dashboard generation"""
    monitor = AlgorithmHealthMonitor()
    
    monitor.register_key({
        "key_id": "KEY-001",
        "algorithm": "KYBER-768",
        "created_timestamp": "2026-03-01T00:00:00Z",
    })
    monitor.register_key({
        "key_id": "KEY-002",
        "algorithm": "RSA-2048",
        "created_timestamp": "2025-06-01T00:00:00Z",
    })
    
    dashboard = monitor.generate_health_dashboard()
    
    # Validate all fields exist
    assert dashboard.overall_security_score > 0
    assert dashboard.keys_tracked == 2
    assert dashboard.algorithms_monitored > 0
    
    assert "algorithm_health_summary" in dashboard.__dict__
    assert "rotation_recommendations" in dashboard.__dict__
    assert "compliance_status" in dashboard.__dict__
    assert "risk_assessment" in dashboard.__dict__
    
    # Should have compliance issues due to RSA
    assert dashboard.compliance_status["quantum_vulnerable_keys"] == 1
    return True


def test_compliance_reporting() -> bool:
    """Test compliance status reporting"""
    monitor = AlgorithmHealthMonitor()
    
    # All quantum-safe keys
    monitor.register_key({
        "key_id": "SAFE-KEY-001",
        "algorithm": "KYBER-768",
        "created_timestamp": "2026-06-01T00:00:00Z",
    })
    monitor.register_key({
        "key_id": "SAFE-KEY-002",
        "algorithm": "DILITHIUM-3",
        "created_timestamp": "2026-06-01T00:00:00Z",
    })
    
    dashboard = monitor.generate_health_dashboard()
    
    # Should be FIPS compliant with no vulnerable keys
    assert dashboard.compliance_status["quantum_vulnerable_keys"] == 0
    assert dashboard.compliance_status["compliance_percentage"] == 100.0
    return True


def test_dashboard_json_export() -> bool:
    """Test dashboard JSON export functionality"""
    monitor = AlgorithmHealthMonitor()
    
    monitor.register_key({
        "key_id": "KEY-001",
        "algorithm": "KYBER-768",
        "created_timestamp": "2026-06-01T00:00:00Z",
    })
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        result = monitor.export_dashboard_json(temp_path)
        assert result is True
        
        with open(temp_path, 'r') as f:
            exported = json.load(f)
        
        assert "overall_security_score" in exported
        assert "compliance_status" in exported
        assert "rotation_recommendations" in exported
        return True
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_statistics_reporting() -> bool:
    """Test statistics reporting"""
    monitor = AlgorithmHealthMonitor()
    
    monitor.register_key({
        "key_id": "KEY-001",
        "algorithm": "KYBER-768",
        "created_timestamp": "2026-06-01T00:00:00Z",
    })
    
    for _ in range(100):
        monitor.record_key_usage("KEY-001", "ENCRYPT")
    
    stats = monitor.get_statistics()
    
    assert stats["keys_tracked"] == 1
    assert stats["algorithms_monitored"] > 0
    assert "total_operations" in stats
    assert "recommendations_pending" in stats
    return True


def test_sample_monitor_function() -> bool:
    """Test the sample monitor creation function"""
    result = create_sample_monitor()
    
    assert "monitor_stats" in result
    assert "dashboard" in result
    assert "recommendations_count" in result
    assert result["monitor_stats"]["keys_tracked"] > 0
    return True


def test_security_level_enum() -> bool:
    """Test security level enum values are correct"""
    assert SecurityLevel.LEVEL_1 == 1
    assert SecurityLevel.LEVEL_3 == 3
    assert SecurityLevel.LEVEL_5 == 5
    return True


def test_algorithm_status_enum() -> bool:
    """Test algorithm status enum"""
    assert AlgorithmStatus.STANDARDIZED == "STANDARDIZED"
    assert AlgorithmStatus.DEPRECATED == "DEPRECATED"
    return True


def main() -> Dict[str, Any]:
    """Run all tests and generate report"""
    tests = [
        ("Algorithm Registry Initialization", test_algorithm_registry_initialization),
        ("Algorithm Health Scoring", test_algorithm_health_scoring),
        ("Recommended Algorithms Filtering", test_recommended_algorithms_filtering),
        ("Monitor Initialization", test_monitor_initialization),
        ("Key Registration", test_key_registration),
        ("Invalid Key Registration Rejection", test_invalid_key_registration_rejection),
        ("Key Usage Tracking", test_key_usage_tracking),
        ("Unknown Key Usage Rejection", test_unknown_key_usage_rejection),
        ("Quantum Risk Calculation", test_quantum_risk_calculation),
        ("Rotation Recommendation (Deprecated Algorithm)", test_rotation_recommendation_for_deprecated_algorithm),
        ("Rotation Recommendation (Old Key)", test_rotation_recommendation_for_old_key),
        ("No Recommendation (Good Key)", test_no_recommendation_for_good_key),
        ("All Rotation Recommendations", test_all_rotation_recommendations),
        ("Health Dashboard Generation", test_health_dashboard_generation),
        ("Compliance Reporting", test_compliance_reporting),
        ("Dashboard JSON Export", test_dashboard_json_export),
        ("Statistics Reporting", test_statistics_reporting),
        ("Sample Monitor Function", test_sample_monitor_function),
        ("Security Level Enum", test_security_level_enum),
        ("Algorithm Status Enum", test_algorithm_status_enum),
    ]
    
    print("=" * 65)
    print("QuantumCrypt Algorithm Health Monitor - Test Suite")
    print("=" * 65)
    
    results = []
    for test_name, test_func in tests:
        print(f"\nRunning: {test_name}...", end=" ")
        result = run_test(test_name, test_func)
        results.append(result)
        
        if result["passed"]:
            print("PASSED")
        else:
            print(f"FAILED: {result['error']}")
    
    # Summary
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    
    print("\n" + "=" * 65)
    print(f"TEST SUMMARY: {passed}/{total} tests passed")
    print("=" * 65)
    
    report = {
        "test_run_timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "module": "post_quantum_algorithm_health_monitor_rotation_advisor",
        "total_tests": total,
        "passed_tests": passed,
        "failed_tests": total - passed,
        "pass_rate": round(passed / total * 100, 2),
        "test_results": results,
        "status": "SUCCESS" if passed == total else "PARTIAL_SUCCESS",
    }
    
    # Save results
    with open("test_results_algorithm_health_monitor.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nResults saved to: test_results_algorithm_health_monitor.json")
    
    return report


if __name__ == "__main__":
    main()
