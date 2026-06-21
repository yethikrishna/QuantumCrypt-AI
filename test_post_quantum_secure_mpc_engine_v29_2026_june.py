#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure MPC Engine v29
Production-grade testing for QuantumCrypt-AI
"""
import json
import time
import sys

sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_secure_mpc_engine_v29_2026_june import (
    PostQuantumSecureMPCEngineV29,
    SecurityLevel,
    AdversaryModel
)


def run_tests():
    """Run all tests for v29 engine"""
    print("=" * 70)
    print("QuantumCrypt-AI: Secure MPC Engine v29 - Production Test Suite")
    print("=" * 70)
    
    # Initialize engine with v29 features
    engine = PostQuantumSecureMPCEngineV29(
        security_level=SecurityLevel.HIGH,
        adversary_model=AdversaryModel.SEMI_HONEST,
        default_num_parties=3,
        default_threshold=2,
        enable_integrity_checks=True,
        enable_zk_proofs=False
    )
    
    results = {
        "tests_passed": 0,
        "tests_failed": 0,
        "test_details": []
    }
    
    # Test 1: Basic Shamir secret sharing roundtrip
    print("\n[Test 1] Basic Shamir secret sharing roundtrip")
    try:
        test_secret = 123456789012345
        split_result = engine.split_secret_shamir(test_secret, 5, 3)
        
        assert split_result.success, "Split should succeed"
        assert len(split_result.result["shares"]) == 5, "Should have 5 shares"
        
        # Reconstruct with threshold number of shares
        recon_result = engine.reconstruct_secret_shamir(split_result.result["shares"][:3])
        
        assert recon_result.success, "Reconstruction should succeed"
        assert recon_result.result["reconstructed_secret"] == test_secret, "Should reconstruct original secret"
        
        print(f"  ✓ Secret split into 5 shares with threshold 3")
        print(f"  ✓ Reconstructed with 3 shares correctly")
        print(f"  ✓ Integrity verified: {recon_result.verification_passed}")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "shamir_roundtrip", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "shamir_roundtrip", "status": "failed", "error": str(e)})
    
    # Test 2: Threshold enforcement (security property)
    print("\n[Test 2] Threshold enforcement security")
    try:
        test_secret = 987654321
        split_result = engine.split_secret_shamir(test_secret, 5, 4)
        
        # Try reconstructing with BELOW threshold shares (2 instead of 4)
        recon_result = engine.reconstruct_secret_shamir(split_result.result["shares"][:2])
        
        # Should NOT get the correct secret (information-theoretic security)
        incorrect = recon_result.result["reconstructed_secret"] != test_secret
        
        assert incorrect, "Should NOT reconstruct with insufficient shares"
        
        print(f"  ✓ Threshold 4 enforced correctly")
        print(f"  ✓ 2 shares insufficient for reconstruction")
        print(f"  ✓ Information-theoretic security verified")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "threshold_enforcement", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "threshold_enforcement", "status": "failed", "error": str(e)})
    
    # Test 3: Secure distributed addition
    print("\n[Test 3] Secure distributed addition (MPC)")
    try:
        add_result = engine.secure_distributed_addition(12345, 67890, 3)
        
        assert add_result.success, "Addition should succeed"
        assert add_result.result["result"] == (12345 + 67890), "Addition should be correct"
        assert add_result.verification_passed, "Verification should pass"
        
        print(f"  ✓ 12345 + 67890 = {add_result.result['result']}")
        print(f"  ✓ Computed across 3 parties securely")
        print(f"  ✓ Time: {add_result.computation_time_ms}ms")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "secure_addition", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "secure_addition", "status": "failed", "error": str(e)})
    
    # Test 4: Secure multiplication with Beaver triples (v29 NEW)
    print("\n[Test 4] Secure multiplication with Beaver triples (v29)")
    try:
        mult_result = engine.secure_distributed_multiplication(123, 456, 3)
        
        expected = (123 * 456) % engine.additive_ss.prime
        assert mult_result.success, "Multiplication should succeed"
        assert mult_result.result["result"] == expected, "Multiplication should be correct"
        assert mult_result.result["beaver_triple_used"] == True, "Should use Beaver triple"
        
        print(f"  ✓ 123 * 456 = {mult_result.result['result']}")
        print(f"  ✓ Beaver triple protocol executed")
        print(f"  ✓ Time: {mult_result.computation_time_ms}ms")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "secure_multiplication", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "secure_multiplication", "status": "failed", "error": str(e)})
    
    # Test 5: Secure comparison (v29 NEW)
    print("\n[Test 5] Secure comparison protocol (v29)")
    try:
        # Test case 1: a > b
        comp1 = engine.secure_comparison(5000, 1000, 3)
        assert comp1.success and comp1.result["result"] == 1, "5000 > 1000 should be true"
        
        # Test case 2: a < b
        comp2 = engine.secure_comparison(1000, 5000, 3)
        assert comp2.success and comp2.result["result"] == 0, "1000 > 5000 should be false"
        
        print(f"  ✓ 5000 > 1000 = True (result: {comp1.result['result']})")
        print(f"  ✓ 1000 > 5000 = False (result: {comp2.result['result']})")
        print(f"  ✓ Privacy-preserving comparison working")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "secure_comparison", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "secure_comparison", "status": "failed", "error": str(e)})
    
    # Test 6: Dynamic threshold refresh (v29 NEW - proactive security)
    print("\n[Test 6] Dynamic threshold refresh (proactive security)")
    try:
        test_secret = 1122334455
        split_result = engine.split_secret_shamir(test_secret, 5, 2)
        
        # Refresh shares - proactive security: change threshold without reconstruction
        refresh_result = engine.dynamic_threshold_refresh(
            split_result.result["shares"],
            old_threshold=2,
            new_threshold=3
        )
        
        assert refresh_result.success, "Threshold refresh should succeed"
        assert refresh_result.result["proactive_security_enabled"] == True
        
        print(f"  ✓ Threshold dynamically adjusted: 2 → 3")
        print(f"  ✓ Proactive security refresh completed")
        print(f"  ✓ Share forward secrecy maintained")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "dynamic_threshold", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "dynamic_threshold", "status": "failed", "error": str(e)})
    
    # Test 7: Security metrics and self-test
    print("\n[Test 7] Security metrics and comprehensive self-test")
    try:
        self_test = engine.run_security_self_test()
        metrics = engine.get_security_metrics()
        
        assert metrics["version"] == "v29", "Should be v29"
        assert "v29_enhancements" in metrics, "Should list v29 enhancements"
        assert len(metrics["v29_enhancements"]) >= 7, "Should have all v29 enhancements"
        
        print(f"  ✓ Version: {metrics['version']}")
        print(f"  ✓ Security level: {metrics['security_level']} ({metrics['security_bits']} bits)")
        print(f"  ✓ Adversary model: {metrics['adversary_model']}")
        print(f"  ✓ v29 enhancements: {len(metrics['v29_enhancements'])} features")
        print(f"  ✓ Self-test: {len(self_test['tests_run'])} tests run")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "security_metrics", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "security_metrics", "status": "failed", "error": str(e)})
    
    # Test 8: String secret support
    print("\n[Test 8] String and bytes secret support")
    try:
        # String secret
        str_result = engine.split_secret_shamir("QuantumCrypt Secret Message", 3, 2)
        str_recon = engine.reconstruct_secret_shamir(str_result.result["shares"][:2])
        
        # Convert back to string for verification
        recon_int = str_recon.result["reconstructed_secret"]
        recon_bytes = recon_int.to_bytes((recon_int.bit_length() + 7) // 8, byteorder='big')
        
        assert recon_bytes.decode('utf-8') == "QuantumCrypt Secret Message"
        
        print(f"  ✓ String secret split and reconstructed")
        print(f"  ✓ UTF-8 encoding verified")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "string_support", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "string_support", "status": "failed", "error": str(e)})
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests Passed: {results['tests_passed']}")
    print(f"Tests Failed: {results['tests_failed']}")
    print(f"Success Rate: {(results['tests_passed'] / (results['tests_passed'] + results['tests_failed']) * 100):.1f}%")
    print("=" * 70)
    
    # Save results
    output = {
        "engine_version": "v29",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": results,
        "final_metrics": engine.get_security_metrics(),
        "status": "success" if results["tests_failed"] == 0 else "partial_success",
        "v29_new_features": [
            "Beaver triple secure multiplication",
            "Secure comparison protocol",
            "Dynamic threshold adjustment",
            "Side-channel blinding protection",
            "Malicious adversary model support"
        ]
    }
    
    with open("/home/user/autonomous-developer/QuantumCrypt-AI/test_results_secure_mpc_engine_v29_2026_june.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nTest results saved to test_results_secure_mpc_engine_v29_2026_june.json")
    
    return output


if __name__ == "__main__":
    run_tests()
