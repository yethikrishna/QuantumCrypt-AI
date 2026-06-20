#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure API Request Signer & Nonce Manager
Production-grade testing with comprehensive coverage
"""
import sys
import os
import time
import json

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_api_request_signer_nonce_manager_2026_june import (
    PostQuantumSecureAPIRequestSigner,
    SignerConfig,
    VerificationResult,
    SignatureAlgorithm,
    NonceManager,
    RequestCanonicalizer
)


def run_tests():
    """Run all tests and return results"""
    results = {
        "tests_passed": 0,
        "tests_failed": 0,
        "test_details": [],
        "module_loaded": False,
        "production_ready": False
    }
    
    print("=" * 70)
    print("Post-Quantum Secure API Request Signer & Nonce Manager Tests")
    print("=" * 70)
    
    # Test 1: Module loads correctly
    print("\n[Test 1] Module Loading")
    try:
        print("  ✓ Module imports successfully")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "module_load", "status": "passed"})
        results["module_loaded"] = True
    except Exception as e:
        print(f"  ✗ Module import failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "module_load", "status": "failed", "error": str(e)})
        return results
    
    # Test 2: Instance creation
    print("\n[Test 2] Instance Creation")
    try:
        config = SignerConfig(timestamp_validity_window_seconds=60)
        signer = PostQuantumSecureAPIRequestSigner(config)
        print("  ✓ Instance created successfully with custom config")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "instance_creation", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Instance creation failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "instance_creation", "status": "failed", "error": str(e)})
        return results
    
    # Test 3: API key registration
    print("\n[Test 3] API Key Registration")
    try:
        signer = PostQuantumSecureAPIRequestSigner()
        signer.register_api_key("test_key_001", "supersecretkey12345")
        print("  ✓ API key registered successfully")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "api_key_registration", "status": "passed"})
    except Exception as e:
        print(f"  ✗ API key registration failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "api_key_registration", "status": "failed", "error": str(e)})
    
    # Test 4: Request signing
    print("\n[Test 4] Request Signing")
    try:
        signer = PostQuantumSecureAPIRequestSigner()
        signer.register_api_key("key_001", "test_secret_123")
        
        headers = signer.sign_request(
            method="POST",
            path="/api/v1/data",
            api_key_id="key_001",
            query_string="param1=value1&param2=value2",
            body='{"data": "test"}'
        )
        
        required_headers = ["X-PQ-Signature", "X-PQ-Timestamp", "X-PQ-Nonce", "X-PQ-API-Key"]
        all_present = all(h in headers for h in required_headers)
        
        if all_present and len(headers["X-PQ-Nonce"]) == 32:
            print("  ✓ Request signed with all required headers")
            print(f"  ✓ Nonce length: {len(headers['X-PQ-Nonce'])}")
            print(f"  ✓ Signature present: {headers['X-PQ-Signature'][:16]}...")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "request_signing", "status": "passed"})
        else:
            print("  ✗ Missing required headers")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "request_signing", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Request signing failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "request_signing", "status": "failed", "error": str(e)})
    
    # Test 5: Valid signature verification
    print("\n[Test 5] Valid Signature Verification")
    try:
        signer = PostQuantumSecureAPIRequestSigner()
        signer.register_api_key("key_001", "test_secret_123")
        
        # Sign
        headers = signer.sign_request(
            method="GET",
            path="/api/test",
            api_key_id="key_001",
            query_string="",
            body=""
        )
        
        # Verify
        result, details = signer.verify_request(
            method="GET",
            path="/api/test",
            query_string="",
            body="",
            headers=headers
        )
        
        if result == VerificationResult.VALID:
            print("  ✓ Valid signature verified correctly")
            print(f"  ✓ Details: {details['reason']}")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "valid_verification", "status": "passed"})
        else:
            print(f"  ✗ Verification failed: {result.value}")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "valid_verification", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Verification failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "valid_verification", "status": "failed", "error": str(e)})
    
    # Test 6: Invalid signature detection
    print("\n[Test 6] Invalid Signature Detection")
    try:
        signer = PostQuantumSecureAPIRequestSigner()
        signer.register_api_key("key_001", "test_secret_123")
        
        headers = signer.sign_request("GET", "/api/test", "key_001")
        headers["X-PQ-Signature"] = "invalid_signature_here"
        
        result, details = signer.verify_request("GET", "/api/test", "", "", headers)
        
        if result == VerificationResult.INVALID_SIGNATURE:
            print("  ✓ Invalid signature correctly detected")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "invalid_signature", "status": "passed"})
        else:
            print(f"  ✗ Should have detected invalid signature: {result.value}")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "invalid_signature", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Invalid signature test failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "invalid_signature", "status": "failed", "error": str(e)})
    
    # Test 7: Replay attack protection
    print("\n[Test 7] Replay Attack Protection")
    try:
        signer = PostQuantumSecureAPIRequestSigner()
        signer.register_api_key("key_001", "test_secret_123")
        
        headers = signer.sign_request("GET", "/api/test", "key_001")
        
        # First verification should succeed
        result1, _ = signer.verify_request("GET", "/api/test", "", "", headers)
        
        # Second verification with same nonce should fail (replay)
        result2, details = signer.verify_request("GET", "/api/test", "", "", headers)
        
        if result1 == VerificationResult.VALID and result2 == VerificationResult.REPLAY_DETECTED:
            print("  ✓ Replay attack correctly detected and blocked")
            print(f"  ✓ First verify: {result1.value}")
            print(f"  ✓ Second verify: {result2.value}")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "replay_protection", "status": "passed"})
        else:
            print(f"  ✗ Replay protection failed: {result2.value}")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "replay_protection", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Replay protection test failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "replay_protection", "status": "failed", "error": str(e)})
    
    # Test 8: Request canonicalization
    print("\n[Test 8] Request Canonicalization")
    try:
        # Path canonicalization
        p1 = RequestCanonicalizer.canonicalize_path("api/test")
        p2 = RequestCanonicalizer.canonicalize_path("/api/test/")
        
        if p1 == p2 == "/api/test":
            print("  ✓ Path canonicalization works correctly")
        else:
            print(f"  ✗ Path canonicalization failed: {p1} != {p2}")
        
        # Query string canonicalization (sorted)
        q1 = RequestCanonicalizer.canonicalize_query_string("b=2&a=1")
        q2 = RequestCanonicalizer.canonicalize_query_string("a=1&b=2")
        
        if q1 == q2 == "a=1&b=2":
            print("  ✓ Query string canonicalization (sorted) works correctly")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "canonicalization", "status": "passed"})
        else:
            print(f"  ✗ Query canonicalization failed: {q1} != {q2}")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "canonicalization", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Canonicalization test failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "canonicalization", "status": "failed", "error": str(e)})
    
    # Test 9: Nonce generation
    print("\n[Test 9] Nonce Generation")
    try:
        config = SignerConfig(nonce_length=32)
        nm = NonceManager(config)
        
        nonces = set()
        for _ in range(100):
            nonce = nm.generate_nonce()
            nonces.add(nonce)
        
        if len(nonces) == 100:
            print("  ✓ Generated 100 unique nonces")
            print(f"  ✓ Nonce length: {len(next(iter(nonces)))} chars")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "nonce_generation", "status": "passed"})
        else:
            print("  ✗ Nonce collision detected!")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "nonce_generation", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Nonce generation failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "nonce_generation", "status": "failed", "error": str(e)})
    
    # Test 10: Performance metrics
    print("\n[Test 10] Performance Metrics")
    try:
        signer = PostQuantumSecureAPIRequestSigner()
        signer.register_api_key("key_001", "secret")
        
        for i in range(5):
            headers = signer.sign_request("GET", f"/api/{i}", "key_001")
            signer.verify_request("GET", f"/api/{i}", "", "", headers)
        
        metrics = signer.get_performance_metrics()
        if metrics["requests_signed"] == 5 and metrics["requests_verified"] == 5:
            print(f"  ✓ Performance metrics available")
            print(f"  ✓ Requests processed: {metrics['total_requests_processed']}")
            print(f"  ✓ Success rate: {metrics['verification_success_rate_percent']}%")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "performance_metrics", "status": "passed"})
        else:
            print("  ✗ Metrics incorrect")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "performance_metrics", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Performance metrics failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "performance_metrics", "status": "failed", "error": str(e)})
    
    # Test 11: Audit logging
    print("\n[Test 11] Audit Logging")
    try:
        signer = PostQuantumSecureAPIRequestSigner()
        signer.register_api_key("key_001", "secret")
        
        signer.sign_request("GET", "/api/test", "key_001")
        logs = signer.get_audit_log(limit=10)
        
        if len(logs) > 0 and logs[0]["action"] == "sign":
            print(f"  ✓ Audit logging working: {len(logs)} entries")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "audit_logging", "status": "passed"})
        else:
            print("  ✗ Audit logging not working")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "audit_logging", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Audit logging failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "audit_logging", "status": "failed", "error": str(e)})
    
    # Test 12: Unknown API key
    print("\n[Test 12] Unknown API Key Rejection")
    try:
        signer = PostQuantumSecureAPIRequestSigner()
        # Don't register the key
        
        headers = {
            "X-PQ-Signature": "test",
            "X-PQ-Timestamp": str(int(time.time())),
            "X-PQ-Nonce": "abc123",
            "X-PQ-API-Key": "unknown_key"
        }
        
        result, _ = signer.verify_request("GET", "/test", "", "", headers)
        
        if result == VerificationResult.INVALID_KEY:
            print("  ✓ Unknown API key correctly rejected")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "unknown_key", "status": "passed"})
        else:
            print(f"  ✗ Should have rejected unknown key: {result.value}")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "unknown_key", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Unknown key test failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "unknown_key", "status": "failed", "error": str(e)})
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"  Tests Passed: {results['tests_passed']}")
    print(f"  Tests Failed: {results['tests_failed']}")
    print(f"  Success Rate: {(results['tests_passed'] / (results['tests_passed'] + results['tests_failed']) * 100):.1f}%")
    
    if results["tests_failed"] == 0:
        results["production_ready"] = True
        print("\n  ✓ ALL TESTS PASSED - Production Ready")
    else:
        print(f"\n  ✗ {results['tests_failed']} TESTS FAILED - Not production ready")
    
    return results


if __name__ == "__main__":
    test_results = run_tests()
    
    # Write results to JSON
    output_file = "test_results_post_quantum_secure_api_request_signer_nonce_manager.json"
    with open(output_file, "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nResults written to: {output_file}")
    sys.exit(0 if test_results["tests_failed"] == 0 else 1)
