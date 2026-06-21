#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure MPC Engine v15
Real production-grade tests for QuantumCrypt-AI
"""

import json
import sys
import time
from typing import Dict, Any

# Add the module to path
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_secure_mpc_engine_v15_2026_june import (
    SecureMPCEngineV15,
    ShamirSecretSharingPQ,
    BeaverTripleGenerator,
    ZeroKnowledgeProverV15,
    ConstantTimeOperations,
    SecurityLevel,
    OperationType,
)


def run_tests() -> Dict[str, Any]:
    """Run all tests and return results"""
    results = {
        "test_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test_module": "SecureMPCEngineV15",
        "engine_version": "v15",
        "tests_passed": 0,
        "tests_failed": 0,
        "test_details": [],
        "performance_metrics": {},
    }
    
    print("=" * 70)
    print("QuantumCrypt-AI: Secure MPC Engine v15 Tests")
    print("=" * 70)
    
    # Test 1: Engine initialization
    print("\n[TEST 1] Engine Initialization")
    try:
        engine = SecureMPCEngineV15(
            num_parties=5,
            threshold=3,
            security_level=SecurityLevel.LEVEL_5,
            enable_side_channel_protection=True,
            enable_verifiable_sharing=True
        )
        
        stats = engine.get_statistics()
        assert stats["engine_version"] == "v15"
        assert stats["num_parties"] == 5
        assert stats["threshold"] == 3
        assert stats["security_level"] == 5
        assert stats["modulus_bits"] == 256
        
        print(f"  ✓ Engine v15 initialized successfully")
        print(f"    - Parties: 5, Threshold: 3, Security: Level 5 (256-bit)")
        print(f"    - VSS enabled: True, Side-channel protection: True")
        
        results["tests_passed"] += 1
        results["test_details"].append({"test": "engine_init", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "engine_init", "status": "FAILED", "error": str(e)})
    
    # Test 2: Secret Sharing and Reconstruction
    print("\n[TEST 2] Verifiable Secret Sharing & Reconstruction")
    try:
        test_secrets = [42, 123456789, 999999999999]
        
        for secret in test_secrets:
            shares, mac_key, vss_meta = engine.share_secret(secret)
            
            assert len(shares) == 5
            assert all(s.modulus == engine.sss.modulus for s in shares)
            
            # Reconstruct with threshold shares
            reconstructed, verified = engine.reconstruct(shares[:3], mac_key)
            
            assert reconstructed == secret
            assert verified == True
            
            print(f"  ✓ Secret {secret} -> reconstructed: {reconstructed}, verified: {verified}")
        
        results["tests_passed"] += 1
        results["test_details"].append({
            "test": "secret_sharing", 
            "status": "PASSED",
            "secrets_tested": len(test_secrets)
        })
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "secret_sharing", "status": "FAILED", "error": str(e)})
    
    # Test 3: Secure Addition
    print("\n[TEST 3] Secure Addition (MPC)")
    try:
        a = 100
        b = 200
        expected = (a + b) % engine.sss.modulus
        
        shares_a, _, _ = engine.share_secret(a)
        shares_b, _, _ = engine.share_secret(b)
        
        result = engine.secure_add(shares_a, shares_b)
        
        assert result.result == expected
        assert result.operation_type == OperationType.ADD
        assert result.verification_passed == True
        
        print(f"  ✓ 100 + 200 = {result.result} (expected: {expected})")
        print(f"    Computation time: {result.computation_time_ms:.4f}ms")
        
        results["tests_passed"] += 1
        results["test_details"].append({
            "test": "secure_add", 
            "status": "PASSED",
            "result": result.result,
            "time_ms": round(result.computation_time_ms, 4)
        })
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "secure_add", "status": "FAILED", "error": str(e)})
    
    # Test 4: Secure Multiplication with Beaver Triples
    print("\n[TEST 4] Secure Multiplication (Beaver Triples)")
    try:
        a = 17
        b = 31
        expected = (a * b) % engine.sss.modulus
        
        shares_a, _, _ = engine.share_secret(a)
        shares_b, _, _ = engine.share_secret(b)
        
        start = time.time()
        result = engine.secure_mul(shares_a, shares_b)
        elapsed = time.time() - start
        
        assert result.result == expected
        assert result.operation_type == OperationType.MUL
        assert result.proof is not None  # ZK proof included
        
        print(f"  ✓ 17 * 31 = {result.result} (expected: {expected})")
        print(f"    Computation time: {result.computation_time_ms:.4f}ms")
        print(f"    ZK Proof included: Yes")
        print(f"    Triple verification: {result.verification_passed}")
        
        results["tests_passed"] += 1
        results["test_details"].append({
            "test": "secure_mul", 
            "status": "PASSED",
            "result": result.result,
            "time_ms": round(result.computation_time_ms, 4),
            "zk_proof": True
        })
        results["performance_metrics"]["mul_time_ms"] = round(result.computation_time_ms, 4)
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "secure_mul", "status": "FAILED", "error": str(e)})
    
    # Test 5: Constant-time Comparison
    print("\n[TEST 5] Constant-time Secure Comparison")
    try:
        # Test equality (static methods)
        assert ConstantTimeOperations.ct_compare_eq(42, 42, 64) == True
        assert ConstantTimeOperations.ct_compare_eq(42, 99, 64) == False
        
        # Test greater than
        assert ConstantTimeOperations.ct_compare_gt(100, 50, 64) == True
        assert ConstantTimeOperations.ct_compare_gt(50, 100, 64) == False
        assert ConstantTimeOperations.ct_compare_gt(50, 50, 64) == False
        
        print("  ✓ Constant-time equality: PASS")
        print("  ✓ Constant-time greater-than: PASS")
        
        # MPC secure compare
        shares_100, _, _ = engine.share_secret(100)
        shares_50, _, _ = engine.share_secret(50)
        
        result_gt = engine.secure_compare(shares_100, shares_50)
        result_eq = engine.secure_equal(shares_100, shares_100)
        
        assert result_gt.result == 1  # 100 > 50
        assert result_eq.result == 1  # 100 == 100
        
        print(f"  ✓ MPC compare (100>50): result={result_gt.result}")
        print(f"  ✓ MPC equal (100==100): result={result_eq.result}")
        
        results["tests_passed"] += 1
        results["test_details"].append({
            "test": "constant_time_compare", 
            "status": "PASSED"
        })
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "constant_time_compare", "status": "FAILED", "error": str(e)})
    
    # Test 6: Beaver Triple Generation & Verification
    print("\n[TEST 6] Beaver Triple Generation & Verification")
    try:
        beaver_gen = BeaverTripleGenerator(engine.sss, 5, 3)
        triple = beaver_gen.generate_triple()
        
        assert triple.verify() == True
        assert triple.verified == True
        
        # Verify c = a * b
        a, _ = ShamirSecretSharingPQ.reconstruct_static(triple.a_shares)
        b, _ = ShamirSecretSharingPQ.reconstruct_static(triple.b_shares)
        c, _ = ShamirSecretSharingPQ.reconstruct_static(triple.c_shares)
        
        expected_c = (a * b) % engine.sss.modulus
        assert c == expected_c
        
        print(f"  ✓ Beaver triple verified: c = a * b")
        print(f"    a = {a}, b = {b}, c = {c}")
        print(f"    a * b mod p = {expected_c}")
        
        results["tests_passed"] += 1
        results["test_details"].append({
            "test": "beaver_triple", 
            "status": "PASSED",
            "verified": triple.verified
        })
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "beaver_triple", "status": "FAILED", "error": str(e)})
    
    # Test 7: Zero-Knowledge Proofs
    print("\n[TEST 7] Zero-Knowledge Proofs (Fiat-Shamir)")
    try:
        zk = ZeroKnowledgeProverV15(SecurityLevel.LEVEL_5)
        
        witness = 12345
        statement = "I know the secret value x"
        
        proof = zk.generate_proof(witness, statement)
        
        assert proof["zk_version"] == "v15"
        assert proof["security_level"] == 5
        assert "commitment" in proof
        assert "challenge" in proof
        assert "response" in proof
        
        # Verify proof
        verified = zk.verify_proof(proof, witness)
        assert verified == True
        
        print(f"  ✓ ZK Proof generated and verified")
        print(f"    Version: {proof['zk_version']}")
        print(f"    Security Level: {proof['security_level']}")
        print(f"    Verification: {verified}")
        
        results["tests_passed"] += 1
        results["test_details"].append({
            "test": "zk_proofs", 
            "status": "PASSED",
            "verified": verified
        })
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "zk_proofs", "status": "FAILED", "error": str(e)})
    
    # Test 8: Pedersen Commitments (VSS)
    print("\n[TEST 8] Pedersen Commitments (Verifiable Secret Sharing)")
    try:
        from quantum_crypt.post_quantum_secure_mpc_engine_v15_2026_june import PedersenCommitment
        
        pedersen = PedersenCommitment(SecurityLevel.LEVEL_5)
        
        value = 999
        commitment, opening = pedersen.commit(value)
        
        # Valid verification
        assert pedersen.verify(commitment, value, opening) == True
        
        # Invalid verification (wrong value)
        assert pedersen.verify(commitment, value + 1, opening) == False
        
        # Invalid verification (wrong opening)
        assert pedersen.verify(commitment, value, opening + 1) == False
        
        print(f"  ✓ Pedersen commitment: valid opening = PASS")
        print(f"  ✓ Pedersen commitment: wrong value = correctly REJECT")
        print(f"  ✓ Pedersen commitment: wrong opening = correctly REJECT")
        
        results["tests_passed"] += 1
        results["test_details"].append({
            "test": "pedersen_commitments", 
            "status": "PASSED"
        })
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "pedersen_commitments", "status": "FAILED", "error": str(e)})
    
    # Test 9: Post-Quantum MAC
    print("\n[TEST 9] Post-Quantum MAC Authentication")
    try:
        from quantum_crypt.post_quantum_secure_mpc_engine_v15_2026_june import PostQuantumMAC
        import secrets
        
        key = secrets.token_bytes(64)
        mac = PostQuantumMAC(key, SecurityLevel.LEVEL_5)
        
        value = 123456789
        tag = mac.generate(value)
        
        assert mac.verify(value, tag) == True
        assert mac.verify(value + 1, tag) == False
        
        print(f"  ✓ PQ MAC: valid tag = VERIFIED")
        print(f"  ✓ PQ MAC: wrong value = correctly REJECTED")
        
        results["tests_passed"] += 1
        results["test_details"].append({
            "test": "pq_mac", 
            "status": "PASSED"
        })
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "pq_mac", "status": "FAILED", "error": str(e)})
    
    # Test 10: Performance Benchmark
    print("\n[TEST 10] Performance Benchmark")
    try:
        num_ops = 20
        start = time.time()
        
        for i in range(num_ops):
            a = i + 1
            b = i + 2
            sa, _, _ = engine.share_secret(a)
            sb, _, _ = engine.share_secret(b)
            engine.secure_add(sa, sb)
        
        total_time = (time.time() - start) * 1000
        avg_time = total_time / num_ops
        
        stats = engine.get_statistics()
        
        print(f"  ✓ {num_ops} MPC operations completed")
        print(f"    Total time: {total_time:.2f}ms")
        print(f"    Avg time: {avg_time:.2f}ms per operation")
        print(f"    Total operations: {stats['operation_count']}")
        print(f"    Avg computation time: {stats['avg_operation_time_ms']}ms")
        
        results["tests_passed"] += 1
        results["test_details"].append({
            "test": "performance", 
            "status": "PASSED",
            "operations": num_ops,
            "avg_time_ms": round(avg_time, 2)
        })
        results["performance_metrics"]["avg_operation_ms"] = round(avg_time, 2)
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "performance", "status": "FAILED", "error": str(e)})
    
    # Summary
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {results['tests_passed']} PASSED, {results['tests_failed']} FAILED")
    print("=" * 70)
    
    print("\nEngine Statistics:")
    for k, v in engine.get_statistics().items():
        print(f"  {k}: {v}")
    
    results["success"] = results["tests_failed"] == 0
    results["final_engine_stats"] = engine.get_statistics()
    
    return results


if __name__ == "__main__":
    test_results = run_tests()
    
    # Save results
    with open("/home/user/autonomous-developer/QuantumCrypt-AI/test_results_secure_mpc_engine_v14.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nResults saved to test_results_secure_mpc_engine_v14.json")
    
    sys.exit(0 if test_results["success"] else 1)
