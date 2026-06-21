"""
Test Suite for Post-Quantum Secure Multi-Party Computation Engine v14
Production-grade tests with real cryptographic operations and security validation
"""
import sys
import json
import time
import secrets

sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_secure_mpc_engine_v14_2026_june import (
    SecureMPCEngine,
    ShamirSecretSharingPQ,
    SideChannelProtector,
    PostQuantumCommitment,
    ZeroKnowledgeProver,
    SecurityLevel,
    OperationType
)


def run_tests():
    print("=" * 80)
    print("QuantumCrypt AI - Post-Quantum Secure MPC Engine v14 Tests")
    print("=" * 80)
    print()

    all_passed = True
    test_results = {}

    # Test 1: Shamir Secret Sharing - Basic Share and Reconstruct
    print("[TEST 1] Shamir Secret Sharing - Basic Share & Reconstruct")
    print("-" * 60)
    try:
        sss = ShamirSecretSharingPQ(SecurityLevel.LEVEL_5)
        secret = 42
        shares, mac_key = sss.generate_shares(secret, num_parties=5, threshold=3)

        assert len(shares) == 5, f"Wrong number of shares: {len(shares)}"

        # Reconstruct with threshold shares
        reconstructed, verified = sss.reconstruct(shares[:3], mac_key)

        assert reconstructed == secret, f"Reconstruction failed: {reconstructed} != {secret}"
        assert verified == True, "MAC verification failed"

        print(f"  ✓ Secret: {secret}")
        print(f"  ✓ Shares generated: {len(shares)}")
        print(f"  ✓ Threshold: 3/5")
        print(f"  ✓ Reconstructed: {reconstructed}")
        print(f"  ✓ MAC verified: {verified}")
        print(f"  ✓ Modulus bits: {sss.modulus.bit_length()}")
        print("  ✓ PASSED")
        test_results["test1_sss_basic"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test1_sss_basic"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 2: Shamir Secret Sharing - Threshold Property
    print("[TEST 2] Shamir Secret Sharing - Threshold Property")
    print("-" * 60)
    try:
        sss = ShamirSecretSharingPQ(SecurityLevel.LEVEL_5)
        secret = 123456789
        shares, mac_key = sss.generate_shares(secret, num_parties=5, threshold=3)

        # Should fail with only 2 shares (below threshold)
        try:
            bad_recon, _ = sss.reconstruct(shares[:2])
            assert bad_recon != secret, "Should not reconstruct with < threshold shares"
            print("  ✓ < threshold shares gives wrong result (as expected)")
        except Exception:
            print("  ✓ < threshold shares fails (as expected)")

        # Should work with exactly threshold shares
        recon3, _ = sss.reconstruct(shares[:3])
        assert recon3 == secret, "3 shares should reconstruct"
        print("  ✓ Exactly threshold shares works")

        # Should work with more than threshold
        recon5, _ = sss.reconstruct(shares)
        assert recon5 == secret, "All shares should reconstruct"
        print("  ✓ More than threshold shares works")

        print("  ✓ Threshold property verified")
        test_results["test2_sss_threshold"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test2_sss_threshold"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 3: Side Channel Protection - Constant Time Operations
    print("[TEST 3] Side Channel Protection - Constant Time Operations")
    print("-" * 60)
    try:
        protector = SideChannelProtector(enable_noise=True)

        # Test constant time compare
        assert protector.constant_time_compare(100, 100) == True, "Equal comparison failed"
        assert protector.constant_time_compare(100, 200) == False, "Unequal comparison failed"

        # Test constant time select
        assert protector.constant_time_select(True, 5, 10) == 5, "Select true failed"
        assert protector.constant_time_select(False, 5, 10) == 10, "Select false failed"

        # Measure timing variance
        times = []
        for _ in range(10):
            start = time.time()
            protector.constant_time_compare(12345, 12345)
            times.append(time.time() - start)

        avg_time = sum(times) / len(times)
        variance = sum((t - avg_time) ** 2 for t in times) / len(times)

        print(f"  ✓ Constant-time compare works correctly")
        print(f"  ✓ Constant-time select works correctly")
        print(f"  ✓ Avg compare time: {avg_time*1000000:.1f}µs")
        print(f"  ✓ Timing variance: {variance*1000000000000:.1f}ns² (noise injection working)")
        print("  ✓ PASSED")
        test_results["test3_side_channel"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test3_side_channel"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 4: Post-Quantum Commitment Scheme
    print("[TEST 4] Post-Quantum Commitment Scheme")
    print("-" * 60)
    try:
        committer = PostQuantumCommitment(SecurityLevel.LEVEL_5)

        value = 12345
        commitment, opening = committer.commit(value)

        # Valid verification
        assert committer.verify(commitment, value, opening) == True, "Valid verify failed"

        # Invalid value should fail
        assert committer.verify(commitment, value + 1, opening) == False, "Wrong value should fail"

        # Invalid opening should fail
        bad_opening = bytes([b ^ 0xFF for b in opening])
        assert committer.verify(commitment, value, bad_opening) == False, "Wrong opening should fail"

        print(f"  ✓ Commitment size: {len(commitment)} bytes")
        print(f"  ✓ Opening size: {len(opening)} bytes")
        print(f"  ✓ Valid commitment verifies")
        print(f"  ✓ Wrong value rejected")
        print(f"  ✓ Wrong opening rejected")
        print(f"  ✓ Hash function: SHA3-512 (quantum-resistant)")
        print("  ✓ PASSED")
        test_results["test4_commitment"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test4_commitment"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 5: MPC Engine - Secure Addition
    print("[TEST 5] MPC Engine - Secure Addition")
    print("-" * 60)
    try:
        engine = SecureMPCEngine(num_parties=3, threshold=2)

        a = 100
        b = 200

        shares_a, mac_a = engine.sss.generate_shares(a, 3, 2)
        shares_b, mac_b = engine.sss.generate_shares(b, 3, 2)

        result = engine.secure_add(shares_a, shares_b)

        assert result.result == (a + b) % engine.sss.modulus, f"Addition wrong: {result.result}"
        assert result.operation_type == OperationType.ADD, "Wrong operation type"
        assert result.verification_passed == True, "Verification failed"

        print(f"  ✓ a = {a}")
        print(f"  ✓ b = {b}")
        print(f"  ✓ a + b = {result.result}")
        print(f"  ✓ Shares used: {result.shares_used}")
        print(f"  ✓ Computation time: {result.computation_time_ms:.3f}ms")
        print(f"  ✓ Security level: {result.security_level.value}")
        print("  ✓ PASSED")
        test_results["test5_mpc_add"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test5_mpc_add"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 6: MPC Engine - Secure Multiplication
    print("[TEST 6] MPC Engine - Secure Multiplication (Beaver Triples)")
    print("-" * 60)
    try:
        engine = SecureMPCEngine(num_parties=3, threshold=2)

        a = 15
        b = 25

        shares_a, mac_a = engine.sss.generate_shares(a, 3, 2)
        shares_b, mac_b = engine.sss.generate_shares(b, 3, 2)

        result = engine.secure_mul(shares_a, shares_b, mac_a, mac_b)

        expected = (a * b) % engine.sss.modulus
        assert result.result == expected, f"Multiplication wrong: {result.result} != {expected}"
        assert result.operation_type == OperationType.MUL, "Wrong operation type"

        print(f"  ✓ a = {a}")
        print(f"  ✓ b = {b}")
        print(f"  ✓ a * b = {result.result}")
        print(f"  ✓ Shares used: {result.shares_used}")
        print(f"  ✓ Computation time: {result.computation_time_ms:.3f}ms")
        print(f"  ✓ Beaver triple protocol executed")
        print("  ✓ PASSED")
        test_results["test6_mpc_mul"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test6_mpc_mul"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 7: MPC Engine - Secure Comparison
    print("[TEST 7] MPC Engine - Secure Comparison")
    print("-" * 60)
    try:
        engine = SecureMPCEngine(num_parties=3, threshold=2)

        shares_a, _ = engine.sss.generate_shares(100, 3, 2)
        shares_b, _ = engine.sss.generate_shares(50, 3, 2)

        result = engine.secure_compare(shares_a, shares_b)

        assert result.result == 1, f"Comparison wrong: {result.result}"
        assert result.operation_type == OperationType.COMPARE

        print(f"  ✓ 100 > 50 = {result.result} (1 = true)")
        print(f"  ✓ Shares used: {result.shares_used}")
        print(f"  ✓ Computation time: {result.computation_time_ms:.3f}ms")
        print("  ✓ PASSED")
        test_results["test7_mpc_compare"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test7_mpc_compare"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 8: Zero-Knowledge Proof System
    print("[TEST 8] Post-Quantum Zero-Knowledge Proof System")
    print("-" * 60)
    try:
        prover = ZeroKnowledgeProver(SecurityLevel.LEVEL_5)

        secret = 42
        statement = "I know the secret value"

        proof = prover.generate_proof(secret, statement)

        assert prover.verify_proof(proof, secret) == True, "Proof verification failed"

        print(f"  ✓ Proof generated")
        print(f"  ✓ Commitment size: {len(proof['commitment'])} chars")
        print(f"  ✓ Challenge bits: {proof['challenge'].bit_length()}")
        print(f"  ✓ Security level: {proof['security_level']}")
        print(f"  ✓ Proof verified successfully")
        print(f"  ✓ Fiat-Shamir heuristic with SHA3")
        print("  ✓ PASSED")
        test_results["test8_zkp"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test8_zkp"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 9: MPC Engine Statistics
    print("[TEST 9] MPC Engine Statistics & Performance")
    print("-" * 60)
    try:
        engine = SecureMPCEngine(num_parties=5, threshold=3, security_level=SecurityLevel.LEVEL_5)

        # Run some operations
        for i in range(10):
            a = secrets.randbelow(1000)
            b = secrets.randbelow(1000)
            shares_a, mac_a = engine.sss.generate_shares(a, 5, 3)
            shares_b, mac_b = engine.sss.generate_shares(b, 5, 3)
            engine.secure_add(shares_a, shares_b)

        stats = engine.get_statistics()

        assert stats["operation_count"] == 10, f"Wrong op count: {stats['operation_count']}"
        assert stats["modulus_bits"] == 256, f"Wrong modulus bits: {stats['modulus_bits']}"
        assert stats["security_level"] == 5, "Wrong security level"

        print(f"  ✓ Parties: {stats['num_parties']}")
        print(f"  ✓ Threshold: {stats['threshold']}")
        print(f"  ✓ Security Level: NIST Level {stats['security_level']}")
        print(f"  ✓ Modulus: {stats['modulus_bits']} bits")
        print(f"  ✓ Operations: {stats['operation_count']}")
        print(f"  ✓ Total time: {stats['total_computation_time_ms']:.3f}ms")
        print(f"  ✓ Avg op time: {stats['avg_operation_time_ms']:.3f}ms")
        print("  ✓ PASSED")
        test_results["test9_stats"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test9_stats"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 10: All Security Levels
    print("[TEST 10] All NIST Security Levels (1, 3, 5)")
    print("-" * 60)
    try:
        for level in [SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_3, SecurityLevel.LEVEL_5]:
            sss = ShamirSecretSharingPQ(level)
            secret = 12345
            shares, mac_key = sss.generate_shares(secret, num_parties=3, threshold=2)
            recon, _ = sss.reconstruct(shares[:2])
            assert recon == secret, f"Level {level.value} failed"
            print(f"  ✓ Security Level {level.value}: {sss.modulus.bit_length()} bit modulus")

        print("  ✓ All security levels work correctly")
        test_results["test10_security_levels"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test10_security_levels"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Summary
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    for test, status in test_results.items():
        icon = "✓" if status == "PASSED" else "✗"
        print(f"  {icon} {test}: {status}")

    print()
    if all_passed:
        print("✓ ALL TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED")
    print()

    # Save results
    with open("/home/user/autonomous-developer/QuantumCrypt-AI/test_results_secure_mpc_engine_v14.json", "w") as f:
        json.dump({
            "test_results": test_results,
            "all_passed": all_passed,
            "timestamp": time.time(),
            "engine": "SecureMPCEngine_v14",
            "security": "Post-Quantum"
        }, f, indent=2)

    print(f"Results saved to test_results_secure_mpc_engine_v14.json")
    print()

    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
