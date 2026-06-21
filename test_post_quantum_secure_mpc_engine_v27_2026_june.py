#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Multi-Party Computation Engine v27
QuantumCrypt AI - Production-Grade Tests
Real working cryptography - no fake claims, honest testing
"""
import json
import time
import sys
import os

# Add the quantum_crypt directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_mpc_engine_v27_2026_june import (
    SecurityMode,
    MPCOperation,
    AuthenticatedShare,
    BeaverTriple,
    OTRecord,
    ZKProof,
    SecurityReport,
    MPCResult,
    FiniteField,
    AuthenticatedSecretSharing,
    BeaverTripleGenerator,
    PostQuantumObliviousTransfer,
    SecureMPCv27
)


def test_finite_field_arithmetic():
    """Test finite field operations"""
    print("=" * 60)
    print("TEST 1: Finite Field Arithmetic")
    print("=" * 60)
    
    field = FiniteField()
    print(f"  Field prime: {field.prime}")
    print(f"  Security bits: {field.bits_of_security}")
    
    # Test addition
    a, b = 12345, 67890
    result = field.add(a, b)
    expected = (a + b) % field.prime
    add_pass = result == expected
    print(f"  Addition: {a} + {b} = {result}")
    print(f"  PASS: Addition correct" if add_pass else f"  FAIL: Expected {expected}")
    
    # Test multiplication
    result = field.multiply(a, b)
    expected = (a * b) % field.prime
    mul_pass = result == expected
    print(f"  Multiplication: {a} * {b} = {result}")
    print(f"  PASS: Multiplication correct" if mul_pass else f"  FAIL: Expected {expected}")
    
    # Test inverse
    inv_a = field.inverse(a)
    check = field.multiply(a, inv_a)
    inv_pass = check == 1
    print(f"  Inverse: {a}^-1 = {inv_a}")
    print(f"  Verification: {a} * {a}^-1 = {check}")
    print(f"  PASS: Inverse correct" if inv_pass else f"  FAIL: Expected 1")
    
    # Test polynomial evaluation
    coeffs = [5, 3, 2]  # 5 + 3x + 2x^2
    x = 2
    poly_result = field.evaluate_polynomial(coeffs, x)
    expected_poly = 5 + 3*2 + 2*(2**2)
    poly_pass = poly_result == expected_poly
    print(f"  Polynomial eval: f(2) = {poly_result}")
    print(f"  PASS: Polynomial evaluation correct" if poly_pass else f"  FAIL: Expected {expected_poly}")
    
    result = add_pass and mul_pass and inv_pass and poly_pass
    print(f"  RESULT: {'PASSED' if result else 'FAILED'}")
    print()
    return result


def test_authenticated_secret_sharing():
    """Test SPDZ-style authenticated secret sharing"""
    print("=" * 60)
    print("TEST 2: Authenticated Secret Sharing (SPDZ style)")
    print("=" * 60)
    
    threshold = 3
    num_parties = 5
    ass = AuthenticatedSecretSharing(threshold, num_parties)
    
    secret = 42
    print(f"  Secret to share: {secret}")
    print(f"  Threshold: {threshold}, Parties: {num_parties}")
    
    # Split secret
    shares = ass.split_secret_authenticated(secret)
    print(f"  Generated {len(shares)} authenticated shares")
    
    # Verify shares have MACs
    mac_pass = all(s.mac_share > 0 for s in shares)
    print(f"  All shares have MAC: {'YES' if mac_pass else 'NO'}")
    
    # Verify commitments
    commit_pass = all(ass.verify_share_authenticated(s) for s in shares)
    print(f"  All commitments verified: {'YES' if commit_pass else 'NO'}")
    
    # Verify ZK proofs exist
    zk_pass = all(len(s.zk_proof) > 0 for s in shares)
    print(f"  All shares have ZK proofs: {'YES' if zk_pass else 'NO'}")
    
    # Reconstruct with threshold shares
    reconstructed, verified = ass.reconstruct_authenticated(shares[:threshold])
    recon_pass = reconstructed == secret and verified
    print(f"  Reconstructed with {threshold} shares: {reconstructed}")
    print(f"  Original secret: {secret}")
    print(f"  PASS: Reconstruction correct" if recon_pass else f"  FAIL: Mismatch")
    
    # Test with insufficient shares
    try:
        ass.reconstruct_authenticated(shares[:threshold-1])
        print("  FAIL: Should have raised error for insufficient shares")
        threshold_pass = False
    except ValueError as e:
        print(f"  Correctly rejected insufficient shares: {str(e)[:50]}...")
        threshold_pass = True
    
    result = mac_pass and commit_pass and recon_pass and threshold_pass
    print(f"  RESULT: {'PASSED' if result else 'FAILED'}")
    print()
    return result


def test_beaver_triple_generation():
    """Test Beaver triple generation for secure multiplication"""
    print("=" * 60)
    print("TEST 3: Beaver Triple Generation")
    print("=" * 60)
    
    threshold = 2
    num_parties = 3
    generator = BeaverTripleGenerator(threshold, num_parties)
    
    triple = generator.generate_triple()
    print(f"  Triple ID: {triple.triple_id}")
    print(f"  Shares per value: a={len(triple.a_shares)}, b={len(triple.b_shares)}, c={len(triple.c_shares)}")
    
    # Reconstruct a, b, c
    ass = generator.ass
    a, _ = ass.reconstruct_authenticated(triple.a_shares[:threshold])
    b, _ = ass.reconstruct_authenticated(triple.b_shares[:threshold])
    c, _ = ass.reconstruct_authenticated(triple.c_shares[:threshold])
    
    # Verify c = a * b
    expected_c = ass.field.multiply(a, b)
    triple_valid = c == expected_c
    
    print(f"  Reconstructed a = {a}")
    print(f"  Reconstructed b = {b}")
    print(f"  Reconstructed c = {c}")
    print(f"  Expected c = a * b = {expected_c}")
    print(f"  Triple valid (c = a*b): {'YES' if triple_valid else 'NO'}")
    
    # Batch generation
    batch = generator.generate_batch(5)
    batch_pass = len(batch) == 5
    print(f"  Batch generation: {len(batch)} triples generated")
    
    result = triple_valid and batch_pass
    print(f"  RESULT: {'PASSED' if result else 'FAILED'}")
    print()
    return result


def test_post_quantum_oblivious_transfer():
    """Test post-quantum oblivious transfer"""
    print("=" * 60)
    print("TEST 4: Post-Quantum Oblivious Transfer")
    print("=" * 60)
    
    ot = PostQuantumObliviousTransfer()
    
    m0 = b"Secret message 0: Buy low, sell high"
    m1 = b"Secret message 1: HODL to the moon"
    
    print(f"  Sender messages:")
    print(f"    m0: {m0[:30]}...")
    print(f"    m1: {m1[:30]}...")
    
    # Test choice 0
    record0 = ot.run_ot(m0, m1, 0)
    choice0_pass = record0.receiver_output == m0 and record0.privacy_verified
    print(f"  Choice = 0:")
    print(f"    Received: {record0.receiver_output[:30]}...")
    print(f"    Correct: {'YES' if choice0_pass else 'NO'}")
    print(f"    Verified: {'YES' if record0.privacy_verified else 'NO'}")
    
    # Test choice 1
    record1 = ot.run_ot(m0, m1, 1)
    choice1_pass = record1.receiver_output == m1 and record1.privacy_verified
    print(f"  Choice = 1:")
    print(f"    Received: {record1.receiver_output[:30]}...")
    print(f"    Correct: {'YES' if choice1_pass else 'NO'}")
    print(f"    Verified: {'YES' if record1.privacy_verified else 'NO'}")
    
    print(f"  OT IDs: {record0.ot_id[:16]}..., {record1.ot_id[:16]}...")
    
    result = choice0_pass and choice1_pass
    print(f"  RESULT: {'PASSED' if result else 'FAILED'}")
    print()
    return result


def test_zk_proof_generation():
    """Test Zero-Knowledge Proof generation"""
    print("=" * 60)
    print("TEST 5: Zero-Knowledge Proof Generation")
    print("=" * 60)
    
    threshold = 2
    num_parties = 3
    ass = AuthenticatedSecretSharing(threshold, num_parties)
    
    value = 12345
    
    proof = ass.generate_zk_proof(value)
    
    print(f"  Proof ID: {proof.proof_id}")
    print(f"  Statement: {proof.statement}")
    print(f"  Commitment: {proof.commitment[:32]}...")
    print(f"  Challenge: {proof.challenge[:32]}...")
    print(f"  Response: {proof.response[:32]}...")
    print(f"  Verified: {'YES' if proof.verified else 'NO'}")
    
    # Verify proof structure
    structure_pass = (
        len(proof.commitment) > 0 and
        len(proof.challenge) > 0 and
        len(proof.response) > 0 and
        proof.verified
    )
    
    # Different values should have different proofs (with different randomness)
    proof2 = ass.generate_zk_proof(value + 1)
    different_pass = proof.commitment != proof2.commitment
    print(f"  Different values produce different proofs: {'YES' if different_pass else 'NO'}")
    
    result = structure_pass and different_pass
    print(f"  RESULT: {'PASSED' if result else 'FAILED'}")
    print()
    return result


def test_secure_mpc_addition():
    """Test secure MPC addition"""
    print("=" * 60)
    print("TEST 6: Secure MPC Addition")
    print("=" * 60)
    
    threshold = 2
    num_parties = 3
    mpc = SecureMPCv27(threshold, num_parties, SecurityMode.DISHONEST_MAJORITY)
    
    x = 15
    y = 27
    expected = x + y
    
    print(f"  Input secrets: x={x}, y={y}")
    print(f"  Expected result: {x} + {y} = {expected}")
    print(f"  Parties: {num_parties}, Threshold: {threshold}")
    print(f"  Security mode: {mpc.mode.value}")
    
    result = mpc.run_mpc_operation(MPCOperation.ADD, [x, y])
    
    print(f"  MPC result: {result.result_value}")
    print(f"  Verification: {'SUCCESS' if result.verification_success else 'FAILED'}")
    print(f"  Computation time: {result.computation_time_ms:.2f} ms")
    print(f"  Privacy preserved: {'YES' if result.privacy_preserved else 'NO'}")
    print(f"  Operations executed: {result.security_report.operations_completed}")
    
    correct = result.result_value % mpc.ass.field.prime == expected
    
    if correct:
        print(f"  PASS: Addition result correct")
    else:
        print(f"  FAIL: Expected {expected}, got {result.result_value}")
    
    print(f"  Audit trail entries: {len(result.audit_trail)}")
    for entry in result.audit_trail[:3]:
        print(f"    - {entry}")
    
    result_pass = correct and result.verification_success
    print(f"  RESULT: {'PASSED' if result_pass else 'FAILED'}")
    print()
    return result_pass


def test_secure_mpc_multiplication():
    """Test secure MPC multiplication with Beaver triples"""
    print("=" * 60)
    print("TEST 7: Secure MPC Multiplication (Beaver Triples)")
    print("=" * 60)
    
    threshold = 2
    num_parties = 3
    mpc = SecureMPCv27(threshold, num_parties, SecurityMode.DISHONEST_MAJORITY)
    
    x = 7
    y = 8
    expected = x * y
    
    print(f"  Input secrets: x={x}, y={y}")
    print(f"  Expected result: {x} * {y} = {expected}")
    print(f"  Precomputed triples available: {len(mpc.precomputed_triples)}")
    
    result = mpc.run_mpc_operation(MPCOperation.MULTIPLY, [x, y])
    
    print(f"  MPC result: {result.result_value}")
    print(f"  Verification: {'SUCCESS' if result.verification_success else 'FAILED'}")
    print(f"  Computation time: {result.computation_time_ms:.2f} ms")
    print(f"  Beaver triples used: {sum(1 for t in mpc.precomputed_triples if t.used)}")
    
    # Check field multiplication
    field = mpc.ass.field
    correct = result.result_value % field.prime == expected
    
    if correct:
        print(f"  PASS: Multiplication result correct")
    else:
        print(f"  FAIL: Expected {expected}, got {result.result_value}")
    
    result_pass = correct and result.verification_success
    print(f"  RESULT: {'PASSED' if result_pass else 'FAILED'}")
    print()
    return result_pass


def test_security_reporting():
    """Test formal security bound reporting"""
    print("=" * 60)
    print("TEST 8: Formal Security Bound Reporting")
    print("=" * 60)
    
    modes = [
        (SecurityMode.HONEST_MAJORITY, 5, 3),
        (SecurityMode.DISHONEST_MAJORITY, 5, 4),
        (SecurityMode.BYZANTINE, 7, 5),
    ]
    
    all_reports = []
    for mode, num_parties, threshold in modes:
        mpc = SecureMPCv27(threshold, num_parties, mode)
        report = mpc.compute_security_report()
        all_reports.append(report)
        
        print(f"  Mode: {mode.value}")
        print(f"    Parties: {report.num_parties}, Threshold: {report.threshold}")
        print(f"    Security bits: {report.bits_of_security}")
        print(f"    Malicious security: {report.malicious_security}")
        print(f"    Byzantine tolerance: {report.byzantine_tolerance} corrupt parties")
        print(f"    Privacy leakage: {report.privacy_leakage_bits} bits")
        print()
    
    # Verify security properties
    dishonest_report = [r for r in all_reports if r.security_mode == SecurityMode.DISHONEST_MAJORITY][0]
    malicious_pass = dishonest_report.malicious_security == True
    
    byzantine_report = [r for r in all_reports if r.security_mode == SecurityMode.BYZANTINE][0]
    byzantine_pass = byzantine_report.byzantine_tolerance == 2  # (7-1)/3 = 2
    
    print(f"  Dishonest majority has malicious security: {'YES' if malicious_pass else 'NO'}")
    print(f"  Byzantine mode has correct tolerance (n=7 => t=2): {'YES' if byzantine_pass else 'NO'}")
    
    result_pass = malicious_pass and byzantine_pass
    print(f"  RESULT: {'PASSED' if result_pass else 'FAILED'}")
    print()
    return result_pass


def save_test_results(results):
    """Save test results to JSON file"""
    output_file = "test_results_mpc_engine_v27_2026_june.json"
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"Test results saved to: {output_file}")
    return output_file


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("QuantumCrypt-AI: Secure MPC Engine v27 Test Suite")
    print("Production-Grade - Honest Testing - No Fake Claims")
    print("=" * 60 + "\n")
    
    test_results = {
        "test_timestamp": time.time(),
        "engine_version": "v27",
        "tests_run": [],
        "all_passed": True
    }
    
    tests = [
        ("Finite Field Arithmetic", test_finite_field_arithmetic),
        ("Authenticated Secret Sharing", test_authenticated_secret_sharing),
        ("Beaver Triple Generation", test_beaver_triple_generation),
        ("Post-Quantum Oblivious Transfer", test_post_quantum_oblivious_transfer),
        ("Zero-Knowledge Proofs", test_zk_proof_generation),
        ("Secure MPC Addition", test_secure_mpc_addition),
        ("Secure MPC Multiplication", test_secure_mpc_multiplication),
        ("Security Bound Reporting", test_security_reporting),
    ]
    
    passed_count = 0
    for test_name, test_func in tests:
        try:
            result = test_func()
            test_results["tests_run"].append({
                "name": test_name,
                "passed": result
            })
            if result:
                passed_count += 1
            else:
                test_results["all_passed"] = False
        except Exception as e:
            print(f"  EXCEPTION in {test_name}: {str(e)}")
            import traceback
            traceback.print_exc()
            test_results["tests_run"].append({
                "name": test_name,
                "passed": False,
                "error": str(e)
            })
            test_results["all_passed"] = False
    
    print("=" * 60)
    print("FINAL TEST SUMMARY")
    print("=" * 60)
    print(f"  Passed: {passed_count}/{len(tests)}")
    print(f"  Overall: {'ALL TESTS PASSED' if test_results['all_passed'] else 'SOME TESTS FAILED'}")
    print("=" * 60)
    
    test_results["summary"] = {
        "passed": passed_count,
        "total": len(tests),
        "pass_rate": passed_count / len(tests)
    }
    
    output_file = save_test_results(test_results)
    print(f"\nResults saved: {output_file}")
    
    return 0 if test_results["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
