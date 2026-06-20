#!/usr/bin/env python3
"""
Test suite for Post-Quantum Key Exchange Simulator & Benchmark
QuantumCrypt-AI - Production-grade testing
"""

import sys
import json
import time
import importlib.util

# Direct import to avoid __init__.py issues
spec = importlib.util.spec_from_file_location(
    "pq_simulator",
    "./quantum_crypt/post_quantum_key_exchange_simulator_benchmark_2026_june.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

PostQuantumKeyExchangeSimulator = module.PostQuantumKeyExchangeSimulator
PostQuantumKEM = module.PostQuantumKEM
DeterministicPRNG = module.DeterministicPRNG
PQAlgorithm = module.PQAlgorithm
ALGORITHM_SPECS = module.ALGORITHM_SPECS
KeyPair = module.KeyPair
EncapsulationResult = module.EncapsulationResult


def test_deterministic_prng():
    """Test deterministic PRNG functionality"""
    print("=== Testing Deterministic PRNG ===")
    
    seed = b'test_seed_12345'
    prng1 = DeterministicPRNG(seed)
    prng2 = DeterministicPRNG(seed)
    
    # Same seed should produce same output
    bytes1 = prng1.get_bytes(32)
    bytes2 = prng2.get_bytes(32)
    
    if bytes1 == bytes2:
        print("  ✓ Same seed produces identical output")
        success1 = True
    else:
        print("  ✗ Same seed produced different output")
        success1 = False
    
    # Different seeds should produce different output
    prng3 = DeterministicPRNG(b'different_seed')
    bytes3 = prng3.get_bytes(32)
    
    if bytes1 != bytes3:
        print("  ✓ Different seeds produce different output")
        success2 = True
    else:
        print("  ✗ Different seeds produced same output")
        success2 = False
    
    # Length test
    for length in [16, 32, 64, 128, 1024]:
        result = prng1.get_bytes(length)
        if len(result) == length:
            print(f"  ✓ Correct output length ({length} bytes)")
        else:
            print(f"  ✗ Wrong length: expected {length}, got {len(result)}")
            success2 = False
    
    return success1 and success2


def test_kem_basic_operations():
    """Test basic KEM operations"""
    print("\n=== Testing KEM Basic Operations ===")
    
    test_algorithms = [
        PQAlgorithm.KYBER_512,
        PQAlgorithm.KYBER_768,
        PQAlgorithm.ECDH_P256,
        PQAlgorithm.NTRU_HPS_2048_509
    ]
    
    all_passed = True
    
    for alg in test_algorithms:
        kem = PostQuantumKEM(alg)
        spec = ALGORITHM_SPECS[alg]
        
        # Key generation
        keypair = kem.keygen()
        
        if len(keypair.public_key) == spec.public_key_size:
            print(f"  ✓ {spec.name}: Public key size correct ({spec.public_key_size} bytes)")
        else:
            print(f"  ✗ {spec.name}: Wrong PK size: {len(keypair.public_key)} vs {spec.public_key_size}")
            all_passed = False
        
        if len(keypair.secret_key) == spec.secret_key_size:
            print(f"  ✓ {spec.name}: Secret key size correct ({spec.secret_key_size} bytes)")
        else:
            print(f"  ✗ {spec.name}: Wrong SK size")
            all_passed = False
        
        # Encapsulation
        encap = kem.encaps(keypair.public_key)
        
        if len(encap.ciphertext) == spec.ciphertext_size:
            print(f"  ✓ {spec.name}: Ciphertext size correct")
        else:
            print(f"  ✗ {spec.name}: Wrong ciphertext size")
            all_passed = False
        
        if len(encap.shared_secret) == spec.shared_secret_size:
            print(f"  ✓ {spec.name}: Shared secret size correct")
        else:
            print(f"  ✗ {spec.name}: Wrong shared secret size")
            all_passed = False
        
        # Decapsulation
        decaps_shared = kem.decaps(encap.ciphertext, keypair.secret_key)
        
        if len(decaps_shared) == spec.shared_secret_size:
            print(f"  ✓ {spec.name}: Decapsulation produces correct size")
        else:
            print(f"  ✗ {spec.name}: Decapsulation wrong size")
            all_passed = False
    
    return all_passed


def test_key_exchange_simulation():
    """Test complete key exchange simulation"""
    print("\n=== Testing Key Exchange Simulation ===")
    
    simulator = PostQuantumKeyExchangeSimulator()
    
    test_cases = [
        (PQAlgorithm.KYBER_512, False),
        (PQAlgorithm.KYBER_768, False),
        (PQAlgorithm.KYBER_768, True),  # Hybrid mode
    ]
    
    all_passed = True
    
    for alg, hybrid in test_cases:
        result = simulator.simulate_key_exchange(alg, hybrid_mode=hybrid)
        
        spec = ALGORITHM_SPECS[alg]
        mode = "Hybrid" if hybrid else "Standard"
        
        if result['exchange_verified']:
            print(f"  ✓ {spec.name} ({mode}): Key exchange verified")
        else:
            print(f"  ✗ {spec.name} ({mode}): Key exchange FAILED")
            all_passed = False
        
        if result['shared_secret_match']:
            print(f"  ✓ {spec.name} ({mode}): Shared secrets match")
        else:
            print(f"  ✗ {spec.name} ({mode}): Shared secret mismatch")
            all_passed = False
        
        # Check timings are present and positive
        if all(t > 0 for t in result['timings'].values()):
            print(f"  ✓ {spec.name} ({mode}): Timings recorded correctly")
        else:
            print(f"  ✗ {spec.name} ({mode}): Invalid timings")
            all_passed = False
    
    return all_passed


def test_benchmarking():
    """Test benchmarking functionality"""
    print("\n=== Testing Benchmarking ===")
    
    simulator = PostQuantumKeyExchangeSimulator()
    
    # Single algorithm benchmark
    benchmark = simulator.benchmark_algorithm(PQAlgorithm.KYBER_512, iterations=20)
    
    print(f"  Algorithm: {benchmark.algorithm}")
    print(f"  Keygen: {benchmark.keygen_time_us:.2f} µs")
    print(f"  Encaps: {benchmark.encaps_time_us:.2f} µs")
    print(f"  Decaps: {benchmark.decaps_time_us:.2f} µs")
    print(f"  Total: {benchmark.total_time_us:.2f} µs")
    print(f"  Ops/sec: {benchmark.operations_per_second:.0f}")
    
    # Verify all timings are positive
    if (benchmark.keygen_time_us > 0 and 
        benchmark.encaps_time_us > 0 and 
        benchmark.decaps_time_us > 0):
        print("  ✓ All timings are positive")
        success1 = True
    else:
        print("  ✗ Invalid timing values")
        success1 = False
    
    if benchmark.operations_per_second > 0:
        print("  ✓ Operations per second calculated correctly")
        success2 = True
    else:
        print("  ✗ Invalid ops/sec calculation")
        success2 = False
    
    return success1 and success2


def test_comparative_benchmark():
    """Test comparative benchmark across algorithms"""
    print("\n=== Testing Comparative Benchmark ===")
    
    simulator = PostQuantumKeyExchangeSimulator()
    
    algorithms = [
        PQAlgorithm.KYBER_512,
        PQAlgorithm.KYBER_768,
        PQAlgorithm.ECDH_P256,
        PQAlgorithm.NTRU_HPS_2048_509
    ]
    
    results = simulator.run_comparative_benchmark(algorithms)
    
    print(f"  Benchmarked {len(results)} algorithms")
    
    # Print comparison table
    print("\n  Algorithm Comparison:")
    print(f"  {'Algorithm':<25} {'Level':<6} {'Total µs':<10} {'Ops/sec':<10} {'PK bytes':<10}")
    print("  " + "-" * 65)
    
    for alg_id, data in results.items():
        print(f"  {data['name']:<25} {data['security_level']:<6} {data['total_us']:<10.1f} {data['ops_per_sec']:<10.0f} {data['pk_size']:<10}")
    
    # Verify all algorithms were benchmarked
    if len(results) == len(algorithms):
        print(f"\n  ✓ All {len(algorithms)} algorithms benchmarked successfully")
        success = True
    else:
        print(f"\n  ✗ Missing benchmark results")
        success = False
    
    return success


def test_security_report():
    """Test security report generation"""
    print("\n=== Testing Security Report Generation ===")
    
    simulator = PostQuantumKeyExchangeSimulator()
    report = simulator.generate_security_report()
    
    print(f"  Quantum-resistant algorithms: {len(report['quantum_resistant_algorithms'])}")
    print(f"  Classical baselines: {len(report['classical_baselines'])}")
    print(f"  NIST standardized: {len(report['nist_standardized'])}")
    
    # Check key size analysis
    if 'kyber_768' in report['key_size_analysis']:
        kyber_ratio = report['key_size_analysis']['kyber_768']['ratio_to_ecdh']
        print(f"  Kyber-768 PK is {kyber_ratio:.1f}x larger than ECDH-P256")
        print("  ✓ Key size ratio analysis available")
        success1 = True
    else:
        print("  ✗ Missing key size analysis")
        success1 = False
    
    # Verify security levels
    if 5 in report['security_level_summary']:
        print("  ✓ Security level 5 algorithms present")
        success2 = True
    else:
        print("  ✗ Missing security level categorization")
        success2 = False
    
    return success1 and success2


def test_compatibility_matrix():
    """Test compatibility matrix generation"""
    print("\n=== Testing Compatibility Matrix ===")
    
    simulator = PostQuantumKeyExchangeSimulator()
    matrix = simulator.get_compatibility_matrix()
    
    # KEM algorithms should be compatible with each other
    kem_compatible = matrix['kyber_768']['ntru_hps_2048_509']
    
    if kem_compatible:
        print("  ✓ KEM algorithms marked as compatible")
        success1 = True
    else:
        print("  ✗ KEM compatibility incorrect")
        success1 = False
    
    # KEM and Signature should NOT be compatible
    cross_compatible = matrix['kyber_768']['dilithium_2']
    
    if not cross_compatible:
        print("  ✓ KEM/Signature correctly marked incompatible")
        success2 = True
    else:
        print("  ✗ Cross-type compatibility incorrect")
        success2 = False
    
    print(f"  Matrix contains {len(matrix)} algorithms")
    
    return success1 and success2


def test_algorithm_specs():
    """Test algorithm specifications integrity"""
    print("\n=== Testing Algorithm Specifications ===")
    
    all_passed = True
    
    for alg, spec in ALGORITHM_SPECS.items():
        # Verify sizes are positive
        if spec.public_key_size > 0:
            pass
        else:
            print(f"  ✗ {spec.name}: Invalid public key size")
            all_passed = False
        
        # Verify security level is 0-5
        if 0 <= spec.nist_security_level <= 5:
            pass
        else:
            print(f"  ✗ {spec.name}: Invalid security level")
            all_passed = False
        
        # Verify performance score positive
        if spec.performance_score > 0:
            pass
        else:
            print(f"  ✗ {spec.name}: Invalid performance score")
            all_passed = False
    
    if all_passed:
        print(f"  ✓ All {len(ALGORITHM_SPECS)} algorithm specs valid")
    
    # Check specific known values
    kyber_spec = ALGORITHM_SPECS[PQAlgorithm.KYBER_768]
    if kyber_spec.public_key_size == 1184 and kyber_spec.nist_security_level == 3:
        print("  ✓ Kyber-768 specs match NIST standard values")
    else:
        print("  ✗ Kyber-768 specs incorrect")
        all_passed = False
    
    return all_passed


def main():
    """Run all tests"""
    print("=" * 65)
    print("QuantumCrypt-AI - Post-Quantum Key Exchange Simulator Tests")
    print("=" * 65)
    
    tests = [
        test_deterministic_prng,
        test_kem_basic_operations,
        test_key_exchange_simulation,
        test_benchmarking,
        test_comparative_benchmark,
        test_security_report,
        test_compatibility_matrix,
        test_algorithm_specs,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"  ✗ Exception: {e}")
            import traceback
            traceback.print_exc()
            results.append(False)
    
    print("\n" + "=" * 65)
    passed = sum(results)
    total = len(results)
    print(f"TEST SUMMARY: {passed}/{total} tests passed")
    
    # Save results
    test_output = {
        'test_name': 'post_quantum_key_exchange_simulator_benchmark',
        'tests_passed': passed,
        'tests_total': total,
        'success_rate': passed / total if total > 0 else 0,
        'timestamp': time.time()
    }
    
    with open('test_results_post_quantum_key_exchange_simulator.json', 'w') as f:
        json.dump(test_output, f, indent=2)
    
    print(f"Results saved to test_results_post_quantum_key_exchange_simulator.json")
    print("=" * 65)
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
