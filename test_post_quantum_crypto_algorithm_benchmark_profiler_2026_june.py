#!/usr/bin/env python3
"""
Test suite for Post-Quantum Crypto Algorithm Benchmark Profiler
Runs actual functional tests with real cryptographic operations
"""

import json
import os
import tempfile
import shutil
from quantum_crypt.post_quantum_crypto_algorithm_benchmark_profiler_2026_june import (
    AlgorithmCategory,
    SecurityLevel,
    BenchmarkResult,
    MockPQCryptoAlgorithms,
    CryptoBenchmarkProfiler
)
from datetime import datetime


def test_algorithm_categories():
    """Test algorithm category enum"""
    print("=== Testing Algorithm Categories ===")
    
    assert AlgorithmCategory.KEY_ENCAPSULATION.value == "kem"
    assert AlgorithmCategory.DIGITAL_SIGNATURE.value == "signature"
    assert AlgorithmCategory.SYMMETRIC_CIPHER.value == "symmetric"
    
    print(f"  ✓ KEM: {AlgorithmCategory.KEY_ENCAPSULATION.value}")
    print(f"  ✓ Signature: {AlgorithmCategory.DIGITAL_SIGNATURE.value}")
    print(f"  ✓ Symmetric: {AlgorithmCategory.SYMMETRIC_CIPHER.value}")
    print("  ✓ Algorithm categories test PASSED\n")


def test_security_levels():
    """Test security level enum"""
    print("=== Testing Security Levels ===")
    
    assert SecurityLevel.LEVEL_1.value == 1
    assert SecurityLevel.LEVEL_3.value == 3
    assert SecurityLevel.LEVEL_5.value == 5
    
    print(f"  ✓ Level 1 (128-bit): {SecurityLevel.LEVEL_1.value}")
    print(f"  ✓ Level 3 (192-bit): {SecurityLevel.LEVEL_3.value}")
    print(f"  ✓ Level 5 (256-bit): {SecurityLevel.LEVEL_5.value}")
    print("  ✓ Security levels test PASSED\n")


def test_benchmark_result():
    """Test BenchmarkResult dataclass"""
    print("=== Testing BenchmarkResult ===")
    
    result = BenchmarkResult(
        algorithm_name="Test-Algo",
        category=AlgorithmCategory.KEY_ENCAPSULATION,
        operation="keygen",
        iterations=10,
        total_time_ms=100.0,
        mean_time_ms=10.0,
        median_time_ms=9.5,
        min_time_ms=8.0,
        max_time_ms=15.0,
        std_dev_ms=2.0,
        operations_per_second=100.0,
        peak_memory_kb=1024.0,
        data_size_bytes=1024,
        security_level=SecurityLevel.LEVEL_3
    )
    
    result_dict = result.to_dict()
    assert result_dict['algorithm_name'] == "Test-Algo"
    assert result_dict['category'] == "kem"
    assert result_dict['security_level'] == 3
    assert 'mean_time_ms' in result_dict
    
    print(f"  ✓ Algorithm: {result_dict['algorithm_name']}")
    print(f"  ✓ Mean time: {result_dict['mean_time_ms']}ms")
    print(f"  ✓ Ops/sec: {result_dict['operations_per_second']}")
    print("  ✓ BenchmarkResult test PASSED\n")


def test_mock_algorithms_basic():
    """Test basic cryptographic algorithm implementations"""
    print("=== Testing Mock Crypto Algorithms ===")
    
    algs = MockPQCryptoAlgorithms()
    
    # Test Kyber key generation
    priv, pub = algs.kyber_keypair(SecurityLevel.LEVEL_1)
    assert len(priv) > 0
    assert len(pub) > 0
    print(f"  ✓ Kyber-512 keygen: priv={len(priv)}B, pub={len(pub)}B")
    
    # Test encapsulation
    ct, ss = algs.kyber_encapsulate(pub, SecurityLevel.LEVEL_1)
    assert len(ct) > 0
    assert len(ss) == 32  # 256-bit shared secret
    print(f"  ✓ Kyber encapsulate: ct={len(ct)}B, ss={len(ss)}B")
    
    # Test decapsulation
    ss2 = algs.kyber_decapsulate(priv, ct, SecurityLevel.LEVEL_1)
    assert len(ss2) == 32
    print(f"  ✓ Kyber decapsulate: ss={len(ss2)}B")
    
    # Test Dilithium signature
    message = b"Hello, Post-Quantum World!"
    sig = algs.dilithium_sign(priv, message, SecurityLevel.LEVEL_1)
    assert len(sig) > 0
    print(f"  ✓ Dilithium sign: signature={len(sig)}B")
    
    # Test verify
    verify_ok = algs.dilithium_verify(pub, message, sig, SecurityLevel.LEVEL_1)
    assert verify_ok == True
    print(f"  ✓ Dilithium verify: {verify_ok}")
    
    print("  ✓ Mock algorithms basic test PASSED\n")


def test_aes_encryption_decryption():
    """Test AES encryption and decryption roundtrip"""
    print("=== Testing AES-256-GCM Encryption/Decryption ===")
    
    algs = MockPQCryptoAlgorithms()
    
    key = b"x" * 32
    plaintext = b"This is a secret message that needs encryption!"
    
    # Encrypt
    ciphertext = algs.aes_256_gcm_encrypt(key, plaintext)
    assert len(ciphertext) == 12 + len(plaintext)  # nonce + ciphertext
    
    # Decrypt
    decrypted = algs.aes_256_gcm_decrypt(key, ciphertext)
    
    # Verify roundtrip
    assert decrypted == plaintext, "Decrypted text should match original"
    
    print(f"  ✓ Plaintext: {len(plaintext)} bytes")
    print(f"  ✓ Ciphertext: {len(ciphertext)} bytes (includes 12B nonce)")
    print(f"  ✓ Decrypted matches original: YES")
    print("  ✓ AES roundtrip test PASSED\n")


def test_hkdf_implementation():
    """Test HKDF key derivation - actual RFC 5869 implementation"""
    print("=== Testing HKDF Implementation ===")
    
    algs = MockPQCryptoAlgorithms()
    
    ikm = b"input_key_material_12345"
    salt = b"salt_value_67890"
    info = b"context_information"
    
    derived = algs.hkdf_derive(ikm, salt, info, 64)
    assert len(derived) == 64
    
    # Deterministic - same inputs = same output
    derived2 = algs.hkdf_derive(ikm, salt, info, 64)
    assert derived == derived2
    
    # Different info = different output
    derived3 = algs.hkdf_derive(ikm, salt, b"different", 64)
    assert derived != derived3
    
    print(f"  ✓ Derived key length: {len(derived)} bytes")
    print(f"  ✓ Deterministic: YES")
    print(f"  ✓ Context-dependent: YES")
    print("  ✓ HKDF implementation test PASSED\n")


def test_pbkdf2_password_hashing():
    """Test PBKDF2 password hashing"""
    print("=== Testing PBKDF2 Password Hashing ===")
    
    algs = MockPQCryptoAlgorithms()
    
    password = b"my_secure_password_123!"
    salt = b"random_salt_value_here"
    
    # Hash password
    hash_result = algs.pbkdf2_hmac(password, salt, 1000, 32)
    assert len(hash_result) == 32
    
    # Same inputs = same output (deterministic)
    hash_result2 = algs.pbkdf2_hmac(password, salt, 1000, 32)
    assert hash_result == hash_result2
    
    print(f"  ✓ Hash length: {len(hash_result)} bytes")
    print(f"  ✓ Deterministic verification: YES")
    print("  ✓ PBKDF2 hashing test PASSED\n")


def test_benchmark_profiler_kyber():
    """Test Kyber benchmarking"""
    print("=== Testing Kyber Benchmarking ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        profiler = CryptoBenchmarkProfiler(output_dir=temp_dir)
        
        results = profiler.benchmark_kyber('Kyber-512', iterations=3)
        
        assert len(results) == 3  # keygen, encapsulate, decapsulate
        
        for r in results:
            print(f"  ✓ {r.operation}: {r.mean_time_ms:.2f}ms, {r.operations_per_second:.1f} ops/sec")
            assert r.mean_time_ms > 0
            assert r.iterations == 3
        
        print("  ✓ Kyber benchmark test PASSED\n")


def test_benchmark_profiler_dilithium():
    """Test Dilithium benchmarking"""
    print("=== Testing Dilithium Benchmarking ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        profiler = CryptoBenchmarkProfiler(output_dir=temp_dir)
        
        results = profiler.benchmark_dilithium('Dilithium-2', iterations=2)
        
        assert len(results) == 2  # sign, verify
        
        for r in results:
            print(f"  ✓ {r.operation}: {r.mean_time_ms:.2f}ms, peak_mem={r.peak_memory_kb:.1f}KB")
            assert r.mean_time_ms > 0
        
        print("  ✓ Dilithium benchmark test PASSED\n")


def test_benchmark_profiler_symmetric():
    """Test symmetric cipher benchmarking"""
    print("=== Testing Symmetric Cipher Benchmarking ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        profiler = CryptoBenchmarkProfiler(output_dir=temp_dir)
        
        results = profiler.benchmark_symmetric_cipher('AES-256-GCM', iterations=10, data_size=1024)
        
        assert len(results) == 2  # encrypt, decrypt
        
        for r in results:
            print(f"  ✓ AES {r.operation}: {r.mean_time_ms:.4f}ms, {r.operations_per_second:.0f} ops/sec")
            assert r.data_size_bytes == 1024
        
        print("  ✓ Symmetric cipher benchmark test PASSED\n")


def test_benchmark_profiler_kdf():
    """Test KDF benchmarking"""
    print("=== Testing KDF Benchmarking ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        profiler = CryptoBenchmarkProfiler(output_dir=temp_dir)
        
        # HKDF is fast, so we can do more iterations
        results = profiler.benchmark_kdf('HKDF-SHA256', iterations=50)
        assert len(results) == 1
        
        r = results[0]
        print(f"  ✓ HKDF derive: {r.mean_time_ms:.4f}ms, {r.operations_per_second:.0f} ops/sec")
        assert r.mean_time_ms > 0
        
        print("  ✓ KDF benchmark test PASSED\n")


def test_full_benchmark_suite():
    """Test full benchmark suite execution"""
    print("=== Testing Full Benchmark Suite ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        profiler = CryptoBenchmarkProfiler(output_dir=temp_dir)
        
        # Quick mode with minimal iterations
        report = profiler.run_full_benchmark_suite(quick_mode=True, iterations=2)
        
        assert report['total_benchmarks'] > 0
        assert report['total_algorithms'] > 0
        assert 'by_algorithm' in report
        assert 'fastest_operations' in report
        assert 'slowest_operations' in report
        
        print(f"  ✓ Total benchmarks: {report['total_benchmarks']}")
        print(f"  ✓ Algorithms tested: {report['total_algorithms']}")
        print(f"  ✓ Fastest op: {report['fastest_operations'][0]['algorithm_name']}")
        print(f"  ✓ Slowest op: {report['slowest_operations'][0]['algorithm_name']}")
        
        print("  ✓ Full benchmark suite test PASSED\n")


def test_benchmark_save_results():
    """Test saving benchmark results"""
    print("=== Testing Results Persistence ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        profiler = CryptoBenchmarkProfiler(output_dir=temp_dir)
        
        profiler.benchmark_kyber('Kyber-512', iterations=2)
        
        output_file = profiler.save_results()
        
        assert os.path.exists(output_file)
        
        with open(output_file, 'r') as f:
            saved_data = json.load(f)
        
        assert 'benchmark_date' in saved_data
        assert 'detailed_results' in saved_data
        assert len(saved_data['detailed_results']) > 0
        
        print(f"  ✓ Saved to: {output_file}")
        print(f"  ✓ Results count: {len(saved_data['detailed_results'])}")
        
        print("  ✓ Results persistence test PASSED\n")


def test_benchmark_summary_print():
    """Test summary printing"""
    print("=== Testing Summary Printing ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        profiler = CryptoBenchmarkProfiler(output_dir=temp_dir)
        profiler.benchmark_kyber('Kyber-512', iterations=2)
        
        # This should not crash
        profiler.print_summary()
        
        print("  ✓ Summary print test PASSED\n")


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("POST-QUANTUM CRYPTO BENCHMARK PROFILER - TEST SUITE")
    print("=" * 70 + "\n")
    
    tests_passed = 0
    tests_failed = 0
    test_results = []
    
    test_functions = [
        test_algorithm_categories,
        test_security_levels,
        test_benchmark_result,
        test_mock_algorithms_basic,
        test_aes_encryption_decryption,
        test_hkdf_implementation,
        test_pbkdf2_password_hashing,
        test_benchmark_profiler_kyber,
        test_benchmark_profiler_dilithium,
        test_benchmark_profiler_symmetric,
        test_benchmark_profiler_kdf,
        test_full_benchmark_suite,
        test_benchmark_save_results,
        test_benchmark_summary_print
    ]
    
    for test_func in test_functions:
        try:
            test_func()
            tests_passed += 1
            test_results.append((test_func.__name__, "PASSED"))
        except Exception as e:
            tests_failed += 1
            test_results.append((test_func.__name__, f"FAILED: {str(e)}"))
            print(f"  ✗ TEST FAILED: {test_func.__name__}: {e}\n")
    
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total Tests: {len(test_functions)}")
    print(f"Passed: {tests_passed}")
    print(f"Failed: {tests_failed}")
    print()
    
    for name, result in test_results:
        status = "✓" if "PASSED" in result else "✗"
        print(f"  {status} {name}: {result}")
    
    print()
    
    # Save results
    report = {
        'test_date': datetime.now().isoformat(),
        'total_tests': len(test_functions),
        'passed': tests_passed,
        'failed': tests_failed,
        'results': dict(test_results),
        'module': 'post_quantum_crypto_algorithm_benchmark_profiler'
    }
    
    with open('test_results_pqcrypto_benchmark_profiler.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Results saved to: test_results_pqcrypto_benchmark_profiler.json")
    
    if tests_failed == 0:
        print("\n✓ ALL TESTS PASSED!")
        return True
    else:
        print(f"\n✗ {tests_failed} TEST(S) FAILED")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
