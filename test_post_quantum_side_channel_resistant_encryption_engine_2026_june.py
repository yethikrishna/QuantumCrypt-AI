"""
Test suite for Post-Quantum Side-Channel Resistant Encryption Engine
Comprehensive tests covering all side-channel countermeasures
"""
import sys
import json
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_side_channel_resistant_encryption_engine_2026_june import (
    PostQuantumSideChannelResistantEncryptionEngine,
    ResistanceLevel,
    SideChannelVulnerabilityType
)
import secrets


def run_tests():
    """Run all tests and generate report"""
    engine = PostQuantumSideChannelResistantEncryptionEngine(
        resistance_level=ResistanceLevel.HIGH,
        target_duration_ns=200000  # 200 microseconds
    )
    
    test_results = {
        "test_timestamp": "2026-06-20",
        "module": "post_quantum_side_channel_resistant_encryption_engine",
        "total_tests": 0,
        "passed_tests": 0,
        "failed_tests": 0,
        "test_cases": []
    }
    
    def run_test(test_name, test_func):
        """Helper to run individual test"""
        test_results["total_tests"] += 1
        try:
            result = test_func()
            if result:
                test_results["passed_tests"] += 1
            else:
                test_results["failed_tests"] += 1
            
            test_results["test_cases"].append({
                "test_name": test_name,
                "passed": result
            })
            
        except Exception as e:
            test_results["failed_tests"] += 1
            test_results["test_cases"].append({
                "test_name": test_name,
                "passed": False,
                "error": str(e)
            })
    
    # Test 1: Basic encryption/decryption roundtrip
    def test_encryption_roundtrip():
        test_key = secrets.token_bytes(32)
        test_plaintext = b"Secret message with side-channel protection"
        
        enc_result = engine.encrypt_side_channel_resistant(test_plaintext, test_key)
        dec_result = engine.decrypt_side_channel_resistant(
            enc_result.ciphertext, test_key, enc_result.iv
        )
        
        return dec_result.ciphertext == test_plaintext
    
    run_test("Encryption/Decryption Roundtrip", test_encryption_roundtrip)
    
    # Test 2: Constant-time comparison
    def test_constant_time_compare():
        a = b"test_data_12345"
        b = b"test_data_12345"
        c = b"test_data_XXXXX"
        
        match = engine._constant_time_compare(a, b)
        no_match = engine._constant_time_compare(a, c)
        return match and not no_match
    
    run_test("Constant-Time Comparison", test_constant_time_compare)
    
    # Test 3: Secure memory wipe
    def test_secure_wipe():
        sensitive = bytearray(b"sensitive_key_material_here")
        original = bytes(sensitive)
        
        engine._secure_wipe(sensitive)
        
        # Should not match original after wipe
        wiped = bytes(sensitive)
        return wiped != original and all(b == 0 for b in sensitive)
    
    run_test("Secure Memory Wipe", test_secure_wipe)
    
    # Test 4: Blinding application
    def test_blinding():
        value = 123456789
        blinded, factor = engine._apply_blinding(value)
        
        # Blinded should differ from original when blinding is enabled
        if engine.enable_power_blinding:
            return blinded != value and factor != 0
        return True
    
    run_test("Power Analysis Blinding", test_blinding)
    
    # Test 5: Masking application
    def test_masking():
        data = b"plaintext_data_here"
        masked, mask = engine._apply_masking(data)
        
        if engine.enable_power_blinding:
            return masked != data and len(mask) == len(data)
        return True
    
    run_test("Boolean Masking", test_masking)
    
    # Test 6: Cache pattern shuffling
    def test_cache_shuffling():
        indices = list(range(16))
        shuffled = engine._cache_pattern_shuffle(indices)
        
        if engine.enable_cache_masking:
            # Should be permutation
            return sorted(shuffled) == indices
        return shuffled == indices
    
    run_test("Cache Pattern Shuffling", test_cache_shuffling)
    
    # Test 7: Timing normalization
    def test_timing_normalization():
        import time
        
        test_key = secrets.token_bytes(32)
        test_data = secrets.token_bytes(64)
        
        times = []
        for _ in range(10):
            start = time.perf_counter_ns()
            _ = engine.encrypt_side_channel_resistant(test_data, test_key)
            elapsed = time.perf_counter_ns() - start
            times.append(elapsed)
        
        # Check that times are at least the target duration
        min_time = min(times)
        return min_time >= engine.target_duration_ns * 0.9  # Allow 10% tolerance
    
    run_test("Timing Normalization", test_timing_normalization)
    
    # Test 8: Side-channel resistance assessment
    def test_resistance_assessment():
        assessment = engine.assess_side_channel_resistance(num_samples=20)
        
        return (
            assessment.resistance_score > 0 and
            assessment.overall_resistance_level in [
                ResistanceLevel.HIGH, ResistanceLevel.MAXIMUM, 
                ResistanceLevel.INTERMEDIATE
            ]
        )
    
    run_test("Side-Channel Resistance Assessment", test_resistance_assessment)
    
    # Test 9: Engine metrics collection
    def test_engine_metrics():
        metrics = engine.get_engine_metrics()
        return (
            "operations_completed" in metrics and
            "resistance_level" in metrics and
            metrics["operations_completed"] > 0
        )
    
    run_test("Engine Metrics Collection", test_engine_metrics)
    
    # Test 10: Different input sizes
    def test_different_input_sizes():
        test_key = secrets.token_bytes(32)
        
        sizes = [16, 32, 64, 128, 256]
        for size in sizes:
            data = secrets.token_bytes(size)
            result = engine.encrypt_side_channel_resistant(data, test_key)
            if not result.success or len(result.ciphertext) != size:
                return False
        return True
    
    run_test("Different Input Sizes", test_different_input_sizes)
    
    # Test 11: Different resistance levels
    def test_resistance_levels():
        levels = [ResistanceLevel.BASIC, ResistanceLevel.INTERMEDIATE, 
                  ResistanceLevel.HIGH, ResistanceLevel.MAXIMUM]
        
        for level in levels:
            e = PostQuantumSideChannelResistantEncryptionEngine(resistance_level=level)
            if e.resistance_level != level:
                return False
        return True
    
    run_test("Resistance Level Configuration", test_resistance_levels)
    
    # Calculate pass rate
    test_results["pass_rate"] = round(test_results["passed_tests"] / test_results["total_tests"] * 100, 2) if test_results["total_tests"] > 0 else 0
    
    # Get final metrics
    test_results["final_engine_metrics"] = engine.get_engine_metrics()
    
    return test_results


if __name__ == "__main__":
    print("=" * 60)
    print("Running Post-Quantum Side-Channel Resistant Encryption Tests")
    print("=" * 60)
    
    results = run_tests()
    
    print(f"\nTotal Tests: {results['total_tests']}")
    print(f"Passed: {results['passed_tests']}")
    print(f"Failed: {results['failed_tests']}")
    print(f"Pass Rate: {results['pass_rate']}%")
    
    print("\n" + "=" * 60)
    print("Test Case Details:")
    print("=" * 60)
    for tc in results["test_cases"]:
        status = "✓ PASS" if tc["passed"] else "✗ FAIL"
        print(f"{status}: {tc['test_name']}")
        if "error" in tc:
            print(f"  Error: {tc['error']}")
    
    # Save results
    with open('/home/user/autonomous-developer/QuantumCrypt-AI/test_results_post_quantum_side_channel_resistant_encryption.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "=" * 60)
    print(f"Results saved to test_results_post_quantum_side_channel_resistant_encryption.json")
    print("=" * 60)
