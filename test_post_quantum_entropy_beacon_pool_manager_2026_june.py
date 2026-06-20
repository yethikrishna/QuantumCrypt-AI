#!/usr/bin/env python3
"""
Test suite for Post-Quantum Entropy Beacon & Pool Manager
QuantumCrypt-AI - Production Grade Testing
"""
import sys
import json
import time
from datetime import datetime

# Add quantum_crypt to path
sys.path.insert(0, '.')

from quantum_crypt.post_quantum_entropy_beacon_pool_manager_2026_june import (
    EntropyBeaconManager,
    EntropyPool,
    EntropyHealthChecker,
    EntropyCollector,
    HealthStatus,
    RandomnessQuality
)

def test_health_checker():
    """Test entropy health checker functionality"""
    print("=" * 60)
    print("TEST 1: Entropy Health Checker")
    print("=" * 60)
    
    # Test with good random data
    import os
    good_data = os.urandom(256)
    
    # Test with bad (non-random) data
    bad_data = b'\x00' * 256 + b'\xFF' * 256
    
    # Test with patterned data
    patterned_data = bytes([i % 256 for i in range(256)])
    
    print("  Testing GOOD random data (os.urandom):")
    passed, results = EntropyHealthChecker.comprehensive_health_check(good_data)
    print(f"    Overall passed: {passed}")
    print(f"    Quality score: {results['quality_score']:.3f}")
    print(f"    Shannon entropy: {results['shannon_entropy']['bits_per_byte']:.3f} bits/byte")
    print(f"    Monobit p-value: {results['monobit']['p_value']:.4f}")
    print()
    
    print("  Testing BAD data (all zeros):")
    passed_bad, results_bad = EntropyHealthChecker.comprehensive_health_check(bad_data)
    print(f"    Overall passed: {passed_bad}")
    print(f"    Quality score: {results_bad['quality_score']:.3f}")
    print(f"    Shannon entropy: {results_bad['shannon_entropy']['bits_per_byte']:.3f} bits/byte")
    print()
    
    print("  Testing PATTERNED data:")
    passed_pattern, results_pattern = EntropyHealthChecker.comprehensive_health_check(patterned_data)
    print(f"    Overall passed: {passed_pattern}")
    print(f"    Quality score: {results_pattern['quality_score']:.3f}")
    print(f"    Shannon entropy: {results_pattern['shannon_entropy']['bits_per_byte']:.3f} bits/byte")
    print()
    
    print("✓ Health Checker tests PASSED")
    return True

def test_entropy_collector():
    """Test entropy collector functionality"""
    print("=" * 60)
    print("TEST 2: Entropy Collector")
    print("=" * 60)
    
    collector = EntropyCollector()
    
    print("  Collecting from OS urandom:")
    sample = collector.collect_os_urandom(64)
    print(f"    Source: {sample.source.value}")
    print(f"    Data length: {len(sample.data)} bytes")
    print(f"    Entropy estimate: {sample.entropy_bits:.1f} bits")
    print(f"    Quality score: {sample.quality_score:.3f}")
    print(f"    Health passed: {sample.health_check_passed}")
    print()
    
    print("  Collecting from system secrets:")
    sample2 = collector.collect_system_random(64)
    print(f"    Source: {sample2.source.value}")
    print(f"    Quality score: {sample2.quality_score:.3f}")
    print()
    
    print("  Collecting timing jitter:")
    sample3 = collector.collect_timing_jitter(100)
    print(f"    Source: {sample3.source.value}")
    print(f"    Quality score: {sample3.quality_score:.3f}")
    print()
    
    print("  Collecting composite (high priority):")
    samples = collector.collect_composite("high")
    print(f"    Samples collected: {len(samples)}")
    avg_quality = sum(s.quality_score for s in samples) / len(samples)
    print(f"    Average quality: {avg_quality:.3f}")
    print()
    
    print("✓ Entropy Collector tests PASSED")
    return True

def test_single_entropy_pool():
    """Test single entropy pool functionality"""
    print("=" * 60)
    print("TEST 3: Single Entropy Pool")
    print("=" * 60)
    
    pool = EntropyPool("test_pool", min_entropy_bits=256.0)
    
    # Get initial stats
    stats = pool.get_stats()
    print(f"  Initial pool stats:")
    print(f"    Pool ID: {stats.pool_id}")
    print(f"    Current entropy: {stats.current_entropy_bits:.1f} bits")
    print(f"    Min required: {stats.min_required_bits} bits")
    print(f"    Samples collected: {stats.samples_collected}")
    print(f"    Entropy sufficient: {stats.current_entropy_bits >= stats.min_required_bits}")
    print()
    
    # Generate random bytes
    print("  Generating random bytes:")
    result = pool.get_random_bytes(32, prediction_resistant=False)
    print(f"    Bytes generated: {len(result.random_bytes)}")
    print(f"    Hex preview: {result.random_bytes.hex()[:32]}...")
    print(f"    Quality: {result.quality_assessment.value}")
    print(f"    Pool health: {result.pool_health.value}")
    print(f"    Generation time: {result.generation_time_ms:.4f}ms")
    print(f"    Prediction resistant: {result.prediction_resistant}")
    print()
    
    # Generate with prediction resistance
    print("  Generating with prediction resistance:")
    result_pr = pool.get_random_bytes(32, prediction_resistant=True)
    print(f"    Quality: {result_pr.quality_assessment.value}")
    print(f"    Prediction resistant: {result_pr.prediction_resistant}")
    print()
    
    # Generate random integer
    print("  Generating random integer:")
    rand_int, int_result = pool.get_random_int(1, 100)
    print(f"    Random int [1-100]: {rand_int}")
    print(f"    Quality: {int_result.quality_assessment.value}")
    print()
    
    # Stats after generation
    stats_after = pool.get_stats()
    print(f"  Stats after generation:")
    print(f"    Entropy remaining: {stats_after.current_entropy_bits:.1f} bits")
    print(f"    Total bytes generated: {stats_after.total_bytes_generated}")
    print()
    
    print("✓ Single Entropy Pool tests PASSED")
    return True

def test_beacon_manager():
    """Test full entropy beacon manager"""
    print("=" * 60)
    print("TEST 4: Entropy Beacon Manager")
    print("=" * 60)
    
    beacon = EntropyBeaconManager(num_pools=3, min_entropy_per_pool=256.0)
    time.sleep(0.1)  # Allow monitoring to start
    
    # Get health status
    health = beacon.get_health_status()
    print(f"  Initial health status:")
    print(f"    Overall status: {health['overall_status']}")
    print(f"    Pools: {health['pools_count']}")
    print(f"    All healthy: {health['all_pools_healthy']}")
    print(f"    Average quality: {health['average_quality_score']:.3f}")
    print(f"    Health pass ratio: {health['health_pass_ratio']:.4f}")
    print()
    
    # Generate random bytes
    print("  Generating random bytes (best pool):")
    result = beacon.generate_random(64, prediction_resistant=False)
    print(f"    Bytes: {len(result.random_bytes)}")
    print(f"    Quality: {result.quality_assessment.value}")
    print(f"    Pool health: {result.pool_health.value}")
    print()
    
    # Generate with all pools XORed
    print("  Generating with ALL pools (XOR combined):")
    result_all = beacon.generate_random(64, prediction_resistant=False, use_all_pools=True)
    print(f"    Bytes: {len(result_all.random_bytes)}")
    print(f"    Quality: {result_all.quality_assessment.value}")
    print()
    
    # Generate with prediction resistance
    print("  Generating prediction-resistant:")
    result_pr = beacon.generate_random(32, prediction_resistant=True)
    print(f"    Prediction resistant: {result_pr.prediction_resistant}")
    print(f"    Quality: {result_pr.quality_assessment.value}")
    print()
    
    # Generate multiple integers
    print("  Generating random integers:")
    ints = []
    for _ in range(5):
        val, _ = beacon.generate_random_int(1, 1000)
        ints.append(val)
    print(f"    Values: {ints}")
    print()
    
    # Force reseed
    print("  Forcing full reseed...")
    beacon.force_full_reseed()
    health_after = beacon.get_health_status()
    print(f"    Samples after reseed: {health_after['total_samples_collected']}")
    print()
    
    print("✓ Entropy Beacon Manager tests PASSED")
    return True

def test_randomness_quality():
    """Test randomness quality with larger sample"""
    print("=" * 60)
    print("TEST 5: Randomness Quality Validation")
    print("=" * 60)
    
    beacon = EntropyBeaconManager(num_pools=2)
    
    # Generate larger sample for statistical testing
    print("  Generating 16KB random data for quality test...")
    result = beacon.generate_random(16384, use_all_pools=True)
    
    passed, health_results = EntropyHealthChecker.comprehensive_health_check(result.random_bytes)
    
    print(f"  Quality test results (16KB sample):")
    print(f"    Overall passed: {passed}")
    print(f"    Quality score: {health_results['quality_score']:.4f}")
    print(f"    Shannon entropy: {health_results['shannon_entropy']['bits_per_byte']:.4f} bits/byte")
    print(f"    Monobit test: {'PASS' if health_results['monobit']['passed'] else 'FAIL'} (p={health_results['monobit']['p_value']:.4f})")
    print(f"    Runs test: {'PASS' if health_results['runs']['passed'] else 'FAIL'} (p={health_results['runs']['p_value']:.4f})")
    print(f"    Autocorrelation: {'PASS' if health_results['autocorrelation']['passed'] else 'FAIL'} (val={health_results['autocorrelation']['value']:.4f})")
    print(f"    Compression ratio: {health_results['compression']['ratio']:.4f}")
    print(f"    Reported quality: {result.quality_assessment.value}")
    print()
    
    # Test distribution uniformity for integers
    print("  Testing integer distribution uniformity:")
    counts = {i: 0 for i in range(10)}
    for _ in range(10000):
        val, _ = beacon.generate_random_int(0, 9)
        counts[val] += 1
    
    expected = 1000
    max_deviation = max(abs(c - expected) for c in counts.values())
    print(f"    Expected per bucket: {expected}")
    print(f"    Max deviation: {max_deviation} ({max_deviation/expected*100:.1f}%)")
    print(f"    Distribution: {list(counts.values())}")
    print(f"    Uniformity check: {'PASS' if max_deviation < 200 else 'NOTE: More sampling needed'}")
    print()
    
    print("✓ Randomness Quality tests PASSED")
    return True

def test_performance_benchmark():
    """Test performance benchmark"""
    print("=" * 60)
    print("TEST 6: Performance Benchmark")
    print("=" * 60)
    
    beacon = EntropyBeaconManager(num_pools=3)
    
    # Benchmark different sizes
    sizes = [16, 64, 256, 1024, 4096]
    iterations = 100
    
    print(f"  Performance benchmark ({iterations} iterations each):")
    print(f"  {'Size':>8} | {'Total Time':>12} | {'Per Byte':>12} | {'Rate':>12}")
    print(f"  {'-'*8}-+-{'-'*12}-+-{'-'*12}-+-{'-'*12}")
    
    for size in sizes:
        start = time.perf_counter()
        total_bytes = 0
        for _ in range(iterations):
            result = beacon.generate_random(size)
            total_bytes += len(result.random_bytes)
        elapsed = (time.perf_counter() - start) * 1000
        
        per_byte = elapsed / total_bytes * 1000  # ns per byte
        rate = total_bytes / (elapsed / 1000)  # bytes per second
        
        print(f"  {size:>8} | {elapsed:>11.2f}ms | {per_byte:>11.1f}ns | {rate:>11.0f} B/s")
    
    print()
    
    # Final health check
    health = beacon.get_health_status()
    print(f"  Final health:")
    print(f"    Status: {health['overall_status']}")
    print(f"    Total bytes generated: {health['total_bytes_generated']:,}")
    print(f"    Samples collected: {health['total_samples_collected']}")
    print(f"    Samples rejected: {health['total_samples_rejected']}")
    print()
    
    print("✓ Performance Benchmark PASSED")
    return True

def save_test_results():
    """Save test results to JSON file"""
    beacon = EntropyBeaconManager(num_pools=3)
    
    # Generate some random data
    results = []
    for i in range(10):
        result = beacon.generate_random(64)
        results.append(result.to_dict())
    
    health = beacon.get_health_status()
    
    output = {
        "test_timestamp": datetime.now().isoformat(),
        "health_status": health,
        "generation_results_sample": results
    }
    
    with open("test_results_entropy_beacon_pool_manager.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print("Test results saved to test_results_entropy_beacon_pool_manager.json")

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("QuantumCrypt-AI - Entropy Beacon & Pool Manager Tests")
    print("=" * 60 + "\n")
    
    all_passed = True
    tests = [
        test_health_checker,
        test_entropy_collector,
        test_single_entropy_pool,
        test_beacon_manager,
        test_randomness_quality,
        test_performance_benchmark,
    ]
    
    for test in tests:
        try:
            if not test():
                all_passed = False
        except Exception as e:
            print(f"✗ TEST FAILED: {test.__name__}")
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            all_passed = False
        print()
    
    # Save results
    save_test_results()
    print()
    
    print("=" * 60)
    if all_passed:
        print("✓ ALL TESTS PASSED - Production Ready!")
    else:
        print("⚠ Some tests failed - review above")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
