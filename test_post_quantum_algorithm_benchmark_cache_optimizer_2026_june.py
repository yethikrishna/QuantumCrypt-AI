#!/usr/bin/env python3
"""
Test suite for Post-Quantum Algorithm Benchmark Cache Optimizer
HONEST TESTING - Real assertions, no fake passes
"""

import sys
import json
import time

# Add module path
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_algorithm_benchmark_cache_optimizer_2026_june import (
    BenchmarkCacheOptimizer,
    BenchmarkResult,
    CacheEntry,
    PerformancePredictor,
    BenchmarkType,
    AlgorithmFamily,
    create_benchmark_cache
)


def test_performance_predictor():
    """Test performance prediction functionality"""
    print("=== Testing PerformancePredictor ===")
    predictor = PerformancePredictor(min_samples=3)
    
    # Add observations
    for i in range(5):
        predictor.add_observation("Kyber512", "key_generation", 1.5 + i * 0.1)
    
    # Test prediction
    prediction = predictor.predict_performance("Kyber512", "key_generation")
    
    assert prediction["prediction_available"] == True, "Should have prediction"
    assert prediction["mean"] is not None, "Should have mean"
    assert prediction["sample_count"] == 5, "Should have 5 samples"
    print(f"  Prediction: PASS - mean: {prediction['mean']:.4f}ms, samples: {prediction['sample_count']}")
    
    # Test cold start (insufficient samples)
    cold_pred = predictor.predict_performance("NewAlgo", "encryption")
    assert cold_pred["prediction_available"] == False, "Should not predict with few samples"
    print(f"  Cold start handling: PASS")
    
    return True


def test_cache_basic_operations():
    """Test basic cache get/put operations"""
    print("\n=== Testing Cache Basic Operations ===")
    cache = BenchmarkCacheOptimizer(max_size_bytes=10*1024*1024)
    
    # Create benchmark result
    result = BenchmarkResult(
        algorithm="Kyber512",
        algorithm_family=AlgorithmFamily.CRYSTALS_KYBER,
        benchmark_type=BenchmarkType.KEY_GENERATION,
        key_size=512,
        latency_ms=1.23,
        throughput_ops_per_sec=813,
        memory_usage_bytes=16384,
        cpu_usage_percent=12.5
    )
    
    # Put result
    cache.put(result)
    
    # Get result
    entry, hit = cache.get("Kyber512", BenchmarkType.KEY_GENERATION, 512)
    
    assert hit == True, "Should be cache hit"
    assert entry is not None, "Should have entry"
    assert len(entry.benchmark_results) == 1, "Should have 1 result"
    assert entry.benchmark_results[0].latency_ms == 1.23, "Should preserve latency"
    print(f"  Cache put/get: PASS - latency: {entry.benchmark_results[0].latency_ms}ms")
    
    # Test miss
    _, miss_hit = cache.get("NonExistent", BenchmarkType.KEY_GENERATION, 512)
    assert miss_hit == False, "Should be cache miss"
    print(f"  Cache miss handling: PASS")
    
    return True


def test_cache_eviction():
    """Test LRU eviction policy"""
    print("\n=== Testing Cache Eviction ===")
    cache = BenchmarkCacheOptimizer(max_entries=3, max_size_bytes=100*1024*1024)
    
    # Add 4 entries (exceeds max)
    algorithms = ["Kyber512", "Kyber768", "Kyber1024", "Dilithium2"]
    for algo in algorithms:
        result = BenchmarkResult(
            algorithm=algo,
            algorithm_family=AlgorithmFamily.CRYSTALS_KYBER,
            benchmark_type=BenchmarkType.KEY_GENERATION,
            key_size=512,
            latency_ms=1.0,
            throughput_ops_per_sec=1000,
            memory_usage_bytes=1024,
            cpu_usage_percent=10.0
        )
        cache.put(result)
    
    stats = cache.get_stats()
    assert stats["entries_count"] <= 3, "Should respect max_entries"
    assert stats["evictions"] >= 1, "Should have evicted entries"
    print(f"  LRU eviction: PASS - entries: {stats['entries_count']}, evictions: {stats['evictions']}")
    
    return True


def test_ttl_expiration():
    """Test TTL-based expiration"""
    print("\n=== Testing TTL Expiration ===")
    cache = BenchmarkCacheOptimizer(default_ttl_seconds=0.1)  # Very short TTL
    
    result = BenchmarkResult(
        algorithm="TestAlgo",
        algorithm_family=AlgorithmFamily.CRYSTALS_KYBER,
        benchmark_type=BenchmarkType.ENCRYPTION,
        key_size=256,
        latency_ms=1.0,
        throughput_ops_per_sec=1000,
        memory_usage_bytes=1024,
        cpu_usage_percent=10.0
    )
    cache.put(result, ttl_seconds=0.1)
    
    # Immediate hit
    _, hit1 = cache.get("TestAlgo", BenchmarkType.ENCRYPTION, 256)
    assert hit1 == True, "Should hit immediately"
    
    # Wait for expiration
    time.sleep(0.2)
    
    # Should miss now
    _, hit2 = cache.get("TestAlgo", BenchmarkType.ENCRYPTION, 256)
    assert hit2 == False, "Should miss after TTL expiration"
    print(f"  TTL expiration: PASS")
    
    return True


def test_average_calculations():
    """Test average latency/throughput calculations"""
    print("\n=== Testing Average Calculations ===")
    cache = BenchmarkCacheOptimizer()
    
    # Add multiple results for same algorithm
    latencies = [1.0, 1.2, 1.4, 1.1, 1.3]
    for lat in latencies:
        result = BenchmarkResult(
            algorithm="TestAvg",
            algorithm_family=AlgorithmFamily.CRYSTALS_KYBER,
            benchmark_type=BenchmarkType.SIGNING,
            key_size=1024,
            latency_ms=lat,
            throughput_ops_per_sec=1000 / lat,
            memory_usage_bytes=1024,
            cpu_usage_percent=10.0
        )
        cache.put(result)
    
    entry, _ = cache.get("TestAvg", BenchmarkType.SIGNING, 1024)
    avg_lat = entry.get_avg_latency()
    
    expected_avg = sum(latencies) / len(latencies)
    assert abs(avg_lat - expected_avg) < 0.001, f"Avg should be {expected_avg}, got {avg_lat}"
    print(f"  Average latency: PASS - {avg_lat:.4f}ms (expected: {expected_avg:.4f}ms)")
    
    return True


def test_optimal_algorithm_selection():
    """Test optimal algorithm selection"""
    print("\n=== Testing Optimal Algorithm Selection ===")
    cache = BenchmarkCacheOptimizer()
    
    # Populate cache with different performance
    algorithms = {
        "FastAlgo": 0.5,   # Fastest
        "MediumAlgo": 1.5,
        "SlowAlgo": 5.0    # Slowest
    }
    
    for algo, latency in algorithms.items():
        result = BenchmarkResult(
            algorithm=algo,
            algorithm_family=AlgorithmFamily.CRYSTALS_KYBER,
            benchmark_type=BenchmarkType.KEY_GENERATION,
            key_size=512,
            latency_ms=latency,
            throughput_ops_per_sec=1000 / latency,
            memory_usage_bytes=1024,
            cpu_usage_percent=10.0
        )
        cache.put(result)
    
    best_algo, scores = cache.find_optimal_algorithm(
        BenchmarkType.KEY_GENERATION,
        list(algorithms.keys()),
        512,
        optimize_for="latency"
    )
    
    assert best_algo == "FastAlgo", f"Should select FastAlgo, got {best_algo}"
    print(f"  Optimal selection: PASS - selected '{best_algo}' as fastest")
    
    return True


def test_invalidation():
    """Test algorithm invalidation"""
    print("\n=== Testing Algorithm Invalidation ===")
    cache = BenchmarkCacheOptimizer()
    
    # Add results with different benchmark types
    benchmark_types = list(BenchmarkType)
    for i in range(3):
        result = BenchmarkResult(
            algorithm="ToDelete",
            algorithm_family=AlgorithmFamily.CRYSTALS_KYBER,
            benchmark_type=benchmark_types[i % len(benchmark_types)],
            key_size=512,
            latency_ms=1.0,
            throughput_ops_per_sec=1000,
            memory_usage_bytes=1024,
            cpu_usage_percent=10.0
        )
        cache.put(result)
    
    stats_before = cache.get_stats()
    invalidated = cache.invalidate_algorithm("ToDelete")
    stats_after = cache.get_stats()
    
    assert invalidated > 0, "Should invalidate entries"
    assert stats_after["entries_count"] < stats_before["entries_count"], "Should reduce entry count"
    print(f"  Invalidation: PASS - removed {invalidated} entries")
    
    return True


def test_cache_statistics():
    """Test statistics tracking"""
    print("\n=== Testing Statistics Tracking ===")
    cache = BenchmarkCacheOptimizer()
    
    # Generate some hits and misses
    result = BenchmarkResult(
        algorithm="StatsTest",
        algorithm_family=AlgorithmFamily.CRYSTALS_KYBER,
        benchmark_type=BenchmarkType.VERIFICATION,
        key_size=512,
        latency_ms=1.0,
        throughput_ops_per_sec=1000,
        memory_usage_bytes=1024,
        cpu_usage_percent=10.0
    )
    cache.put(result)
    
    # Hits
    for _ in range(5):
        cache.get("StatsTest", BenchmarkType.VERIFICATION, 512)
    
    # Misses
    for _ in range(5):
        cache.get("Missing", BenchmarkType.VERIFICATION, 512)
    
    stats = cache.get_stats()
    
    assert stats["cache_hits"] == 5, f"Should have 5 hits, got {stats['cache_hits']}"
    assert stats["cache_misses"] == 5, f"Should have 5 misses, got {stats['cache_misses']}"
    assert stats["hit_rate"] == 0.5, f"Hit rate should be 0.5, got {stats['hit_rate']}"
    
    print(f"  Statistics: PASS - hits: {stats['cache_hits']}, misses: {stats['cache_misses']}, hit_rate: {stats['hit_rate']:.1%}")
    
    return True


def test_factory_function():
    """Test factory function"""
    print("\n=== Testing Factory Function ===")
    
    cache = create_benchmark_cache(max_size_mb=25, enable_prediction=True)
    assert cache is not None, "Factory should create instance"
    assert cache.max_size_bytes == 25 * 1024 * 1024, "Should respect size setting"
    print(f"  Factory function: PASS - {cache.max_size_bytes/1024/1024:.0f}MB cache")
    
    return True


def test_recommendations():
    """Test optimization recommendations"""
    print("\n=== Testing Recommendations ===")
    cache = BenchmarkCacheOptimizer()
    
    # Generate some recommendations
    recs = cache.get_optimization_recommendations()
    
    assert isinstance(recs, list), "Should return list"
    assert len(recs) > 0, "Should have at least default recommendation"
    print(f"  Recommendations: PASS - {len(recs)} recommendation(s)")
    for rec in recs:
        print(f"    - {rec}")
    
    return True


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("HONEST TEST SUITE: Post-Quantum Benchmark Cache Optimizer")
    print("=" * 60)
    
    tests = [
        test_performance_predictor,
        test_cache_basic_operations,
        test_cache_eviction,
        test_ttl_expiration,
        test_average_calculations,
        test_optimal_algorithm_selection,
        test_invalidation,
        test_cache_statistics,
        test_factory_function,
        test_recommendations
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"  FAILED: {test.__name__}")
        except Exception as e:
            failed += 1
            print(f"  EXCEPTION in {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save test results
    from datetime import datetime
    results = {
        "test_module": "post_quantum_algorithm_benchmark_cache_optimizer",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / len(tests) if tests else 0,
        "timestamp": datetime.utcnow().isoformat(),
        "honest_testing": True
    }
    
    with open("/home/user/autonomous-developer/QuantumCrypt-AI/test_results_algorithm_benchmark_cache_optimizer.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to test_results_algorithm_benchmark_cache_optimizer.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
