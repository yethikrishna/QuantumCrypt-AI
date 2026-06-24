"""
Test suite for Post-Quantum Benchmark Cache Optimizer v76
ADD-ONLY TEST - no existing tests modified
All existing tests will continue to pass
"""

import pytest
import sys
import os
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_benchmark_cache_optimizer_v76_2026_june import (
    PQBenchmarkCacheOptimizer,
    BenchmarkCacheEntry,
    CacheStatistics,
    CacheStrategy,
    AlgorithmCategory,
    benchmark_cache
)


class TestPQBenchmarkCacheOptimizer:
    """Test benchmark caching functionality"""
    
    def test_cache_initialization(self):
        """Test basic cache initialization"""
        cache = PQBenchmarkCacheOptimizer(enable_disk_cache=False)
        assert cache.strategy == CacheStrategy.HYBRID
        assert cache.default_ttl == 3600
        assert cache.max_memory_entries == 1000
    
    def test_cache_put_and_get(self):
        """Test basic put and get operations"""
        cache = PQBenchmarkCacheOptimizer(enable_disk_cache=False)
        
        result = {"latency_ms": 10.5, "throughput": 1000}
        
        cache.put(
            algorithm="CRYSTALS-Kyber",
            category="key_encapsulation_mechanism",
            operation="keygen",
            key_size=768,
            iterations=1000,
            result=result
        )
        
        cached = cache.get(
            algorithm="CRYSTALS-Kyber",
            category="key_encapsulation_mechanism",
            operation="keygen",
            key_size=768,
            iterations=1000
        )
        
        assert cached is not None
        assert cached["latency_ms"] == 10.5
        assert cached["throughput"] == 1000
    
    def test_cache_miss(self):
        """Test cache miss behavior"""
        cache = PQBenchmarkCacheOptimizer(enable_disk_cache=False)
        
        cached = cache.get(
            algorithm="NonExistent-Alg",
            category="KEM",
            operation="keygen",
            key_size=512,
            iterations=100
        )
        
        assert cached is None
    
    def test_cache_hit_miss_statistics(self):
        """Test hit/miss statistics tracking"""
        cache = PQBenchmarkCacheOptimizer(enable_disk_cache=False)
        
        # Populate cache
        cache.put("Test-Alg", "KEM", "encap", 512, 100, {"test": True})
        
        # Hit
        cache.get("Test-Alg", "KEM", "encap", 512, 100)
        # Miss
        cache.get("Test-Alg", "KEM", "encap", 512, 999)
        
        stats = cache.get_statistics()
        assert stats["hits"] >= 1
        assert stats["misses"] >= 1
        assert "hit_rate" in stats
    
    def test_cached_benchmark_wrapper(self):
        """Test the cached_benchmark wrapper function"""
        cache = PQBenchmarkCacheOptimizer(enable_disk_cache=False)
        
        call_count = [0]
        
        def mock_benchmark():
            call_count[0] += 1
            return {"latency_ms": 42.0, "ops_per_second": 1000}
        
        # First call - should execute benchmark
        result1, cached1 = cache.cached_benchmark(
            mock_benchmark,
            algorithm="Test-Alg",
            category="KEM",
            operation="keygen",
            key_size=512,
            iterations=100
        )
        
        assert cached1 is False
        assert call_count[0] == 1
        assert result1["latency_ms"] == 42.0
        
        # Second call - should hit cache
        result2, cached2 = cache.cached_benchmark(
            mock_benchmark,
            algorithm="Test-Alg",
            category="KEM",
            operation="keygen",
            key_size=512,
            iterations=100
        )
        
        assert cached2 is True
        assert call_count[0] == 1  # Not called again
        assert result2["latency_ms"] == 42.0
    
    def test_different_key_size_different_cache(self):
        """Test that different parameters get different cache entries"""
        cache = PQBenchmarkCacheOptimizer(enable_disk_cache=False)
        
        cache.put("Test-Alg", "KEM", "keygen", 512, 100, {"size": 512})
        cache.put("Test-Alg", "KEM", "keygen", 1024, 100, {"size": 1024})
        
        result_512 = cache.get("Test-Alg", "KEM", "keygen", 512, 100)
        result_1024 = cache.get("Test-Alg", "KEM", "keygen", 1024, 100)
        
        assert result_512["size"] == 512
        assert result_1024["size"] == 1024
    
    def test_invalidate_by_algorithm(self):
        """Test cache invalidation by algorithm"""
        cache = PQBenchmarkCacheOptimizer(enable_disk_cache=False)
        
        cache.put("Alg-A", "KEM", "keygen", 512, 100, {"alg": "A"})
        cache.put("Alg-B", "KEM", "keygen", 512, 100, {"alg": "B"})
        
        cache.invalidate(algorithm="Alg-A")
        
        assert cache.get("Alg-A", "KEM", "keygen", 512, 100) is None
        assert cache.get("Alg-B", "KEM", "keygen", 512, 100) is not None
    
    def test_clear_all(self):
        """Test clearing entire cache"""
        cache = PQBenchmarkCacheOptimizer(enable_disk_cache=False)
        
        cache.put("Alg-A", "KEM", "keygen", 512, 100, {"alg": "A"})
        cache.put("Alg-B", "KEM", "keygen", 512, 100, {"alg": "B"})
        
        cache.clear_all()
        
        assert cache.get("Alg-A", "KEM", "keygen", 512, 100) is None
        assert cache.get("Alg-B", "KEM", "keygen", 512, 100) is None
    
    def test_cache_entry_expiration(self):
        """Test TTL-based cache expiration"""
        entry = BenchmarkCacheEntry(
            algorithm="Test",
            category="KEM",
            operation="keygen",
            key_size=512,
            iterations=100,
            result={},
            timestamp=time.time() - 10,  # 10 seconds old
            ttl_seconds=5  # Expires after 5 seconds
        )
        
        assert entry.is_expired() is True
    
    def test_cache_entry_not_expired(self):
        """Test non-expired cache entry"""
        entry = BenchmarkCacheEntry(
            algorithm="Test",
            category="KEM",
            operation="keygen",
            key_size=512,
            iterations=100,
            result={},
            timestamp=time.time(),
            ttl_seconds=3600
        )
        
        assert entry.is_expired() is False
    
    def test_never_expire_strategy(self):
        """Test never expire TTL"""
        entry = BenchmarkCacheEntry(
            algorithm="Test",
            category="KEM",
            operation="keygen",
            key_size=512,
            iterations=100,
            result={},
            timestamp=time.time() - 999999,
            ttl_seconds=-1  # Never expire
        )
        
        assert entry.is_expired() is False
    
    def test_cache_summary(self):
        """Test cache summary generation"""
        cache = PQBenchmarkCacheOptimizer(enable_disk_cache=False)
        
        cache.put("Kyber", "KEM", "keygen", 512, 100, {})
        cache.put("Kyber", "KEM", "encap", 512, 100, {})
        cache.put("Dilithium", "SIGNATURE", "sign", 1024, 100, {})
        
        summary = cache.get_cache_summary()
        
        assert "by_algorithm" in summary
        assert "by_category" in summary
        assert "by_operation" in summary
        assert summary["by_algorithm"].get("Kyber", 0) >= 2
    
    def test_disk_cache_persistence(self):
        """Test disk cache persistence"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache1 = PQBenchmarkCacheOptimizer(cache_dir=tmpdir, enable_disk_cache=True)
            
            cache1.put("Test-Alg", "KEM", "keygen", 512, 100, {"disk": True})
            
            # Create new cache instance pointing to same directory
            cache2 = PQBenchmarkCacheOptimizer(cache_dir=tmpdir, enable_disk_cache=True)
            
            result = cache2.get("Test-Alg", "KEM", "keygen", 512, 100)
            assert result is not None
            assert result["disk"] is True
    
    def test_lru_eviction(self):
        """Test LRU eviction when cache exceeds max size"""
        cache = PQBenchmarkCacheOptimizer(
            enable_disk_cache=False,
            max_memory_entries=2
        )
        
        cache.put("Alg-1", "KEM", "keygen", 512, 100, {"alg": 1})
        cache.put("Alg-2", "KEM", "keygen", 512, 100, {"alg": 2})
        cache.put("Alg-3", "KEM", "keygen", 512, 100, {"alg": 3})
        
        stats = cache.get_statistics()
        assert stats["evictions"] >= 1
    
    def test_cache_entry_serialization(self):
        """Test cache entry to_dict conversion"""
        entry = BenchmarkCacheEntry(
            algorithm="Test",
            category="KEM",
            operation="keygen",
            key_size=512,
            iterations=100,
            result={"test": True},
            timestamp=1234567890.0,
            ttl_seconds=3600
        )
        
        d = entry.to_dict()
        assert d["algorithm"] == "Test"
        assert d["key_size"] == 512
        assert d["result"]["test"] is True
    
    def test_cache_statistics_hit_rate(self):
        """Test cache statistics hit rate calculation"""
        stats = CacheStatistics()
        stats.hits = 90
        stats.misses = 10
        
        assert stats.hit_rate == 0.9
        d = stats.to_dict()
        assert d["hit_rate"] == 90.0
    
    def test_singleton_instance(self):
        """Test that singleton instance exists"""
        assert benchmark_cache is not None
        assert isinstance(benchmark_cache, PQBenchmarkCacheOptimizer)
    
    def test_algorithm_category_enum(self):
        """Test algorithm category enum values"""
        assert AlgorithmCategory.KEM.value == "key_encapsulation_mechanism"
        assert AlgorithmCategory.SIGNATURE.value == "digital_signature"
    
    def test_cache_strategy_enum(self):
        """Test cache strategy enum values"""
        assert CacheStrategy.TIME_BASED.value == "time_based"
        assert CacheStrategy.HYBRID.value == "hybrid"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
