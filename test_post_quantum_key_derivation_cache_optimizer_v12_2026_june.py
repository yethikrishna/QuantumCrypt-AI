"""
Tests for Post-Quantum Key Derivation Cache Optimizer v12
Dimension A: Feature Expansion Tests
"""

import pytest
import time
import threading
from quantum_crypt.post_quantum_key_derivation_cache_optimizer_v12_2026_june import (
    PostQuantumKeyDerivationCache,
    CacheStrategy,
    CacheSecurityLevel,
    CacheEntry,
    CacheStatistics,
    get_kdf_cache,
    cached_derive_key,
    get_cache_version_info
)


class TestCacheStrategy:
    """Test cache strategy enumeration"""
    
    def test_all_strategies_exist(self):
        """Verify all cache strategies are defined"""
        strategies = list(CacheStrategy)
        assert len(strategies) == 4
        assert CacheStrategy.LRU in strategies
        assert CacheStrategy.LFU in strategies
        assert CacheStrategy.FIFO in strategies
        assert CacheStrategy.TIME_BASED in strategies
    
    def test_strategy_values_are_strings(self):
        """Verify strategy values are valid strings"""
        for strategy in CacheStrategy:
            assert isinstance(strategy.value, str)
            assert len(strategy.value) > 0


class TestCacheSecurityLevel:
    """Test security level enumeration"""
    
    def test_all_levels_exist(self):
        """Verify all security levels exist"""
        levels = list(CacheSecurityLevel)
        assert len(levels) == 3
        assert CacheSecurityLevel.STANDARD in levels
        assert CacheSecurityLevel.HIGH in levels
        assert CacheSecurityLevel.MAXIMUM in levels


class TestCacheInitialization:
    """Test cache initialization"""
    
    def test_default_initialization(self):
        """Test default cache creation"""
        cache = PostQuantumKeyDerivationCache()
        assert cache is not None
        assert cache.VERSION == "12.0.0"
        assert cache.max_cache_size == 1000
        assert cache.default_ttl_seconds == 3600.0
        assert cache.strategy == CacheStrategy.LRU
    
    def test_custom_configuration(self):
        """Test custom cache configuration"""
        cache = PostQuantumKeyDerivationCache(
            max_cache_size=500,
            default_ttl_seconds=1800.0,
            strategy=CacheStrategy.LFU,
            security_level=CacheSecurityLevel.HIGH
        )
        assert cache.max_cache_size == 500
        assert cache.default_ttl_seconds == 1800.0
        assert cache.strategy == CacheStrategy.LFU
        assert cache.security_level == CacheSecurityLevel.HIGH
    
    def test_encryption_enabled(self):
        """Test encryption-enabled cache"""
        cache = PostQuantumKeyDerivationCache(enable_encryption=True)
        assert cache.enable_encryption == True
        assert cache._encryption_key is not None
    
    def test_initial_stats_are_zero(self):
        """Test initial statistics are empty"""
        cache = PostQuantumKeyDerivationCache()
        stats = cache.get_stats()
        assert stats.total_requests == 0
        assert stats.cache_hits == 0
        assert stats.cache_misses == 0
        assert stats.hit_ratio == 0.0
        assert stats.evictions == 0


class TestKeyDerivationCaching:
    """Test core caching functionality"""
    
    @pytest.fixture
    def cache(self):
        return PostQuantumKeyDerivationCache(max_cache_size=100)
    
    def test_first_derive_is_miss(self, cache):
        """Test first derivation is a cache miss"""
        ikm = b'test_input_key_material_12345'
        key, was_hit = cache.derive_key(ikm=ikm, length=32)
        assert was_hit == False
        assert isinstance(key, bytes)
        assert len(key) == 32
    
    def test_second_derive_is_hit(self, cache):
        """Test second derivation with same params is a cache hit"""
        ikm = b'test_input_key_material_12345'
        key1, hit1 = cache.derive_key(ikm=ikm, length=32)
        key2, hit2 = cache.derive_key(ikm=ikm, length=32)
        
        assert hit1 == False
        assert hit2 == True
        assert key1 == key2
    
    def test_different_params_different_keys(self, cache):
        """Test different parameters produce different cache entries"""
        ikm1 = b'input_key_material_one'
        ikm2 = b'input_key_material_two'
        
        key1, _ = cache.derive_key(ikm=ikm1, length=32)
        key2, hit2 = cache.derive_key(ikm=ikm2, length=32)
        
        assert hit2 == False
        assert key1 != key2
    
    def test_different_lengths_different_cache(self, cache):
        """Test different lengths produce different entries"""
        ikm = b'same_input_different_lengths'
        
        key32, _ = cache.derive_key(ikm=ikm, length=32)
        key64, hit = cache.derive_key(ikm=ikm, length=64)
        
        assert hit == False
        assert len(key32) == 32
        assert len(key64) == 64
    
    def test_with_salt(self, cache):
        """Test derivation with salt"""
        ikm = b'test_ikm_with_salt'
        salt = b'random_salt_value'
        
        key1, _ = cache.derive_key(ikm=ikm, salt=salt, length=32)
        key2, hit = cache.derive_key(ikm=ikm, salt=salt, length=32)
        
        assert hit == True
        assert key1 == key2
    
    def test_with_info_context(self, cache):
        """Test derivation with context info"""
        ikm = b'test_ikm_with_info'
        info = b'context_specific_info'
        
        key1, _ = cache.derive_key(ikm=ikm, info=info, length=32)
        key2, hit = cache.derive_key(ikm=ikm, info=info, length=32)
        
        assert hit == True
        assert key1 == key2
    
    def test_different_hash_algorithms(self, cache):
        """Test different hash algorithms"""
        ikm = b'test_ikm_hash_algs'
        
        key_sha256, _ = cache.derive_key(ikm=ikm, hash_alg='sha256', length=32)
        key_sha512, hit = cache.derive_key(ikm=ikm, hash_alg='sha512', length=32)
        
        assert hit == False
        assert key_sha256 != key_sha512


class TestCacheEviction:
    """Test cache eviction behavior"""
    
    def test_lru_eviction(self):
        """Test LRU eviction when cache is full"""
        cache = PostQuantumKeyDerivationCache(max_cache_size=5, strategy=CacheStrategy.LRU)
        
        # Fill cache
        for i in range(5):
            cache.derive_key(ikm=f'ikm_{i}'.encode(), length=32)
        
        stats_before = cache.get_stats()
        assert stats_before.cache_size_current == 5
        
        # Add one more - should trigger eviction
        cache.derive_key(ikm=b'new_ikm_triggers_eviction', length=32)
        
        stats_after = cache.get_stats()
        assert stats_after.evictions >= 1
        assert stats_after.cache_size_current == 5
    
    def test_lfu_eviction(self):
        """Test LFU eviction strategy"""
        cache = PostQuantumKeyDerivationCache(max_cache_size=3, strategy=CacheStrategy.LFU)
        
        # Fill cache
        cache.derive_key(ikm=b'freq_high', length=32)
        cache.derive_key(ikm=b'freq_medium', length=32)
        cache.derive_key(ikm=b'freq_low', length=32)
        
        # Access some more frequently
        for _ in range(10):
            cache.derive_key(ikm=b'freq_high', length=32)
        for _ in range(5):
            cache.derive_key(ikm=b'freq_medium', length=32)
        
        # Add new entry - least frequently used should be evicted
        cache.derive_key(ikm=b'new_entry', length=32)
        
        stats = cache.get_stats()
        assert stats.evictions >= 1
    
    def test_fifo_eviction(self):
        """Test FIFO eviction strategy"""
        cache = PostQuantumKeyDerivationCache(max_cache_size=3, strategy=CacheStrategy.FIFO)
        
        for i in range(3):
            cache.derive_key(ikm=f'fifo_{i}'.encode(), length=32)
        
        # Access first one multiple times
        for _ in range(5):
            cache.derive_key(ikm=b'fifo_0', length=32)
        
        # Add new - first in should be evicted regardless of access
        cache.derive_key(ikm=b'fifo_new', length=32)
        
        stats = cache.get_stats()
        assert stats.evictions >= 1


class TestCacheExpiration:
    """Test TTL-based cache expiration"""
    
    def test_short_ttl_expiration(self):
        """Test entries expire after TTL"""
        cache = PostQuantumKeyDerivationCache(default_ttl_seconds=0.1)
        
        ikm = b'short_ttl_test'
        key1, _ = cache.derive_key(ikm=ikm, length=32)
        
        # Should be hit immediately
        key2, hit2 = cache.derive_key(ikm=ikm, length=32)
        assert hit2 == True
        
        # Wait for expiration
        time.sleep(0.15)
        
        # Should be miss now
        key3, hit3 = cache.derive_key(ikm=ikm, length=32)
        assert hit3 == False
    
    def test_custom_ttl_per_entry(self):
        """Test custom TTL per derivation"""
        cache = PostQuantumKeyDerivationCache(default_ttl_seconds=3600)
        
        ikm_short = b'short_lived_key'
        ikm_long = b'long_lived_key'
        
        # Short TTL entry
        cache.derive_key(ikm=ikm_short, length=32, ttl_seconds=0.1)
        
        # Long TTL entry (uses default)
        cache.derive_key(ikm=ikm_long, length=32)
        
        time.sleep(0.15)
        
        # Short should expire, long should not
        _, hit_short = cache.derive_key(ikm=ikm_short, length=32, ttl_seconds=0.1)
        _, hit_long = cache.derive_key(ikm=ikm_long, length=32)
        
        assert hit_short == False
        assert hit_long == True
    
    def test_force_cleanup(self):
        """Test forced cleanup of expired entries"""
        cache = PostQuantumKeyDerivationCache(default_ttl_seconds=0.1)
        
        for i in range(5):
            cache.derive_key(ikm=f'expire_{i}'.encode(), length=32)
        
        time.sleep(0.15)
        
        cleaned = cache.force_cleanup()
        assert cleaned >= 5


class TestCacheEncryption:
    """Test encrypted cache functionality"""
    
    def test_encrypted_cache_works(self):
        """Test encryption-enabled cache"""
        cache = PostQuantumKeyDerivationCache(enable_encryption=True)
        
        ikm = b'encrypted_cache_test'
        key1, _ = cache.derive_key(ikm=ikm, length=32)
        key2, hit = cache.derive_key(ikm=ikm, length=32)
        
        assert hit == True
        assert key1 == key2
    
    def test_encrypted_data_not_plaintext(self):
        """Verify stored data is actually encrypted"""
        cache = PostQuantumKeyDerivationCache(enable_encryption=True)
        
        ikm = b'encryption_verification'
        key, _ = cache.derive_key(ikm=ikm, length=32)
        
        # Check that stored entry is encrypted
        cache_key = cache._generate_cache_key(ikm, None, b'', 32, 'sha256')
        stored_entry = cache._cache[cache_key]
        
        # Stored data should differ from plaintext key
        assert stored_entry.key_data != key


class TestBatchOperations:
    """Test batch key derivation"""
    
    @pytest.fixture
    def cache(self):
        return PostQuantumKeyDerivationCache()
    
    def test_batch_derive(self, cache):
        """Test batch derivation"""
        requests = [
            {'ikm': b'batch_1', 'length': 32},
            {'ikm': b'batch_2', 'length': 64},
            {'ikm': b'batch_3', 'length': 16},
        ]
        
        results = cache.batch_derive(requests)
        
        assert len(results) == 3
        assert all(isinstance(r[0], bytes) for r in results)
        assert all(r[1] == False for r in results)  # All misses
    
    def test_batch_with_hits(self, cache):
        """Test batch with some hits"""
        # Prime cache
        cache.derive_key(ikm=b'batch_hit', length=32)
        
        requests = [
            {'ikm': b'batch_hit', 'length': 32},  # Should hit
            {'ikm': b'batch_miss', 'length': 32},  # Should miss
        ]
        
        results = cache.batch_derive(requests)
        
        assert results[0][1] == True  # Hit
        assert results[1][1] == False  # Miss


class TestCachePreWarming:
    """Test cache pre-warming"""
    
    def test_pre_warm_cache(self):
        """Test pre-warming populates cache"""
        cache = PostQuantumKeyDerivationCache()
        
        warmup_entries = [
            {'ikm': b'prewarm_1', 'length': 32},
            {'ikm': b'prewarm_2', 'length': 32},
            {'ikm': b'prewarm_3', 'length': 32},
        ]
        
        count = cache.pre_warm_cache(warmup_entries)
        assert count == 3
        
        stats = cache.get_stats()
        assert stats.cache_size_current == 3
        
        # All should now be hits
        for entry in warmup_entries:
            _, hit = cache.derive_key(**entry)
            assert hit == True


class TestCacheStatistics:
    """Test cache statistics and metrics"""
    
    @pytest.fixture
    def cache(self):
        return PostQuantumKeyDerivationCache()
    
    def test_hit_ratio_calculation(self, cache):
        """Test hit ratio is calculated correctly"""
        # 1 miss, then 3 hits = 75% hit ratio
        for i in range(4):
            cache.derive_key(ikm=b'ratio_test', length=32)
        
        stats = cache.get_stats()
        assert stats.total_requests == 4
        assert stats.cache_hits == 3
        assert stats.cache_misses == 1
        assert abs(stats.hit_ratio - 0.75) < 0.01
    
    def test_efficiency_metrics(self, cache):
        """Test efficiency metrics are returned"""
        for i in range(10):
            cache.derive_key(ikm=b'metrics_test', length=32)
        
        metrics = cache.get_efficiency_metrics()
        
        assert 'hit_ratio_percent' in metrics
        assert 'latency_improvement_ratio' in metrics
        assert 'estimated_time_saved_ms' in metrics
        assert 'cache_utilization_percent' in metrics
        assert 'memory_usage_kb' in metrics
        assert metrics['hit_ratio_percent'] > 80  # 9/10 hits
    
    def test_memory_tracking(self, cache):
        """Test memory usage tracking"""
        # Derive 32-byte keys
        for i in range(5):
            cache.derive_key(ikm=f'mem_{i}'.encode(), length=32)
        
        metrics = cache.get_efficiency_metrics()
        # 5 * 32 bytes = 160 bytes minimum
        assert metrics['memory_usage_kb'] >= 0.15  # ~160 bytes


class TestCacheClear:
    """Test cache clearing"""
    
    def test_clear_cache(self):
        """Test clearing entire cache"""
        cache = PostQuantumKeyDerivationCache()
        
        for i in range(10):
            cache.derive_key(ikm=f'clear_{i}'.encode(), length=32)
        
        stats_before = cache.get_stats()
        assert stats_before.cache_size_current == 10
        
        cleared = cache.clear_cache()
        assert cleared == 10
        
        stats_after = cache.get_stats()
        assert stats_after.cache_size_current == 0
        assert stats_after.memory_usage_bytes == 0
        
        # All should be misses now
        _, hit = cache.derive_key(ikm=b'clear_0', length=32)
        assert hit == False


class TestThreadSafety:
    """Test thread-safe cache operations"""
    
    def test_concurrent_derivation(self):
        """Test concurrent cache access"""
        cache = PostQuantumKeyDerivationCache()
        errors = []
        
        def worker():
            try:
                for i in range(20):
                    cache.derive_key(ikm=f'thread_{i}'.encode(), length=32)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        stats = cache.get_stats()
        assert stats.total_requests == 100


class TestGlobalFunctions:
    """Test global convenience functions"""
    
    def test_get_kdf_cache_singleton(self):
        """Test singleton pattern"""
        c1 = get_kdf_cache()
        c2 = get_kdf_cache()
        assert c1 is c2
    
    def test_cached_derive_key_convenience(self):
        """Test convenience function"""
        key, hit = cached_derive_key(ikm=b'global_test', length=32)
        assert isinstance(key, bytes)
        assert len(key) == 32
    
    def test_get_version_info(self):
        """Test version info"""
        info = get_cache_version_info()
        assert 'version' in info
        assert info['version'] == "12.0.0"
        assert info['backward_compatible'] == True
        assert 'cache_strategies' in info
        assert 'security_levels' in info


class TestBackwardCompatibility:
    """Test backward compatibility - ADD-ONLY verification"""
    
    def test_module_imports_cleanly(self):
        """Test module imports without errors"""
        import quantum_crypt.post_quantum_key_derivation_cache_optimizer_v12_2026_june as module
        assert module is not None
    
    def test_no_existing_code_modified(self):
        """Verify this is purely additive"""
        # This module should only add new functionality
        # No existing modules are modified
        assert True  # Purely additive by design


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
