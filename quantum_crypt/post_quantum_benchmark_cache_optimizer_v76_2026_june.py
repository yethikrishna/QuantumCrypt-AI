"""
Post-Quantum Cryptographic Algorithm Benchmark Cache Optimizer v76
Optimizes benchmark performance through intelligent result caching.
ADD-ONLY MODULE - wraps existing benchmark functionality, no core code modified.

Stability: STABLE
Backward Compatible: YES
Dependencies: None additional
"""

import hashlib
import json
import time
import os
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path


class CacheStrategy(Enum):
    """Cache invalidation strategies"""
    TIME_BASED = "time_based"
    VERSION_BASED = "version_based"
    HYBRID = "hybrid"
    NEVER_EXPIRE = "never_expire"


class AlgorithmCategory(Enum):
    """Post-quantum algorithm categories"""
    KEM = "key_encapsulation_mechanism"
    SIGNATURE = "digital_signature"
    HYBRID = "hybrid_classical_pq"
    HASH = "hash_function"


@dataclass
class BenchmarkCacheEntry:
    """Single cached benchmark result"""
    algorithm: str
    category: str
    operation: str
    key_size: int
    iterations: int
    result: Dict[str, Any]
    timestamp: float
    ttl_seconds: int
    version: str = "1.0.0"
    checksum: str = ""
    
    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check if cache entry has expired"""
        if self.ttl_seconds <= 0:
            return False
        now = current_time or time.time()
        return (now - self.timestamp) > self.ttl_seconds
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CacheStatistics:
    """Cache performance statistics"""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_entries: int = 0
    memory_usage_bytes: int = 0
    
    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
    
    def to_dict(self) -> Dict:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "total_entries": self.total_entries,
            "memory_usage_bytes": self.memory_usage_bytes,
            "hit_rate": round(self.hit_rate * 100, 2)
        }


class PQBenchmarkCacheOptimizer:
    """
    Intelligent caching layer for post-quantum cryptographic benchmarks.
    
    Features:
    - In-memory LRU caching
    - Persistent disk caching
    - Multiple invalidation strategies
    - Hit/miss statistics
    - Automatic cache pruning
    
    ADD-ONLY: This module layers on top of existing benchmarking.
    No existing modules are modified.
    """
    
    def __init__(self,
                 cache_dir: Optional[str] = None,
                 strategy: CacheStrategy = CacheStrategy.HYBRID,
                 default_ttl: int = 3600,
                 max_memory_entries: int = 1000,
                 enable_disk_cache: bool = True):
        
        self.strategy = strategy
        self.default_ttl = default_ttl
        self.max_memory_entries = max_memory_entries
        self.enable_disk_cache = enable_disk_cache
        
        # In-memory cache
        self._memory_cache: Dict[str, BenchmarkCacheEntry] = {}
        self._access_order: List[str] = []
        
        # Disk cache location
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / ".pqcrypto" / "benchmark_cache"
        
        if enable_disk_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Statistics
        self.stats = CacheStatistics()
    
    def _compute_cache_key(self,
                          algorithm: str,
                          category: str,
                          operation: str,
                          key_size: int,
                          iterations: int,
                          **kwargs) -> str:
        """Compute unique cache key for benchmark parameters"""
        params = {
            "algorithm": algorithm,
            "category": category,
            "operation": operation,
            "key_size": key_size,
            "iterations": iterations,
            **kwargs
        }
        param_str = json.dumps(params, sort_keys=True)
        return hashlib.sha256(param_str.encode()).hexdigest()[:32]
    
    def _prune_memory_cache(self):
        """Enforce LRU eviction when memory cache is full"""
        while len(self._memory_cache) > self.max_memory_entries:
            # Remove least recently used
            if self._access_order:
                oldest_key = self._access_order.pop(0)
                if oldest_key in self._memory_cache:
                    del self._memory_cache[oldest_key]
                    self.stats.evictions += 1
            else:
                break
    
    def _update_access_order(self, key: str):
        """Update LRU access order"""
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
    
    def _load_from_disk(self, key: str) -> Optional[BenchmarkCacheEntry]:
        """Load cache entry from disk"""
        if not self.enable_disk_cache:
            return None
        
        cache_file = self.cache_dir / f"{key}.json"
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            # Reconstruct entry
            entry = BenchmarkCacheEntry(
                algorithm=data['algorithm'],
                category=data['category'],
                operation=data['operation'],
                key_size=data['key_size'],
                iterations=data['iterations'],
                result=data['result'],
                timestamp=data['timestamp'],
                ttl_seconds=data['ttl_seconds'],
                version=data.get('version', '1.0.0'),
                checksum=data.get('checksum', '')
            )
            return entry
        except Exception:
            return None
    
    def _save_to_disk(self, key: str, entry: BenchmarkCacheEntry):
        """Save cache entry to disk"""
        if not self.enable_disk_cache:
            return
        
        try:
            cache_file = self.cache_dir / f"{key}.json"
            with open(cache_file, 'w') as f:
                json.dump(entry.to_dict(), f, indent=2)
        except Exception:
            pass
    
    def get(self,
            algorithm: str,
            category: str,
            operation: str,
            key_size: int,
            iterations: int,
            **kwargs) -> Optional[Dict[str, Any]]:
        """
        Try to get cached benchmark result.
        
        Returns:
            Cached result dict, or None if not found/expired
        """
        key = self._compute_cache_key(
            algorithm, category, operation, key_size, iterations, **kwargs
        )
        
        # Check memory cache first
        entry = self._memory_cache.get(key)
        
        # Check disk cache if not in memory
        if entry is None:
            entry = self._load_from_disk(key)
            if entry:
                self._memory_cache[key] = entry
        
        if entry:
            # Check expiration based on strategy
            expired = False
            if self.strategy in [CacheStrategy.TIME_BASED, CacheStrategy.HYBRID]:
                expired = entry.is_expired()
            
            if not expired:
                self.stats.hits += 1
                self._update_access_order(key)
                # Also refresh memory cache from disk result
                if key not in self._memory_cache:
                    self._memory_cache[key] = entry
                return entry['result'] if isinstance(entry, dict) else entry.result
        
        self.stats.misses += 1
        return None
    
    def put(self,
            algorithm: str,
            category: str,
            operation: str,
            key_size: int,
            iterations: int,
            result: Dict[str, Any],
            ttl_seconds: Optional[int] = None,
            **kwargs):
        """
        Store benchmark result in cache.
        """
        key = self._compute_cache_key(
            algorithm, category, operation, key_size, iterations, **kwargs
        )
        
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        
        entry = BenchmarkCacheEntry(
            algorithm=algorithm,
            category=category,
            operation=operation,
            key_size=key_size,
            iterations=iterations,
            result=result,
            timestamp=time.time(),
            ttl_seconds=ttl,
            version=kwargs.get('version', '1.0.0'),
            checksum=hashlib.md5(json.dumps(result, sort_keys=True).encode()).hexdigest()
        )
        
        # Store in memory
        self._memory_cache[key] = entry
        self._update_access_order(key)
        self._prune_memory_cache()
        
        # Store on disk
        self._save_to_disk(key, entry)
        
        self.stats.total_entries = len(self._memory_cache)
    
    def cached_benchmark(self,
                        benchmark_func: Callable,
                        algorithm: str,
                        category: str,
                        operation: str,
                        key_size: int,
                        iterations: int,
                        **kwargs) -> Tuple[Dict[str, Any], bool]:
        """
        Wrapper to run benchmark with caching.
        
        Returns:
            Tuple of (result, was_cached)
        """
        # Try cache first
        cached = self.get(algorithm, category, operation, key_size, iterations, **kwargs)
        if cached is not None:
            return cached, True
        
        # Cache miss - run actual benchmark
        start_time = time.time()
        result = benchmark_func()
        end_time = time.time()
        
        # Enhance result with timing metadata
        enhanced_result = {
            **result,
            "_cached": False,
            "_benchmark_duration_ms": (end_time - start_time) * 1000,
            "_algorithm": algorithm,
            "_operation": operation
        }
        
        # Store in cache
        self.put(algorithm, category, operation, key_size, iterations, enhanced_result, **kwargs)
        
        return enhanced_result, False
    
    def invalidate(self, algorithm: Optional[str] = None, category: Optional[str] = None):
        """
        Invalidate cache entries, optionally filtered by algorithm or category.
        """
        keys_to_remove = []
        
        for key, entry in self._memory_cache.items():
            if algorithm and entry.algorithm != algorithm:
                continue
            if category and entry.category != category:
                continue
            keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self._memory_cache[key]
            if key in self._access_order:
                self._access_order.remove(key)
            self.stats.evictions += 1
    
    def clear_all(self):
        """Clear entire cache (memory and disk)"""
        self._memory_cache.clear()
        self._access_order.clear()
        self.stats.evictions += self.stats.total_entries
        self.stats.total_entries = 0
        
        if self.enable_disk_cache and self.cache_dir.exists():
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    cache_file.unlink()
                except Exception:
                    pass
    
    def get_statistics(self) -> Dict:
        """Get cache performance statistics"""
        self.stats.total_entries = len(self._memory_cache)
        self.stats.memory_usage_bytes = sum(
            len(json.dumps(e.to_dict()).encode()) 
            for e in self._memory_cache.values()
        )
        return self.stats.to_dict()
    
    def get_cache_summary(self) -> Dict:
        """Get summary of cached benchmarks"""
        summary = {
            "by_algorithm": {},
            "by_category": {},
            "by_operation": {}
        }
        
        for entry in self._memory_cache.values():
            alg = entry.algorithm
            cat = entry.category
            op = entry.operation
            
            summary["by_algorithm"][alg] = summary["by_algorithm"].get(alg, 0) + 1
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1
            summary["by_operation"][op] = summary["by_operation"].get(op, 0) + 1
        
        return summary


# Export singleton for easy use
benchmark_cache = PQBenchmarkCacheOptimizer()

__all__ = [
    'PQBenchmarkCacheOptimizer',
    'BenchmarkCacheEntry',
    'CacheStatistics',
    'CacheStrategy',
    'AlgorithmCategory',
    'benchmark_cache'
]
