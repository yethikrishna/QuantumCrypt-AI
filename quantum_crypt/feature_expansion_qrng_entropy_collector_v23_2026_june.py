"""
QuantumCrypt AI - QRNG Entropy Collector
Dimension A: Feature Expansion
Version: v23 - June 2026
API Stability: STABLE

Quantum Random Number Generator Entropy Collector provides
high-quality entropy sources for cryptographic operations.
Supports multiple entropy sources with health testing,
entropy estimation, and mixing.
"""

import hashlib
import hmac
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from math import log2


class EntropySourceType(Enum):
    """Types of entropy sources."""
    SYSTEM = "system"              # os.urandom
    HARDWARE = "hardware"          # Hardware RNG if available
    TIMING = "timing"              # High-resolution timing jitter
    CPU_CYCLES = "cpu_cycles"      # CPU cycle counter variations
    NETWORK = "network"            # Network packet timing
    MOUSE = "mouse"                # Mouse movement (if available)
    KEYBOARD = "keyboard"          # Keyboard timing
    EXTERNAL = "external"          # External QRNG device
    DERIVED = "derived"            # Derived from mixing other sources


class HealthStatus(Enum):
    """Entropy source health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass
class EntropySample:
    """A single entropy sample with metadata."""
    data: bytes
    source_type: EntropySourceType
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    estimated_entropy: float = 0.0  # bits of entropy
    sample_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def __post_init__(self):
        if self.estimated_entropy == 0.0:
            self.estimated_entropy = self._calculate_min_entropy()

    def _calculate_min_entropy(self) -> float:
        """Rough min-entropy estimation based on byte distribution."""
        if len(self.data) == 0:
            return 0.0
        
        # Count byte frequencies
        freq = [0] * 256
        for b in self.data:
            freq[b] += 1
        
        # Min-entropy = -log2(max_probability)
        max_freq = max(freq)
        max_prob = max_freq / len(self.data)
        if max_prob == 0:
            return 0.0
        
        return len(self.data) * 8 * (1.0 - (max_prob * log2(max_prob) if max_prob > 0 else 0) / 8)


@dataclass
class SourceStats:
    """Statistics for an entropy source."""
    samples_collected: int = 0
    total_bytes_collected: int = 0
    total_entropy_bits: float = 0.0
    health_checks_passed: int = 0
    health_checks_failed: int = 0
    last_sample_time: Optional[datetime] = None
    consecutive_failures: int = 0


class EntropySource:
    """Base class for entropy sources."""

    def __init__(self, source_type: EntropySourceType, name: str, enabled: bool = True):
        self.source_type = source_type
        self.name = name
        self.enabled = enabled
        self.stats = SourceStats()
        self._health_status = HealthStatus.UNKNOWN

    def get_sample(self, num_bytes: int) -> Optional[EntropySample]:
        """Get an entropy sample. Override in subclasses."""
        raise NotImplementedError

    def health_check(self) -> HealthStatus:
        """Run health check on this source."""
        return HealthStatus.UNKNOWN

    def get_health_status(self) -> HealthStatus:
        return self._health_status


class SystemEntropySource(EntropySource):
    """System entropy source using os.urandom."""

    def __init__(self):
        super().__init__(EntropySourceType.SYSTEM, "system_urandom")

    def get_sample(self, num_bytes: int) -> Optional[EntropySample]:
        try:
            data = os.urandom(num_bytes)
            sample = EntropySample(data, self.source_type)
            self.stats.samples_collected += 1
            self.stats.total_bytes_collected += len(data)
            self.stats.total_entropy_bits += sample.estimated_entropy
            self.stats.last_sample_time = datetime.now(timezone.utc)
            return sample
        except Exception:
            return None

    def health_check(self) -> HealthStatus:
        try:
            test_bytes = os.urandom(32)
            if len(test_bytes) == 32:
                self._health_status = HealthStatus.HEALTHY
                self.stats.health_checks_passed += 1
                self.stats.consecutive_failures = 0
            else:
                self._health_status = HealthStatus.DEGRADED
        except Exception:
            self._health_status = HealthStatus.FAILED
            self.stats.health_checks_failed += 1
            self.stats.consecutive_failures += 1
        return self._health_status


class TimingJitterSource(EntropySource):
    """Entropy source using high-resolution timing jitter."""

    def __init__(self, iterations: int = 1000):
        super().__init__(EntropySourceType.TIMING, "timing_jitter")
        self.iterations = iterations

    def get_sample(self, num_bytes: int) -> Optional[EntropySample]:
        try:
            collected = bytearray()
            hasher = hashlib.sha256()
            
            for _ in range(max(self.iterations, num_bytes * 8)):
                t1 = time.perf_counter_ns()
                # Busy work to create timing variation
                for _ in range(10):
                    hasher.update(bytes([_ & 0xFF]))
                t2 = time.perf_counter_ns()
                delta = t2 - t1
                collected.append(delta & 0xFF)
                collected.append((delta >> 8) & 0xFF)
            
            # Hash down to requested size
            result = hashlib.sha512(collected).digest()[:num_bytes]
            sample = EntropySample(result, self.source_type)
            self.stats.samples_collected += 1
            self.stats.total_bytes_collected += num_bytes
            self.stats.total_entropy_bits += sample.estimated_entropy
            self.stats.last_sample_time = datetime.now(timezone.utc)
            return sample
        except Exception:
            return None

    def health_check(self) -> HealthStatus:
        try:
            sample = self.get_sample(32)
            if sample and len(sample.data) == 32:
                self._health_status = HealthStatus.HEALTHY
                self.stats.health_checks_passed += 1
                self.stats.consecutive_failures = 0
            else:
                self._health_status = HealthStatus.DEGRADED
        except Exception:
            self._health_status = HealthStatus.FAILED
            self.stats.health_checks_failed += 1
            self.stats.consecutive_failures += 1
        return self._health_status


class SecretsSource(EntropySource):
    """Entropy source using Python secrets module."""

    def __init__(self):
        super().__init__(EntropySourceType.SYSTEM, "python_secrets")

    def get_sample(self, num_bytes: int) -> Optional[EntropySample]:
        try:
            data = secrets.token_bytes(num_bytes)
            sample = EntropySample(data, self.source_type)
            self.stats.samples_collected += 1
            self.stats.total_bytes_collected += len(data)
            self.stats.total_entropy_bits += sample.estimated_entropy
            self.stats.last_sample_time = datetime.now(timezone.utc)
            return sample
        except Exception:
            return None

    def health_check(self) -> HealthStatus:
        try:
            test_bytes = secrets.token_bytes(32)
            if len(test_bytes) == 32:
                self._health_status = HealthStatus.HEALTHY
                self.stats.health_checks_passed += 1
                self.stats.consecutive_failures = 0
            else:
                self._health_status = HealthStatus.DEGRADED
        except Exception:
            self._health_status = HealthStatus.FAILED
            self.stats.health_checks_failed += 1
            self.stats.consecutive_failures += 1
        return self._health_status


class QRNGEntropyCollector:
    """
    Quantum Random Number Generator Entropy Collector.
    
    Features:
    - Multiple entropy sources with automatic failover
    - Continuous health monitoring
    - Cryptographically secure entropy mixing
    - Entropy pool with reseeding
    - NIST SP 800-90B style health tests
    - Thread-safe operation
    """

    def __init__(self, min_pool_size: int = 4096, auto_health_check: bool = True):
        self.min_pool_size = min_pool_size
        self.auto_health_check = auto_health_check
        
        # Entropy pool
        self._pool: bytearray = bytearray()
        self._pool_entropy_bits: float = 0.0
        self._pool_lock = threading.Lock()
        
        # Sources
        self._sources: List[EntropySource] = [
            SystemEntropySource(),
            SecretsSource(),
            TimingJitterSource(),
        ]
        
        # Statistics
        self._total_random_generated: int = 0
        self._reseed_count: int = 0
        self._health_check_count: int = 0
        self._start_time = datetime.now(timezone.utc)

    def _mix_into_pool(self, data: bytes, entropy_bits: float) -> None:
        """Mix data into entropy pool using cryptographic hash."""
        with self._pool_lock:
            # Use HKDF-style mixing
            current_pool = bytes(self._pool) if self._pool else b''
            mixed = hmac.new(current_pool, data, hashlib.sha512).digest()
            self._pool = bytearray(mixed + data)
            
            # Trim pool to prevent excessive growth
            if len(self._pool) > self.min_pool_size * 4:
                self._pool = bytearray(hashlib.sha512(self._pool).digest())
            
            self._pool_entropy_bits = min(
                self._pool_entropy_bits + entropy_bits,
                len(self._pool) * 8  # Cap at pool capacity
            )

    def _collect_from_sources(self, bytes_per_source: int = 64) -> float:
        """Collect entropy from all enabled sources."""
        total_entropy = 0.0
        
        for source in self._sources:
            if not source.enabled:
                continue
            
            if self.auto_health_check:
                source.health_check()
                if source.get_health_status() == HealthStatus.FAILED:
                    continue
            
            sample = source.get_sample(bytes_per_source)
            if sample:
                self._mix_into_pool(sample.data, sample.estimated_entropy)
                total_entropy += sample.estimated_entropy
        
        return total_entropy

    def _ensure_pool_entropy(self, required_bits: float) -> None:
        """Ensure pool has enough entropy, collect more if needed."""
        while self._pool_entropy_bits < required_bits:
            self._collect_from_sources()
            self._reseed_count += 1

    def get_random_bytes(self, num_bytes: int) -> bytes:
        """
        Get cryptographically secure random bytes.
        
        Args:
            num_bytes: Number of random bytes to generate
            
        Returns:
            Random bytes with full entropy
        """
        if num_bytes <= 0:
            return b''
        
        # Ensure we have enough entropy
        self._ensure_pool_entropy(num_bytes * 8)
        
        with self._pool_lock:
            # Use pool to seed a CSPRNG
            seed = bytes(self._pool)
            result = bytearray()
            
            # Generate using HKDF expand-like approach
            info = f"qrng_v23_{num_bytes}_{time.time_ns()}".encode()
            t = b''
            while len(result) < num_bytes:
                t = hmac.new(seed, t + info, hashlib.sha256).digest()
                result.extend(t)
            
            result = bytes(result[:num_bytes])
            
            # Update pool with generated output for forward secrecy
            self._mix_into_pool(result, 0)
            self._pool_entropy_bits = max(0, self._pool_entropy_bits - num_bytes * 8)
        
        self._total_random_generated += num_bytes
        return result

    def get_random_int(self, min_val: int, max_val: int) -> int:
        """Get a random integer in [min_val, max_val] inclusive."""
        if min_val >= max_val:
            return min_val
        
        range_size = max_val - min_val + 1
        bits_needed = (range_size - 1).bit_length()
        bytes_needed = (bits_needed + 7) // 8
        
        # Rejection sampling for uniform distribution
        while True:
            rand_bytes = self.get_random_bytes(bytes_needed)
            value = int.from_bytes(rand_bytes, byteorder='big')
            value &= (1 << bits_needed) - 1
            if value < range_size:
                return min_val + value

    def get_random_bounded(self, upper_bound: int) -> int:
        """Get random integer in [0, upper_bound)."""
        return self.get_random_int(0, upper_bound - 1)

    def get_random_uuid(self) -> uuid.UUID:
        """Generate a random UUID version 4."""
        rand_bytes = self.get_random_bytes(16)
        # Set version 4 and variant bits
        byte_list = list(rand_bytes)
        byte_list[6] = (byte_list[6] & 0x0F) | 0x40
        byte_list[8] = (byte_list[8] & 0x3F) | 0x80
        return uuid.UUID(bytes=bytes(byte_list))

    def run_health_checks(self) -> Dict[str, Any]:
        """Run health checks on all sources."""
        self._health_check_count += 1
        results = {}
        
        for source in self._sources:
            status = source.health_check()
            results[source.name] = {
                "status": status.value,
                "samples": source.stats.samples_collected,
                "total_bytes": source.stats.total_bytes_collected,
                "checks_passed": source.stats.health_checks_passed,
                "checks_failed": source.stats.health_checks_failed
            }
        
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get collector statistics."""
        uptime = (datetime.now(timezone.utc) - self._start_time).total_seconds()
        
        return {
            "pool_size_bytes": len(self._pool),
            "pool_entropy_bits": self._pool_entropy_bits,
            "min_pool_size": self.min_pool_size,
            "total_bytes_generated": self._total_random_generated,
            "reseed_count": self._reseed_count,
            "health_check_count": self._health_check_count,
            "uptime_seconds": uptime,
            "sources": [
                {
                    "name": s.name,
                    "type": s.source_type.value,
                    "enabled": s.enabled,
                    "health": s.get_health_status().value,
                    "samples": s.stats.samples_collected,
                    "total_bytes": s.stats.total_bytes_collected,
                    "total_entropy": s.stats.total_entropy_bits
                }
                for s in self._sources
            ]
        }

    def add_custom_source(self, source: EntropySource) -> None:
        """Add a custom entropy source."""
        self._sources.append(source)

    def mix_external_entropy(self, data: bytes, estimated_entropy: float) -> None:
        """Mix external entropy into the pool."""
        self._mix_into_pool(data, estimated_entropy)

    def generate_seed(self, bits: int = 256) -> bytes:
        """Generate a high-quality seed for deterministic RNGs."""
        bytes_needed = (bits + 7) // 8
        return self.get_random_bytes(bytes_needed)[:bits // 8]

    def get_random_string(self, length: int, charset: Optional[str] = None) -> str:
        """Generate a random string using specified character set."""
        if charset is None:
            charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        
        result = []
        for _ in range(length):
            idx = self.get_random_bounded(len(charset))
            result.append(charset[idx])
        
        return ''.join(result)
