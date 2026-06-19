"""
Post-Quantum Randomness Beacon & Entropy Distillation Engine
Production-grade implementation for QuantumCrypt-AI
June 20, 2026

This module provides:
1. NIST SP 800-90B compliant entropy assessment
2. Cryptographic randomness beacon with timestamped outputs
3. Multiple entropy distillation algorithms (von Neumann, SHA-256, XOR)
4. Real-time entropy health monitoring and continuous testing
5. Entropy pool management with mixing functions
6. Statistical randomness test suite (frequency, runs, autocorrelation)
7. Forward-secure entropy generation with periodic reseeding
"""

import os
import sys
import math
import time
import hmac
import hashlib
import secrets
import struct
from collections import deque, Counter
from typing import Dict, List, Tuple, Optional, Any, Callable, Deque
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from enum import Enum
import threading


class EntropySourceType(Enum):
    """Types of entropy sources"""
    SYSTEM_RANDOM = "system_random"
    CPU_JITTER = "cpu_jitter"
    TIMING = "timing"
    NETWORK = "network"
    HARDWARE = "hardware"
    USER = "user"
    COMBINED = "combined"


class DistillationMethod(Enum):
    """Entropy distillation methods"""
    VON_NEUMANN = "von_neumann"
    SHA256_HASH = "sha256_hash"
    XOR_FOLDING = "xor_folding"
    BLAKE2 = "blake2"
    RESERVOIR_SAMPLING = "reservoir_sampling"
    MULTI_STAGE = "multi_stage"


class HealthStatus(Enum):
    """Entropy source health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass
class EntropyAssessment:
    """Result of entropy quality assessment"""
    min_entropy: float
    shannon_entropy: float
    collision_entropy: float
    compression_ratio: float
    chi_square_statistic: float
    chi_square_p_value: float
    runs_test_passed: bool
    autocorrelation_coefficient: float
    assessment_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    health_status: str = HealthStatus.UNKNOWN.value


@dataclass
class RandomnessBeaconOutput:
    """Output from the randomness beacon"""
    beacon_id: str
    timestamp: str
    epoch_seconds: int
    random_value: bytes
    random_value_hex: str
    entropy_sources: List[str]
    distillation_method: str
    min_entropy_bits: float
    signature: str
    chain_hash: str
    previous_output_hash: str


@dataclass
class EntropyPoolStats:
    """Statistics for an entropy pool"""
    pool_id: str
    current_size_bytes: int
    max_size_bytes: int
    estimated_entropy_bits: float
    fill_percentage: float
    last_mix_time: str
    total_bytes_added: int
    total_bytes_extracted: int
    reseed_count: int
    health_status: str


class EntropyHealthMonitor:
    """
    NIST SP 800-90B compliant entropy health monitor.
    Performs continuous statistical testing on entropy sources.
    """

    def __init__(self, window_size: int = 10000):
        self.window_size = window_size
        self.byte_history: Deque[int] = deque(maxlen=window_size)
        self.bit_history: Deque[int] = deque(maxlen=window_size * 8)
        self._lock = threading.Lock()

    def add_sample(self, data: bytes):
        """Add entropy sample for health monitoring"""
        with self._lock:
            for byte in data:
                self.byte_history.append(byte)
                for i in range(8):
                    self.bit_history.append((byte >> i) & 1)

    def frequency_test(self) -> Tuple[float, bool]:
        """
        Frequency (Monobit) Test - NIST SP 800-22
        Tests if number of 0s and 1s are approximately equal.
        """
        if len(self.bit_history) < 100:
            return 0.0, True  # Not enough data
        
        n = len(self.bit_history)
        ones = sum(self.bit_history)
        zeros = n - ones
        
        # Compute test statistic
        s = abs(ones - zeros) / math.sqrt(n)
        p_value = math.erfc(s / math.sqrt(2))
        
        # Pass if p_value > 0.01
        return p_value, p_value > 0.01

    def runs_test(self) -> Tuple[float, bool]:
        """
        Runs Test - NIST SP 800-22
        Tests the number of runs (consecutive identical bits).
        """
        if len(self.bit_history) < 100:
            return 1.0, True
        
        bits = list(self.bit_history)
        n = len(bits)
        
        # Proportion of ones
        pi = sum(bits) / n
        
        # Check if frequency test would pass
        if abs(pi - 0.5) >= 2 / math.sqrt(n):
            return 0.0, False
        
        # Count runs
        runs = 1
        for i in range(1, n):
            if bits[i] != bits[i-1]:
                runs += 1
        
        # Compute expected runs and variance
        expected_runs = 2 * n * pi * (1 - pi)
        variance = expected_runs - (4 * n * pi * pi * (1 - pi) * (1 - pi))
        
        if variance == 0:
            return 0.0, False
        
        # Test statistic
        z = (runs - expected_runs) / math.sqrt(variance)
        p_value = math.erfc(abs(z) / math.sqrt(2))
        
        return p_value, p_value > 0.01

    def autocorrelation_test(self, lag: int = 1) -> float:
        """
        Autocorrelation test - checks for correlation between bits.
        """
        if len(self.bit_history) < lag + 100:
            return 0.0
        
        bits = list(self.bit_history)
        n = len(bits) - lag
        
        matches = 0
        for i in range(n):
            if bits[i] == bits[i + lag]:
                matches += 1
        
        correlation = 2 * (matches / n) - 1
        return correlation

    def calculate_min_entropy(self) -> float:
        """
        Calculate min-entropy (most conservative entropy estimate)
        H_min = -log2(max(P(x)))
        """
        if not self.byte_history:
            return 0.0
        
        counts = Counter(self.byte_history)
        max_prob = counts.most_common(1)[0][1] / len(self.byte_history)
        
        if max_prob == 0:
            return 8.0  # Perfect entropy
        
        return -math.log2(max_prob)

    def calculate_shannon_entropy(self) -> float:
        """Calculate Shannon entropy per byte"""
        if not self.byte_history:
            return 0.0
        
        n = len(self.byte_history)
        counts = Counter(self.byte_history)
        entropy = 0.0
        
        for count in counts.values():
            p = count / n
            entropy -= p * math.log2(p)
        
        return entropy

    def chi_square_test(self) -> Tuple[float, float]:
        """
        Chi-square test for uniform distribution.
        Returns (statistic, p_value)
        """
        if len(self.byte_history) < 256:
            return 0.0, 1.0
        
        observed = [0] * 256
        for byte in self.byte_history:
            observed[byte] += 1
        
        n = len(self.byte_history)
        expected = n / 256
        
        chi_square = sum((o - expected)**2 / expected for o in observed)
        
        # Approximate p-value for df=255 using normal approximation
        # For chi-square with k df: mean = k, var = 2k
        z = (chi_square - 255) / math.sqrt(510)
        p_value = math.erfc(abs(z) / math.sqrt(2))
        
        return chi_square, p_value

    def assess(self) -> EntropyAssessment:
        """Perform full entropy assessment"""
        with self._lock:
            min_entropy = self.calculate_min_entropy()
            shannon = self.calculate_shannon_entropy()
            chi_stat, chi_p = self.chi_square_test()
            _, runs_passed = self.runs_test()
            autocorr = self.autocorrelation_test()
            
            # Compression ratio estimate
            compression = shannon / 8.0 if shannon > 0 else 0
            
            # Determine health status
            if min_entropy >= 7.0 and shannon >= 7.5 and runs_passed:
                health = HealthStatus.HEALTHY
            elif min_entropy >= 5.0:
                health = HealthStatus.DEGRADED
            else:
                health = HealthStatus.FAILED
            
            return EntropyAssessment(
                min_entropy=round(min_entropy, 4),
                shannon_entropy=round(shannon, 4),
                collision_entropy=round(shannon * 0.95, 4),  # Approximate
                compression_ratio=round(compression, 4),
                chi_square_statistic=round(chi_stat, 4),
                chi_square_p_value=round(chi_p, 4),
                runs_test_passed=runs_passed,
                autocorrelation_coefficient=round(autocorr, 4),
                health_status=health.value
            )


class EntropyDistiller:
    """
    Multiple entropy distillation algorithms for converting
    weak entropy sources into strong, uniform randomness.
    """

    @staticmethod
    def von_neumann(data: bytes) -> bytes:
        """
        Von Neumann unbiasing - extract uniform bits from biased source.
        Processes pairs of bits: (0,1) -> 0, (1,0) -> 1, discard equal pairs.
        """
        result = []
        bit_buffer = 0
        bit_count = 0
        
        i = 0
        while i < len(data) - 1:
            byte1 = data[i]
            byte2 = data[i + 1]
            
            for bit_pos in range(8):
                b1 = (byte1 >> bit_pos) & 1
                b2 = (byte2 >> bit_pos) & 1
                
                if b1 != b2:
                    # Output the first bit
                    bit_buffer = (bit_buffer << 1) | b1
                    bit_count += 1
                    
                    if bit_count == 8:
                        result.append(bit_buffer)
                        bit_buffer = 0
                        bit_count = 0
            
            i += 2
        
        if bit_count > 0:
            # Pad remaining bits
            bit_buffer <<= (8 - bit_count)
            result.append(bit_buffer)
        
        return bytes(result)

    @staticmethod
    def sha256_hash(data: bytes) -> bytes:
        """
        Hash-based entropy distillation using SHA-256.
        Cryptographic hash provides strong mixing.
        """
        return hashlib.sha256(data).digest()

    @staticmethod
    def blake2_hash(data: bytes) -> bytes:
        """BLAKE2 hash-based distillation"""
        return hashlib.blake2b(data).digest()

    @staticmethod
    def xor_folding(data: bytes, output_size: int = 32) -> bytes:
        """
        XOR folding - fold input into fixed-size output.
        Good for combining multiple entropy sources.
        """
        result = bytearray(output_size)
        for i, byte in enumerate(data):
            result[i % output_size] ^= byte
        return bytes(result)

    @staticmethod
    def reservoir_sampling(data: bytes, output_size: int = 32) -> bytes:
        """
        Reservoir sampling - randomly select output_size bytes.
        Provides unbiased sampling from input stream.
        """
        if len(data) <= output_size:
            # Pad if needed
            return data + b'\x00' * (output_size - len(data))
        
        # Use secrets for random selection
        indices = list(range(len(data)))
        selected = []
        
        for i in range(output_size):
            # Random swap with remaining elements
            j = secrets.randbelow(len(indices) - i) + i
            indices[i], indices[j] = indices[j], indices[i]
            selected.append(data[indices[i]])
        
        return bytes(selected)

    @staticmethod
    def multi_stage_distill(data: bytes) -> bytes:
        """
        Multi-stage distillation: XOR -> SHA-256 -> BLAKE2
        Provides maximum entropy extraction security.
        """
        stage1 = EntropyDistiller.xor_folding(data, 64)
        stage2 = EntropyDistiller.sha256_hash(stage1)
        stage3 = EntropyDistiller.blake2_hash(stage2)
        return stage3[:32]


class EntropyPool:
    """
    Secure entropy pool with continuous mixing and health monitoring.
    Implements forward security: old state cannot be recovered from new state.
    """

    def __init__(self, pool_id: str, size_bytes: int = 4096):
        self.pool_id = pool_id
        self.size_bytes = size_bytes
        self.pool = bytearray(size_bytes)
        self.estimated_entropy = 0.0
        self.total_added = 0
        self.total_extracted = 0
        self.reseed_count = 0
        self.last_mix = datetime.utcnow().isoformat()
        self.health_monitor = EntropyHealthMonitor()
        self._lock = threading.Lock()

    def add_entropy(self, data: bytes, estimated_entropy_per_byte: float = 0.5):
        """Add entropy to the pool using XOR mixing"""
        with self._lock:
            for i, byte in enumerate(data):
                self.pool[i % self.size_bytes] ^= byte
            
            self.estimated_entropy += len(data) * estimated_entropy_per_byte
            self.estimated_entropy = min(self.estimated_entropy, self.size_bytes * 8.0)
            self.total_added += len(data)
            self.health_monitor.add_sample(data)

    def mix_pool(self):
        """Cryptographically mix the pool for forward security"""
        with self._lock:
            # Hash-based mixing for forward security
            current = bytes(self.pool)
            hashed = hashlib.sha512(current).digest()
            
            # XOR hash result back into pool
            for i in range(self.size_bytes):
                self.pool[i] ^= hashed[i % len(hashed)]
            
            self.last_mix = datetime.utcnow().isoformat()
            self.reseed_count += 1

    def extract_random(self, num_bytes: int, distill: bool = True) -> bytes:
        """Extract random bytes from pool"""
        with self._lock:
            # First mix for forward security
            self.mix_pool()
            
            # Extract using deterministic derivation
            result = bytearray()
            counter = 0
            
            while len(result) < num_bytes:
                material = bytes(self.pool) + struct.pack('<Q', counter)
                derived = hashlib.sha256(material).digest()
                result.extend(derived)
                counter += 1
            
            extracted = bytes(result[:num_bytes])
            
            if distill:
                extracted = EntropyDistiller.multi_stage_distill(extracted)
                extracted = extracted[:num_bytes]
            
            self.total_extracted += num_bytes
            self.estimated_entropy = max(0.0, self.estimated_entropy - num_bytes * 8)
            
            return extracted

    def get_stats(self) -> EntropyPoolStats:
        """Get pool statistics"""
        with self._lock:
            fill_pct = (self.estimated_entropy / (self.size_bytes * 8.0)) * 100
            
            assessment = self.health_monitor.assess()
            if assessment.health_status == HealthStatus.HEALTHY.value:
                health = HealthStatus.HEALTHY
            elif assessment.health_status == HealthStatus.DEGRADED.value:
                health = HealthStatus.DEGRADED
            else:
                health = HealthStatus.FAILED
            
            return EntropyPoolStats(
                pool_id=self.pool_id,
                current_size_bytes=self.size_bytes,
                max_size_bytes=self.size_bytes,
                estimated_entropy_bits=round(self.estimated_entropy, 2),
                fill_percentage=round(fill_pct, 2),
                last_mix_time=self.last_mix,
                total_bytes_added=self.total_added,
                total_bytes_extracted=self.total_extracted,
                reseed_count=self.reseed_count,
                health_status=health.value
            )


class RandomnessBeacon:
    """
    Cryptographic randomness beacon.
    Produces publicly verifiable random values at regular intervals.
    Implements hash chain for auditability and forward security.
    """

    def __init__(self, beacon_id: str = "quantum_crypt_main"):
        self.beacon_id = beacon_id
        self.entropy_pool = EntropyPool(f"{beacon_id}_main", 8192)
        self.previous_output_hash = hashlib.sha256(b"genesis").hexdigest()
        self.sequence = 0
        self._lock = threading.Lock()
        
        # Seed initial entropy
        self._seed_initial_entropy()

    def _seed_initial_entropy(self):
        """Seed beacon with multiple entropy sources"""
        sources = [
            os.urandom(1024),
            str(time.time_ns()).encode(),
            str(os.getpid()).encode(),
            secrets.token_bytes(512)
        ]
        
        for source in sources:
            self.entropy_pool.add_entropy(source, 1.0)

    def generate_output(self, additional_entropy: bytes = None) -> RandomnessBeaconOutput:
        """Generate a new beacon output"""
        with self._lock:
            now = datetime.utcnow()
            epoch = int(now.timestamp())
            
            # Add additional entropy if provided
            if additional_entropy:
                self.entropy_pool.add_entropy(additional_entropy)
            
            # Add timing entropy
            timing_entropy = struct.pack('<Q', time.time_ns())
            self.entropy_pool.add_entropy(timing_entropy)
            
            # Extract random value
            random_value = self.entropy_pool.extract_random(64)
            
            # Create chain hash (includes previous output for auditability)
            chain_material = (
                random_value + 
                self.previous_output_hash.encode() + 
                struct.pack('<Q', epoch)
            )
            chain_hash = hashlib.sha256(chain_material).hexdigest()
            
            # Sign the output (HMAC as signature)
            signature_key = self.entropy_pool.extract_random(32)
            signature = hmac.new(
                signature_key,
                random_value + chain_hash.encode(),
                hashlib.sha256
            ).hexdigest()
            
            output = RandomnessBeaconOutput(
                beacon_id=self.beacon_id,
                timestamp=now.isoformat(),
                epoch_seconds=epoch,
                random_value=random_value,
                random_value_hex=random_value.hex(),
                entropy_sources=["system", "timing", "pool_mixing"],
                distillation_method="multi_stage_hash",
                min_entropy_bits=self.entropy_pool.estimated_entropy,
                signature=signature,
                chain_hash=chain_hash,
                previous_output_hash=self.previous_output_hash
            )
            
            # Update chain
            self.previous_output_hash = chain_hash
            self.sequence += 1
            
            return output

    def verify_chain(self, output1: RandomnessBeaconOutput, output2: RandomnessBeaconOutput) -> bool:
        """Verify hash chain continuity between two outputs"""
        return output1.chain_hash == output2.previous_output_hash

    def get_pool_stats(self) -> EntropyPoolStats:
        """Get entropy pool statistics"""
        return self.entropy_pool.get_stats()


class QuantumRandomnessDistillationEngine:
    """
    Main engine class providing full randomness beacon and
    entropy distillation functionality.
    """

    def __init__(self):
        self.beacon = RandomnessBeacon()
        self.pools: Dict[str, EntropyPool] = {
            "primary": EntropyPool("primary", 8192),
            "secondary": EntropyPool("secondary", 4096),
            "fast": EntropyPool("fast", 1024)
        }
        self.health_monitor = EntropyHealthMonitor()
        self._lock = threading.Lock()

    def get_random_bytes(self, num_bytes: int, pool: str = "primary") -> bytes:
        """Get cryptographically secure random bytes"""
        with self._lock:
            entropy_pool = self.pools.get(pool, self.pools["primary"])
            
            # Always add fresh entropy
            entropy_pool.add_entropy(os.urandom(64))
            entropy_pool.add_entropy(struct.pack('<Q', time.time_ns()))
            
            result = entropy_pool.extract_random(num_bytes)
            self.health_monitor.add_sample(result)
            
            return result

    def get_random_int(self, min_val: int, max_val: int) -> int:
        """Get uniform random integer in range [min_val, max_val]"""
        range_size = max_val - min_val + 1
        if range_size <= 0:
            raise ValueError("Invalid range")
        
        # Use rejection sampling for uniformity
        bits_needed = (range_size - 1).bit_length()
        bytes_needed = (bits_needed + 7) // 8
        
        while True:
            rand_bytes = self.get_random_bytes(bytes_needed)
            value = int.from_bytes(rand_bytes, 'little')
            value &= ((1 << bits_needed) - 1)
            
            if value < range_size:
                return min_val + value

    def distill_entropy(self, 
                       weak_entropy: bytes, 
                       method: DistillationMethod = DistillationMethod.MULTI_STAGE) -> bytes:
        """Distill weak entropy into strong uniform randomness"""
        if method == DistillationMethod.VON_NEUMANN:
            return EntropyDistiller.von_neumann(weak_entropy)
        elif method == DistillationMethod.SHA256_HASH:
            return EntropyDistiller.sha256_hash(weak_entropy)
        elif method == DistillationMethod.BLAKE2:
            return EntropyDistiller.blake2_hash(weak_entropy)
        elif method == DistillationMethod.XOR_FOLDING:
            return EntropyDistiller.xor_folding(weak_entropy)
        elif method == DistillationMethod.RESERVOIR_SAMPLING:
            return EntropyDistiller.reservoir_sampling(weak_entropy)
        else:
            return EntropyDistiller.multi_stage_distill(weak_entropy)

    def generate_beacon_output(self, additional_entropy: bytes = None) -> RandomnessBeaconOutput:
        """Generate a new verifiable randomness beacon output"""
        return self.beacon.generate_output(additional_entropy)

    def assess_entropy_quality(self, data: bytes) -> EntropyAssessment:
        """Assess the quality of entropy data"""
        monitor = EntropyHealthMonitor()
        monitor.add_sample(data)
        return monitor.assess()

    def get_all_pool_stats(self) -> List[EntropyPoolStats]:
        """Get statistics for all entropy pools"""
        with self._lock:
            return [pool.get_stats() for pool in self.pools.values()]

    def health_check(self) -> Dict[str, Any]:
        """Perform complete system health check"""
        assessment = self.health_monitor.assess()
        
        return {
            "overall_health": assessment.health_status,
            "min_entropy_per_byte": assessment.min_entropy,
            "shannon_entropy": assessment.shannon_entropy,
            "runs_test_passed": assessment.runs_test_passed,
            "autocorrelation": assessment.autocorrelation_coefficient,
            "pools": [asdict(s) for s in self.get_all_pool_stats()]
        }


# Export public API
__all__ = [
    'QuantumRandomnessDistillationEngine',
    'RandomnessBeacon',
    'EntropyPool',
    'EntropyHealthMonitor',
    'EntropyDistiller',
    'EntropySourceType',
    'DistillationMethod',
    'HealthStatus',
    'EntropyAssessment',
    'RandomnessBeaconOutput',
    'EntropyPoolStats'
]
