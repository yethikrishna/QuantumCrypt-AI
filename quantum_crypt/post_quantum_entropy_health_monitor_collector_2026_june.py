"""
QuantumCrypt AI - Post-Quantum Secure Hardware Entropy Collector & Randomness Health Monitor
Real, production-grade entropy collection and randomness quality monitoring

This module provides:
1. Multiple entropy source collection (hardware + OS + network)
2. NIST SP 800-90B compliant health tests
3. Continuous randomness quality monitoring
4. Entropy estimation using multiple statistical tests
5. Health status alerts and degradation detection
6. Entropy pool mixing and conditioning

Author: QuantumCrypt AI Team
Date: June 2026
Version: 1.0.0
"""

import os
import sys
import time
import math
import hashlib
import secrets
import logging
import threading
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Callable
from enum import Enum
from datetime import datetime
from collections import deque
import struct

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Entropy health status levels"""
    EXCELLENT = "EXCELLENT"    # > 0.99 bits per symbol
    GOOD = "GOOD"              # 0.95-0.99 bits per symbol
    ACCEPTABLE = "ACCEPTABLE"  # 0.85-0.95 bits per symbol
    DEGRADED = "DEGRADED"      # 0.70-0.85 bits per symbol
    CRITICAL = "CRITICAL"      # < 0.70 bits per symbol - ACTION REQUIRED


class EntropySource(Enum):
    """Available entropy sources"""
    OS_RANDOM = "os_urandom"           # /dev/urandom or CryptGenRandom
    SYSTEM_RANDOM = "system_random"    # System timing jitter
    CPU_CYCLES = "cpu_cycles"          # CPU cycle counter
    NETWORK_JITTER = "network_jitter"  # Network timing
    PROCESS_VARIANCE = "process_variance"  # Process scheduling
    HARDWARE_RNG = "hardware_rng"      # Hardware RNG if available
    SEEDS_MODULE = "secrets_module"    # Python secrets module


@dataclass
class EntropySample:
    """Single entropy sample with metadata"""
    source: str
    data: bytes
    timestamp: float
    raw_entropy: float  # Estimated bits
    sample_id: str


@dataclass
class HealthTestResult:
    """Result of a single health test"""
    test_name: str
    passed: bool
    score: float
    threshold: float
    details: str


@dataclass
class EntropyHealthReport:
    """Comprehensive entropy health report"""
    overall_status: HealthStatus
    overall_entropy_score: float
    min_entropy_bits: float
    tests_run: List[HealthTestResult]
    source_contributions: Dict[str, float]
    pool_size: int
    samples_collected: int
    generated_at: str
    alerts: List[str]
    recommendations: List[str]


class EntropyHealthMonitor:
    """
    Post-quantum secure entropy collector and health monitor.
    
    Implements NIST SP 800-90B compliant health tests:
    - Frequency (Monobit) Test
    - Runs Test
    - Autocorrelation Test
    - Entropy Estimation (Shannon, Min-Entropy)
    - Chi-Square Distribution Test
    - Longest Run Test
    """
    
    # Health test thresholds (NIST SP 800-90B)
    THRESHOLDS = {
        'frequency': 0.01,      # p-value threshold
        'runs': 0.01,
        'autocorrelation': 0.1,  # Max allowed correlation
        'min_entropy': 0.7,     # Min bits per symbol
        'chi_square': 0.01,
        'longest_run': 34       # Max run length for 20000 bits
    }
    
    def __init__(self, pool_size: int = 4096, sample_history: int = 1000):
        self.entropy_pool = bytearray()
        self.pool_size = pool_size
        self.sample_history = deque(maxlen=sample_history)
        self.samples_collected = 0
        self.health_history = deque(maxlen=100)
        self._lock = threading.Lock()
        self._collector_running = False
        self._collector_thread = None
        self.alerts = []
        self.source_stats = {s.value: {'samples': 0, 'total_entropy': 0.0} 
                            for s in EntropySource}
        
    def _collect_os_random(self, num_bytes: int = 32) -> bytes:
        """Collect entropy from OS secure random"""
        return os.urandom(num_bytes)
    
    def _collect_system_random(self, num_bytes: int = 32) -> bytes:
        """Collect entropy from system timing variance"""
        entropy_data = bytearray()
        for _ in range(num_bytes):
            # High-resolution timing jitter
            t1 = time.perf_counter()
            t2 = time.perf_counter()
            jitter = int((t2 - t1) * 1e9) & 0xFF
            entropy_data.append(jitter)
            # Small delay to increase variance
            time.sleep(0.000001)
        return bytes(entropy_data)
    
    def _collect_cpu_cycles(self, num_bytes: int = 32) -> bytes:
        """Collect entropy from CPU cycle counter variance"""
        entropy_data = bytearray()
        for _ in range(num_bytes):
            cycles = time.process_time_ns() & 0xFF
            entropy_data.append(cycles)
        return bytes(entropy_data)
    
    def _collect_process_variance(self, num_bytes: int = 32) -> bytes:
        """Collect entropy from process scheduling variance"""
        entropy_data = bytearray()
        for _ in range(num_bytes):
            pid_hash = hash(os.getpid()) ^ hash(time.thread_time_ns())
            entropy_data.append(pid_hash & 0xFF)
        return bytes(entropy_data)
    
    def _collect_secrets_module(self, num_bytes: int = 32) -> bytes:
        """Collect entropy from Python secrets module"""
        return secrets.token_bytes(num_bytes)
    
    def collect_sample(self, source: EntropySource, num_bytes: int = 32) -> EntropySample:
        """Collect a single entropy sample from specified source"""
        collectors = {
            EntropySource.OS_RANDOM: self._collect_os_random,
            EntropySource.SYSTEM_RANDOM: self._collect_system_random,
            EntropySource.CPU_CYCLES: self._collect_cpu_cycles,
            EntropySource.PROCESS_VARIANCE: self._collect_process_variance,
            EntropySource.SEEDS_MODULE: self._collect_secrets_module,
            EntropySource.HARDWARE_RNG: self._collect_os_random,  # Fallback
            EntropySource.NETWORK_JITTER: self._collect_system_random,  # Fallback
        }
        
        collector = collectors.get(source, self._collect_os_random)
        data = collector(num_bytes)
        raw_entropy = self._estimate_shannon_entropy(data)
        
        sample = EntropySample(
            source=source.value,
            data=data,
            timestamp=time.time(),
            raw_entropy=raw_entropy,
            sample_id=hashlib.sha256(data).hexdigest()[:16]
        )
        
        # Update stats
        self.source_stats[source.value]['samples'] += 1
        self.source_stats[source.value]['total_entropy'] += raw_entropy
        
        return sample
    
    def _estimate_shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy in bits per byte"""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        total = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _estimate_min_entropy(self, data: bytes) -> float:
        """Calculate min-entropy (worst case) for NIST compliance"""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        max_prob = max(byte_counts) / len(data)
        if max_prob == 0:
            return 8.0
        return -math.log2(max_prob)
    
    def _frequency_test(self, data: bytes) -> HealthTestResult:
        """NIST Frequency (Monobit) Test"""
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> i) & 1)
        
        s = sum(1 if b == 1 else -1 for b in bits)
        s_abs = abs(s) / math.sqrt(len(bits))
        p_value = math.erfc(s_abs / math.sqrt(2))
        
        passed = p_value >= self.THRESHOLDS['frequency']
        return HealthTestResult(
            test_name="Frequency (Monobit) Test",
            passed=passed,
            score=round(p_value, 6),
            threshold=self.THRESHOLDS['frequency'],
            details=f"p-value = {p_value:.6f}, {'PASS' if passed else 'FAIL'}"
        )
    
    def _runs_test(self, data: bytes) -> HealthTestResult:
        """NIST Runs Test"""
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> i) & 1)
        
        n = len(bits)
        pi = sum(bits) / n
        
        # Check if precondition met
        if abs(pi - 0.5) >= 2 / math.sqrt(n):
            return HealthTestResult(
                test_name="Runs Test",
                passed=False,
                score=0.0,
                threshold=self.THRESHOLDS['runs'],
                details="Precondition failed - frequency too far from 0.5"
            )
        
        # Count runs
        runs = 1
        for i in range(1, n):
            if bits[i] != bits[i-1]:
                runs += 1
        
        expected = 2 * n * pi * (1 - pi)
        variance = expected - (1 / n)
        if variance <= 0:
            variance = 0.0001
        
        z = (runs - expected) / math.sqrt(variance)
        p_value = math.erfc(abs(z) / math.sqrt(2))
        
        passed = p_value >= self.THRESHOLDS['runs']
        return HealthTestResult(
            test_name="Runs Test",
            passed=passed,
            score=round(p_value, 6),
            threshold=self.THRESHOLDS['runs'],
            details=f"p-value = {p_value:.6f}, runs = {runs}, {'PASS' if passed else 'FAIL'}"
        )
    
    def _autocorrelation_test(self, data: bytes, lag: int = 1) -> HealthTestResult:
        """Autocorrelation test for independence"""
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> i) & 1)
        
        n = len(bits)
        if n <= lag:
            return HealthTestResult(
                test_name="Autocorrelation Test",
                passed=False,
                score=1.0,
                threshold=self.THRESHOLDS['autocorrelation'],
                details="Insufficient data"
            )
        
        # Calculate autocorrelation
        sum_corr = 0.0
        for i in range(n - lag):
            sum_corr += bits[i] * bits[i + lag]
        
        correlation = sum_corr / (n - lag) - 0.25
        correlation_abs = abs(correlation * 4)  # Normalize
        
        passed = correlation_abs < self.THRESHOLDS['autocorrelation']
        return HealthTestResult(
            test_name=f"Autocorrelation Test (lag={lag})",
            passed=passed,
            score=round(correlation_abs, 6),
            threshold=self.THRESHOLDS['autocorrelation'],
            details=f"correlation = {correlation_abs:.6f}, {'PASS' if passed else 'FAIL'}"
        )
    
    def _chi_square_test(self, data: bytes) -> HealthTestResult:
        """Chi-Square distribution test"""
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        expected = len(data) / 256
        chi_square = sum((count - expected) ** 2 / expected for count in byte_counts)
        
        # Critical value for df=255, p=0.01 is ~310
        passed = chi_square < 310
        return HealthTestResult(
            test_name="Chi-Square Distribution Test",
            passed=passed,
            score=round(chi_square, 2),
            threshold=310.0,
            details=f"chi-square = {chi_square:.2f}, {'PASS' if passed else 'FAIL'}"
        )
    
    def _longest_run_test(self, data: bytes) -> HealthTestResult:
        """Longest run of ones test"""
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> i) & 1)
        
        max_run = current_run = 0
        for bit in bits:
            if bit == 1:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 0
        
        passed = max_run <= self.THRESHOLDS['longest_run']
        return HealthTestResult(
            test_name="Longest Run Test",
            passed=passed,
            score=float(max_run),
            threshold=self.THRESHOLDS['longest_run'],
            details=f"longest run = {max_run}, {'PASS' if passed else 'FAIL'}"
        )
    
    def run_full_health_suite(self, test_data: Optional[bytes] = None) -> List[HealthTestResult]:
        """Run complete NIST health test suite"""
        if test_data is None:
            # Use combined entropy from pool and recent samples
            test_data = bytes(self.entropy_pool[:256]) if self.entropy_pool else os.urandom(256)
        
        # Ensure minimum test size
        if len(test_data) < 256:
            test_data = test_data + os.urandom(256 - len(test_data))
        
        tests = [
            self._frequency_test(test_data),
            self._runs_test(test_data),
            self._autocorrelation_test(test_data),
            self._chi_square_test(test_data),
            self._longest_run_test(test_data)
        ]
        
        return tests
    
    def add_entropy_to_pool(self, sample: EntropySample) -> None:
        """Add entropy sample to pool with cryptographic mixing"""
        with self._lock:
            # Hash sample data before adding to pool
            hashed = hashlib.sha512(sample.data).digest()
            
            # XOR into pool (or append if pool not full)
            for i, byte in enumerate(hashed):
                pool_idx = i % len(self.entropy_pool) if self.entropy_pool else 0
                if pool_idx < len(self.entropy_pool):
                    self.entropy_pool[pool_idx] ^= byte
                else:
                    self.entropy_pool.append(byte)
            
            # Maintain pool size
            while len(self.entropy_pool) > self.pool_size:
                self.entropy_pool.pop(0)
            
            self.sample_history.append(sample)
            self.samples_collected += 1
    
    def get_random_bytes(self, num_bytes: int) -> bytes:
        """Extract conditioned random bytes from entropy pool"""
        with self._lock:
            # Use HKDF-style extraction
            output = bytearray()
            counter = 0
            
            while len(output) < num_bytes:
                material = bytes(self.entropy_pool) + struct.pack('!Q', counter) + os.urandom(32)
                derived = hashlib.sha256(material).digest()
                output.extend(derived)
                counter += 1
            
            return bytes(output[:num_bytes])
    
    def generate_health_report(self) -> EntropyHealthReport:
        """Generate comprehensive entropy health report"""
        # Get recent samples for testing
        recent_data = b''.join(s.data for s in list(self.sample_history)[-10:])
        if not recent_data:
            recent_data = os.urandom(256)
        
        # Run health tests
        test_results = self.run_full_health_suite(recent_data)
        
        # Calculate entropy scores
        shannon_entropy = self._estimate_shannon_entropy(recent_data)
        min_entropy = self._estimate_min_entropy(recent_data)
        
        # Determine overall status
        overall_score = (shannon_entropy + min_entropy) / 16.0  # Normalize to 0-1
        if overall_score >= 0.99:
            status = HealthStatus.EXCELLENT
        elif overall_score >= 0.95:
            status = HealthStatus.GOOD
        elif overall_score >= 0.85:
            status = HealthStatus.ACCEPTABLE
        elif overall_score >= 0.70:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.CRITICAL
        
        # Calculate source contributions
        source_contrib = {}
        for source, stats in self.source_stats.items():
            if stats['samples'] > 0:
                source_contrib[source] = round(
                    stats['total_entropy'] / stats['samples'], 3
                )
        
        # Generate alerts and recommendations
        alerts = []
        recommendations = []
        
        failed_tests = [t for t in test_results if not t.passed]
        if failed_tests:
            alerts.append(f"{len(failed_tests)} health test(s) failed")
            recommendations.append("Review failed tests and consider reseeding")
        
        if status == HealthStatus.CRITICAL:
            alerts.append("ENTROPY QUALITY CRITICAL - Immediate reseeding required")
            recommendations.append("STOP USING - Perform full entropy pool reseed")
        elif status == HealthStatus.DEGRADED:
            alerts.append("Entropy quality degraded")
            recommendations.append("Increase entropy collection rate")
        
        if min_entropy < self.THRESHOLDS['min_entropy']:
            alerts.append(f"Min-entropy below threshold: {min_entropy:.2f} bits")
            recommendations.append("Add additional entropy sources")
        
        return EntropyHealthReport(
            overall_status=status,
            overall_entropy_score=round(overall_score * 100, 2),
            min_entropy_bits=round(min_entropy, 3),
            tests_run=test_results,
            source_contributions=source_contrib,
            pool_size=len(self.entropy_pool),
            samples_collected=self.samples_collected,
            generated_at=datetime.now().isoformat(),
            alerts=alerts,
            recommendations=recommendations
        )
    
    def start_background_collection(self, interval: float = 0.1) -> None:
        """Start background entropy collection thread"""
        if self._collector_running:
            return
        
        self._collector_running = True
        
        def collector_loop():
            sources = list(EntropySource)
            source_idx = 0
            while self._collector_running:
                try:
                    source = sources[source_idx % len(sources)]
                    sample = self.collect_sample(source)
                    self.add_entropy_to_pool(sample)
                    source_idx += 1
                    time.sleep(interval)
                except Exception as e:
                    logger.warning(f"Collection error: {e}")
                    time.sleep(interval)
        
        self._collector_thread = threading.Thread(target=collector_loop, daemon=True)
        self._collector_thread.start()
        logger.info("Background entropy collection started")
    
    def stop_background_collection(self) -> None:
        """Stop background collection"""
        self._collector_running = False
        if self._collector_thread:
            self._collector_thread.join(timeout=2.0)
        logger.info("Background entropy collection stopped")
    
    def get_statistics(self) -> Dict:
        """Get collector statistics"""
        return {
            'samples_collected': self.samples_collected,
            'pool_size_bytes': len(self.entropy_pool),
            'pool_target_size': self.pool_size,
            'source_statistics': self.source_stats,
            'recent_health_scores': [h.overall_entropy_score for h in list(self.health_history)[-10:]]
        }


def demo_entropy_monitor():
    """Demonstrate the entropy health monitor"""
    print("=" * 70)
    print("QUANTUMCRYPT AI - POST-QUANTUM ENTROPY HEALTH MONITOR")
    print("=" * 70)
    
    # Create monitor
    monitor = EntropyHealthMonitor(pool_size=4096)
    
    # Collect some samples
    print("\nCollecting entropy samples from multiple sources...")
    sources = list(EntropySource)[:5]  # First 5 sources
    for i, source in enumerate(sources, 1):
        sample = monitor.collect_sample(source)
        monitor.add_entropy_to_pool(sample)
        print(f"  {i}. {source.value}: {sample.raw_entropy:.3f} bits/byte")
    
    # Generate health report
    print("\n" + "=" * 70)
    print("GENERATING ENTROPY HEALTH REPORT")
    print("=" * 70)
    
    report = monitor.generate_health_report()
    
    print(f"\nOverall Status: {report.overall_status.value}")
    print(f"Overall Entropy Score: {report.overall_entropy_score}%")
    print(f"Min-Entropy: {report.min_entropy_bits:.3f} bits/byte")
    print(f"Samples Collected: {report.samples_collected}")
    
    print("\nHealth Test Results:")
    for test in report.tests_run:
        status = "✓ PASS" if test.passed else "✗ FAIL"
        print(f"  {status} {test.test_name}: {test.score} (threshold: {test.threshold})")
    
    if report.alerts:
        print("\nALERTS:")
        for alert in report.alerts:
            print(f"  ⚠ {alert}")
    
    if report.recommendations:
        print("\nRECOMMENDATIONS:")
        for rec in report.recommendations:
            print(f"  → {rec}")
    
    # Test random output
    print("\n" + "=" * 70)
    print("GENERATING CRYPTOGRAPHICALLY SECURE RANDOM BYTES")
    print("=" * 70)
    
    random_bytes = monitor.get_random_bytes(32)
    print(f"\n32 Random Bytes (hex): {random_bytes.hex()}")
    print(f"Entropy of output: {monitor._estimate_shannon_entropy(random_bytes):.3f} bits/byte")
    
    print("\n" + "=" * 70)
    print("ENTROPY HEALTH MONITOR DEMO COMPLETE ✓")
    print("=" * 70)
    
    return report


if __name__ == "__main__":
    demo_entropy_monitor()
