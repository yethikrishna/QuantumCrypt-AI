"""
Post-Quantum Algorithm Benchmark Performance Profiler v3
QuantumCrypt AI - Post-Quantum Cryptography Module

This module provides comprehensive benchmarking and performance profiling
capabilities for post-quantum cryptographic algorithms. It enables detailed
performance analysis, comparison across algorithms, and optimization guidance.

API Stability: STABLE
Backward Compatible: YES
Incremental Addition: YES (no existing code modified)
"""

import time
import hashlib
import json
import statistics
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import threading
import os
import platform
import sys


class PQAlgorithm(Enum):
    """Post-quantum cryptographic algorithms"""
    # Key Encapsulation Mechanisms (NIST Round 4)
    CRYSTALS_KYBER_512 = "CRYSTALS-Kyber-512"
    CRYSTALS_KYBER_768 = "CRYSTALS-Kyber-768"
    CRYSTALS_KYBER_1024 = "CRYSTALS-Kyber-1024"

    # Digital Signatures (NIST Round 4)
    CRYSTALS_DILITHIUM_2 = "CRYSTALS-Dilithium-2"
    CRYSTALS_DILITHIUM_3 = "CRYSTALS-Dilithium-3"
    CRYSTALS_DILITHIUM_5 = "CRYSTALS-Dilithium-5"
    FALCON_512 = "Falcon-512"
    FALCON_1024 = "Falcon-1024"
    SPHINCS_PLUS_128F = "SPHINCS+-128f"
    SPHINCS_PLUS_128S = "SPHINCS+-128s"
    SPHINCS_PLUS_256F = "SPHINCS+-256f"
    SPHINCS_PLUS_256S = "SPHINCS+-256s"

    # Hash-based signatures
    XMSS = "XMSS"
    XMSS_MT = "XMSS-MT"
    LMS = "LMS"

    # Code-based
    CLASSIC_MCELIECE = "Classic-McEliece"

    # Isogeny-based
    SIKE = "SIKE"

    # Multivariate
    RAINBOW = "Rainbow"


class BenchmarkMetric(Enum):
    """Types of benchmark metrics"""
    KEY_GENERATION_TIME = "key_gen_time"
    ENCRYPTION_TIME = "encryption_time"
    DECRYPTION_TIME = "decryption_time"
    SIGNING_TIME = "signing_time"
    VERIFICATION_TIME = "verification_time"
    MEMORY_USAGE = "memory_usage"
    PUBLIC_KEY_SIZE = "public_key_size"
    PRIVATE_KEY_SIZE = "private_key_size"
    CIPHERTEXT_SIZE = "ciphertext_size"
    SIGNATURE_SIZE = "signature_size"
    CPU_UTILIZATION = "cpu_utilization"
    THROUGHPUT = "throughput"


class SecurityLevel(Enum):
    """NIST security levels"""
    LEVEL_1 = 1  # AES-128 equivalent
    LEVEL_2 = 2
    LEVEL_3 = 3  # AES-192 equivalent
    LEVEL_4 = 4
    LEVEL_5 = 5  # AES-256 equivalent


@dataclass
class BenchmarkResult:
    """Data structure for benchmark results"""
    algorithm: str
    metric: str
    security_level: int
    mean_value: float
    median_value: float
    min_value: float
    max_value: float
    std_dev: float
    p95_value: float
    p99_value: float
    sample_count: int
    unit: str
    timestamp: float = field(default_factory=time.time)
    system_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "algorithm": self.algorithm,
            "metric": self.metric,
            "security_level": self.security_level,
            "mean": self.mean_value,
            "median": self.median_value,
            "min": self.min_value,
            "max": self.max_value,
            "std_dev": self.std_dev,
            "p95": self.p95_value,
            "p99": self.p99_value,
            "samples": self.sample_count,
            "unit": self.unit,
            "timestamp": self.timestamp,
            "system_info": self.system_info
        }


@dataclass
class AlgorithmProfile:
    """Comprehensive profile of a PQ algorithm"""
    algorithm: str
    security_level: int
    nist_standardized: bool
    benchmarks: Dict[str, BenchmarkResult] = field(default_factory=dict)
    performance_score: float = 0.0
    efficiency_rating: str = "unknown"
    use_case_recommendations: List[str] = field(default_factory=list)
    known_limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "algorithm": self.algorithm,
            "security_level": self.security_level,
            "nist_standardized": self.nist_standardized,
            "benchmarks": {k: v.to_dict() for k, v in self.benchmarks.items()},
            "performance_score": self.performance_score,
            "efficiency_rating": self.efficiency_rating,
            "use_case_recommendations": self.use_case_recommendations,
            "known_limitations": self.known_limitations
        }


class PerformanceTimer:
    """High-precision performance timer"""

    def __init__(self):
        self.start_time: Optional[float] = None
        self.elapsed: float = 0.0

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    def start(self):
        """Start timing"""
        self.start_time = time.perf_counter()

    def stop(self) -> float:
        """Stop timing and return elapsed milliseconds"""
        if self.start_time is not None:
            self.elapsed = (time.perf_counter() - self.start_time) * 1000
            self.start_time = None
        return self.elapsed

    def reset(self):
        """Reset timer"""
        self.start_time = None
        self.elapsed = 0.0


class AlgorithmSimulator:
    """Simulator for PQ algorithm performance characteristics"""

    # Reference performance characteristics (based on NIST submission data)
    ALGORITHM_CHARACTERISTICS = {
        "CRYSTALS-Kyber-512": {
            "security_level": 1, "nist_standardized": True,
            "key_gen_ms": (0.05, 0.02), "encap_ms": (0.03, 0.01), "decap_ms": (0.08, 0.03),
            "pubkey_bytes": 800, "privkey_bytes": 1632, "ciphertext_bytes": 768,
            "memory_kb": 50
        },
        "CRYSTALS-Kyber-768": {
            "security_level": 3, "nist_standardized": True,
            "key_gen_ms": (0.08, 0.03), "encap_ms": (0.05, 0.02), "decap_ms": (0.12, 0.04),
            "pubkey_bytes": 1184, "privkey_bytes": 2400, "ciphertext_bytes": 1088,
            "memory_kb": 75
        },
        "CRYSTALS-Kyber-1024": {
            "security_level": 5, "nist_standardized": True,
            "key_gen_ms": (0.12, 0.04), "encap_ms": (0.08, 0.03), "decap_ms": (0.18, 0.05),
            "pubkey_bytes": 1568, "privkey_bytes": 3168, "ciphertext_bytes": 1568,
            "memory_kb": 100
        },
        "CRYSTALS-Dilithium-2": {
            "security_level": 2, "nist_standardized": True,
            "key_gen_ms": (0.15, 0.05), "sign_ms": (0.25, 0.08), "verify_ms": (0.08, 0.03),
            "pubkey_bytes": 1312, "privkey_bytes": 2528, "signature_bytes": 2420,
            "memory_kb": 80
        },
        "CRYSTALS-Dilithium-3": {
            "security_level": 3, "nist_standardized": True,
            "key_gen_ms": (0.22, 0.07), "sign_ms": (0.35, 0.10), "verify_ms": (0.12, 0.04),
            "pubkey_bytes": 1952, "privkey_bytes": 4000, "signature_bytes": 3293,
            "memory_kb": 120
        },
        "CRYSTALS-Dilithium-5": {
            "security_level": 5, "nist_standardized": True,
            "key_gen_ms": (0.30, 0.09), "sign_ms": (0.50, 0.15), "verify_ms": (0.18, 0.05),
            "pubkey_bytes": 2592, "privkey_bytes": 4864, "signature_bytes": 4595,
            "memory_kb": 160
        },
        "Falcon-512": {
            "security_level": 1, "nist_standardized": True,
            "key_gen_ms": (1.5, 0.5), "sign_ms": (0.8, 0.3), "verify_ms": (0.05, 0.02),
            "pubkey_bytes": 897, "privkey_bytes": 1281, "signature_bytes": 666,
            "memory_kb": 200
        },
        "Falcon-1024": {
            "security_level": 5, "nist_standardized": True,
            "key_gen_ms": (8.0, 2.0), "sign_ms": (3.0, 1.0), "verify_ms": (0.10, 0.03),
            "pubkey_bytes": 1793, "privkey_bytes": 2305, "signature_bytes": 1280,
            "memory_kb": 400
        },
        "SPHINCS+-128f": {
            "security_level": 1, "nist_standardized": True,
            "key_gen_ms": (0.5, 0.2), "sign_ms": (15.0, 5.0), "verify_ms": (0.02, 0.01),
            "pubkey_bytes": 32, "privkey_bytes": 64, "signature_bytes": 17088,
            "memory_kb": 50
        },
        "SPHINCS+-256f": {
            "security_level": 5, "nist_standardized": True,
            "key_gen_ms": (1.0, 0.3), "sign_ms": (30.0, 10.0), "verify_ms": (0.04, 0.01),
            "pubkey_bytes": 64, "privkey_bytes": 128, "signature_bytes": 49856,
            "memory_kb": 100
        },
        "Classic-McEliece": {
            "security_level": 5, "nist_standardized": True,
            "key_gen_ms": (500.0, 100.0), "encap_ms": (0.02, 0.01), "decap_ms": (0.5, 0.2),
            "pubkey_bytes": 1357824, "privkey_bytes": 14080, "ciphertext_bytes": 240,
            "memory_kb": 2000
        }
    }

    @classmethod
    def get_characteristic(cls, algorithm: str, characteristic: str) -> Any:
        """Get algorithm performance characteristic"""
        if algorithm not in cls.ALGORITHM_CHARACTERISTICS:
            return None
        return cls.ALGORITHM_CHARACTERISTICS[algorithm].get(characteristic)

    @classmethod
    def simulate_operation(cls, algorithm: str, operation: str,
                           variance_factor: float = 1.0) -> float:
        """Simulate operation time with realistic variance"""
        char = cls.ALGORITHM_CHARACTERISTICS.get(algorithm, {})

        op_map = {
            "key_gen": "key_gen_ms",
            "encryption": "encap_ms",
            "encapsulation": "encap_ms",
            "decryption": "decap_ms",
            "decapsulation": "decap_ms",
            "signing": "sign_ms",
            "verification": "verify_ms"
        }

        key = op_map.get(operation)
        if not key or key not in char:
            return 0.0

        mean, std = char[key]
        # Generate value with normal distribution, ensure non-negative
        import random
        value = random.gauss(mean * variance_factor, std * variance_factor)
        return max(0.001, value)


class BenchmarkRunner:
    """Runner for PQ algorithm benchmarks"""

    def __init__(self, iterations: int = 100, warmup: int = 10):
        self.iterations = iterations
        self.warmup = warmup
        self.system_info = self._collect_system_info()
        self._lock = threading.Lock()

    def _collect_system_info(self) -> Dict[str, Any]:
        """Collect system information"""
        return {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": sys.version,
            "cpu_count": os.cpu_count(),
            "benchmark_version": "v3"
        }

    def run_benchmark(self, algorithm: str, operation: str,
                      metric: str, unit: str,
                      custom_func: Optional[Callable] = None) -> BenchmarkResult:
        """Run benchmark for a specific operation"""
        measurements = []

        # Warmup runs
        for _ in range(self.warmup):
            if custom_func:
                custom_func()
            else:
                AlgorithmSimulator.simulate_operation(algorithm, operation)

        # Actual benchmark runs
        for _ in range(self.iterations):
            with PerformanceTimer() as timer:
                if custom_func:
                    custom_func()
                else:
                    AlgorithmSimulator.simulate_operation(algorithm, operation)
            measurements.append(timer.elapsed)

        # Calculate statistics
        char = AlgorithmSimulator.ALGORITHM_CHARACTERISTICS.get(algorithm, {})
        security_level = char.get("security_level", 1)

        measurements_sorted = sorted(measurements)
        p95_idx = int(len(measurements_sorted) * 0.95)
        p99_idx = int(len(measurements_sorted) * 0.99)

        return BenchmarkResult(
            algorithm=algorithm,
            metric=metric,
            security_level=security_level,
            mean_value=statistics.mean(measurements),
            median_value=statistics.median(measurements),
            min_value=min(measurements),
            max_value=max(measurements),
            std_dev=statistics.stdev(measurements) if len(measurements) > 1 else 0.0,
            p95_value=measurements_sorted[p95_idx],
            p99_value=measurements_sorted[p99_idx],
            sample_count=len(measurements),
            unit=unit,
            system_info=self.system_info.copy()
        )

    def run_size_benchmark(self, algorithm: str, size_type: str) -> BenchmarkResult:
        """Run size benchmark (key sizes, etc.)"""
        char = AlgorithmSimulator.ALGORITHM_CHARACTERISTICS.get(algorithm, {})

        size_map = {
            "public_key": "pubkey_bytes",
            "private_key": "privkey_bytes",
            "ciphertext": "ciphertext_bytes",
            "signature": "signature_bytes"
        }

        key = size_map.get(size_type)
        size = char.get(key, 0)
        security_level = char.get("security_level", 1)

        return BenchmarkResult(
            algorithm=algorithm,
            metric=f"{size_type}_size",
            security_level=security_level,
            mean_value=float(size),
            median_value=float(size),
            min_value=float(size),
            max_value=float(size),
            std_dev=0.0,
            p95_value=float(size),
            p99_value=float(size),
            sample_count=1,
            unit="bytes",
            system_info=self.system_info.copy()
        )


class PQAlgorithmPerformanceProfiler:
    """
    Main class for Post-Quantum Algorithm Performance Profiler v3

    Provides comprehensive benchmarking, profiling, and comparison
    capabilities for post-quantum cryptographic algorithms.
    """

    def __init__(self, iterations: int = 100):
        self.benchmark_runner = BenchmarkRunner(iterations=iterations)
        self.profiles: Dict[str, AlgorithmProfile] = {}
        self.comparison_results: List[Dict[str, Any]] = []
        self.benchmark_history: List[BenchmarkResult] = []
        self._lock = threading.Lock()

    def profile_algorithm(self, algorithm_name: str) -> AlgorithmProfile:
        """
        Create comprehensive performance profile for an algorithm

        Args:
            algorithm_name: Name of the PQ algorithm

        Returns:
            Complete algorithm profile with benchmarks
        """
        with self._lock:
            char = AlgorithmSimulator.ALGORITHM_CHARACTERISTICS.get(algorithm_name, {})
            if not char:
                raise ValueError(f"Unknown algorithm: {algorithm_name}")

            profile = AlgorithmProfile(
                algorithm=algorithm_name,
                security_level=char.get("security_level", 1),
                nist_standardized=char.get("nist_standardized", False)
            )

            # Run timing benchmarks
            if "key_gen_ms" in char:
                profile.benchmarks["key_generation"] = self.benchmark_runner.run_benchmark(
                    algorithm_name, "key_gen", "key_generation_time", "ms"
                )

            if "encap_ms" in char:
                profile.benchmarks["encapsulation"] = self.benchmark_runner.run_benchmark(
                    algorithm_name, "encapsulation", "encapsulation_time", "ms"
                )

            if "decap_ms" in char:
                profile.benchmarks["decapsulation"] = self.benchmark_runner.run_benchmark(
                    algorithm_name, "decapsulation", "decapsulation_time", "ms"
                )

            if "sign_ms" in char:
                profile.benchmarks["signing"] = self.benchmark_runner.run_benchmark(
                    algorithm_name, "signing", "signing_time", "ms"
                )

            if "verify_ms" in char:
                profile.benchmarks["verification"] = self.benchmark_runner.run_benchmark(
                    algorithm_name, "verification", "verification_time", "ms"
                )

            # Run size benchmarks
            profile.benchmarks["public_key_size"] = self.benchmark_runner.run_size_benchmark(
                algorithm_name, "public_key"
            )
            profile.benchmarks["private_key_size"] = self.benchmark_runner.run_size_benchmark(
                algorithm_name, "private_key"
            )

            if "ciphertext_bytes" in char:
                profile.benchmarks["ciphertext_size"] = self.benchmark_runner.run_size_benchmark(
                    algorithm_name, "ciphertext"
                )

            if "signature_bytes" in char:
                profile.benchmarks["signature_size"] = self.benchmark_runner.run_size_benchmark(
                    algorithm_name, "signature"
                )

            # Calculate performance score and rating
            profile.performance_score = self._calculate_performance_score(profile)
            profile.efficiency_rating = self._get_efficiency_rating(profile.performance_score)
            profile.use_case_recommendations = self._get_use_case_recommendations(profile)
            profile.known_limitations = self._get_known_limitations(profile)

            self.profiles[algorithm_name] = profile

            # Store benchmark history
            for bench in profile.benchmarks.values():
                self.benchmark_history.append(bench)

            return profile

    def _calculate_performance_score(self, profile: AlgorithmProfile) -> float:
        """Calculate overall performance score (0-100)"""
        score = 0.0
        weights = 0

        # Time-based metrics (lower is better)
        time_metrics = ["key_generation", "encapsulation", "decapsulation",
                        "signing", "verification"]

        for metric in time_metrics:
            if metric in profile.benchmarks:
                mean_time = profile.benchmarks[metric].mean_value
                # Score: faster = higher score
                if mean_time < 0.1:
                    metric_score = 100
                elif mean_time < 1.0:
                    metric_score = 90
                elif mean_time < 5.0:
                    metric_score = 70
                elif mean_time < 50.0:
                    metric_score = 50
                else:
                    metric_score = 20

                weight = 1.0
                score += metric_score * weight
                weights += weight

        # Size-based metrics (lower is better)
        size_metrics = ["public_key_size", "private_key_size", "signature_size"]
        for metric in size_metrics:
            if metric in profile.benchmarks:
                size_kb = profile.benchmarks[metric].mean_value / 1024
                if size_kb < 2:
                    metric_score = 100
                elif size_kb < 10:
                    metric_score = 80
                elif size_kb < 100:
                    metric_score = 60
                else:
                    metric_score = 30

                weight = 0.5
                score += metric_score * weight
                weights += weight

        return score / weights if weights > 0 else 50.0

    def _get_efficiency_rating(self, score: float) -> str:
        """Get efficiency rating from score"""
        if score >= 90:
            return "excellent"
        elif score >= 75:
            return "very_good"
        elif score >= 60:
            return "good"
        elif score >= 40:
            return "moderate"
        else:
            return "poor"

    def _get_use_case_recommendations(self, profile: AlgorithmProfile) -> List[str]:
        """Get recommended use cases"""
        recommendations = []
        score = profile.performance_score
        sec_level = profile.security_level

        if score >= 70:
            recommendations.append("high_performance_tls")
            recommendations.append("real_time_communication")

        if sec_level >= 3:
            recommendations.append("government_communications")
            recommendations.append("financial_services")

        if "signature" in profile.benchmarks:
            sig_size = profile.benchmarks["signature_size"].mean_value
            if sig_size < 5000:
                recommendations.append("code_signing")
                recommendations.append("digital_certificates")

        if profile.algorithm.startswith("CRYSTALS-Kyber"):
            recommendations.append("key_exchange")
            recommendations.append("tls_1_3")
            recommendations.append("vpn_tunnels")

        if profile.algorithm.startswith("SPHINCS"):
            recommendations.append("long_term_signing")
            recommendations.append("root_certificates")

        return list(set(recommendations))

    def _get_known_limitations(self, profile: AlgorithmProfile) -> List[str]:
        """Get known limitations"""
        limitations = []

        if "signature_size" in profile.benchmarks:
            sig_size = profile.benchmarks["signature_size"].mean_value
            if sig_size > 10000:
                limitations.append("large_signature_size")

        if "private_key_size" in profile.benchmarks:
            key_size = profile.benchmarks["private_key_size"].mean_value
            if key_size > 5000:
                limitations.append("large_key_size")

        if "signing" in profile.benchmarks:
            sign_time = profile.benchmarks["signing"].mean_value
            if sign_time > 10:
                limitations.append("slow_signing_performance")

        if "key_generation" in profile.benchmarks:
            kg_time = profile.benchmarks["key_generation"].mean_value
            if kg_time > 100:
                limitations.append("very_slow_key_generation")

        if profile.security_level == 5 and profile.performance_score < 60:
            limitations.append("performance_security_tradeoff")

        return list(set(limitations))

    def compare_algorithms(self, algorithm_names: List[str]) -> Dict[str, Any]:
        """Compare multiple algorithms side-by-side"""
        comparison = {
            "algorithms": algorithm_names,
            "profiles": {},
            "rankings": {},
            "recommendations": {}
        }

        # Profile all algorithms
        for algo in algorithm_names:
            if algo not in self.profiles:
                self.profile_algorithm(algo)
            comparison["profiles"][algo] = self.profiles[algo].to_dict()

        # Rank by performance
        ranked = sorted(
            [(algo, self.profiles[algo].performance_score) for algo in algorithm_names],
            key=lambda x: x[1],
            reverse=True
        )
        comparison["rankings"]["performance"] = [
            {"algorithm": algo, "score": score, "rank": i + 1}
            for i, (algo, score) in enumerate(ranked)
        ]

        # Rank by security level
        ranked_sec = sorted(
            [(algo, self.profiles[algo].security_level) for algo in algorithm_names],
            key=lambda x: x[1],
            reverse=True
        )
        comparison["rankings"]["security_level"] = [
            {"algorithm": algo, "level": level, "rank": i + 1}
            for i, (algo, level) in enumerate(ranked_sec)
        ]

        self.comparison_results.append(comparison)
        return comparison

    def get_optimization_guidance(self, algorithm_name: str) -> Dict[str, Any]:
        """Get optimization guidance for an algorithm"""
        if algorithm_name not in self.profiles:
            self.profile_algorithm(algorithm_name)

        profile = self.profiles[algorithm_name]
        guidance = {
            "algorithm": algorithm_name,
            "performance_score": profile.performance_score,
            "bottlenecks": [],
            "optimizations": [],
            "deployment_tips": []
        }

        # Identify bottlenecks
        if "signing" in profile.benchmarks:
            if profile.benchmarks["signing"].mean_value > 5.0:
                guidance["bottlenecks"].append("signing_performance")
                guidance["optimizations"].append("precompute_signing_parameters")
                guidance["optimizations"].append("hardware_acceleration")

        if "key_generation" in profile.benchmarks:
            if profile.benchmarks["key_generation"].mean_value > 50.0:
                guidance["bottlenecks"].append("key_generation_latency")
                guidance["optimizations"].append("precompute_keys")
                guidance["optimizations"].append("key_caching")

        if profile.benchmarks.get("public_key_size", BenchmarkResult(
            algorithm_name, "public_key_size", 1, 0, 0, 0, 0, 0, 0, 0, 1, "bytes"
        )).mean_value > 10000:
            guidance["bottlenecks"].append("large_public_key")
            guidance["deployment_tips"].append("key_compression")
            guidance["deployment_tips"].append("protocol_specific_encoding")

        guidance["deployment_tips"].append("use_nist_standardized_algorithms")
        guidance["deployment_tips"].append("implement_hybrid_modes")
        guidance["deployment_tips"].append("monitor_performance_in_production")

        return guidance

    def generate_report(self, algorithm_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Generate comprehensive profiling report"""
        if algorithm_names is None:
            algorithm_names = list(self.profiles.keys())

        report = {
            "report_version": "v3",
            "generated_at": time.time(),
            "system_info": self.benchmark_runner.system_info,
            "algorithm_profiles": {},
            "summary_statistics": {
                "total_algorithms_profiled": len(algorithm_names),
                "benchmarks_run": len(self.benchmark_history),
                "nist_standardized_count": 0
            }
        }

        for algo in algorithm_names:
            if algo not in self.profiles:
                self.profile_algorithm(algo)
            profile = self.profiles[algo]
            report["algorithm_profiles"][algo] = profile.to_dict()

            if profile.nist_standardized:
                report["summary_statistics"]["nist_standardized_count"] += 1

        return report


# Export public interface
__all__ = [
    "PQAlgorithmPerformanceProfiler",
    "PQAlgorithm",
    "BenchmarkMetric",
    "SecurityLevel",
    "BenchmarkResult",
    "AlgorithmProfile",
    "BenchmarkRunner",
    "AlgorithmSimulator"
]
