"""
QuantumCrypt AI - Post-Quantum Cryptography Algorithm Benchmark Profiler
Production-grade implementation for benchmarking and comparing PQC algorithms.

This module provides comprehensive performance profiling, memory usage tracking,
and comparative analysis of NIST-standardized post-quantum cryptography algorithms.
"""

import time
import json
import hashlib
import os
import tracemalloc
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict


class AlgorithmCategory(Enum):
    KEY_ENCAPSULATION = "kem"
    DIGITAL_SIGNATURE = "signature"
    HASH_FUNCTION = "hash"
    SYMMETRIC_CIPHER = "cipher"
    KEY_EXCHANGE = "key_exchange"


class SecurityLevel(Enum):
    LEVEL_1 = 1  # NIST Security Level 1 (AES-128)
    LEVEL_2 = 2  # NIST Security Level 2
    LEVEL_3 = 3  # NIST Security Level 3 (AES-192)
    LEVEL_4 = 4  # NIST Security Level 4
    LEVEL_5 = 5  # NIST Security Level 5 (AES-256)


class AlgorithmStatus(Enum):
    STANDARDIZED = "standardized"
    FINALIST = "finalist"
    CANDIDATE = "candidate"
    DEPRECATED = "deprecated"
    EXPERIMENTAL = "experimental"


@dataclass
class AlgorithmInfo:
    algorithm_id: str
    name: str
    category: AlgorithmCategory
    security_level: SecurityLevel
    status: AlgorithmStatus
    public_key_size: int  # bytes
    secret_key_size: int  # bytes
    ciphertext_size: Optional[int] = None  # bytes (for KEM)
    signature_size: Optional[int] = None  # bytes (for signatures)
    nist_standard: bool = False
    year_standardized: Optional[int] = None
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkResult:
    algorithm_id: str
    operation: str
    iterations: int
    avg_time_ms: float
    min_time_ms: float
    max_time_ms: float
    std_dev_ms: float
    throughput_ops_per_sec: float
    avg_memory_kb: float
    peak_memory_kb: float
    cpu_cycles_estimate: int
    timestamp: str
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class ComparativeBenchmark:
    benchmark_id: str
    name: str
    description: str
    algorithms_tested: List[str]
    results: Dict[str, List[BenchmarkResult]]
    overall_ranking: Dict[str, float]
    created_at: str
    completed_at: str


class MockPQCAlgorithm:
    """
    Mock implementations of PQC algorithms for benchmarking purposes.
    These simulate the computational characteristics of real PQC algorithms.
    """
    
    @staticmethod
    def kyber_512_keygen() -> Tuple[bytes, bytes]:
        """Simulate Kyber-512 key generation (Level 1 KEM)"""
        iterations = 1000
        result = bytearray(800)
        for i in range(iterations):
            result[i % 800] = (result[i % 800] + i) & 0xFF
            if i % 100 == 0:
                hashlib.sha256(result).digest()
        pk = bytes(result[:384])
        sk = bytes(result[384:])
        return pk, sk
    
    @staticmethod
    def kyber_768_keygen() -> Tuple[bytes, bytes]:
        """Simulate Kyber-768 key generation (Level 3 KEM)"""
        iterations = 2000
        result = bytearray(1568)
        for i in range(iterations):
            result[i % 1568] = (result[i % 1568] + i * 2) & 0xFF
            if i % 80 == 0:
                hashlib.sha512(result).digest()
        pk = bytes(result[:1088])
        sk = bytes(result[1088:])
        return pk, sk
    
    @staticmethod
    def kyber_1024_keygen() -> Tuple[bytes, bytes]:
        """Simulate Kyber-1024 key generation (Level 5 KEM)"""
        iterations = 3500
        result = bytearray(2400)
        for i in range(iterations):
            result[i % 2400] = (result[i % 2400] + i * 3) & 0xFF
            if i % 60 == 0:
                hashlib.sha3_512(result).digest()
        pk = bytes(result[:1568])
        sk = bytes(result[1568:])
        return pk, sk
    
    @staticmethod
    def dilithium_2_keygen() -> Tuple[bytes, bytes]:
        """Simulate Dilithium-2 key generation (Level 2 signature)"""
        iterations = 1500
        result = bytearray(2800)
        for i in range(iterations):
            result[i % 2800] = (result[i % 2800] + i) & 0xFF
            if i % 100 == 0:
                hashlib.sha256(result).digest()
        pk = bytes(result[:1312])
        sk = bytes(result[1312:])
        return pk, sk
    
    @staticmethod
    def dilithium_3_keygen() -> Tuple[bytes, bytes]:
        """Simulate Dilithium-3 key generation (Level 3 signature)"""
        iterations = 2500
        result = bytearray(4000)
        for i in range(iterations):
            result[i % 4000] = (result[i % 4000] + i * 2) & 0xFF
            if i % 80 == 0:
                hashlib.sha512(result).digest()
        pk = bytes(result[:1952])
        sk = bytes(result[1952:])
        return pk, sk
    
    @staticmethod
    def dilithium_5_keygen() -> Tuple[bytes, bytes]:
        """Simulate Dilithium-5 key generation (Level 5 signature)"""
        iterations = 4000
        result = bytearray(5500)
        for i in range(iterations):
            result[i % 5500] = (result[i % 5500] + i * 3) & 0xFF
            if i % 60 == 0:
                hashlib.sha3_512(result).digest()
        pk = bytes(result[:2592])
        sk = bytes(result[2592:])
        return pk, sk
    
    @staticmethod
    def falcon_512_keygen() -> Tuple[bytes, bytes]:
        """Simulate Falcon-512 key generation"""
        iterations = 5000
        result = bytearray(1281)
        for i in range(iterations):
            result[i % 1281] = (result[i % 1281] + i) & 0xFF
            if i % 50 == 0:
                hashlib.sha256(result).digest()
        pk = bytes(result[:897])
        sk = bytes(result[897:])
        return pk, sk
    
    @staticmethod
    def sphincs_plus_sha2_128f_keygen() -> Tuple[bytes, bytes]:
        """Simulate SPHINCS+-SHA2-128f key generation"""
        iterations = 8000
        result = bytearray(64)
        for i in range(iterations):
            result[i % 64] = (result[i % 64] + i) & 0xFF
            if i % 20 == 0:
                hashlib.sha256(result).digest()
        pk = bytes(result[:32])
        sk = bytes(result[32:])
        return pk, sk


class PostQuantumBenchmarkProfiler:
    """
    Production-grade benchmark profiler for post-quantum cryptography algorithms.
    Measures execution time, memory usage, throughput, and provides comparative analysis.
    """
    
    # Algorithm registry with real NIST parameters
    ALGORITHM_REGISTRY: Dict[str, AlgorithmInfo] = {
        "kyber_512": AlgorithmInfo(
            algorithm_id="kyber_512",
            name="CRYSTALS-Kyber-512",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            security_level=SecurityLevel.LEVEL_1,
            status=AlgorithmStatus.STANDARDIZED,
            public_key_size=800,
            secret_key_size=1632,
            ciphertext_size=768,
            nist_standard=True,
            year_standardized=2024,
            description="NIST Level 1 Key Encapsulation Mechanism"
        ),
        "kyber_768": AlgorithmInfo(
            algorithm_id="kyber_768",
            name="CRYSTALS-Kyber-768",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            security_level=SecurityLevel.LEVEL_3,
            status=AlgorithmStatus.STANDARDIZED,
            public_key_size=1184,
            secret_key_size=2400,
            ciphertext_size=1088,
            nist_standard=True,
            year_standardized=2024,
            description="NIST Level 3 Key Encapsulation Mechanism"
        ),
        "kyber_1024": AlgorithmInfo(
            algorithm_id="kyber_1024",
            name="CRYSTALS-Kyber-1024",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            security_level=SecurityLevel.LEVEL_5,
            status=AlgorithmStatus.STANDARDIZED,
            public_key_size=1568,
            secret_key_size=3168,
            ciphertext_size=1568,
            nist_standard=True,
            year_standardized=2024,
            description="NIST Level 5 Key Encapsulation Mechanism"
        ),
        "dilithium_2": AlgorithmInfo(
            algorithm_id="dilithium_2",
            name="CRYSTALS-Dilithium-2",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            security_level=SecurityLevel.LEVEL_2,
            status=AlgorithmStatus.STANDARDIZED,
            public_key_size=1312,
            secret_key_size=2528,
            signature_size=2420,
            nist_standard=True,
            year_standardized=2024,
            description="NIST Level 2 Digital Signature Algorithm"
        ),
        "dilithium_3": AlgorithmInfo(
            algorithm_id="dilithium_3",
            name="CRYSTALS-Dilithium-3",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            security_level=SecurityLevel.LEVEL_3,
            status=AlgorithmStatus.STANDARDIZED,
            public_key_size=1952,
            secret_key_size=4000,
            signature_size=3293,
            nist_standard=True,
            year_standardized=2024,
            description="NIST Level 3 Digital Signature Algorithm"
        ),
        "dilithium_5": AlgorithmInfo(
            algorithm_id="dilithium_5",
            name="CRYSTALS-Dilithium-5",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            security_level=SecurityLevel.LEVEL_5,
            status=AlgorithmStatus.STANDARDIZED,
            public_key_size=2592,
            secret_key_size=4864,
            signature_size=4595,
            nist_standard=True,
            year_standardized=2024,
            description="NIST Level 5 Digital Signature Algorithm"
        ),
        "falcon_512": AlgorithmInfo(
            algorithm_id="falcon_512",
            name="Falcon-512",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            security_level=SecurityLevel.LEVEL_1,
            status=AlgorithmStatus.STANDARDIZED,
            public_key_size=897,
            secret_key_size=1281,
            signature_size=666,
            nist_standard=True,
            year_standardized=2024,
            description="NIST Level 1 Lattice-Based Signature"
        ),
        "sphincs_plus_sha2_128f": AlgorithmInfo(
            algorithm_id="sphincs_plus_sha2_128f",
            name="SPHINCS+-SHA2-128f",
            category=AlgorithmCategory.DIGITAL_SIGNATURE,
            security_level=SecurityLevel.LEVEL_1,
            status=AlgorithmStatus.STANDARDIZED,
            public_key_size=32,
            secret_key_size=64,
            signature_size=17088,
            nist_standard=True,
            year_standardized=2024,
            description="NIST Level 1 Hash-Based Signature (Fast)"
        )
    }
    
    # Mock implementations mapping
    ALGORITHM_IMPLEMENTATIONS = {
        "kyber_512": MockPQCAlgorithm.kyber_512_keygen,
        "kyber_768": MockPQCAlgorithm.kyber_768_keygen,
        "kyber_1024": MockPQCAlgorithm.kyber_1024_keygen,
        "dilithium_2": MockPQCAlgorithm.dilithium_2_keygen,
        "dilithium_3": MockPQCAlgorithm.dilithium_3_keygen,
        "dilithium_5": MockPQCAlgorithm.dilithium_5_keygen,
        "falcon_512": MockPQCAlgorithm.falcon_512_keygen,
        "sphincs_plus_sha2_128f": MockPQCAlgorithm.sphincs_plus_sha2_128f_keygen
    }
    
    def __init__(self):
        self.benchmark_history: List[BenchmarkResult] = []
        self.comparative_results: List[ComparativeBenchmark] = []
        
    def benchmark_operation(
        self,
        algorithm_id: str,
        operation: str,
        func: Callable,
        iterations: int = 100,
        warmup_iterations: int = 10
    ) -> BenchmarkResult:
        """
        Benchmark a single algorithm operation with detailed metrics.
        
        Args:
            algorithm_id: Algorithm identifier
            operation: Operation name (keygen, sign, verify, encaps, decaps)
            func: Function to benchmark
            iterations: Number of test iterations
            warmup_iterations: Number of warmup iterations
        
        Returns:
            BenchmarkResult with performance metrics
        """
        # Warmup phase
        for _ in range(warmup_iterations):
            try:
                func()
            except Exception:
                pass
        
        # Benchmark phase
        times: List[float] = []
        memory_samples: List[int] = []
        
        tracemalloc.start()
        
        for _ in range(iterations):
            start = time.perf_counter()
            try:
                func()
                elapsed = (time.perf_counter() - start) * 1000  # ms
                times.append(elapsed)
                
                current, peak = tracemalloc.get_traced_memory()
                memory_samples.append(current)
            except Exception as e:
                tracemalloc.stop()
                return BenchmarkResult(
                    algorithm_id=algorithm_id,
                    operation=operation,
                    iterations=iterations,
                    avg_time_ms=0,
                    min_time_ms=0,
                    max_time_ms=0,
                    std_dev_ms=0,
                    throughput_ops_per_sec=0,
                    avg_memory_kb=0,
                    peak_memory_kb=0,
                    cpu_cycles_estimate=0,
                    timestamp=datetime.now().isoformat(),
                    success=False,
                    error_message=str(e)
                )
        
        tracemalloc.stop()
        
        # Calculate statistics
        if times:
            avg_time = sum(times) / len(times)
            min_time = min(times)
            max_time = max(times)
            variance = sum((t - avg_time) ** 2 for t in times) / len(times)
            std_dev = variance ** 0.5
            throughput = 1000 / avg_time if avg_time > 0 else 0
        else:
            avg_time = min_time = max_time = std_dev = throughput = 0
        
        if memory_samples:
            avg_memory = sum(memory_samples) / len(memory_samples) / 1024  # KB
            peak_memory = max(memory_samples) / 1024  # KB
        else:
            avg_memory = peak_memory = 0
        
        # Estimate CPU cycles (rough estimate based on time)
        cpu_cycles = int(avg_time * 3_000_000)  # Assuming 3GHz CPU
        
        result = BenchmarkResult(
            algorithm_id=algorithm_id,
            operation=operation,
            iterations=iterations,
            avg_time_ms=avg_time,
            min_time_ms=min_time,
            max_time_ms=max_time,
            std_dev_ms=std_dev,
            throughput_ops_per_sec=throughput,
            avg_memory_kb=avg_memory,
            peak_memory_kb=peak_memory,
            cpu_cycles_estimate=cpu_cycles,
            timestamp=datetime.now().isoformat(),
            success=True
        )
        
        self.benchmark_history.append(result)
        return result
    
    def benchmark_algorithm(
        self,
        algorithm_id: str,
        iterations: int = 50
    ) -> List[BenchmarkResult]:
        """
        Run complete benchmark suite for an algorithm.
        
        Args:
            algorithm_id: Algorithm to benchmark
            iterations: Number of iterations per test
        
        Returns:
            List of BenchmarkResult objects
        """
        if algorithm_id not in self.ALGORITHM_IMPLEMENTATIONS:
            raise ValueError(f"Unknown algorithm: {algorithm_id}")
        
        results = []
        
        # Benchmark key generation
        keygen_func = self.ALGORITHM_IMPLEMENTATIONS[algorithm_id]
        keygen_result = self.benchmark_operation(
            algorithm_id=algorithm_id,
            operation="keygen",
            func=keygen_func,
            iterations=iterations
        )
        results.append(keygen_result)
        
        return results
    
    def run_comparative_benchmark(
        self,
        name: str,
        description: str,
        algorithm_ids: List[str],
        iterations: int = 50
    ) -> ComparativeBenchmark:
        """
        Run comparative benchmark across multiple algorithms.
        
        Args:
            name: Benchmark suite name
            description: Benchmark description
            algorithm_ids: List of algorithms to compare
            iterations: Iterations per algorithm
        
        Returns:
            ComparativeBenchmark with all results and rankings
        """
        benchmark_id = hashlib.md5(f"{name}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        created_at = datetime.now().isoformat()
        
        all_results: Dict[str, List[BenchmarkResult]] = {}
        performance_scores: Dict[str, float] = {}
        
        for alg_id in algorithm_ids:
            try:
                results = self.benchmark_algorithm(alg_id, iterations)
                all_results[alg_id] = results
                
                # Calculate performance score (lower is better)
                keygen_result = next((r for r in results if r.operation == "keygen"), None)
                if keygen_result and keygen_result.success:
                    # Score based on time and memory
                    time_score = keygen_result.avg_time_ms
                    memory_score = keygen_result.peak_memory_kb / 10
                    performance_scores[alg_id] = time_score + memory_score
            except Exception as e:
                print(f"Error benchmarking {alg_id}: {e}")
        
        # Create ranking (sorted by performance score)
        ranking = {k: v for k, v in sorted(performance_scores.items(), key=lambda x: x[1])}
        
        completed_at = datetime.now().isoformat()
        
        comparative = ComparativeBenchmark(
            benchmark_id=benchmark_id,
            name=name,
            description=description,
            algorithms_tested=algorithm_ids,
            results=all_results,
            overall_ranking=ranking,
            created_at=created_at,
            completed_at=completed_at
        )
        
        self.comparative_results.append(comparative)
        return comparative
    
    def get_algorithm_info(self, algorithm_id: str) -> Optional[AlgorithmInfo]:
        """Get metadata for an algorithm."""
        return self.ALGORITHM_REGISTRY.get(algorithm_id)
    
    def list_algorithms(self, category: Optional[AlgorithmCategory] = None) -> List[AlgorithmInfo]:
        """List all available algorithms, optionally filtered by category."""
        if category:
            return [info for info in self.ALGORITHM_REGISTRY.values() if info.category == category]
        return list(self.ALGORITHM_REGISTRY.values())
    
    def generate_comparison_report(self, benchmark: ComparativeBenchmark) -> Dict[str, Any]:
        """Generate detailed comparison report."""
        report = {
            "benchmark_id": benchmark.benchmark_id,
            "name": benchmark.name,
            "description": benchmark.description,
            "created_at": benchmark.created_at,
            "completed_at": benchmark.completed_at,
            "algorithms": [],
            "ranking": benchmark.overall_ranking,
            "summary": {}
        }
        
        for alg_id in benchmark.algorithms_tested:
            alg_info = self.get_algorithm_info(alg_id)
            alg_results = benchmark.results.get(alg_id, [])
            
            # Properly serialize enums
            info_dict = None
            if alg_info:
                info_dict = {
                    "algorithm_id": alg_info.algorithm_id,
                    "name": alg_info.name,
                    "category": alg_info.category.value,
                    "security_level": alg_info.security_level.value,
                    "status": alg_info.status.value,
                    "public_key_size": alg_info.public_key_size,
                    "secret_key_size": alg_info.secret_key_size,
                    "ciphertext_size": alg_info.ciphertext_size,
                    "signature_size": alg_info.signature_size,
                    "nist_standard": alg_info.nist_standard,
                    "year_standardized": alg_info.year_standardized,
                    "description": alg_info.description
                }
            
            results_dicts = []
            for r in alg_results:
                results_dicts.append({
                    "algorithm_id": r.algorithm_id,
                    "operation": r.operation,
                    "iterations": r.iterations,
                    "avg_time_ms": r.avg_time_ms,
                    "min_time_ms": r.min_time_ms,
                    "max_time_ms": r.max_time_ms,
                    "std_dev_ms": r.std_dev_ms,
                    "throughput_ops_per_sec": r.throughput_ops_per_sec,
                    "avg_memory_kb": r.avg_memory_kb,
                    "peak_memory_kb": r.peak_memory_kb,
                    "cpu_cycles_estimate": r.cpu_cycles_estimate,
                    "timestamp": r.timestamp,
                    "success": r.success,
                    "error_message": r.error_message
                })
            
            alg_data = {
                "algorithm_id": alg_id,
                "info": info_dict,
                "results": results_dicts
            }
            report["algorithms"].append(alg_data)
        
        # Generate summary statistics
        report["summary"] = {
            "total_algorithms_tested": len(benchmark.algorithms_tested),
            "fastest_algorithm": next(iter(benchmark.overall_ranking.keys()), None),
            "benchmark_duration_seconds": (
                datetime.fromisoformat(benchmark.completed_at) - 
                datetime.fromisoformat(benchmark.created_at)
            ).total_seconds()
        }
        
        return report
    
    def export_to_json(self, benchmark: ComparativeBenchmark, output_path: str) -> None:
        """Export benchmark results to JSON file."""
        report = self.generate_comparison_report(benchmark)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
    
    def export_to_markdown(self, benchmark: ComparativeBenchmark, output_path: Optional[str] = None) -> str:
        """Export benchmark results to formatted markdown report."""
        report = self.generate_comparison_report(benchmark)
        
        md = f"""# Post-Quantum Cryptography Benchmark: {benchmark.name}

**Benchmark ID:** `{benchmark.benchmark_id}`  
**Created:** {datetime.fromisoformat(benchmark.created_at).strftime('%Y-%m-%d %H:%M:%S')}  
**Completed:** {datetime.fromisoformat(benchmark.completed_at).strftime('%Y-%m-%d %H:%M:%S')}  
**Duration:** {report['summary']['benchmark_duration_seconds']:.2f} seconds

## Description

{benchmark.description}

## Algorithms Tested

| Algorithm | Category | Security Level | Public Key | Secret Key | Status |
|-----------|----------|----------------|------------|------------|--------|
"""
        
        for alg_id in benchmark.algorithms_tested:
            info = self.get_algorithm_info(alg_id)
            if info:
                cat = info.category.value.upper()
                level = info.security_level.value
                status = info.status.value.upper()
                md += f"| {info.name} | {cat} | Level {level} | {info.public_key_size} B | {info.secret_key_size} B | {status} |\n"
        
        md += """
## Performance Results

### Key Generation Performance

| Algorithm | Avg Time (ms) | Min (ms) | Max (ms) | Std Dev | Throughput (ops/sec) | Peak Memory (KB) |
|-----------|---------------|----------|----------|---------|----------------------|------------------|
"""
        
        for alg_id in benchmark.algorithms_tested:
            info = self.get_algorithm_info(alg_id)
            alg_results = benchmark.results.get(alg_id, [])
            for result in alg_results:
                if result.operation == "keygen" and result.success:
                    name = info.name if info else alg_id
                    md += f"| {name} | {result.avg_time_ms:.3f} | {result.min_time_ms:.3f} | {result.max_time_ms:.3f} | {result.std_dev_ms:.3f} | {result.throughput_ops_per_sec:.1f} | {result.peak_memory_kb:.1f} |\n"
        
        md += """
## Performance Ranking (Lower = Better)

"""
        for rank, (alg_id, score) in enumerate(benchmark.overall_ranking.items(), 1):
            info = self.get_algorithm_info(alg_id)
            name = info.name if info else alg_id
            md += f"{rank}. **{name}**: Score = {score:.2f}\n"
        
        md += """
---
*Benchmark generated by QuantumCrypt PQC Benchmark Profiler*
"""
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(md)
        
        return md


if __name__ == "__main__":
    # Example usage and self-test
    profiler = PostQuantumBenchmarkProfiler()
    
    print("=== QuantumCrypt PQC Algorithm Benchmark Profiler ===")
    print()
    
    # List available algorithms
    print("Available Algorithms:")
    for alg in profiler.list_algorithms():
        print(f"  - {alg.name} ({alg.category.value}, Level {alg.security_level.value})")
    print()
    
    # Run quick benchmark
    print("Running benchmark on Kyber family...")
    benchmark = profiler.run_comparative_benchmark(
        name="Kyber Family Performance Test",
        description="Key generation performance comparison of Kyber KEM variants",
        algorithm_ids=["kyber_512", "kyber_768", "kyber_1024"],
        iterations=20
    )
    
    print()
    print("Results:")
    print(profiler.export_to_markdown(benchmark))
    
    print("\n✓ Post-Quantum Benchmark Profiler loaded successfully!")
