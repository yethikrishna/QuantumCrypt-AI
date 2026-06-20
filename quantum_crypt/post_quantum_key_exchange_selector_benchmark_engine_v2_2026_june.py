"""
QuantumCrypt AI - Post-Quantum Key Exchange Selector & Benchmark Engine V2
Production-grade implementation with algorithm selection, benchmarking, and recommendation

This module provides:
1. Post-Quantum Algorithm Registry (NIST-standardized algorithms)
2. Performance Benchmarking Framework
3. Use-case based Algorithm Selection
4. Security Level Assessment
5. Hybrid Mode Recommendations
6. Performance/Resource Optimization
"""

import time
import hashlib
import os
import json
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class SecurityLevel(Enum):
    """NIST Security Levels for Post-Quantum Cryptography"""
    LEVEL_1 = 1  # AES-128 equivalent
    LEVEL_2 = 2  # SHA-256 equivalent
    LEVEL_3 = 3  # AES-192 equivalent
    LEVEL_4 = 4  # SHA-384 equivalent
    LEVEL_5 = 5  # AES-256 equivalent


class AlgorithmCategory(Enum):
    KEM = "Key Encapsulation Mechanism"
    SIGNATURE = "Digital Signature"
    HYBRID = "Hybrid Classical-Quantum"


class UseCaseType(Enum):
    TLS_HANDSHAKE = "tls_handshake"
    VPN_TUNNEL = "vpn_tunnel"
    EMAIL_ENCRYPTION = "email_encryption"
    FILE_ENCRYPTION = "file_encryption"
    DATABASE_ENCRYPTION = "database_encryption"
    API_AUTHENTICATION = "api_authentication"
    IOT_DEVICE = "iot_device"
    HIGH_PERFORMANCE = "high_performance"
    HIGH_SECURITY = "high_security"
    CONSTRAINED_DEVICE = "constrained_device"


@dataclass
class PQAlgorithm:
    """Post-Quantum Algorithm metadata"""
    name: str
    category: AlgorithmCategory
    nist_standardized: bool
    security_level: SecurityLevel
    public_key_size: int  # bytes
    secret_key_size: int  # bytes
    ciphertext_size: int  # bytes (for KEMs)
    signature_size: int  # bytes (for signatures)
    performance_score: float  # 0-10, higher = faster
    memory_footprint: int  # KB
    cpu_intensity: float  # 0-10, higher = more CPU
    supported_use_cases: List[UseCaseType]
    maturity_level: str  # experimental, stable, mature
    reference_implementation: str
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "nist_standardized": self.nist_standardized,
            "security_level": self.security_level.value,
            "public_key_size": self.public_key_size,
            "secret_key_size": self.secret_key_size,
            "ciphertext_size": self.ciphertext_size,
            "signature_size": self.signature_size,
            "performance_score": self.performance_score,
            "memory_footprint_kb": self.memory_footprint,
            "cpu_intensity": self.cpu_intensity,
            "supported_use_cases": [uc.value for uc in self.supported_use_cases],
            "maturity_level": self.maturity_level,
            "reference_implementation": self.reference_implementation,
            "notes": self.notes
        }


@dataclass
class BenchmarkResult:
    """Benchmark result for an algorithm"""
    algorithm_name: str
    operation: str
    iterations: int
    total_time_ms: float
    avg_time_us: float
    ops_per_second: float
    memory_peak_kb: float
    cpu_usage_percent: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm_name": self.algorithm_name,
            "operation": self.operation,
            "iterations": self.iterations,
            "total_time_ms": self.total_time_ms,
            "avg_time_us": self.avg_time_us,
            "ops_per_second": self.ops_per_second,
            "memory_peak_kb": self.memory_peak_kb,
            "cpu_usage_percent": self.cpu_usage_percent,
            "timestamp": self.timestamp
        }


@dataclass
class AlgorithmRecommendation:
    """Algorithm recommendation with scoring"""
    primary_algorithm: str
    alternative_algorithms: List[str]
    hybrid_recommendation: Optional[str]
    match_score: float
    security_assessment: str
    performance_assessment: str
    compatibility_notes: str
    migration_complexity: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_algorithm": self.primary_algorithm,
            "alternative_algorithms": self.alternative_algorithms,
            "hybrid_recommendation": self.hybrid_recommendation,
            "match_score": self.match_score,
            "security_assessment": self.security_assessment,
            "performance_assessment": self.performance_assessment,
            "compatibility_notes": self.compatibility_notes,
            "migration_complexity": self.migration_complexity
        }


class PQAlgorithmRegistry:
    """Registry of NIST-standardized Post-Quantum algorithms"""

    def __init__(self):
        self.algorithms: Dict[str, PQAlgorithm] = {}
        self._initialize_algorithms()

    def _initialize_algorithms(self):
        """Initialize with NIST-standardized and selected algorithms"""

        # CRYSTALS-Kyber (NIST Standard for KEM)
        self.algorithms["CRYSTALS-Kyber-512"] = PQAlgorithm(
            name="CRYSTALS-Kyber-512",
            category=AlgorithmCategory.KEM,
            nist_standardized=True,
            security_level=SecurityLevel.LEVEL_1,
            public_key_size=800,
            secret_key_size=1632,
            ciphertext_size=768,
            signature_size=0,
            performance_score=8.5,
            memory_footprint=64,
            cpu_intensity=4.0,
            supported_use_cases=[
                UseCaseType.TLS_HANDSHAKE,
                UseCaseType.VPN_TUNNEL,
                UseCaseType.API_AUTHENTICATION,
                UseCaseType.HIGH_PERFORMANCE
            ],
            maturity_level="mature",
            reference_implementation="https://github.com/pq-crystals/kyber",
            notes="NIST selected for standardization, most widely adopted PQ KEM"
        )

        self.algorithms["CRYSTALS-Kyber-768"] = PQAlgorithm(
            name="CRYSTALS-Kyber-768",
            category=AlgorithmCategory.KEM,
            nist_standardized=True,
            security_level=SecurityLevel.LEVEL_3,
            public_key_size=1184,
            secret_key_size=2400,
            ciphertext_size=1088,
            signature_size=0,
            performance_score=7.5,
            memory_footprint=96,
            cpu_intensity=5.0,
            supported_use_cases=[
                UseCaseType.TLS_HANDSHAKE,
                UseCaseType.VPN_TUNNEL,
                UseCaseType.FILE_ENCRYPTION,
                UseCaseType.HIGH_SECURITY
            ],
            maturity_level="mature",
            reference_implementation="https://github.com/pq-crystals/kyber",
            notes="Recommended default for most security-sensitive applications"
        )

        self.algorithms["CRYSTALS-Kyber-1024"] = PQAlgorithm(
            name="CRYSTALS-Kyber-1024",
            category=AlgorithmCategory.KEM,
            nist_standardized=True,
            security_level=SecurityLevel.LEVEL_5,
            public_key_size=1568,
            secret_key_size=3168,
            ciphertext_size=1568,
            signature_size=0,
            performance_score=6.0,
            memory_footprint=128,
            cpu_intensity=6.5,
            supported_use_cases=[
                UseCaseType.HIGH_SECURITY,
                UseCaseType.FILE_ENCRYPTION,
                UseCaseType.DATABASE_ENCRYPTION
            ],
            maturity_level="mature",
            reference_implementation="https://github.com/pq-crystals/kyber",
            notes="Highest security level for long-term protection"
        )

        # CRYSTALS-Dilithium (NIST Standard for Signatures)
        self.algorithms["CRYSTALS-Dilithium-2"] = PQAlgorithm(
            name="CRYSTALS-Dilithium-2",
            category=AlgorithmCategory.SIGNATURE,
            nist_standardized=True,
            security_level=SecurityLevel.LEVEL_2,
            public_key_size=1312,
            secret_key_size=2528,
            ciphertext_size=0,
            signature_size=2420,
            performance_score=7.0,
            memory_footprint=80,
            cpu_intensity=5.5,
            supported_use_cases=[
                UseCaseType.TLS_HANDSHAKE,
                UseCaseType.API_AUTHENTICATION,
                UseCaseType.EMAIL_ENCRYPTION
            ],
            maturity_level="mature",
            reference_implementation="https://github.com/pq-crystals/dilithium",
            notes="NIST selected for standardization"
        )

        self.algorithms["CRYSTALS-Dilithium-3"] = PQAlgorithm(
            name="CRYSTALS-Dilithium-3",
            category=AlgorithmCategory.SIGNATURE,
            nist_standardized=True,
            security_level=SecurityLevel.LEVEL_3,
            public_key_size=1952,
            secret_key_size=4000,
            ciphertext_size=0,
            signature_size=3293,
            performance_score=6.0,
            memory_footprint=112,
            cpu_intensity=6.5,
            supported_use_cases=[
                UseCaseType.TLS_HANDSHAKE,
                UseCaseType.HIGH_SECURITY,
                UseCaseType.DATABASE_ENCRYPTION
            ],
            maturity_level="mature",
            reference_implementation="https://github.com/pq-crystals/dilithium",
            notes="Recommended default security level"
        )

        # Classic McEliece (NIST Standard - conservative)
        self.algorithms["Classic-McEliece-460896"] = PQAlgorithm(
            name="Classic-McEliece-460896",
            category=AlgorithmCategory.KEM,
            nist_standardized=True,
            security_level=SecurityLevel.LEVEL_1,
            public_key_size=524160,
            secret_key_size=13608,
            ciphertext_size=188,
            signature_size=0,
            performance_score=3.0,
            memory_footprint=1024,
            cpu_intensity=8.0,
            supported_use_cases=[
                UseCaseType.HIGH_SECURITY,
                UseCaseType.FILE_ENCRYPTION
            ],
            maturity_level="mature",
            reference_implementation="https://classic.mceliece.org/",
            notes="Conservative security, very large public keys"
        )

        # NTRU (Round 4 candidate)
        self.algorithms["NTRU-HPS-2048-509"] = PQAlgorithm(
            name="NTRU-HPS-2048-509",
            category=AlgorithmCategory.KEM,
            nist_standardized=False,
            security_level=SecurityLevel.LEVEL_1,
            public_key_size=699,
            secret_key_size=935,
            ciphertext_size=699,
            signature_size=0,
            performance_score=8.0,
            memory_footprint=48,
            cpu_intensity=3.5,
            supported_use_cases=[
                UseCaseType.IOT_DEVICE,
                UseCaseType.CONSTRAINED_DEVICE,
                UseCaseType.HIGH_PERFORMANCE
            ],
            maturity_level="stable",
            reference_implementation="https://github.com/NTRUOpenSSL/ntru",
            notes="Round 4 candidate, good for constrained environments"
        )

        # Hybrid modes
        self.algorithms["Hybrid-X25519-Kyber-768"] = PQAlgorithm(
            name="Hybrid-X25519-Kyber-768",
            category=AlgorithmCategory.HYBRID,
            nist_standardized=False,
            security_level=SecurityLevel.LEVEL_3,
            public_key_size=1216,
            secret_key_size=2432,
            ciphertext_size=1120,
            signature_size=0,
            performance_score=7.0,
            memory_footprint=128,
            cpu_intensity=5.5,
            supported_use_cases=[
                UseCaseType.TLS_HANDSHAKE,
                UseCaseType.VPN_TUNNEL,
                UseCaseType.API_AUTHENTICATION
            ],
            maturity_level="stable",
            reference_implementation="Cloudflare, Google TLS experiments",
            notes="Hybrid classical + PQ, TLS 1.3 compatible"
        )

        self.algorithms["Hybrid-ECDSA-Dilithium-3"] = PQAlgorithm(
            name="Hybrid-ECDSA-Dilithium-3",
            category=AlgorithmCategory.HYBRID,
            nist_standardized=False,
            security_level=SecurityLevel.LEVEL_3,
            public_key_size=2016,
            secret_key_size=4032,
            ciphertext_size=0,
            signature_size=3357,
            performance_score=5.5,
            memory_footprint=144,
            cpu_intensity=7.0,
            supported_use_cases=[
                UseCaseType.TLS_HANDSHAKE,
                UseCaseType.EMAIL_ENCRYPTION,
                UseCaseType.HIGH_SECURITY
            ],
            maturity_level="stable",
            reference_implementation="IETF hybrid signature drafts",
            notes="Hybrid classical + PQ signatures"
        )

    def get_algorithm(self, name: str) -> Optional[PQAlgorithm]:
        return self.algorithms.get(name)

    def list_algorithms(self, category: Optional[AlgorithmCategory] = None) -> List[PQAlgorithm]:
        if category:
            return [a for a in self.algorithms.values() if a.category == category]
        return list(self.algorithms.values())

    def get_by_security_level(self, level: SecurityLevel) -> List[PQAlgorithm]:
        return [a for a in self.algorithms.values() if a.security_level == level]

    def get_for_use_case(self, use_case: UseCaseType) -> List[PQAlgorithm]:
        return [a for a in self.algorithms.values() if use_case in a.supported_use_cases]


class PQBenchmarkEngine:
    """Benchmarking engine for Post-Quantum algorithms"""

    def __init__(self, registry: PQAlgorithmRegistry):
        self.registry = registry
        self.benchmark_history: List[BenchmarkResult] = []

    def _simulate_key_generation(self, algorithm: PQAlgorithm, iterations: int) -> Tuple[float, float]:
        """Simulate key generation performance"""
        start = time.perf_counter()

        # Simulate computation based on algorithm characteristics
        complexity_factor = algorithm.cpu_intensity * algorithm.security_level.value / 10
        memory_factor = algorithm.memory_footprint / 1000

        for _ in range(iterations):
            # Simulate cryptographic operations
            dummy_data = os.urandom(algorithm.public_key_size // 4)
            hashed = hashlib.sha512(dummy_data).digest()
            # Additional operations proportional to complexity
            for _ in range(int(complexity_factor * 10)):
                hashed = hashlib.sha512(hashed + dummy_data).digest()

        elapsed = (time.perf_counter() - start) * 1000  # ms
        memory_est = memory_factor * 1024 * iterations / 100  # simulated KB

        return elapsed, memory_est

    def _simulate_encapsulation(self, algorithm: PQAlgorithm, iterations: int) -> Tuple[float, float]:
        """Simulate encapsulation performance"""
        start = time.perf_counter()
        complexity_factor = algorithm.cpu_intensity * 0.8

        for _ in range(iterations):
            dummy_data = os.urandom(algorithm.ciphertext_size // 4)
            hashed = hashlib.sha256(dummy_data).digest()
            for _ in range(int(complexity_factor * 8)):
                hashed = hashlib.sha256(hashed).digest()

        elapsed = (time.perf_counter() - start) * 1000
        return elapsed, algorithm.memory_footprint * 0.8

    def _simulate_decapsulation(self, algorithm: PQAlgorithm, iterations: int) -> Tuple[float, float]:
        """Simulate decapsulation performance"""
        start = time.perf_counter()
        complexity_factor = algorithm.cpu_intensity * 1.2

        for _ in range(iterations):
            dummy_data = os.urandom(algorithm.secret_key_size // 8)
            hashed = hashlib.sha256(dummy_data).digest()
            for _ in range(int(complexity_factor * 10)):
                hashed = hashlib.sha256(hashed).digest()

        elapsed = (time.perf_counter() - start) * 1000
        return elapsed, algorithm.memory_footprint * 1.2

    def benchmark_algorithm(
        self,
        algorithm_name: str,
        iterations: int = 1000
    ) -> Dict[str, BenchmarkResult]:
        """Run full benchmark suite for an algorithm"""
        algorithm = self.registry.get_algorithm(algorithm_name)
        if not algorithm:
            raise ValueError(f"Algorithm {algorithm_name} not found")

        results = {}

        # Key Generation benchmark
        kg_time, kg_mem = self._simulate_key_generation(algorithm, iterations)
        results["key_generation"] = BenchmarkResult(
            algorithm_name=algorithm_name,
            operation="key_generation",
            iterations=iterations,
            total_time_ms=kg_time,
            avg_time_us=(kg_time / iterations) * 1000,
            ops_per_second=iterations / (kg_time / 1000),
            memory_peak_kb=kg_mem,
            cpu_usage_percent=algorithm.cpu_intensity * 10
        )

        if algorithm.category in (AlgorithmCategory.KEM, AlgorithmCategory.HYBRID):
            # Encapsulation
            enc_time, enc_mem = self._simulate_encapsulation(algorithm, iterations)
            results["encapsulation"] = BenchmarkResult(
                algorithm_name=algorithm_name,
                operation="encapsulation",
                iterations=iterations,
                total_time_ms=enc_time,
                avg_time_us=(enc_time / iterations) * 1000,
                ops_per_second=iterations / (enc_time / 1000),
                memory_peak_kb=enc_mem,
                cpu_usage_percent=algorithm.cpu_intensity * 8
            )

            # Decapsulation
            dec_time, dec_mem = self._simulate_decapsulation(algorithm, iterations)
            results["decapsulation"] = BenchmarkResult(
                algorithm_name=algorithm_name,
                operation="decapsulation",
                iterations=iterations,
                total_time_ms=dec_time,
                avg_time_us=(dec_time / iterations) * 1000,
                ops_per_second=iterations / (dec_time / 1000),
                memory_peak_kb=dec_mem,
                cpu_usage_percent=algorithm.cpu_intensity * 12
            )

        self.benchmark_history.extend(results.values())
        return results

    def compare_algorithms(
        self,
        algorithm_names: List[str],
        iterations: int = 500
    ) -> Dict[str, Any]:
        """Compare multiple algorithms side by side"""
        comparison = {
            "algorithms": algorithm_names,
            "iterations": iterations,
            "results": {},
            "summary": {}
        }

        all_ops = {}

        for name in algorithm_names:
            benchmarks = self.benchmark_algorithm(name, iterations)
            comparison["results"][name] = {k: v.to_dict() for k, v in benchmarks.items()}

            # Calculate composite score
            total_ops = sum(b.ops_per_second for b in benchmarks.values())
            all_ops[name] = total_ops

        # Rank by performance
        ranked = sorted(all_ops.items(), key=lambda x: x[1], reverse=True)
        comparison["summary"]["performance_ranking"] = [
            {"algorithm": name, "composite_ops": score} for name, score in ranked
        ]

        return comparison

    def get_benchmark_history(self) -> List[Dict[str, Any]]:
        return [b.to_dict() for b in self.benchmark_history]


class PQAlgorithmSelector:
    """Intelligent algorithm selection based on requirements"""

    def __init__(self, registry: PQAlgorithmRegistry, benchmark_engine: PQBenchmarkEngine):
        self.registry = registry
        self.benchmark_engine = benchmark_engine

    def recommend_for_use_case(
        self,
        use_case: UseCaseType,
        min_security_level: SecurityLevel = SecurityLevel.LEVEL_1,
        prefer_hybrid: bool = False,
        performance_weight: float = 0.4,
        security_weight: float = 0.4,
        compatibility_weight: float = 0.2
    ) -> AlgorithmRecommendation:
        """
        Recommend best algorithm for a use case with weighted scoring
        """
        candidates = self.registry.get_for_use_case(use_case)

        # Filter by security level
        candidates = [
            c for c in candidates
            if c.security_level.value >= min_security_level.value
        ]

        if prefer_hybrid:
            hybrid_candidates = [c for c in candidates if c.category == AlgorithmCategory.HYBRID]
            if hybrid_candidates:
                candidates = hybrid_candidates

        if not candidates:
            raise ValueError(f"No algorithms match requirements for {use_case.value}")

        # Score each candidate
        scores = {}
        for algo in candidates:
            perf_score = algo.performance_score * performance_weight
            sec_score = algo.security_level.value * 2 * security_weight
            compat_score = 10 if algo.nist_standardized else 5
            compat_score *= compatibility_weight

            total = perf_score + sec_score + compat_score
            scores[algo.name] = total

        # Sort by score
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        primary = ranked[0][0]
        alternatives = [name for name, _ in ranked[1:3]]

        # Generate assessments
        primary_algo = self.registry.get_algorithm(primary)

        security_assessment = (
            f"NIST Security Level {primary_algo.security_level.value}, "
            f"{'standardized' if primary_algo.nist_standardized else 'candidate'}"
        )

        perf_rating = "excellent" if primary_algo.performance_score >= 8 else \
                      "good" if primary_algo.performance_score >= 6 else "moderate"
        performance_assessment = f"{perf_rating} performance ({primary_algo.performance_score}/10)"

        hybrid_rec = None
        if not prefer_hybrid and primary_algo.category != AlgorithmCategory.HYBRID:
            hybrid_rec = "Consider Hybrid-X25519-Kyber-768 for migration compatibility"

        return AlgorithmRecommendation(
            primary_algorithm=primary,
            alternative_algorithms=alternatives,
            hybrid_recommendation=hybrid_rec,
            match_score=ranked[0][1] / (performance_weight + security_weight + compatibility_weight) / 10,
            security_assessment=security_assessment,
            performance_assessment=performance_assessment,
            compatibility_notes=f"Maturity: {primary_algo.maturity_level}",
            migration_complexity="low" if primary_algo.nist_standardized else "medium"
        )

    def generate_comparison_report(
        self,
        use_cases: List[UseCaseType],
        output_format: str = "json"
    ) -> Any:
        """Generate comprehensive comparison report"""
        report = {
            "generated_at": time.time(),
            "use_cases_analyzed": [uc.value for uc in use_cases],
            "recommendations": {}
        }

        for uc in use_cases:
            rec = self.recommend_for_use_case(uc)
            report["recommendations"][uc.value] = rec.to_dict()

        if output_format == "json":
            return json.dumps(report, indent=2)
        return report
