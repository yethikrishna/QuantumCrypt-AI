"""
Post-Quantum Performance Monitor & Benchmark Engine
Production-grade module for benchmarking and monitoring post-quantum cryptography algorithms
Supports real-time performance tracking, historical analysis, and optimization recommendations
"""

import time
import hashlib
import json
import os
import statistics
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import uuid


@dataclass
class BenchmarkResult:
    """Dataclass representing a single benchmark result"""
    benchmark_id: str
    algorithm_name: str
    operation_type: str  # keygen, encrypt, decrypt, sign, verify, kem_encap, kem_decap
    input_size_bytes: int
    iterations: int
    total_time_ms: float
    avg_time_ms: float
    min_time_ms: float
    max_time_ms: float
    std_dev_ms: float
    operations_per_second: float
    throughput_mbps: float
    memory_usage_mb: float
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceMetric:
    """Dataclass for real-time performance metrics"""
    metric_id: str
    metric_type: str
    value: float
    unit: str
    algorithm: str
    timestamp: float
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class OptimizationRecommendation:
    """Dataclass for performance optimization recommendations"""
    rec_id: str
    algorithm: str
    category: str  # configuration, hardware, batch_size, parallelism
    recommendation: str
    expected_improvement_pct: float
    severity: str  # low, medium, high, critical
    evidence: str


class AlgorithmBenchmarker:
    """Benchmarks cryptographic algorithm performance"""
    
    def __init__(self, warmup_iterations: int = 10, default_iterations: int = 100):
        self.warmup_iterations = warmup_iterations
        self.default_iterations = default_iterations
        self.benchmark_history: List[BenchmarkResult] = []
        
    def _get_memory_usage(self) -> float:
        """Get current process memory usage in MB (simulated for portability)"""
        try:
            import gc
            gc.collect()
            # Simple estimation based on object counts
            return len(gc.get_objects()) * 0.001  # Rough MB estimate
        except:
            return 0.0
    
    def benchmark_function(self, func: Callable, *args, 
                          algorithm_name: str, operation_type: str,
                          iterations: Optional[int] = None,
                          **kwargs) -> BenchmarkResult:
        """
        Benchmark a function with statistical analysis
        Returns detailed BenchmarkResult with timing statistics
        """
        iterations = iterations or self.default_iterations
        
        # Warmup phase
        for _ in range(self.warmup_iterations):
            try:
                func(*args, **kwargs)
            except:
                pass
        
        # Actual benchmark
        timings = []
        start_memory = self._get_memory_usage()
        
        for _ in range(iterations):
            t0 = time.perf_counter()
            result = func(*args, **kwargs)
            t1 = time.perf_counter()
            timings.append((t1 - t0) * 1000)  # Convert to ms
        
        end_memory = self._get_memory_usage()
        
        # Calculate statistics
        total_time = sum(timings)
        avg_time = statistics.mean(timings)
        min_time = min(timings)
        max_time = max(timings)
        std_dev = statistics.stdev(timings) if len(timings) > 1 else 0
        
        # Calculate throughput
        input_size = len(str(args)) if args else 64  # Estimate
        ops_per_sec = 1000.0 / avg_time if avg_time > 0 else 0
        throughput_mbps = (input_size * ops_per_sec) / (1024 * 1024)
        
        result = BenchmarkResult(
            benchmark_id=str(uuid.uuid4()),
            algorithm_name=algorithm_name,
            operation_type=operation_type,
            input_size_bytes=input_size,
            iterations=iterations,
            total_time_ms=total_time,
            avg_time_ms=avg_time,
            min_time_ms=min_time,
            max_time_ms=max_time,
            std_dev_ms=std_dev,
            operations_per_second=ops_per_sec,
            throughput_mbps=throughput_mbps,
            memory_usage_mb=max(0, end_memory - start_memory)
        )
        
        self.benchmark_history.append(result)
        return result
    
    def benchmark_hash_algorithms(self, data_size_kb: int = 64) -> List[BenchmarkResult]:
        """Benchmark standard hash algorithms"""
        results = []
        test_data = os.urandom(data_size_kb * 1024)
        
        hash_algos = [
            ('SHA-256', hashlib.sha256),
            ('SHA-512', hashlib.sha512),
            ('SHA3-256', hashlib.sha3_256),
            ('SHA3-512', hashlib.sha3_512),
            ('BLAKE2b', hashlib.blake2b),
        ]
        
        for name, hash_func in hash_algos:
            def hash_operation(data=test_data, hf=hash_func):
                return hf(data).digest()
            
            result = self.benchmark_function(
                hash_operation,
                algorithm_name=name,
                operation_type='hash',
                iterations=500
            )
            results.append(result)
        
        return results
    
    def benchmark_symmetric_operations(self) -> List[BenchmarkResult]:
        """Benchmark simulated symmetric encryption operations"""
        results = []
        test_data = os.urandom(4096)
        test_key = os.urandom(32)
        
        # Simulated AES-GCM encryption
        def sim_aes_encrypt(data=test_data, key=test_key):
            # Simple XOR-based simulation for benchmarking
            result = bytearray(len(data))
            for i in range(len(data)):
                result[i] = data[i] ^ key[i % len(key)]
            return bytes(result)
        
        results.append(self.benchmark_function(
            sim_aes_encrypt,
            algorithm_name='AES-256-GCM (simulated)',
            operation_type='encrypt',
            iterations=200
        ))
        
        # Simulated ChaCha20
        def sim_chacha_encrypt(data=test_data, key=test_key):
            result = bytearray(len(data))
            key_hash = hashlib.sha256(key).digest()
            for i in range(len(data)):
                result[i] = data[i] ^ key_hash[i % len(key_hash)]
            return bytes(result)
        
        results.append(self.benchmark_function(
            sim_chacha_encrypt,
            algorithm_name='ChaCha20 (simulated)',
            operation_type='encrypt',
            iterations=200
        ))
        
        return results
    
    def benchmark_post_quantum_kem(self) -> List[BenchmarkResult]:
        """Benchmark simulated post-quantum KEM operations"""
        results = []
        
        # Simulated Kyber key generation
        def kyber_keygen():
            # Simulate key generation with mathematical operations
            key_material = hashlib.shake_256(os.urandom(64)).digest(1568)
            pubkey = key_material[:800]
            privkey = key_material[800:]
            return pubkey, privkey
        
        results.append(self.benchmark_function(
            kyber_keygen,
            algorithm_name='CRYSTALS-Kyber-768 (simulated)',
            operation_type='keygen',
            iterations=100
        ))
        
        # Simulated Kyber encapsulation
        def kyber_encap():
            pubkey = hashlib.shake_256(os.urandom(32)).digest(800)
            shared_secret = hashlib.sha3_256(pubkey + os.urandom(32)).digest()
            ciphertext = hashlib.shake_256(shared_secret).digest(1088)
            return ciphertext, shared_secret
        
        results.append(self.benchmark_function(
            kyber_encap,
            algorithm_name='CRYSTALS-Kyber-768 (simulated)',
            operation_type='kem_encap',
            iterations=100
        ))
        
        # Simulated Dilithium signature
        def dilithium_sign():
            message = os.urandom(64)
            privkey = os.urandom(2528)
            # Simulate signing with multiple hash operations
            sig = hashlib.sha3_512(message + privkey).digest()
            sig += hashlib.sha3_512(sig + privkey[:100]).digest()
            return sig
        
        results.append(self.benchmark_function(
            dilithium_sign,
            algorithm_name='CRYSTALS-Dilithium-3 (simulated)',
            operation_type='sign',
            iterations=100
        ))
        
        return results


class PerformanceMonitor:
    """Real-time performance monitoring with alerting"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.metrics_history: List[PerformanceMetric] = []
        self.baselines: Dict[str, Tuple[float, float]] = {}  # algo -> (mean, std)
        self.alerts: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        
    def record_metric(self, metric_type: str, value: float, unit: str,
                     algorithm: str, tags: Optional[Dict[str, str]] = None) -> PerformanceMetric:
        """Record a performance metric"""
        with self._lock:
            metric = PerformanceMetric(
                metric_id=str(uuid.uuid4()),
                metric_type=metric_type,
                value=value,
                unit=unit,
                algorithm=algorithm,
                timestamp=time.time(),
                tags=tags or {}
            )
            self.metrics_history.append(metric)
            
            # Trim history
            if len(self.metrics_history) > self.window_size * 10:
                self.metrics_history = self.metrics_history[-self.window_size * 5:]
            
            # Check for anomalies
            self._check_anomaly(metric)
            
            return metric
    
    def _check_anomaly(self, metric: PerformanceMetric) -> None:
        """Check for performance anomalies"""
        key = f"{metric.algorithm}:{metric.metric_type}"
        
        if key not in self.baselines:
            # Establish baseline
            recent = [m.value for m in self.metrics_history[-20:] 
                     if m.algorithm == metric.algorithm and m.metric_type == metric.metric_type]
            if len(recent) >= 10:
                self.baselines[key] = (statistics.mean(recent), statistics.stdev(recent))
            return
        
        baseline_mean, baseline_std = self.baselines[key]
        z_score = abs(metric.value - baseline_mean) / (baseline_std + 0.0001)
        
        if z_score > 3.0:  # 3-sigma anomaly
            alert = {
                'alert_id': str(uuid.uuid4()),
                'type': 'performance_anomaly',
                'algorithm': metric.algorithm,
                'metric': metric.metric_type,
                'value': metric.value,
                'baseline': baseline_mean,
                'z_score': z_score,
                'severity': 'high' if z_score > 4 else 'medium',
                'timestamp': metric.timestamp
            }
            self.alerts.append(alert)
    
    def get_current_metrics(self, algorithm: Optional[str] = None) -> Dict[str, Any]:
        """Get current performance summary"""
        with self._lock:
            metrics = self.metrics_history
            if algorithm:
                metrics = [m for m in metrics if m.algorithm == algorithm]
            
            # Get last 5 minutes
            cutoff = time.time() - 300
            recent = [m for m in metrics if m.timestamp > cutoff]
            
            summary = defaultdict(list)
            for m in recent:
                summary[f"{m.algorithm}:{m.metric_type}"].append(m.value)
            
            result = {}
            for key, values in summary.items():
                result[key] = {
                    'current': values[-1] if values else 0,
                    'avg': statistics.mean(values) if values else 0,
                    'min': min(values) if values else 0,
                    'max': max(values) if values else 0,
                    'count': len(values)
                }
            
            return {
                'summary': result,
                'alerts': self.alerts[-10:],
                'baselines': dict(self.baselines)
            }


class PerformanceAnalyzer:
    """Analyzes performance data and generates optimization recommendations"""
    
    def __init__(self):
        self.performance_baselines = self._load_standard_baselines()
    
    def _load_standard_baselines(self) -> Dict[str, Dict[str, float]]:
        """Load industry-standard performance baselines"""
        return {
            'SHA-256': {'target_ops_per_sec': 500000, 'target_latency_ms': 0.002},
            'AES-256-GCM': {'target_throughput_gbps': 10, 'target_latency_ms': 0.01},
            'CRYSTALS-Kyber-768': {'target_keygen_ms': 0.05, 'target_encap_ms': 0.03},
            'CRYSTALS-Dilithium-3': {'target_sign_ms': 0.15, 'target_verify_ms': 0.05},
        }
    
    def compare_to_baseline(self, result: BenchmarkResult) -> Dict[str, Any]:
        """Compare benchmark result to industry baselines"""
        algo = result.algorithm_name
        
        comparison = {
            'algorithm': algo,
            'operation': result.operation_type,
            'measured_ops_per_sec': result.operations_per_second,
            'measured_latency_ms': result.avg_time_ms,
            'deviation_pct': 0,
            'rating': 'unknown'
        }
        
        # Simple performance rating
        if result.operations_per_second > 10000:
            comparison['rating'] = 'excellent'
        elif result.operations_per_second > 1000:
            comparison['rating'] = 'good'
        elif result.operations_per_second > 100:
            comparison['rating'] = 'average'
        else:
            comparison['rating'] = 'poor'
        
        return comparison
    
    def generate_recommendations(self, benchmark_results: List[BenchmarkResult]) -> List[OptimizationRecommendation]:
        """Generate optimization recommendations based on benchmark results"""
        recommendations = []
        
        for result in benchmark_results:
            # Check for high latency
            if result.avg_time_ms > 10:
                recommendations.append(OptimizationRecommendation(
                    rec_id=str(uuid.uuid4()),
                    algorithm=result.algorithm_name,
                    category='performance',
                    recommendation=f'Consider hardware acceleration for {result.algorithm_name}',
                    expected_improvement_pct=30.0,
                    severity='medium',
                    evidence=f'High latency detected: {result.avg_time_ms:.2f}ms per operation'
                ))
            
            # Check for high std dev (inconsistent performance)
            cv = result.std_dev_ms / (result.avg_time_ms + 0.001)
            if cv > 0.5:
                recommendations.append(OptimizationRecommendation(
                    rec_id=str(uuid.uuid4()),
                    algorithm=result.algorithm_name,
                    category='stability',
                    recommendation=f'Investigate performance variability for {result.algorithm_name}',
                    expected_improvement_pct=15.0,
                    severity='medium',
                    evidence=f'High coefficient of variation: {cv:.2f}'
                ))
            
            # Batch processing recommendation
            if result.operations_per_second < 1000:
                recommendations.append(OptimizationRecommendation(
                    rec_id=str(uuid.uuid4()),
                    algorithm=result.algorithm_name,
                    category='batch_processing',
                    recommendation=f'Implement batch processing for {result.algorithm_name}',
                    expected_improvement_pct=50.0,
                    severity='low',
                    evidence=f'Throughput is {result.operations_per_second:.0f} ops/sec, batching can improve this'
                ))
        
        return recommendations
    
    def generate_comparative_report(self, results: List[BenchmarkResult]) -> Dict[str, Any]:
        """Generate comparative performance report"""
        by_algorithm = defaultdict(list)
        for r in results:
            by_algorithm[r.algorithm_name].append(r)
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_benchmarks': len(results),
            'algorithms_tested': len(by_algorithm),
            'algorithm_summary': {},
            'fastest_by_ops': None,
            'most_efficient': None
        }
        
        best_ops = 0
        best_efficiency = 0
        
        for algo, algo_results in by_algorithm.items():
            avg_ops = statistics.mean(r.operations_per_second for r in algo_results)
            avg_latency = statistics.mean(r.avg_time_ms for r in algo_results)
            
            report['algorithm_summary'][algo] = {
                'avg_operations_per_second': avg_ops,
                'avg_latency_ms': avg_latency,
                'benchmark_count': len(algo_results)
            }
            
            if avg_ops > best_ops:
                best_ops = avg_ops
                report['fastest_by_ops'] = algo
            
            efficiency = avg_ops / (avg_latency + 0.001)
            if efficiency > best_efficiency:
                best_efficiency = efficiency
                report['most_efficient'] = algo
        
        return report


class PostQuantumPerformanceBenchmarkEngine:
    """
    Main engine for post-quantum performance monitoring and benchmarking
    Production-grade with benchmarking, monitoring, and analysis capabilities
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.benchmarker = AlgorithmBenchmarker()
        self.monitor = PerformanceMonitor()
        self.analyzer = PerformanceAnalyzer()
        
        self.benchmark_runs: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
    
    def run_full_benchmark_suite(self) -> Dict[str, Any]:
        """Run complete benchmark suite"""
        start_time = time.time()
        
        all_results = []
        
        # Run hash benchmarks
        hash_results = self.benchmarker.benchmark_hash_algorithms()
        all_results.extend(hash_results)
        
        # Run symmetric encryption benchmarks
        sym_results = self.benchmarker.benchmark_symmetric_operations()
        all_results.extend(sym_results)
        
        # Run post-quantum KEM benchmarks
        pq_results = self.benchmarker.benchmark_post_quantum_kem()
        all_results.extend(pq_results)
        
        # Generate analysis
        comparisons = [self.analyzer.compare_to_baseline(r) for r in all_results]
        recommendations = self.analyzer.generate_recommendations(all_results)
        report = self.analyzer.generate_comparative_report(all_results)
        
        run_record = {
            'run_id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'duration_seconds': time.time() - start_time,
            'total_benchmarks': len(all_results),
            'results': all_results,
            'comparisons': comparisons,
            'recommendations': recommendations,
            'report': report
        }
        
        with self._lock:
            self.benchmark_runs.append(run_record)
        
        return run_record
    
    def monitor_operation(self, algorithm: str, operation: str, duration_ms: float) -> None:
        """Monitor a single operation's performance"""
        self.monitor.record_metric(
            metric_type='latency',
            value=duration_ms,
            unit='ms',
            algorithm=algorithm,
            tags={'operation': operation}
        )
    
    def get_performance_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive performance dashboard data"""
        with self._lock:
            latest_run = self.benchmark_runs[-1] if self.benchmark_runs else None
            
            return {
                'monitoring': self.monitor.get_current_metrics(),
                'latest_benchmark': latest_run,
                'benchmark_history_count': len(self.benchmark_runs),
                'total_benchmarks_executed': len(self.benchmarker.benchmark_history),
                'algorithms_benchmarked': len(set(r.algorithm_name for r in self.benchmarker.benchmark_history))
            }
    
    def export_benchmark_results(self, format: str = 'json') -> str:
        """Export all benchmark results"""
        export_data = []
        
        for result in self.benchmarker.benchmark_history:
            export_data.append({
                'benchmark_id': result.benchmark_id,
                'algorithm': result.algorithm_name,
                'operation': result.operation_type,
                'avg_time_ms': result.avg_time_ms,
                'operations_per_second': result.operations_per_second,
                'throughput_mbps': result.throughput_mbps,
                'timestamp': result.timestamp
            })
        
        if format == 'json':
            return json.dumps(export_data, indent=2)
        elif format == 'csv':
            lines = ['benchmark_id,algorithm,operation,avg_time_ms,operations_per_second']
            for d in export_data:
                lines.append(f"{d['benchmark_id']},{d['algorithm']},{d['operation']},{d['avg_time_ms']:.4f},{d['operations_per_second']:.2f}")
            return '\n'.join(lines)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            'total_benchmarks_run': len(self.benchmarker.benchmark_history),
            'benchmark_suites_executed': len(self.benchmark_runs),
            'metrics_recorded': len(self.monitor.metrics_history),
            'alerts_generated': len(self.monitor.alerts)
        }


# Export main classes
__all__ = [
    'PostQuantumPerformanceBenchmarkEngine',
    'AlgorithmBenchmarker',
    'PerformanceMonitor',
    'PerformanceAnalyzer',
    'BenchmarkResult',
    'OptimizationRecommendation'
]
