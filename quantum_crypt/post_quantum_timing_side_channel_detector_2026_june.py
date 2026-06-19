"""
Post-Quantum Cryptography Timing Side-Channel Attack Detector
Production-grade implementation for QuantumCrypt-AI

This module provides:
1. Execution timing measurement and analysis
2. Timing variance statistical detection
3. Constant-time operation verification
4. Side-channel vulnerability assessment
5. Real-time timing anomaly detection
"""

import time
import math
import statistics
import hashlib
import secrets
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass
from collections import defaultdict
from enum import Enum
import threading


class VulnerabilityLevel(Enum):
    """Side-channel vulnerability severity levels"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TimingTestType(Enum):
    """Types of timing analysis tests"""
    CONSTANT_TIME_VERIFICATION = "constant_time"
    INPUT_DEPENDENCE_ANALYSIS = "input_dependence"
    SECRET_LEAKAGE_DETECTION = "secret_leakage"
    BRANCH_PREDICTION_ANALYSIS = "branch_prediction"


@dataclass
class TimingMeasurement:
    """Single timing measurement result"""
    operation_id: str
    input_pattern: str
    execution_time_ns: int
    cpu_cycles: Optional[int] = None
    memory_accesses: Optional[int] = None
    timestamp: float = 0.0


@dataclass
class TimingAnalysisResult:
    """Complete timing analysis result"""
    test_type: str
    operation_name: str
    vulnerability_level: VulnerabilityLevel
    mean_time_ns: float
    std_dev_ns: float
    variance_ns: float
    min_time_ns: int
    max_time_ns: int
    coefficient_of_variation: float
    timing_leakage_score: float
    input_correlation: float
    recommendations: List[str]
    measurements_count: int
    test_timestamp: float


class HighPrecisionTimer:
    """High-precision timer for cryptographic operation timing"""
    
    @staticmethod
    def measure_ns(func: Callable, *args, **kwargs) -> Tuple[int, Any]:
        """Measure function execution time in nanoseconds"""
        start = time.perf_counter_ns()
        result = func(*args, **kwargs)
        end = time.perf_counter_ns()
        return (end - start, result)
    
    @staticmethod
    def measure_multiple(
        func: Callable,
        iterations: int,
        *args,
        **kwargs
    ) -> List[int]:
        """Measure multiple executions and return timing list"""
        timings = []
        for _ in range(iterations):
            t, _ = HighPrecisionTimer.measure_ns(func, *args, **kwargs)
            timings.append(t)
        return timings


class StatisticalAnalyzer:
    """Statistical analysis for timing side-channel detection"""
    
    @staticmethod
    def calculate_statistics(timings: List[int]) -> Dict[str, float]:
        """Calculate comprehensive timing statistics"""
        if not timings:
            return {}
        
        n = len(timings)
        mean = statistics.mean(timings)
        variance = statistics.variance(timings) if n > 1 else 0
        std_dev = math.sqrt(variance) if variance > 0 else 0
        cv = (std_dev / mean) * 100 if mean > 0 else 0
        
        return {
            'mean': mean,
            'variance': variance,
            'std_dev': std_dev,
            'min': min(timings),
            'max': max(timings),
            'range': max(timings) - min(timings),
            'cv_percent': cv,
            'median': statistics.median(timings),
            'count': n
        }
    
    @staticmethod
    def welch_t_test(
        timings_a: List[int],
        timings_b: List[int]
    ) -> Tuple[float, float]:
        """
        Welch's t-test for comparing two timing distributions
        Returns: (t-statistic, p-value approximation)
        """
        if len(timings_a) < 2 or len(timings_b) < 2:
            return (0.0, 1.0)
        
        mean_a = statistics.mean(timings_a)
        mean_b = statistics.mean(timings_b)
        var_a = statistics.variance(timings_a)
        var_b = statistics.variance(timings_b)
        n_a = len(timings_a)
        n_b = len(timings_b)
        
        # T-statistic
        denom = math.sqrt(var_a / n_a + var_b / n_b)
        if denom == 0:
            return (0.0, 1.0)
        
        t_stat = abs(mean_a - mean_b) / denom
        
        # Simplified p-value approximation (for large n)
        # Using error function approximation
        p_value = math.erfc(t_stat / math.sqrt(2)) / 2
        
        return (t_stat, p_value)
    
    @staticmethod
    def detect_outliers(timings: List[int], threshold: float = 3.0) -> List[int]:
        """Detect timing outliers using Z-score"""
        if len(timings) < 3:
            return []
        
        mean = statistics.mean(timings)
        std = statistics.stdev(timings) if len(timings) > 1 else 0
        
        if std == 0:
            return []
        
        outliers = []
        for t in timings:
            z_score = abs(t - mean) / std
            if z_score > threshold:
                outliers.append(t)
        
        return outliers


class TimingSideChannelDetector:
    """
    Production-grade timing side-channel attack detector
    
    Features:
    - High-precision timing measurement
    - Statistical variance analysis
    - Input-dependent timing detection
    - Constant-time operation verification
    - Secret leakage assessment
    """
    
    def __init__(
        self,
        significance_threshold: float = 0.01,
        cv_warning_threshold: float = 5.0,
        min_iterations: int = 100,
        warmup_iterations: int = 10
    ):
        self.significance_threshold = significance_threshold
        self.cv_warning_threshold = cv_warning_threshold
        self.min_iterations = min_iterations
        self.warmup_iterations = warmup_iterations
        
        self._baseline_timings: Dict[str, List[int]] = defaultdict(list)
        self._lock = threading.RLock()
        self._test_history: List[TimingAnalysisResult] = []
    
    def _warmup(self, func: Callable, *args, **kwargs) -> None:
        """Warm up function to eliminate JIT/cache effects"""
        for _ in range(self.warmup_iterations):
            try:
                func(*args, **kwargs)
            except:
                pass
    
    def establish_baseline(
        self,
        operation_name: str,
        func: Callable,
        iterations: int = 1000,
        *args,
        **kwargs
    ) -> Dict[str, float]:
        """Establish timing baseline for an operation"""
        with self._lock:
            self._warmup(func, *args, **kwargs)
            timings = HighPrecisionTimer.measure_multiple(
                func, iterations, *args, **kwargs
            )
            stats = StatisticalAnalyzer.calculate_statistics(timings)
            self._baseline_timings[operation_name] = timings
            return stats
    
    def test_constant_time(
        self,
        operation_name: str,
        func: Callable,
        test_inputs: List[Any],
        iterations_per_input: int = 200
    ) -> TimingAnalysisResult:
        """
        Test if operation executes in constant time regardless of input
        
        This is the core test for timing side-channel vulnerabilities
        """
        all_timings: List[int] = []
        input_timing_groups: Dict[str, List[int]] = {}
        
        # Warmup
        if test_inputs:
            self._warmup(func, test_inputs[0])
        
        # Measure each input pattern
        for i, test_input in enumerate(test_inputs):
            input_id = f"input_{i}"
            timings = HighPrecisionTimer.measure_multiple(
                func, iterations_per_input, test_input
            )
            input_timing_groups[input_id] = timings
            all_timings.extend(timings)
        
        # Calculate overall statistics
        stats = StatisticalAnalyzer.calculate_statistics(all_timings)
        
        # Compare timing distributions between inputs
        max_t_stat = 0.0
        min_p_value = 1.0
        input_names = list(input_timing_groups.keys())
        
        for i in range(len(input_names)):
            for j in range(i + 1, len(input_names)):
                t_stat, p_val = StatisticalAnalyzer.welch_t_test(
                    input_timing_groups[input_names[i]],
                    input_timing_groups[input_names[j]]
                )
                max_t_stat = max(max_t_stat, t_stat)
                min_p_value = min(min_p_value, p_val)
        
        # Calculate leakage score (0-1, higher = more vulnerable)
        cv = stats.get('cv_percent', 0)
        timing_range = stats.get('range', 0)
        
        # Leakage score based on multiple factors
        leakage_score = 0.0
        if cv > self.cv_warning_threshold:
            leakage_score += min(0.3, cv / 100)
        if min_p_value < self.significance_threshold:
            leakage_score += 0.4
        if timing_range > stats.get('mean', 1) * 0.1:  # >10% range
            leakage_score += 0.3
        
        # Determine vulnerability level
        if leakage_score < 0.1:
            vuln_level = VulnerabilityLevel.SAFE
        elif leakage_score < 0.3:
            vuln_level = VulnerabilityLevel.LOW
        elif leakage_score < 0.5:
            vuln_level = VulnerabilityLevel.MEDIUM
        elif leakage_score < 0.7:
            vuln_level = VulnerabilityLevel.HIGH
        else:
            vuln_level = VulnerabilityLevel.CRITICAL
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            vuln_level, leakage_score, cv, min_p_value
        )
        
        result = TimingAnalysisResult(
            test_type=TimingTestType.CONSTANT_TIME_VERIFICATION.value,
            operation_name=operation_name,
            vulnerability_level=vuln_level,
            mean_time_ns=stats.get('mean', 0),
            std_dev_ns=stats.get('std_dev', 0),
            variance_ns=stats.get('variance', 0),
            min_time_ns=int(stats.get('min', 0)),
            max_time_ns=int(stats.get('max', 0)),
            coefficient_of_variation=cv,
            timing_leakage_score=round(leakage_score, 4),
            input_correlation=max_t_stat,
            recommendations=recommendations,
            measurements_count=len(all_timings),
            test_timestamp=time.time()
        )
        
        with self._lock:
            self._test_history.append(result)
        
        return result
    
    def test_secret_dependent_timing(
        self,
        operation_name: str,
        func: Callable,
        secret_generator: Callable[[], Any],
        public_input: Any,
        iterations: int = 500
    ) -> TimingAnalysisResult:
        """Test if timing correlates with secret values"""
        timings_by_secret: Dict[str, List[int]] = defaultdict(list)
        
        # Warmup
        self._warmup(func, public_input, secret_generator())
        
        # Collect timings for different secrets
        for _ in range(iterations):
            secret = secret_generator()
            secret_hash = hashlib.md5(str(secret).encode()).hexdigest()[:8]
            timing, _ = HighPrecisionTimer.measure_ns(
                func, public_input, secret
            )
            timings_by_secret[secret_hash].append(timing)
        
        all_timings = []
        for timings in timings_by_secret.values():
            all_timings.extend(timings)
        
        stats = StatisticalAnalyzer.calculate_statistics(all_timings)
        
        # Analyze variance between secret groups
        secret_groups = list(timings_by_secret.values())
        max_t_stat = 0.0
        min_p_value = 1.0
        
        for i in range(len(secret_groups)):
            for j in range(i + 1, len(secret_groups)):
                t_stat, p_val = StatisticalAnalyzer.welch_t_test(
                    secret_groups[i], secret_groups[j]
                )
                max_t_stat = max(max_t_stat, t_stat)
                min_p_value = min(min_p_value, p_val)
        
        cv = stats.get('cv_percent', 0)
        leakage_score = 0.0
        
        if min_p_value < self.significance_threshold:
            leakage_score += 0.5
        if cv > self.cv_warning_threshold:
            leakage_score += 0.3
        if max_t_stat > 3.0:
            leakage_score += 0.2
        
        # Vulnerability level
        if leakage_score < 0.1:
            vuln_level = VulnerabilityLevel.SAFE
        elif leakage_score < 0.3:
            vuln_level = VulnerabilityLevel.LOW
        elif leakage_score < 0.5:
            vuln_level = VulnerabilityLevel.MEDIUM
        elif leakage_score < 0.7:
            vuln_level = VulnerabilityLevel.HIGH
        else:
            vuln_level = VulnerabilityLevel.CRITICAL
        
        recommendations = self._generate_recommendations(
            vuln_level, leakage_score, cv, min_p_value
        )
        
        result = TimingAnalysisResult(
            test_type=TimingTestType.SECRET_LEAKAGE_DETECTION.value,
            operation_name=operation_name,
            vulnerability_level=vuln_level,
            mean_time_ns=stats.get('mean', 0),
            std_dev_ns=stats.get('std_dev', 0),
            variance_ns=stats.get('variance', 0),
            min_time_ns=int(stats.get('min', 0)),
            max_time_ns=int(stats.get('max', 0)),
            coefficient_of_variation=cv,
            timing_leakage_score=round(leakage_score, 4),
            input_correlation=max_t_stat,
            recommendations=recommendations,
            measurements_count=len(all_timings),
            test_timestamp=time.time()
        )
        
        with self._lock:
            self._test_history.append(result)
        
        return result
    
    def _generate_recommendations(
        self,
        vuln_level: VulnerabilityLevel,
        leakage_score: float,
        cv: float,
        p_value: float
    ) -> List[str]:
        """Generate security recommendations based on test results"""
        recommendations = []
        
        if vuln_level in (VulnerabilityLevel.HIGH, VulnerabilityLevel.CRITICAL):
            recommendations.append("CRITICAL: Significant timing side-channel detected!")
            recommendations.append("Immediate code audit recommended for constant-time compliance")
        
        if vuln_level == VulnerabilityLevel.MEDIUM:
            recommendations.append("WARNING: Moderate timing variance detected")
            recommendations.append("Review conditional branches for secret-dependent execution")
        
        if vuln_level == VulnerabilityLevel.LOW:
            recommendations.append("Minor timing variations detected - monitor for changes")
        
        if cv > self.cv_warning_threshold:
            recommendations.append(f"High coefficient of variation ({cv:.2f}%) indicates inconsistent timing")
        
        if p_value < self.significance_threshold:
            recommendations.append("Statistically significant timing differences between inputs detected")
        
        if vuln_level == VulnerabilityLevel.SAFE:
            recommendations.append("Operation appears constant-time - no significant leakage detected")
        
        recommendations.append("Consider implementing formal constant-time verification")
        recommendations.append("Run tests under different CPU load conditions for validation")
        
        return recommendations
    
    def get_test_history(self) -> List[TimingAnalysisResult]:
        """Get historical test results"""
        with self._lock:
            return list(self._test_history)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get detector summary statistics"""
        with self._lock:
            if not self._test_history:
                return {'tests_run': 0}
            
            vuln_counts = defaultdict(int)
            for result in self._test_history:
                vuln_counts[result.vulnerability_level.value] += 1
            
            return {
                'tests_run': len(self._test_history),
                'vulnerability_distribution': dict(vuln_counts),
                'baseline_operations': len(self._baseline_timings)
            }


# Helper functions for cryptographic testing
def generate_test_byte_patterns(length: int = 32) -> List[bytes]:
    """Generate diverse byte patterns for timing tests"""
    patterns = [
        b'\x00' * length,                    # All zeros
        b'\xff' * length,                    # All ones
        secrets.token_bytes(length),         # Random
        b'\x01\x00' * (length // 2),         # Alternating
        b'\xaa' * length,                    # Repeating pattern
    ]
    return patterns


def timing_safe_compare(a: bytes, b: bytes) -> bool:
    """Constant-time bytes comparison (reference implementation)"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def timing_unsafe_compare(a: bytes, b: bytes) -> bool:
    """Timing-unsafe comparison (early exit - for testing purposes)"""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True
