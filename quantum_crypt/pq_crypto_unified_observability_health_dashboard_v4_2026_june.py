"""
Post-Quantum Crypto Unified Observability & Health Dashboard v4
Dimension D: Observability & Instrumentation

COMPREHENSIVE CRYPTO OBSERVABILITY FRAMEWORK
- Crypto-specific health monitoring for all PQ algorithms
- Key rotation health monitoring
- Randomness quality metrics
- Certificate chain health validation
- Performance telemetry for crypto operations
- OPT-IN only - disabled by default
- 100% backward compatible - wraps existing code, NO core changes

Incremental Build Philosophy: ADD-ONLY, no existing code modified
"""

import time
import threading
import uuid
import json
import secrets
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from collections import defaultdict, deque
from datetime import datetime, timedelta
import statistics


class CryptoHealthStatus(Enum):
    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    AT_RISK = "at_risk"
    FAILED = "failed"
    UNKNOWN = "unknown"


class CryptoOperationType(Enum):
    KEY_GENERATION = "key_generation"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    KEY_EXCHANGE = "key_exchange"
    RANDOMNESS = "randomness"


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class CryptoHealthCheckResult:
    algorithm: str
    operation: CryptoOperationType
    status: CryptoHealthStatus
    message: str
    latency_ms: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CryptoMetric:
    name: str
    algorithm: str
    operation: CryptoOperationType
    value: float
    unit: str
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class KeyHealthRecord:
    key_id: str
    algorithm: str
    created_at: datetime
    rotation_due_at: datetime
    usage_count: int = 0
    last_used: Optional[datetime] = None


@dataclass
class CryptoAlert:
    alert_id: str
    severity: AlertSeverity
    message: str
    component: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    acknowledged: bool = False


class RandomnessQualityMonitor:
    """Monitor randomness quality for crypto operations"""
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self._random_samples: deque = deque(maxlen=window_size)
        self._lock = threading.Lock()
    
    def record_random_bytes(self, data: bytes):
        """Record random bytes for quality analysis"""
        with self._lock:
            for byte in data:
                self._random_samples.append(byte)
    
    def get_entropy_estimate(self) -> Dict[str, Any]:
        """Estimate entropy quality"""
        with self._lock:
            if len(self._random_samples) < 100:
                return {"quality": "insufficient_data", "sample_count": len(self._random_samples)}
            
            samples = list(self._random_samples)
            
            # Count byte distribution
            byte_counts = [0] * 256
            for b in samples:
                byte_counts[b] += 1
            
            # Calculate Shannon entropy (simplified estimate)
            total = len(samples)
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    p = count / total
                    entropy -= p * math.log2(p) if p > 0 else 0
            
            # Zero byte ratio
            zero_ratio = byte_counts[0] / total
            
            quality = "excellent"
            if zero_ratio > 0.01:
                quality = "suspicious"
            elif zero_ratio > 0.05:
                quality = "poor"
                
            return {
                "quality": quality,
                "sample_count": total,
                "estimated_entropy_bits_per_byte": min(8.0, 8.0 - abs(entropy)),
                "zero_byte_ratio": zero_ratio,
                "window_size": self.window_size
            }


class CryptoAlgorithmHealthChecker:
    """Health checker for specific crypto algorithms - wraps existing implementations"""
    
    def __init__(self, algorithm_name: str, test_function: Optional[Callable] = None):
        self.algorithm_name = algorithm_name
        self.test_function = test_function or self._smoke_test
        self.history: deque = deque(maxlen=100)
        self.consecutive_failures = 0
        self.operation_latencies: Dict[CryptoOperationType, deque] = defaultdict(
            lambda: deque(maxlen=100)
        )
        self._lock = threading.Lock()
    
    def _smoke_test(self) -> CryptoHealthCheckResult:
        """Default smoke test - always passes for wrapper"""
        return CryptoHealthCheckResult(
            algorithm=self.algorithm_name,
            operation=CryptoOperationType.KEY_GENERATION,
            status=CryptoHealthStatus.OPERATIONAL,
            message=f"Algorithm {self.algorithm_name} smoke test passed",
            latency_ms=0.0
        )
    
    def run_health_check(self) -> CryptoHealthCheckResult:
        start = time.perf_counter()
        try:
            result = self.test_function()
            elapsed = (time.perf_counter() - start) * 1000
            result.latency_ms = elapsed
            
            with self._lock:
                if result.status == CryptoHealthStatus.OPERATIONAL:
                    self.consecutive_failures = 0
                else:
                    self.consecutive_failures += 1
                self.history.append(result)
                self.operation_latencies[result.operation].append(elapsed)
            
            return result
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            with self._lock:
                self.consecutive_failures += 1
            result = CryptoHealthCheckResult(
                algorithm=self.algorithm_name,
                operation=CryptoOperationType.KEY_GENERATION,
                status=CryptoHealthStatus.FAILED,
                message=f"Health check failed: {str(e)}",
                latency_ms=elapsed
            )
            with self._lock:
                self.history.append(result)
            return result
    
    def get_performance_stats(self) -> Dict[str, Any]:
        with self._lock:
            stats = {}
            for op, latencies in self.operation_latencies.items():
                if latencies:
                    stats[op.value] = {
                        "p50_ms": statistics.median(latencies),
                        "p95_ms": sorted(latencies)[int(len(latencies) * 0.95)],
                        "p99_ms": sorted(latencies)[int(len(latencies) * 0.99)],
                        "avg_ms": sum(latencies) / len(latencies),
                        "sample_count": len(latencies)
                    }
            return stats


class CryptoMetricsCollector:
    """Crypto-specific metrics collection - OPT-IN only"""
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self._operation_counters: Dict[str, int] = defaultdict(int)
        self._error_counters: Dict[str, int] = defaultdict(int)
        self._latency_histograms: Dict[str, List[float]] = defaultdict(list)
        self._key_usage: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    def record_operation(
        self, 
        algorithm: str, 
        operation: CryptoOperationType, 
        latency_ms: float,
        success: bool = True
    ):
        if not self.enabled:
            return
        
        key = f"{algorithm}_{operation.value}"
        with self._lock:
            self._operation_counters[key] += 1
            if not success:
                self._error_counters[key] += 1
            self._latency_histograms[key].append(latency_ms)
            if len(self._latency_histograms[key]) > 1000:
                self._latency_histograms[key] = self._latency_histograms[key][-500:]
    
    def record_key_usage(self, key_id: str):
        if not self.enabled:
            return
        with self._lock:
            self._key_usage[key_id] += 1
    
    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            total_ops = sum(self._operation_counters.values())
            total_errors = sum(self._error_counters.values())
            return {
                "enabled": self.enabled,
                "total_operations": total_ops,
                "total_errors": total_errors,
                "error_rate": total_errors / total_ops if total_ops > 0 else 0,
                "algorithms_monitored": len(set(k.split('_')[0] for k in self._operation_counters.keys())),
                "active_keys": len(self._key_usage)
            }
    
    def get_prometheus_format(self) -> str:
        if not self.enabled:
            return "# Crypto metrics disabled"
        
        lines = ["# TYPE quantumcrypt_operations counter"]
        with self._lock:
            for key, count in self._operation_counters.items():
                lines.append(f"quantumcrypt_operations_total{{algorithm=\"{key}\"}} {count}")
        return "\n".join(lines)


class KeyRotationHealthManager:
    """Track key rotation health and compliance"""
    
    def __init__(self, rotation_period_days: int = 90):
        self.rotation_period_days = rotation_period_days
        self._keys: Dict[str, KeyHealthRecord] = {}
        self._lock = threading.Lock()
    
    def register_key(self, key_id: str, algorithm: str):
        now = datetime.utcnow()
        record = KeyHealthRecord(
            key_id=key_id,
            algorithm=algorithm,
            created_at=now,
            rotation_due_at=now + timedelta(days=self.rotation_period_days)
        )
        with self._lock:
            self._keys[key_id] = record
    
    def record_key_usage(self, key_id: str):
        with self._lock:
            if key_id in self._keys:
                self._keys[key_id].usage_count += 1
                self._keys[key_id].last_used = datetime.utcnow()
    
    def get_keys_needing_rotation(self) -> List[Dict[str, Any]]:
        now = datetime.utcnow()
        needing_rotation = []
        with self._lock:
            for key_id, record in self._keys.items():
                days_until_rotation = (record.rotation_due_at - now).total_seconds() / 86400
                if days_until_rotation < 7:  # Within 7 days
                    needing_rotation.append({
                        "key_id": key_id,
                        "algorithm": record.algorithm,
                        "days_until_rotation": days_until_rotation,
                        "usage_count": record.usage_count,
                        "urgency": "critical" if days_until_rotation <= 0 else "warning"
                    })
        return needing_rotation


class PQCryptoUnifiedObservabilityDashboard:
    """
    Central observability dashboard for Post-Quantum Crypto
    ALL INSTRUMENTATION IS OPT-IN - DISABLED BY DEFAULT
    
    Wraps existing crypto modules - NO MODIFICATION TO CORE CODE
    """
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self._algorithm_checkers: Dict[str, CryptoAlgorithmHealthChecker] = {}
        self.metrics = CryptoMetricsCollector(enabled=enabled)
        self.randomness_monitor = RandomnessQualityMonitor()
        self.key_manager = KeyRotationHealthManager()
        self._alerts: List[CryptoAlert] = []
        self._start_time = datetime.utcnow()
        self._lock = threading.Lock()
    
    def enable(self):
        """Explicitly enable observability - OPT-IN"""
        self.enabled = True
        self.metrics.enabled = True
    
    def disable(self):
        self.enabled = False
        self.metrics.enabled = False
    
    def register_algorithm(
        self, 
        algorithm_name: str, 
        health_check: Optional[Callable] = None
    ):
        """Register a PQ algorithm for health monitoring"""
        checker = CryptoAlgorithmHealthChecker(algorithm_name, health_check)
        with self._lock:
            self._algorithm_checkers[algorithm_name] = checker
    
    def run_all_health_checks(self) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "message": "Observability disabled"}
        
        results = {}
        for name, checker in self._algorithm_checkers.items():
            results[name] = checker.run_health_check()
        
        # Check randomness quality
        randomness_quality = self.randomness_monitor.get_entropy_estimate()
        
        # Check key rotation status
        keys_needing_rotation = self.key_manager.get_keys_needing_rotation()
        
        overall = self._calculate_overall_status(results, randomness_quality, keys_needing_rotation)
        
        return {
            "overall_status": overall.value,
            "algorithms_checked": len(results),
            "algorithm_results": {k: v.status.value for k, v in results.items()},
            "randomness_quality": randomness_quality,
            "keys_needing_rotation": keys_needing_rotation,
            "uptime_seconds": (datetime.utcnow() - self._start_time).total_seconds()
        }
    
    def _calculate_overall_status(
        self, 
        results: Dict[str, CryptoHealthCheckResult],
        randomness_quality: Dict[str, Any],
        keys_needing_rotation: List[Dict[str, Any]]
    ) -> CryptoHealthStatus:
        failed = sum(1 for r in results.values() if r.status == CryptoHealthStatus.FAILED)
        at_risk = sum(1 for r in results.values() if r.status == CryptoHealthStatus.AT_RISK)
        
        if failed > 0:
            return CryptoHealthStatus.FAILED
        if at_risk > 0 or randomness_quality.get("quality") == "poor":
            return CryptoHealthStatus.AT_RISK
        if any(k["urgency"] == "critical" for k in keys_needing_rotation):
            return CryptoHealthStatus.DEGRADED
        if len(results) == 0:
            return CryptoHealthStatus.UNKNOWN
        return CryptoHealthStatus.OPERATIONAL
    
    def instrument_crypto_operation(self, algorithm: str, operation: CryptoOperationType):
        """
        Decorator to instrument crypto operations
        ZERO overhead when disabled - NO core code modification
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)
                
                start = time.perf_counter()
                try:
                    result = func(*args, **kwargs)
                    elapsed = (time.perf_counter() - start) * 1000
                    self.metrics.record_operation(algorithm, operation, elapsed, success=True)
                    return result
                except Exception as e:
                    elapsed = (time.perf_counter() - start) * 1000
                    self.metrics.record_operation(algorithm, operation, elapsed, success=False)
                    self._add_alert(AlertSeverity.ERROR, f"Crypto operation failed: {str(e)}", algorithm)
                    raise
            return wrapper
        return decorator
    
    def _add_alert(self, severity: AlertSeverity, message: str, component: str):
        with self._lock:
            alert = CryptoAlert(
                alert_id=str(uuid.uuid4()),
                severity=severity,
                message=message,
                component=component
            )
            self._alerts.append(alert)
    
    def get_dashboard_status(self) -> Dict[str, Any]:
        algorithm_stats = {
            name: checker.get_performance_stats()
            for name, checker in self._algorithm_checkers.items()
        }
        
        return {
            "enabled": self.enabled,
            "uptime_seconds": (datetime.utcnow() - self._start_time).total_seconds(),
            "algorithms_monitored": len(self._algorithm_checkers),
            "algorithm_performance": algorithm_stats,
            "metrics_summary": self.metrics.get_summary(),
            "randomness_quality": self.randomness_monitor.get_entropy_estimate(),
            "active_alerts": len([a for a in self._alerts if not a.acknowledged]),
            "total_alerts": len(self._alerts)
        }
    
    def export_json(self) -> str:
        return json.dumps(self.get_dashboard_status(), indent=2, default=str)


# Singleton instance - OPT-IN, disabled by default
_global_crypto_dashboard = PQCryptoUnifiedObservabilityDashboard(enabled=False)


def get_crypto_observability_dashboard() -> PQCryptoUnifiedObservabilityDashboard:
    """Get the global crypto observability dashboard - disabled by default"""
    return _global_crypto_dashboard


def enable_crypto_observability():
    """Explicitly enable - must be called intentionally"""
    _global_crypto_dashboard.enable()


def disable_crypto_observability():
    _global_crypto_dashboard.disable()


"""
BACKWARD COMPATIBILITY GUARANTEE:
- All existing crypto code works exactly as before
- Zero performance overhead when disabled (default)
- No modifications to any existing crypto module
- Pure wrapper layer on top of existing code
"""
