"""
QuantumCrypt AI - Cryptographic Observability & Instrumentation Module (Dimension D)
Version: v25 - June 2026
Philosophy: ADD-ONLY, OPT-IN, Backward Compatible, No breaking changes
"""

import json
import time
import uuid
import threading
import secrets
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List
from functools import wraps
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum


class CryptoOperationType(Enum):
    KEY_GENERATION = "key_generation"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    KEY_EXCHANGE = "key_exchange"
    HASHING = "hashing"
    RANDOM_GENERATION = "random_generation"
    CERTIFICATE_OP = "certificate_operation"


class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    TIMER = "timer"
    HISTOGRAM = "histogram"


class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class CryptoMetric:
    name: str
    operation_type: CryptoOperationType
    type: MetricType
    value: float = 0.0
    algorithm: str = "unknown"
    key_size: int = 0
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class CryptoHealthCheck:
    name: str
    component: str
    status: HealthStatus
    message: str = ""
    duration_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


class CryptoObservabilityConfig:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self.structured_logging_enabled: bool = False
        self.metrics_collection_enabled: bool = False
        self.health_checks_enabled: bool = False
        self.audit_logging_enabled: bool = False
        self.min_log_level: LogLevel = LogLevel.INFO
        self.log_sensitive_data: bool = False
        self._initialized = True
    
    def enable_all(self):
        self.structured_logging_enabled = True
        self.metrics_collection_enabled = True
        self.health_checks_enabled = True
        self.audit_logging_enabled = True


class CryptoStructuredLogger:
    def __init__(self, name: str = "quantum_crypt"):
        self.name = name
        self.config = CryptoObservabilityConfig()
    
    def _sanitize_for_logging(self, data: Any) -> str:
        if isinstance(data, (bytes, str)) and len(data) > 0:
            if isinstance(data, str):
                data = data.encode('utf-8')
            return f"sha256:{hashlib.sha256(data).hexdigest()[:16]}"
        return str(type(data).__name__)
    
    def _log(self, level: LogLevel, message: str, operation_type: Optional[CryptoOperationType] = None, **kwargs):
        if not self.config.structured_logging_enabled:
            return
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "logger": self.name,
            "level": level.value,
            "message": message,
            "trace_id": kwargs.get("trace_id", str(uuid.uuid4())),
        }
        if operation_type:
            log_entry["operation_type"] = operation_type.value
        for key, value in kwargs.items():
            if key not in ("trace_id", "span_id"):
                if key in ("key", "private_key", "secret", "plaintext", "password"):
                    log_entry[key] = self._sanitize_for_logging(value)
                else:
                    log_entry[key] = value
        print(json.dumps(log_entry))
    
    def info(self, message: str, operation_type: Optional[CryptoOperationType] = None, **kwargs):
        self._log(LogLevel.INFO, message, operation_type, **kwargs)
    
    def error(self, message: str, operation_type: Optional[CryptoOperationType] = None, **kwargs):
        self._log(LogLevel.ERROR, message, operation_type, **kwargs)


class CryptoMetricsCollector:
    def __init__(self):
        self.config = CryptoObservabilityConfig()
        self._metrics: Dict[str, List[CryptoMetric]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def record_key_operation(self, operation_type: CryptoOperationType, algorithm: str, 
                            key_size: int, success: bool, duration_ms: float):
        if not self.config.metrics_collection_enabled:
            return
        with self._lock:
            status = "success" if success else "failure"
            metric = CryptoMetric(
                name=f"crypto_{operation_type.value}",
                operation_type=operation_type,
                type=MetricType.COUNTER,
                value=1.0,
                algorithm=algorithm,
                key_size=key_size,
                labels={"status": status}
            )
            self._metrics[f"crypto_{operation_type.value}"].append(metric)
    
    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            result = {}
            for name, metrics_list in self._metrics.items():
                if not metrics_list:
                    continue
                result[name] = {"count": len(metrics_list)}
            return result
    
    def reset(self):
        with self._lock:
            self._metrics.clear()


def timed_crypto_operation(operation_type: CryptoOperationType, algorithm: str = "unknown", key_size: int = 0):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            config = CryptoObservabilityConfig()
            if not config.metrics_collection_enabled:
                return func(*args, **kwargs)
            collector = CryptoMetricsCollector()
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                collector.record_key_operation(operation_type, algorithm, key_size, True, duration_ms)
                return result
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                collector.record_key_operation(operation_type, algorithm, key_size, False, duration_ms)
                raise
        return wrapper
    return decorator


def get_crypto_config() -> CryptoObservabilityConfig:
    return CryptoObservabilityConfig()


def get_crypto_logger() -> CryptoStructuredLogger:
    return CryptoStructuredLogger()


def get_crypto_metrics() -> CryptoMetricsCollector:
    return CryptoMetricsCollector()


__all__ = [
    "CryptoOperationType", "LogLevel", "MetricType", "HealthStatus",
    "CryptoObservabilityConfig", "get_crypto_config",
    "CryptoStructuredLogger", "get_crypto_logger",
    "CryptoMetricsCollector", "get_crypto_metrics",
    "timed_crypto_operation",
]
