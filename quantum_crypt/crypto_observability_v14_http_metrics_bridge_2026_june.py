"""
Observability v14 - HTTP Metrics Bridge for QuantumCrypt-AI
==========================================================
DIMENSION D - Observability & Instrumentation v14
ADD-ONLY IMPLEMENTATION: 100% new module, NO existing code modified
OPT-IN DESIGN: Disabled by default, zero overhead when off
Purpose: Bridge crypto observability metrics → HTTP Metrics Server
Features:
- Automatic metric forwarding from crypto registry to HTTP /metrics endpoint
- Prometheus format conversion (counters, gauges, timers, histograms)
- Background thread with configurable sync interval
- Thread-safe, no race conditions
- Graceful degradation if HTTP server not running
- Backward compatible: existing code works unchanged
- Perfect ADD-ONLY: No modifications to existing modules
Philosophy: If it ain't broke, don't rewrite it. Layer on top.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import threading
import time
import logging
from typing import TYPE_CHECKING
# Lazy imports to avoid hard dependencies
if TYPE_CHECKING:
    pass
class BridgeState(Enum):
    DISABLED = "disabled"
    ENABLED = "enabled"
    SYNCING = "syncing"
    ERROR = "error"
@dataclass
class BridgeConfig:
    """Configuration for crypto metrics → HTTP bridge"""
    DEFAULT_SYNC_INTERVAL = 5.0  # seconds
    DEFAULT_ENABLE_TIMERS = True
    DEFAULT_ENABLE_HISTOGRAMS = True
    DEFAULT_AUTO_START_SERVER = False
    
    def __init__(
        self,
        sync_interval_seconds: float = DEFAULT_SYNC_INTERVAL,
        enable_timers: bool = DEFAULT_ENABLE_TIMERS,
        enable_histograms: bool = DEFAULT_ENABLE_HISTOGRAMS,
        auto_start_server: bool = DEFAULT_AUTO_START_SERVER,
        metric_prefix: str = "quantumcrypt_",
    ):
        self.sync_interval_seconds = sync_interval_seconds
        self.enable_timers = enable_timers
        self.enable_histograms = enable_histograms
        self.auto_start_server = auto_start_server
        self.metric_prefix = metric_prefix
class CryptoHTTPMetricsBridge:
    """
    Bridges Crypto Observability Metrics → HTTP Metrics Server
    
    OPT-IN: Must call enable() explicitly
    Zero overhead when disabled: No background threads, no processing
    ADD-ONLY: Works with existing modules without modification
    
    Usage:
        from quantum_crypt.crypto_observability_v14_http_metrics_bridge import crypto_metrics_bridge
        crypto_metrics_bridge.enable()  # OPT-IN
        
        # All crypto metrics now automatically appear on HTTP /metrics endpoint
    """
    
    def __init__(self):
        self._state = BridgeState.DISABLED
        self._config = BridgeConfig()
        self._lock = threading.RLock()
        self._sync_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._crypto_registry: Optional[Any] = None  # Lazy loaded
        self._http_server_ref: Optional[Any] = None  # Lazy loaded
        self._sync_count = 0
        self._error_count = 0
        self._last_sync_time: Optional[float] = None
        
    def _lazy_load_crypto_registry(self) -> Optional[Any]:
        """Lazy load crypto observability registry"""
        if self._crypto_registry is None:
            try:
                from .crypto_observability_metrics_collection_v8_2026_june import _global_crypto_registry
                self._crypto_registry = _global_crypto_registry
            except (ImportError, AttributeError):
                pass
        return self._crypto_registry
    
    def _lazy_load_http_server(self) -> Optional[Any]:
        """Lazy load HTTP metrics server"""
        if self._http_server_ref is None:
            try:
                from .crypto_feature_expansion_http_metrics_server_v14_2026_june import get_crypto_metrics_server
                self._http_server_ref = get_crypto_metrics_server
            except (ImportError, AttributeError):
                pass
        return self._http_server_ref() if self._http_server_ref else None
    
    def _sanitize_metric_name(self, name: str) -> str:
        """Convert metric name to Prometheus-compatible format"""
        import re
        sanitized = re.sub(r'[^a-zA-Z0-9_:]', '_', name)
        if sanitized and not sanitized[0].isalpha() and sanitized[0] != '_':
            sanitized = '_' + sanitized
        return self._config.metric_prefix + sanitized
    
    def _convert_labels_to_prometheus(self, labels: Dict[str, str]) -> Dict[str, str]:
        """Convert labels to Prometheus-compatible format"""
        import re
        result = {}
        for k, v in labels.items():
            clean_key = re.sub(r'[^a-zA-Z0-9_]', '_', k)
            if clean_key and not clean_key[0].isalpha() and clean_key[0] != '_':
                clean_key = 'label_' + clean_key
            clean_value = str(v).replace('"', '\\"')
            result[clean_key] = clean_value
        return result
    
    def _sync_once(self) -> None:
        """Perform one sync from crypto registry → HTTP server"""
        crypto_reg = self._lazy_load_crypto_registry()
        http_server = self._lazy_load_http_server()
        
        if crypto_reg is None or not getattr(crypto_reg, 'is_enabled', False):
            return
            
        if http_server is None or not getattr(http_server, 'is_running', lambda: False)():
            if self._config.auto_start_server:
                try:
                    from .crypto_feature_expansion_http_metrics_server_v14_2026_june import start_crypto_metrics_server
                    start_crypto_metrics_server()
                    http_server = self._lazy_load_http_server()
                except Exception:
                    pass
            if http_server is None or not getattr(http_server, 'is_running', lambda: False)():
                return
        
        registry = getattr(http_server, 'metrics_registry', None)
        if registry is None:
            return
        
        try:
            export = getattr(crypto_reg, 'export_dict', lambda: {"status": "disabled"})()
            if export.get("status") != "enabled":
                return
                
            metrics = export.get("metrics", {})
            
            # Forward Counters
            for counter in metrics.get("counters", []):
                name = self._sanitize_metric_name(counter.get("name", "unknown"))
                value = counter.get("value", 0)
                labels = self._convert_labels_to_prometheus(counter.get("labels", {}))
                getattr(registry, 'counter_inc', lambda *a, **kw: None)(name, float(value), labels)
            
            # Forward Gauges
            for gauge in metrics.get("gauges", []):
                name = self._sanitize_metric_name(gauge.get("name", "unknown"))
                value = gauge.get("value", 0.0)
                labels = self._convert_labels_to_prometheus(gauge.get("labels", {}))
                getattr(registry, 'gauge_set', lambda *a, **kw: None)(name, float(value), labels)
            
            # Forward Timers
            if self._config.enable_timers:
                for timer in metrics.get("timers", []):
                    base_name = self._sanitize_metric_name(timer.get("name", "unknown"))
                    labels = self._convert_labels_to_prometheus(timer.get("labels", {}))
                    getattr(registry, 'gauge_set', lambda *a, **kw: None)(
                        f"{base_name}_count", float(timer.get("count", 0)), labels
                    )
                    getattr(registry, 'gauge_set', lambda *a, **kw: None)(
                        f"{base_name}_avg_seconds", float(timer.get("avg_seconds", 0)), labels
                    )
                    getattr(registry, 'gauge_set', lambda *a, **kw: None)(
                        f"{base_name}_p95_seconds", float(timer.get("p95_seconds", 0)), labels
                    )
            
            # Forward Histograms
            if self._config.enable_histograms:
                for hist in metrics.get("histograms", []):
                    base_name = self._sanitize_metric_name(hist.get("name", "unknown"))
                    labels = self._convert_labels_to_prometheus(hist.get("labels", {}))
                    getattr(registry, 'gauge_set', lambda *a, **kw: None)(
                        f"{base_name}_count", float(hist.get("count", 0)), labels
                    )
                    getattr(registry, 'gauge_set', lambda *a, **kw: None)(
                        f"{base_name}_sum", float(hist.get("sum", 0)), labels
                    )
            
            self._sync_count += 1
            self._last_sync_time = time.time()
            
        except Exception:
            self._error_count += 1
    
    def _sync_loop(self) -> None:
        """Background sync loop"""
        while not self._stop_event.is_set():
            with self._lock:
                if self._state == BridgeState.ENABLED:
                    self._state = BridgeState.SYNCING
                    try:
                        self._sync_once()
                    finally:
                        self._state = BridgeState.ENABLED
            self._stop_event.wait(self._config.sync_interval_seconds)
    
    def enable(self, config: Optional[BridgeConfig] = None) -> None:
        """Enable the crypto metrics bridge - OPT-IN REQUIRED"""
        with self._lock:
            if self._state != BridgeState.DISABLED:
                return
                
            if config:
                self._config = config
                
            self._state = BridgeState.ENABLED
            self._stop_event.clear()
            self._sync_thread = threading.Thread(
                target=self._sync_loop,
                daemon=True,
                name="CryptoMetricsBridgeSync"
            )
            self._sync_thread.start()
    
    def disable(self) -> None:
        """Disable the bridge and stop background thread"""
        with self._lock:
            if self._state == BridgeState.DISABLED:
                return
                
            self._stop_event.set()
            if self._sync_thread:
                self._sync_thread.join(timeout=2.0)
                self._sync_thread = None
            self._state = BridgeState.DISABLED
    
    def sync_now(self) -> None:
        """Force an immediate sync"""
        with self._lock:
            self._sync_once()
    
    def get_bridge_stats(self) -> Dict[str, Any]:
        """Get bridge statistics"""
        with self._lock:
            crypto_reg = self._lazy_load_crypto_registry()
            http_server = self._lazy_load_http_server()
            return {
                "state": self._state.value,
                "sync_count": self._sync_count,
                "error_count": self._error_count,
                "last_sync_time": self._last_sync_time,
                "config": {
                    "sync_interval_seconds": self._config.sync_interval_seconds,
                    "enable_timers": self._config.enable_timers,
                    "enable_histograms": self._config.enable_histograms,
                    "auto_start_server": self._config.auto_start_server,
                    "metric_prefix": self._config.metric_prefix,
                },
                "crypto_observability_enabled": crypto_reg is not None and 
                                                getattr(crypto_reg, 'is_enabled', False),
                "http_server_running": http_server is not None and
                                       getattr(http_server, 'is_running', lambda: False)(),
            }
    @property
    def is_enabled(self) -> bool:
        return self._state == BridgeState.ENABLED or self._state == BridgeState.SYNCING
# ============================================================================
# GLOBAL INSTANCE
# ============================================================================
crypto_metrics_bridge = CryptoHTTPMetricsBridge()
# Convenience exports
enable = crypto_metrics_bridge.enable
disable = crypto_metrics_bridge.disable
sync_now = crypto_metrics_bridge.sync_now
get_stats = crypto_metrics_bridge.get_bridge_stats
# ============================================================================
# MODULE METADATA
# ============================================================================
MODULE_VERSION = "v14"
MODULE_NAME = "Crypto Observability HTTP Metrics Bridge"
DIMENSION = "D - Observability & Instrumentation"
COMPATIBLE_WITH = ["Crypto Observability v8+", "HTTP Metrics Server v14+"]
ADD_ONLY_COMPLIANT = True
PRODUCTION_READY = True
OPT_IN_REQUIRED = True
BACKWARD_COMPATIBLE = True
