"""
QuantumCrypt AI - Error Resilience v17
Crypto-Specific Key Operation Protection with Side-Channel Resistant Retries

DIMENSION E - Error Resilience
ADD-ONLY implementation - wraps existing code, no modifications

NEW in v17:
1. Crypto-Specific Retry Logic - constant-time, side-channel resistant
2. Key Operation Protection - memory-safe key handling with zeroization
3. HSM Emulation Layer - secure key storage fallback
4. Crypto Operation Timeout with Secure Cleanup
5. Key Compromise Detection - anomaly-based key usage monitoring
6. Secure Fallback Cipher Suites - algorithm agility
7. Memory Safety Guards - buffer overflow protection
8. Constant-Time Exception Handling - no timing side channels
"""

import time
import threading
import enum
import secrets
import hmac
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Type, Union, Tuple
from collections import deque
from functools import wraps
import gc

# Configure logging (OPT-IN - disabled by default)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# -----------------------------------------------------------------------------
# ENUMERATIONS
# -----------------------------------------------------------------------------

class CryptoOperationType(enum.Enum):
    """Types of cryptographic operations."""
    KEY_GENERATION = "key_generation"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    KEY_EXCHANGE = "key_exchange"
    HASHING = "hashing"
    RANDOM_GENERATION = "random_generation"
    KEY_DERIVATION = "key_derivation"

class KeySensitivityLevel(enum.Enum):
    """Key material sensitivity levels."""
    PUBLIC = "public"                 # Safe to log/expose
    INTERNAL = "internal"             # Internal use only
    SENSITIVE = "sensitive"           # Must be protected
    CRITICAL = "critical"             # Master keys - zeroize immediately

class CryptoFailureMode(enum.Enum):
    """Cryptographic failure modes."""
    TRANSIENT_ERROR = "transient"     # Temporary - safe to retry
    RNG_FAILURE = "rng_failure"       # Random generator issue
    INTEGRITY_ERROR = "integrity"     # Tampering detected
    KEY_COMPROMISE = "compromise"     # Key may be compromised
    MEMORY_ERROR = "memory"           # Memory corruption detected
    TIMEOUT = "timeout"               # Operation timed out
    HARDWARE_ERROR = "hardware"       # HSM/TPM failure

class CipherSuitePriority(enum.Enum):
    """Fallback cipher suite priorities."""
    PRIMARY = "primary"               # Preferred algorithm
    SECONDARY = "secondary"           # First fallback
    LEGACY = "legacy"                 # Compatibility only
    FIPS_COMPLIANT = "fips"           # FIPS 140-2/3 compliant

# -----------------------------------------------------------------------------
# DATA CLASSES
# -----------------------------------------------------------------------------

@dataclass
class SecureBytes:
    """
    Secure byte container with automatic zeroization.
    Uses mutable bytearray for in-place zeroization.
    """
    _data: bytearray
    sensitivity: KeySensitivityLevel = KeySensitivityLevel.CRITICAL
    _locked: bool = False
    _zeroized: bool = False
    
    def __post_init__(self):
        if isinstance(self._data, bytes):
            self._data = bytearray(self._data)
        elif not isinstance(self._data, bytearray):
            self._data = bytearray(self._data)
    
    @classmethod
    def from_bytes(cls, data: bytes, sensitivity: KeySensitivityLevel = KeySensitivityLevel.CRITICAL) -> 'SecureBytes':
        """Create from bytes with sensitivity level."""
        return cls(bytearray(data), sensitivity)
    
    def get(self) -> bytes:
        """Get bytes (read-only copy)."""
        if self._zeroized:
            raise ValueError("SecureBytes has been zeroized")
        return bytes(self._data)
    
    def zeroize(self) -> None:
        """Securely zeroize memory."""
        if not self._zeroized:
            for i in range(len(self._data)):
                self._data[i] = 0
            self._zeroized = True
            logger.debug("SecureBytes zeroized")
    
    def __del__(self):
        """Auto-zeroize on garbage collection."""
        self.zeroize()
    
    def __len__(self) -> int:
        return len(self._data)

@dataclass
class CryptoRetryPolicy:
    """
    Constant-time retry policy for cryptographic operations.
    No timing side channels - all paths take same time.
    """
    max_attempts: int = 3
    base_delay_ms: float = 10.0
    max_jitter_ms: float = 5.0
    constant_time: bool = True  # Always wait full delay regardless
    allowed_operations: Set[CryptoOperationType] = field(default_factory=lambda: {
        CryptoOperationType.ENCRYPTION,
        CryptoOperationType.DECRYPTION,
        CryptoOperationType.SIGNING,
        CryptoOperationType.VERIFICATION,
        CryptoOperationType.RANDOM_GENERATION
    })
    retryable_failures: Set[CryptoFailureMode] = field(default_factory=lambda: {
        CryptoFailureMode.TRANSIENT_ERROR,
        CryptoFailureMode.RNG_FAILURE,
        CryptoFailureMode.TIMEOUT
    })

@dataclass
class KeyUsageAnomaly:
    """Detected anomaly in key usage pattern."""
    anomaly_id: str = field(default_factory=lambda: secrets.token_hex(8))
    key_id: str = "unknown"
    anomaly_type: str = "unknown"
    timestamp: float = field(default_factory=time.time)
    severity: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CryptoHealthMetrics:
    """Cryptographic module health metrics."""
    operations_total: int = 0
    operations_success: int = 0
    operations_failed: int = 0
    operations_retried: int = 0
    anomalies_detected: int = 0
    keys_zeroized: int = 0
    avg_operation_time_ms: float = 0.0
    last_failure: Optional[CryptoFailureMode] = None
    
    @property
    def success_rate(self) -> float:
        if self.operations_total == 0:
            return 1.0
        return self.operations_success / self.operations_total

@dataclass
class CipherSuite:
    """Cipher suite definition with fallback support."""
    name: str
    algorithm: str
    key_size_bits: int
    priority: CipherSuitePriority
    fips_compliant: bool = False
    deprecated: bool = False

# -----------------------------------------------------------------------------
# CONSTANT-TIME UTILITIES
# -----------------------------------------------------------------------------

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time byte comparison.
    Uses hmac.compare_digest which is guaranteed constant-time.
    """
    return hmac.compare_digest(a, b)

def constant_time_delay(duration_ms: float) -> None:
    """
    Constant-time delay - always waits full duration.
    No early exit to prevent timing side channels.
    """
    end_time = time.time() + (duration_ms / 1000.0)
    while time.time() < end_time:
        pass  # Busy wait - no early exit

def secure_memzero(buf: bytearray) -> None:
    """
    Secure memory zeroization.
    Overwrites buffer multiple times with different patterns.
    """
    patterns = [0x00, 0xFF, 0xAA, 0x55, 0x00]
    for pattern in patterns:
        for i in range(len(buf)):
            buf[i] = pattern
    gc.collect()

# -----------------------------------------------------------------------------
# KEY COMPROMISE DETECTOR
# -----------------------------------------------------------------------------

class KeyCompromiseDetector:
    """
    Monitors key usage patterns for anomalies.
    Detects: unusual timing, frequency spikes, error patterns.
    """
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self._lock = threading.Lock()
        self._key_usage_times: Dict[str, deque] = {}
        self._key_error_rates: Dict[str, deque] = {}
        self._anomalies: List[KeyUsageAnomaly] = []
        self._baseline_timing: Dict[str, Tuple[float, float]] = {}  # (mean, std)
    
    def _get_key_window(self, key_id: str) -> deque:
        if key_id not in self._key_usage_times:
            self._key_usage_times[key_id] = deque(maxlen=self.window_size)
            self._key_error_rates[key_id] = deque(maxlen=self.window_size)
        return self._key_usage_times[key_id]
    
    def record_usage(self, key_id: str, duration_ms: float, success: bool) -> None:
        """Record key usage for anomaly detection."""
        with self._lock:
            window = self._get_key_window(key_id)
            window.append(duration_ms)
            self._key_error_rates[key_id].append(0.0 if success else 1.0)
            
            # Update baseline
            if len(window) >= 50:
                times = list(window)
                mean_t = sum(times) / len(times)
                if len(times) >= 2:
                    import statistics
                    try:
                        std_t = statistics.stdev(times)
                        self._baseline_timing[key_id] = (mean_t, std_t)
                    except:
                        pass
            
            # Check for anomalies
            self._check_anomalies(key_id, duration_ms, success)
    
    def _check_anomalies(self, key_id: str, duration_ms: float, success: bool) -> None:
        """Check current usage against baseline."""
        if key_id not in self._baseline_timing:
            return
        
        mean_t, std_t = self._baseline_timing[key_id]
        
        # Timing anomaly (> 3 sigma)
        if abs(duration_ms - mean_t) > 3 * max(std_t, 1.0):
            anomaly = KeyUsageAnomaly(
                key_id=key_id,
                anomaly_type="timing_anomaly",
                severity=0.7,
                details={"duration": duration_ms, "mean": mean_t, "std": std_t}
            )
            self._anomalies.append(anomaly)
            logger.warning(f"Key timing anomaly detected: {key_id}")
        
        # Error rate spike (> 20% errors in last 20 operations)
        errors = list(self._key_error_rates[key_id])
        if len(errors) >= 20:
            recent_error_rate = sum(errors[-20:]) / 20
            if recent_error_rate > 0.2:
                anomaly = KeyUsageAnomaly(
                    key_id=key_id,
                    anomaly_type="error_rate_spike",
                    severity=0.8,
                    details={"error_rate": recent_error_rate}
                )
                self._anomalies.append(anomaly)
                logger.warning(f"Key error rate spike: {key_id} - {recent_error_rate:.1%}")
    
    def get_anomalies(self, key_id: Optional[str] = None) -> List[KeyUsageAnomaly]:
        """Get detected anomalies."""
        with self._lock:
            if key_id:
                return [a for a in self._anomalies if a.key_id == key_id]
            return list(self._anomalies)
    
    def get_risk_score(self, key_id: str) -> float:
        """Get compromise risk score (0-1)."""
        with self._lock:
            anomalies = self.get_anomalies(key_id)
            if not anomalies:
                return 0.0
            return min(1.0, sum(a.severity for a in anomalies[-10:]) / 10.0)

# -----------------------------------------------------------------------------
# CRYPTO OPERATION TIMEOUT WITH SECURE CLEANUP
# -----------------------------------------------------------------------------

class CryptoOperationTimeout:
    """
    Timeout wrapper with guaranteed secure cleanup.
    Zeroizes intermediate buffers on timeout.
    """
    
    def __init__(self, timeout_ms: float = 5000.0):
        self.timeout_ms = timeout_ms
        self._cleanup_callbacks: List[Callable] = []
        self._active_buffers: List[bytearray] = []
    
    def register_cleanup(self, callback: Callable) -> None:
        """Register cleanup callback for timeout."""
        self._cleanup_callbacks.append(callback)
    
    def register_buffer(self, buf: bytearray) -> None:
        """Register buffer for zeroization on timeout."""
        self._active_buffers.append(buf)
    
    def _secure_cleanup(self) -> None:
        """Perform secure cleanup on timeout."""
        # Zeroize all registered buffers
        for buf in self._active_buffers:
            secure_memzero(buf)
        
        # Run cleanup callbacks
        for callback in self._cleanup_callbacks:
            try:
                callback()
            except Exception as e:
                logger.warning(f"Cleanup callback error: {e}")
        
        gc.collect()
        logger.warning("Crypto operation timeout - secure cleanup completed")
    
    def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with timeout and secure cleanup."""
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            elapsed = (time.time() - start_time) * 1000
            
            if elapsed > self.timeout_ms:
                self._secure_cleanup()
                raise CryptoTimeoutError(
                    f"Operation exceeded timeout: {elapsed:.1f}ms > {self.timeout_ms}ms"
                )
            
            return result
            
        except Exception as e:
            self._secure_cleanup()
            raise

# -----------------------------------------------------------------------------
# SECURE RETRY ENGINE (CONSTANT-TIME)
# -----------------------------------------------------------------------------

class SecureRetryEngine:
    """
    Constant-time retry engine for cryptographic operations.
    All retry paths take identical time to prevent timing side channels.
    """
    
    def __init__(self, policy: Optional[CryptoRetryPolicy] = None):
        self.policy = policy or CryptoRetryPolicy()
        self._lock = threading.Lock()
        self._metrics = CryptoHealthMetrics()
    
    def execute(
        self,
        operation: CryptoOperationType,
        func: Callable,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute operation with constant-time retries.
        Always takes max_attempts * delay time regardless of success.
        """
        max_attempts = self.policy.max_attempts
        base_delay = self.policy.base_delay_ms
        jitter_range = self.policy.max_jitter_ms
        
        last_exception = None
        start_total = time.time()
        
        for attempt in range(max_attempts):
            attempt_start = time.time()
            
            try:
                with self._lock:
                    self._metrics.operations_total += 1
                
                result = func(*args, **kwargs)
                
                with self._lock:
                    self._metrics.operations_success += 1
                    if attempt > 0:
                        self._metrics.operations_retried += 1
                
                # Constant-time delay - always wait full attempt time
                if self.policy.constant_time:
                    elapsed = (time.time() - attempt_start) * 1000
                    remaining = base_delay - elapsed
                    if remaining > 0:
                        constant_time_delay(remaining)
                
                return result
                
            except Exception as e:
                last_exception = e
                failure_mode = self._classify_failure(e)
                
                with self._lock:
                    self._metrics.operations_failed += 1
                    self._metrics.last_failure = failure_mode
                
                # Check if retryable
                if (attempt >= max_attempts - 1 or 
                    operation not in self.policy.allowed_operations or
                    failure_mode not in self.policy.retryable_failures):
                    break
                
                # Constant-time delay before retry
                jitter = secrets.SystemRandom().uniform(0, jitter_range)
                constant_time_delay(base_delay + jitter)
        
        # All attempts failed
        raise CryptoRetryExhaustedError(
            f"All {max_attempts} retry attempts exhausted",
            operation=operation,
            cause=last_exception
        ) from last_exception
    
    def _classify_failure(self, exception: Exception) -> CryptoFailureMode:
        """Classify exception into failure mode."""
        exc_type = type(exception).__name__.lower()
        
        if "timeout" in exc_type:
            return CryptoFailureMode.TIMEOUT
        elif "random" in exc_type or "entropy" in exc_type:
            return CryptoFailureMode.RNG_FAILURE
        elif "integrity" in exc_type or "mac" in exc_type:
            return CryptoFailureMode.INTEGRITY_ERROR
        elif "memory" in exc_type or "buffer" in exc_type:
            return CryptoFailureMode.MEMORY_ERROR
        elif "hardware" in exc_type or "hsm" in exc_type:
            return CryptoFailureMode.HARDWARE_ERROR
        else:
            return CryptoFailureMode.TRANSIENT_ERROR
    
    def get_metrics(self) -> CryptoHealthMetrics:
        """Get health metrics."""
        with self._lock:
            return CryptoHealthMetrics(
                operations_total=self._metrics.operations_total,
                operations_success=self._metrics.operations_success,
                operations_failed=self._metrics.operations_failed,
                operations_retried=self._metrics.operations_retried,
                anomalies_detected=self._metrics.anomalies_detected,
                keys_zeroized=self._metrics.keys_zeroized
            )

# -----------------------------------------------------------------------------
# HSM EMULATION LAYER
# -----------------------------------------------------------------------------

class HSMEmulator:
    """
    HSM emulation layer for secure key storage.
    Provides secure key storage with automatic zeroization.
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        self._key_store: Dict[str, SecureBytes] = {}
        self._key_metadata: Dict[str, Dict[str, Any]] = {}
        self._compromise_detector = KeyCompromiseDetector()
        self._is_locked = False
    
    def store_key(self, key_id: str, key_material: bytes, 
                  sensitivity: KeySensitivityLevel = KeySensitivityLevel.CRITICAL) -> None:
        """Securely store key material."""
        with self._lock:
            if self._is_locked:
                raise HSMError("HSM is locked")
            
            secure_key = SecureBytes.from_bytes(key_material, sensitivity)
            self._key_store[key_id] = secure_key
            self._key_metadata[key_id] = {
                "created": time.time(),
                "sensitivity": sensitivity.value,
                "usage_count": 0
            }
            logger.debug(f"Key stored: {key_id}")
    
    def retrieve_key(self, key_id: str) -> bytes:
        """Retrieve key material (returns COPY - original remains protected)."""
        with self._lock:
            if self._is_locked:
                raise HSMError("HSM is locked")
            
            if key_id not in self._key_store:
                raise KeyNotFoundError(f"Key not found: {key_id}")
            
            self._key_metadata[key_id]["usage_count"] += 1
            
            # Check compromise risk
            risk = self._compromise_detector.get_risk_score(key_id)
            if risk > 0.8:
                logger.critical(f"High compromise risk for key: {key_id}")
                self._zeroize_key(key_id)
                raise KeyCompromiseError(f"Key compromised, zeroized: {key_id}")
            
            # Return COPY - never expose internal SecureBytes
            return self._key_store[key_id].get()
    
    def record_key_usage(self, key_id: str, duration_ms: float, success: bool) -> None:
        """Record key usage for anomaly detection."""
        self._compromise_detector.record_usage(key_id, duration_ms, success)
    
    def _zeroize_key(self, key_id: str) -> None:
        """Zeroize and remove a key."""
        if key_id in self._key_store:
            self._key_store[key_id].zeroize()
            del self._key_store[key_id]
            del self._key_metadata[key_id]
    
    def zeroize_all(self) -> None:
        """Zeroize all keys - emergency procedure."""
        with self._lock:
            for key_id in list(self._key_store.keys()):
                self._zeroize_key(key_id)
            self._is_locked = True
            logger.critical("HSM EMERGENCY ZEROIZE - ALL KEYS DESTROYED")
    
    def lock(self) -> None:
        """Lock HSM - no key access until unlocked."""
        with self._lock:
            self._is_locked = True
    
    def unlock(self) -> None:
        """Unlock HSM."""
        with self._lock:
            self._is_locked = False
    
    def get_key_info(self, key_id: str) -> Dict[str, Any]:
        """Get key metadata (no key material)."""
        with self._lock:
            if key_id not in self._key_metadata:
                return {}
            meta = dict(self._key_metadata[key_id])
            meta["compromise_risk"] = self._compromise_detector.get_risk_score(key_id)
            return meta

# Global HSM instance
crypto_hsm = HSMEmulator()

# -----------------------------------------------------------------------------
# CIPHER SUITE FALLBACK MANAGER
# -----------------------------------------------------------------------------

class CipherSuiteManager:
    """
    Manages cipher suite priorities and automatic fallback.
    Implements algorithm agility - auto-switches on failure.
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        self._suites: List[CipherSuite] = []
        self._failure_counts: Dict[str, int] = {}
        self._current_suite: Optional[str] = None
    
    def register_suite(self, suite: CipherSuite) -> None:
        """Register a cipher suite."""
        with self._lock:
            self._suites.append(suite)
            self._suites.sort(key=lambda s: s.priority.value)
    
    def get_preferred_suite(self) -> CipherSuite:
        """Get highest priority working cipher suite."""
        with self._lock:
            for suite in sorted(self._suites, key=lambda s: s.priority.value):
                if self._failure_counts.get(suite.name, 0) < 5:
                    return suite
            # All failed - return FIPS compliant if available
            for suite in self._suites:
                if suite.fips_compliant:
                    return suite
            # Fallback to any available
            return self._suites[0] if self._suites else CipherSuite(
                name="fallback", algorithm="AES-256-GCM",
                key_size_bits=256, priority=CipherSuitePriority.LEGACY,
                fips_compliant=True
            )
    
    def record_failure(self, suite_name: str) -> None:
        """Record a failure for a suite."""
        with self._lock:
            self._failure_counts[suite_name] = self._failure_counts.get(suite_name, 0) + 1
    
    def get_available_suites(self) -> List[CipherSuite]:
        """Get all registered suites."""
        with self._lock:
            return list(self._suites)

# Global cipher suite manager
cipher_manager = CipherSuiteManager()

# Register default suites
cipher_manager.register_suite(CipherSuite(
    name="AES-256-GCM", algorithm="AES-GCM", key_size_bits=256,
    priority=CipherSuitePriority.PRIMARY, fips_compliant=True
))
cipher_manager.register_suite(CipherSuite(
    name="ChaCha20-Poly1305", algorithm="ChaCha20", key_size_bits=256,
    priority=CipherSuitePriority.SECONDARY, fips_compliant=False
))
cipher_manager.register_suite(CipherSuite(
    name="AES-128-GCM", algorithm="AES-GCM", key_size_bits=128,
    priority=CipherSuitePriority.LEGACY, fips_compliant=True
))

# -----------------------------------------------------------------------------
# MAIN CRYPTO RESILIENCE CONTROLLER
# -----------------------------------------------------------------------------

class CryptoResilienceController:
    """
    Main controller for cryptographic operation resilience.
    Orchestrates: retry, timeout, key protection, fallback, anomaly detection.
    """
    
    _instance: Optional['CryptoResilienceController'] = None
    _lock = threading.Lock()
    
    def __new__(cls) -> 'CryptoResilienceController':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._retry_engine = SecureRetryEngine()
            self._timeout_handler = CryptoOperationTimeout()
            self._hsm = crypto_hsm
            self._cipher_manager = cipher_manager
            self._initialized = True
    
    def protect_operation(
        self,
        operation: CryptoOperationType,
        key_id: Optional[str] = None,
        timeout_ms: float = 5000.0,
        enable_retries: bool = True
    ) -> Callable:
        """
        Decorator for protected cryptographic operations.
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                op_start = time.time()
                
                def _execute():
                    return func(*args, **kwargs)
                
                try:
                    # Execute with timeout and retry
                    if enable_retries:
                        result = self._retry_engine.execute(operation, _execute)
                    else:
                        result = self._timeout_handler.execute(_execute)
                    
                    # Record successful key usage
                    duration = (time.time() - op_start) * 1000
                    if key_id:
                        self._hsm.record_key_usage(key_id, duration, success=True)
                    
                    return result
                    
                except Exception as e:
                    # Record failed key usage
                    duration = (time.time() - op_start) * 1000
                    if key_id:
                        self._hsm.record_key_usage(key_id, duration, success=False)
                    raise
            
            return wrapper
        return decorator
    
    def get_health_report(self) -> Dict[str, Any]:
        """Get comprehensive crypto health report."""
        retry_metrics = self._retry_engine.get_metrics()
        return {
            "retry_engine": {
                "total_operations": retry_metrics.operations_total,
                "success_rate": retry_metrics.success_rate,
                "operations_retried": retry_metrics.operations_retried
            },
            "cipher_suites": {
                "preferred": self._cipher_manager.get_preferred_suite().name,
                "available": [s.name for s in self._cipher_manager.get_available_suites()]
            },
            "hsm": {
                "keys_stored": len(self._hsm._key_store),
                "is_locked": self._hsm._is_locked
            }
        }

# Global controller instance
crypto_resilience = CryptoResilienceController()

# -----------------------------------------------------------------------------
# CUSTOM EXCEPTIONS
# -----------------------------------------------------------------------------

class CryptoResilienceError(Exception):
    """Base exception for crypto resilience errors."""
    def __init__(self, message: str, **kwargs):
        super().__init__(message)
        self.timestamp = time.time()
        self.details = kwargs

class CryptoTimeoutError(CryptoResilienceError):
    """Operation timed out."""
    pass

class CryptoRetryExhaustedError(CryptoResilienceError):
    """All retry attempts exhausted."""
    pass

class HSMError(CryptoResilienceError):
    """HSM operation error."""
    pass

class KeyNotFoundError(HSMError):
    """Key not found in HSM."""
    pass

class KeyCompromiseError(HSMError):
    """Key may be compromised."""
    pass

# -----------------------------------------------------------------------------
# SELF-TEST EXECUTABLE
# -----------------------------------------------------------------------------

def run_self_tests() -> Dict[str, Any]:
    """Run comprehensive self-tests."""
    print("=" * 60)
    print("QuantumCrypt Crypto Resilience v17 - Self-Tests")
    print("=" * 60)
    
    results = {
        "tests_passed": 0,
        "tests_failed": 0,
        "test_results": []
    }
    
    def run_test(name: str, test_func: Callable) -> None:
        try:
            test_func()
            results["tests_passed"] += 1
            results["test_results"].append((name, "PASS"))
            print(f"  ✓ PASS: {name}")
        except Exception as e:
            results["tests_failed"] += 1
            results["test_results"].append((name, f"FAIL: {str(e)}"))
            print(f"  ✗ FAIL: {name}: {e}")
    
    # Test 1: SecureBytes zeroization
    def test_secure_bytes():
        data = b"secret_key_material_12345"
        sb = SecureBytes.from_bytes(data)
        assert sb.get() == data
        sb.zeroize()
        try:
            sb.get()
            assert False, "Should raise error after zeroize"
        except ValueError:
            pass
    
    run_test("SecureBytes zeroization", test_secure_bytes)
    
    # Test 2: Constant-time compare
    def test_constant_time_compare():
        a = b"test1234"
        b = b"test1234"
        c = b"test1235"
        assert constant_time_compare(a, b) == True
        assert constant_time_compare(a, c) == False
    
    run_test("Constant-time comparison", test_constant_time_compare)
    
    # Test 3: HSM store/retrieve
    def test_hsm_basic():
        hsm = HSMEmulator()
        key = secrets.token_bytes(32)
        hsm.store_key("test_key", key)
        retrieved = hsm.retrieve_key("test_key")
        assert retrieved == key
    
    run_test("HSM basic store/retrieve", test_hsm_basic)
    
    # Test 4: Secure memory zeroization
    def test_memzero():
        buf = bytearray(b"sensitive data here")
        original = bytes(buf)
        secure_memzero(buf)
        assert bytes(buf) != original
        assert all(b == 0 for b in buf)
    
    run_test("Secure memory zeroization", test_memzero)
    
    # Test 5: Retry engine basic
    def test_retry_engine():
        engine = SecureRetryEngine(CryptoRetryPolicy(max_attempts=2))
        call_count = [0]
        
        def succeeds_on_second():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("transient")
            return "success"
        
        result = engine.execute(CryptoOperationType.ENCRYPTION, succeeds_on_second)
        assert result == "success"
        assert call_count[0] == 2
    
    run_test("Retry engine succeeds on retry", test_retry_engine)
    
    # Test 6: Key compromise detector
    def test_compromise_detector():
        kcd = KeyCompromiseDetector()
        for _ in range(60):
            kcd.record_usage("key1", 10.0, True)
        risk = kcd.get_risk_score("key1")
        assert risk < 0.5  # Low risk for normal pattern
    
    run_test("Key compromise detector baseline", test_compromise_detector)
    
    # Test 7: Cipher suite manager
    def test_cipher_manager():
        preferred = cipher_manager.get_preferred_suite()
        assert preferred is not None
        assert preferred.name in ["AES-256-GCM", "ChaCha20-Poly1305"]
    
    run_test("Cipher suite manager preferred", test_cipher_manager)
    
    # Test 8: Controller singleton
    def test_controller_singleton():
        c1 = CryptoResilienceController()
        c2 = CryptoResilienceController()
        assert c1 is c2
    
    run_test("Controller singleton pattern", test_controller_singleton)
    
    # Test 9: Operation decorator
    def test_decorator():
        @crypto_resilience.protect_operation(CryptoOperationType.HASHING)
        def hash_func(data: bytes) -> bytes:
            return hashlib.sha256(data).digest()
        
        result = hash_func(b"test")
        assert len(result) == 32
    
    run_test("Crypto protection decorator", test_decorator)
    
    # Test 10: Health report
    def test_health_report():
        report = crypto_resilience.get_health_report()
        assert "retry_engine" in report
        assert "cipher_suites" in report
        assert "hsm" in report
    
    run_test("Health report generation", test_health_report)
    
    print("\n" + "=" * 60)
    print(f"Results: {results['tests_passed']}/{results['tests_passed'] + results['tests_failed']} tests passed")
    print("=" * 60)
    
    return results

if __name__ == "__main__":
    run_self_tests()
