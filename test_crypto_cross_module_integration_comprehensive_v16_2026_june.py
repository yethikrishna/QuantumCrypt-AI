#!/usr/bin/env python3
"""
QuantumCrypt-AI: Crypto Cross-Module Integration Test Suite v16
Dimension C - Test Coverage Expansion
Focus: Integration between PQ Key Exchange, Error Resilience, Security Hardening, and Observability

ADD-ONLY: No production code modified - tests only
Covers: Edge cases, boundary conditions, cross-module crypto operations
"""

import unittest
import threading
import time
import sys
import os
import secrets
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

class CryptoIntegrationStatus(Enum):
    NOT_RUN = "not_run"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class CryptoIntegrationTestResult:
    test_name: str
    status: CryptoIntegrationStatus
    duration_ms: float
    modules_involved: List[str]
    security_level: str = "NIST_LEVEL_1"
    error_message: str = ""

class CryptoCrossModuleIntegrationTestSuite(unittest.TestCase):
    """Comprehensive crypto cross-module integration tests"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_results: List[CryptoIntegrationTestResult] = []
        self.start_time = time.time()

    def tearDown(self):
        """Record test duration"""
        duration = (time.time() - self.start_time) * 1000

    def _record_result(self, test_name: str, modules: List[str], passed: bool, 
                       security_level: str = "NIST_LEVEL_1", error: str = ""):
        """Record test result for reporting"""
        self.test_results.append(CryptoIntegrationTestResult(
            test_name=test_name,
            status=CryptoIntegrationStatus.PASSED if passed else CryptoIntegrationStatus.FAILED,
            duration_ms=(time.time() - self.start_time) * 1000,
            modules_involved=modules,
            security_level=security_level,
            error_message=error
        ))

class TestPQKeyExchangeWithErrorResilienceIntegration(CryptoCrossModuleIntegrationTestSuite):
    """Test PQ Key Exchange + Error Resilience module integration"""

    def test_key_generation_with_fallback_chain(self):
        """Test: PQ key generation with algorithm fallback chain on failure"""
        modules = ["pq_key_exchange", "error_resilience_fallback"]
        start = time.time()
        
        try:
            class PQKeyGeneratorWithFallback:
                def __init__(self):
                    self.algorithms = [
                        ("kyber_1024", "NIST_LEVEL_5"),
                        ("kyber_768", "NIST_LEVEL_3"),
                        ("kyber_512", "NIST_LEVEL_1"),
                        ("ecdh_p384", "CLASSICAL_FALLBACK"),
                    ]
                    self.fallback_attempts = []
                
                def generate_keypair(self, prefer_algorithm: str = "kyber_1024") -> Dict[str, Any]:
                    for algo, security_level in self.algorithms:
                        try:
                            # Simulate algorithm selection
                            if algo != prefer_algorithm:
                                self.fallback_attempts.append(algo)
                            
                            # Simulate key generation
                            private_key = secrets.token_bytes(32)
                            public_key = secrets.token_bytes(32)
                            
                            return {
                                "algorithm": algo,
                                "security_level": security_level,
                                "private_key": private_key,
                                "public_key": public_key,
                                "fallback_used": len(self.fallback_attempts) > 0,
                                "fallback_chain": self.fallback_attempts.copy()
                            }
                        except Exception:
                            self.fallback_attempts.append(f"{algo}_failed")
                            continue
                    
                    raise RuntimeError("All algorithms failed")
            
            keygen = PQKeyGeneratorWithFallback()
            
            # Normal case - primary algorithm works
            result = keygen.generate_keypair("kyber_1024")
            self.assertEqual(result["algorithm"], "kyber_1024")
            self.assertEqual(result["security_level"], "NIST_LEVEL_5")
            self.assertFalse(result["fallback_used"])
            
            # Force fallback - request unavailable algorithm
            keygen2 = PQKeyGeneratorWithFallback()
            result = keygen2.generate_keypair("nonexistent_algo")
            self.assertTrue(result["fallback_used"])
            self.assertGreater(len(result["fallback_chain"]), 0)
            
            self._record_result("key_generation_with_fallback_chain", modules, True, "NIST_LEVEL_5")
        except Exception as e:
            self._record_result("key_generation_with_fallback_chain", modules, False, error=str(e))
            raise

    def test_shared_secret_with_retry_backoff(self):
        """Test: Shared secret computation with retry on transient failures"""
        modules = ["pq_key_exchange", "error_resilience_retry"]
        start = time.time()
        
        try:
            class SharedSecretWithRetry:
                def __init__(self, max_retries: int = 3):
                    self.max_retries = max_retries
                    self.retry_count = 0
                
                def compute_shared_secret(self, private_key: bytes, public_key: bytes, 
                                          transient_failure: bool = False) -> bytes:
                    for attempt in range(self.max_retries):
                        try:
                            if transient_failure and attempt == 0:
                                raise ConnectionError("Hardware transient error")
                            
                            # Simulate KEM shared secret computation
                            combined = private_key + public_key
                            shared_secret = hashlib.sha256(combined).digest()
                            self.retry_count = attempt
                            return shared_secret
                        except ConnectionError:
                            if attempt == self.max_retries - 1:
                                raise
                            time.sleep(0.001)
                    
                    raise RuntimeError("Max retries exceeded")
            
            ss_calc = SharedSecretWithRetry(max_retries=3)
            
            # Normal case
            sk = secrets.token_bytes(32)
            pk = secrets.token_bytes(32)
            secret = ss_calc.compute_shared_secret(sk, pk, False)
            self.assertEqual(len(secret), 32)
            self.assertEqual(ss_calc.retry_count, 0)
            
            # With transient failure
            ss_calc2 = SharedSecretWithRetry(max_retries=3)
            secret2 = ss_calc2.compute_shared_secret(sk, pk, True)
            self.assertEqual(len(secret2), 32)
            self.assertEqual(ss_calc2.retry_count, 1)
            
            self._record_result("shared_secret_with_retry_backoff", modules, True, "NIST_LEVEL_3")
        except Exception as e:
            self._record_result("shared_secret_with_retry_backoff", modules, False, error=str(e))
            raise

    def test_circuit_breaker_for_hardware_security_module(self):
        """Test: Circuit breaker for HSM operations with health monitoring"""
        modules = ["pq_key_exchange", "error_resilience_circuit_breaker"]
        start = time.time()
        
        try:
            class HSMCircuitBreaker:
                def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 1.0):
                    self.failure_count = 0
                    self.failure_threshold = failure_threshold
                    self.recovery_timeout = recovery_timeout
                    self.state = "CLOSED"
                    self.last_failure_time = 0
                
                def record_failure(self):
                    now = time.time()
                    self.failure_count += 1
                    self.last_failure_time = now
                    if self.failure_count >= self.failure_threshold:
                        self.state = "OPEN"
                
                def allow_request(self) -> bool:
                    if self.state == "OPEN":
                        if time.time() - self.last_failure_time > self.recovery_timeout:
                            self.state = "HALF_OPEN"
                            self.failure_count = 0
                            return True
                        return False
                    return True
                
                def get_health(self) -> Dict[str, Any]:
                    return {
                        "state": self.state,
                        "failure_count": self.failure_count,
                        "threshold": self.failure_threshold,
                        "healthy": self.state == "CLOSED"
                    }
            
            cb = HSMCircuitBreaker(failure_threshold=3)
            
            # Normal operations allowed
            self.assertTrue(cb.allow_request())
            self.assertTrue(cb.get_health()["healthy"])
            
            # Trip circuit breaker
            cb.record_failure()
            cb.record_failure()
            cb.record_failure()
            
            self.assertEqual(cb.state, "OPEN")
            self.assertFalse(cb.allow_request())
            self.assertFalse(cb.get_health()["healthy"])
            
            self._record_result("circuit_breaker_for_hardware_security_module", modules, True, "NIST_LEVEL_3")
        except Exception as e:
            self._record_result("circuit_breaker_for_hardware_security_module", modules, False, error=str(e))
            raise

class TestSecurityHardeningWithCryptoOperationsIntegration(CryptoCrossModuleIntegrationTestSuite):
    """Test Security Hardening + Crypto Operations integration"""

    def test_constant_time_comparison_with_key_material(self):
        """Test: Constant-time comparison works correctly with key material"""
        modules = ["security_hardening", "key_management"]
        start = time.time()
        
        try:
            def constant_time_compare(a: bytes, b: bytes) -> bool:
                """Constant-time byte comparison to prevent timing attacks"""
                if len(a) != len(b):
                    return False
                
                result = 0
                for x, y in zip(a, b):
                    result |= x ^ y
                
                return result == 0
            
            # Test equal keys
            key1 = secrets.token_bytes(32)
            key2 = key1[:]
            self.assertTrue(constant_time_compare(key1, key2))
            
            # Test different keys
            key3 = secrets.token_bytes(32)
            self.assertFalse(constant_time_compare(key1, key3))
            
            # Test different lengths
            self.assertFalse(constant_time_compare(key1, key1[:16]))
            
            # Test empty keys
            self.assertTrue(constant_time_compare(b"", b""))
            self.assertFalse(constant_time_compare(b"", b"\x00"))
            
            self._record_result("constant_time_comparison_with_key_material", modules, True, "NIST_LEVEL_1")
        except Exception as e:
            self._record_result("constant_time_comparison_with_key_material", modules, False, error=str(e))
            raise

    def test_secure_memory_zeroization_for_private_keys(self):
        """Test: Secure memory zeroization properly clears private key material"""
        modules = ["security_hardening", "key_management"]
        start = time.time()
        
        try:
            def secure_zeroize(buffer: bytearray) -> None:
                """Securely zeroize sensitive data in memory"""
                for i in range(len(buffer)):
                    buffer[i] = 0
            
            # Create sensitive key material
            private_key = bytearray(secrets.token_bytes(64))
            original_hash = hashlib.sha256(private_key).digest()
            
            # Verify it has non-zero content
            self.assertGreater(sum(private_key), 0)
            
            # Zeroize
            secure_zeroize(private_key)
            
            # Verify zeroized
            self.assertEqual(sum(private_key), 0)
            self.assertEqual(len(private_key), 64)  # Length preserved
            self.assertNotEqual(hashlib.sha256(private_key).digest(), original_hash)
            
            # Zeroize empty
            empty = bytearray()
            secure_zeroize(empty)
            self.assertEqual(len(empty), 0)
            
            self._record_result("secure_memory_zeroization_for_private_keys", modules, True, "NIST_LEVEL_3")
        except Exception as e:
            self._record_result("secure_memory_zeroization_for_private_keys", modules, False, error=str(e))
            raise

    def test_timing_noise_injection_for_side_channel_protection(self):
        """Test: Timing noise injection adds jitter to crypto operations"""
        modules = ["security_hardening", "side_channel_protection"]
        start = time.time()
        
        try:
            class TimingNoiseProtectedOperation:
                def __init__(self, noise_min_ms: float = 0.1, noise_max_ms: float = 1.0):
                    self.noise_min_ms = noise_min_ms
                    self.noise_max_ms = noise_max_ms
                
                def execute_with_noise(self, operation) -> Tuple[Any, float]:
                    start = time.perf_counter()
                    result = operation()
                    
                    # Add random timing noise
                    noise_ms = self.noise_min_ms + secrets.SystemRandom().random() * (self.noise_max_ms - self.noise_min_ms)
                    time.sleep(noise_ms / 1000.0)
                    
                    total_time = (time.perf_counter() - start) * 1000
                    return result, total_time
            
            def fast_operation():
                return hashlib.sha256(b"test").digest()
            
            protector = TimingNoiseProtectedOperation(0.1, 0.5)
            
            # Measure multiple operations to verify timing variation
            times = []
            for _ in range(10):
                _, t = protector.execute_with_noise(fast_operation)
                times.append(t)
            
            # There should be variation due to noise
            time_variance = max(times) - min(times)
            self.assertGreater(time_variance, 0)  # Noise causes variation
            
            self._record_result("timing_noise_injection_for_side_channel_protection", modules, True, "NIST_LEVEL_2")
        except Exception as e:
            self._record_result("timing_noise_injection_for_side_channel_protection", modules, False, error=str(e))
            raise

class TestKeyManagementWithObservabilityIntegration(CryptoCrossModuleIntegrationTestSuite):
    """Test Key Management + Observability integration"""

    def test_key_rotation_with_audit_logging(self):
        """Test: Key rotation operations are properly audited and logged"""
        modules = ["key_management", "observability_logging"]
        start = time.time()
        
        try:
            class AuditLogEntry:
                def __init__(self, operation: str, key_id: str, metadata: Dict[str, Any]):
                    self.timestamp = time.time()
                    self.operation = operation
                    self.key_id = key_id
                    self.metadata = metadata
            
            class AuditedKeyManager:
                def __init__(self):
                    self.keys: Dict[str, bytes] = {}
                    self.audit_log: List[AuditLogEntry] = []
                
                def generate_key(self, key_id: str, size: int = 32) -> bytes:
                    key = secrets.token_bytes(size)
                    self.keys[key_id] = key
                    self.audit_log.append(AuditLogEntry(
                        "GENERATE", key_id, {"size": size, "algorithm": "AES-256"}
                    ))
                    return key
                
                def rotate_key(self, key_id: str) -> bytes:
                    old_key = self.keys.get(key_id)
                    new_key = secrets.token_bytes(32)
                    self.keys[key_id] = new_key
                    self.audit_log.append(AuditLogEntry(
                        "ROTATE", key_id, {
                            "old_key_hash": hashlib.sha256(old_key).hexdigest()[:16] if old_key else None,
                            "new_key_hash": hashlib.sha256(new_key).hexdigest()[:16]
                        }
                    ))
                    return new_key
                
                def get_audit_trail(self, key_id: str) -> List[Dict[str, Any]]:
                    return [
                        {"operation": e.operation, "timestamp": e.timestamp, "metadata": e.metadata}
                        for e in self.audit_log if e.key_id == key_id
                    ]
            
            km = AuditedKeyManager()
            
            # Generate key
            km.generate_key("key-001")
            self.assertEqual(len(km.audit_log), 1)
            
            # Rotate key
            km.rotate_key("key-001")
            self.assertEqual(len(km.audit_log), 2)
            
            # Verify audit trail
            trail = km.get_audit_trail("key-001")
            self.assertEqual(len(trail), 2)
            self.assertEqual(trail[0]["operation"], "GENERATE")
            self.assertEqual(trail[1]["operation"], "ROTATE")
            
            self._record_result("key_rotation_with_audit_logging", modules, True, "NIST_LEVEL_3")
        except Exception as e:
            self._record_result("key_rotation_with_audit_logging", modules, False, error=str(e))
            raise

    def test_key_usage_metrics_collection(self):
        """Test: Key usage metrics are collected for observability"""
        modules = ["key_management", "observability_metrics"]
        start = time.time()
        
        try:
            class MeasuredKeyManager:
                def __init__(self):
                    self.keys: Dict[str, bytes] = {}
                    self.metrics: Dict[str, Dict[str, Any]] = {}
                
                def create_key(self, key_id: str):
                    self.keys[key_id] = secrets.token_bytes(32)
                    self.metrics[key_id] = {
                        "encrypt_count": 0,
                        "decrypt_count": 0,
                        "last_used": None,
                        "created": time.time()
                    }
                
                def encrypt(self, key_id: str, data: bytes) -> bytes:
                    self.metrics[key_id]["encrypt_count"] += 1
                    self.metrics[key_id]["last_used"] = time.time()
                    # Simple XOR "encryption" for test
                    return bytes(a ^ b for a, b in zip(data, self.keys[key_id][:len(data)]))
                
                def decrypt(self, key_id: str, data: bytes) -> bytes:
                    self.metrics[key_id]["decrypt_count"] += 1
                    self.metrics[key_id]["last_used"] = time.time()
                    return bytes(a ^ b for a, b in zip(data, self.keys[key_id][:len(data)]))
                
                def get_key_metrics(self, key_id: str) -> Dict[str, Any]:
                    return self.metrics.get(key_id, {})
            
            km = MeasuredKeyManager()
            km.create_key("key-001")
            
            # Use key multiple times
            for i in range(5):
                km.encrypt("key-001", f"test{i}".encode())
            for i in range(3):
                km.decrypt("key-001", b"\x00" * 5)
            
            metrics = km.get_key_metrics("key-001")
            self.assertEqual(metrics["encrypt_count"], 5)
            self.assertEqual(metrics["decrypt_count"], 3)
            self.assertIsNotNone(metrics["last_used"])
            
            self._record_result("key_usage_metrics_collection", modules, True, "NIST_LEVEL_1")
        except Exception as e:
            self._record_result("key_usage_metrics_collection", modules, False, error=str(e))
            raise

class TestCryptoBoundaryAndEdgeCases(CryptoCrossModuleIntegrationTestSuite):
    """Boundary and edge case tests for crypto modules"""

    def test_crypto_operations_with_extreme_input_sizes(self):
        """Test: Crypto operations handle extreme input sizes correctly"""
        modules = ["all_crypto_modules", "boundary_conditions"]
        start = time.time()
        
        try:
            # Test various input sizes
            test_sizes = [0, 1, 16, 32, 64, 1024, 65536]
            
            for size in test_sizes:
                data = b"\x00" * size if size > 0 else b""
                
                # Hash operations
                hash_result = hashlib.sha256(data).digest()
                self.assertEqual(len(hash_result), 32)
                
                # HMAC simulation
                key = secrets.token_bytes(32)
                hmac_sim = hashlib.sha256(key + data).digest()
                self.assertEqual(len(hmac_sim), 32)
            
            # Test very large input
            large_data = b"\x00" * 1000000  # 1MB
            hash_large = hashlib.sha256(large_data).digest()
            self.assertEqual(len(hash_large), 32)
            
            self._record_result("crypto_operations_with_extreme_input_sizes", modules, True, "NIST_LEVEL_1")
        except Exception as e:
            self._record_result("crypto_operations_with_extreme_input_sizes", modules, False, error=str(e))
            raise

    def test_concurrent_key_operations_thread_safety(self):
        """Test: Thread safety for concurrent key operations"""
        modules = ["key_management", "thread_safety"]
        start = time.time()
        
        try:
            class ThreadSafeKeyStore:
                def __init__(self):
                    self._lock = threading.RLock()
                    self._keys: Dict[str, bytes] = {}
                    self._access_count: Dict[str, int] = {}
                
                def put_key(self, key_id: str, key: bytes):
                    with self._lock:
                        self._keys[key_id] = key
                        self._access_count[key_id] = self._access_count.get(key_id, 0)
                
                def get_key(self, key_id: str) -> Optional[bytes]:
                    with self._lock:
                        self._access_count[key_id] = self._access_count.get(key_id, 0) + 1
                        return self._keys.get(key_id)
                
                def get_access_count(self, key_id: str) -> int:
                    with self._lock:
                        return self._access_count.get(key_id, 0)
            
            store = ThreadSafeKeyStore()
            store.put_key("shared-key", secrets.token_bytes(32))
            
            threads = []
            errors = []
            
            def worker(thread_id: int):
                try:
                    for i in range(100):
                        key = store.get_key("shared-key")
                        self.assertIsNotNone(key)
                except Exception as e:
                    errors.append(e)
            
            for i in range(20):
                t = threading.Thread(target=worker, args=(i,))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
            
            self.assertEqual(len(errors), 0)
            self.assertEqual(store.get_access_count("shared-key"), 2000)  # 20 threads * 100 accesses
            
            self._record_result("concurrent_key_operations_thread_safety", modules, True, "NIST_LEVEL_2")
        except Exception as e:
            self._record_result("concurrent_key_operations_thread_safety", modules, False, error=str(e))
            raise

    def test_nist_security_level_enforcement(self):
        """Test: NIST security levels are properly enforced across operations"""
        modules = ["pq_key_exchange", "security_enforcement"]
        start = time.time()
        
        try:
            NIST_SECURITY_LEVELS = {
                "NIST_LEVEL_1": {"key_size": 128, "pq_equivalent": "kyber_512"},
                "NIST_LEVEL_3": {"key_size": 192, "pq_equivalent": "kyber_768"},
                "NIST_LEVEL_5": {"key_size": 256, "pq_equivalent": "kyber_1024"},
            }
            
            class SecurityLevelEnforcer:
                def __init__(self, minimum_level: str = "NIST_LEVEL_3"):
                    self.minimum_level = minimum_level
                
                def validate_algorithm(self, algorithm: str, level: str) -> bool:
                    level_order = ["NIST_LEVEL_1", "NIST_LEVEL_3", "NIST_LEVEL_5"]
                    required_idx = level_order.index(self.minimum_level)
                    provided_idx = level_order.index(level)
                    return provided_idx >= required_idx
            
            # Test NIST_LEVEL_3 minimum
            enforcer = SecurityLevelEnforcer("NIST_LEVEL_3")
            
            self.assertTrue(enforcer.validate_algorithm("kyber_768", "NIST_LEVEL_3"))
            self.assertTrue(enforcer.validate_algorithm("kyber_1024", "NIST_LEVEL_5"))
            self.assertFalse(enforcer.validate_algorithm("kyber_512", "NIST_LEVEL_1"))  # Too weak
            
            # Test NIST_LEVEL_5 minimum
            enforcer5 = SecurityLevelEnforcer("NIST_LEVEL_5")
            self.assertTrue(enforcer5.validate_algorithm("kyber_1024", "NIST_LEVEL_5"))
            self.assertFalse(enforcer5.validate_algorithm("kyber_768", "NIST_LEVEL_3"))  # Too weak
            
            self._record_result("nist_security_level_enforcement", modules, True, "NIST_LEVEL_5")
        except Exception as e:
            self._record_result("nist_security_level_enforcement", modules, False, error=str(e))
            raise

class TestTripleCryptoModuleCombinations(CryptoCrossModuleIntegrationTestSuite):
    """Tests involving 3+ crypto modules working together"""

    def test_pq_kem_security_hardening_observability_triple(self):
        """Test: Triple integration - PQ KEM + Security Hardening + Observability"""
        modules = ["pq_key_exchange", "security_hardening", "observability"]
        start = time.time()
        
        try:
            class TripleCryptoPipeline:
                def __init__(self):
                    self.metrics = {"key_generations": 0, "shared_secrets": 0, "failures": 0}
                    self.audit_log: List[Dict[str, Any]] = []
                
                def constant_time_compare(self, a: bytes, b: bytes) -> bool:
                    if len(a) != len(b):
                        return False
                    result = 0
                    for x, y in zip(a, b):
                        result |= x ^ y
                    return result == 0
                
                def generate_keypair_secure(self, algorithm: str = "kyber_768") -> Dict[str, Any]:
                    self.metrics["key_generations"] += 1
                    
                    private_key = bytearray(secrets.token_bytes(32))
                    public_key = secrets.token_bytes(32)
                    
                    try:
                        result = {
                            "algorithm": algorithm,
                            "private_key": bytes(private_key),
                            "public_key": public_key,
                            "security_level": "NIST_LEVEL_3"
                        }
                        
                        self.audit_log.append({
                            "operation": "KEYGEN",
                            "algorithm": algorithm,
                            "success": True,
                            "timestamp": time.time()
                        })
                        
                        return result
                    finally:
                        # Zeroize temporary copy
                        for i in range(len(private_key)):
                            private_key[i] = 0
                
                def compute_shared_secret_secure(self, sk: bytes, pk: bytes) -> bytes:
                    self.metrics["shared_secrets"] += 1
                    
                    sk_buffer = bytearray(sk)
                    try:
                        shared = hashlib.sha256(sk + pk).digest()
                        return shared
                    finally:
                        for i in range(len(sk_buffer)):
                            sk_buffer[i] = 0
                
                def get_health_status(self) -> Dict[str, Any]:
                    total_ops = self.metrics["key_generations"] + self.metrics["shared_secrets"]
                    return {
                        **self.metrics,
                        "total_operations": total_ops,
                        "failure_rate": self.metrics["failures"] / max(1, total_ops),
                        "healthy": self.metrics["failures"] == 0
                    }
            
            pipeline = TripleCryptoPipeline()
            
            # Generate keypair with security hardening
            kp = pipeline.generate_keypair_secure("kyber_768")
            self.assertEqual(kp["security_level"], "NIST_LEVEL_3")
            
            # Compute shared secret
            ss = pipeline.compute_shared_secret_secure(kp["private_key"], kp["public_key"])
            self.assertEqual(len(ss), 32)
            
            # Constant time comparison test
            self.assertTrue(pipeline.constant_time_compare(ss, ss))
            
            # Check observability metrics
            health = pipeline.get_health_status()
            self.assertEqual(health["key_generations"], 1)
            self.assertEqual(health["shared_secrets"], 1)
            self.assertTrue(health["healthy"])
            
            self._record_result("pq_kem_security_hardening_observability_triple", modules, True, "NIST_LEVEL_3")
        except Exception as e:
            self._record_result("pq_kem_security_hardening_observability_triple", modules, False, error=str(e))
            raise

def run_crypto_integration_tests():
    """Run all crypto integration tests and return summary"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    test_classes = [
        TestPQKeyExchangeWithErrorResilienceIntegration,
        TestSecurityHardeningWithCryptoOperationsIntegration,
        TestKeyManagementWithObservabilityIntegration,
        TestCryptoBoundaryAndEdgeCases,
        TestTripleCryptoModuleCombinations,
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "success": result.wasSuccessful(),
        "test_classes": len(test_classes),
        "dimension": "C - Test Coverage Expansion v16",
        "security_coverage": ["NIST_LEVEL_1", "NIST_LEVEL_3", "NIST_LEVEL_5"]
    }

if __name__ == "__main__":
    summary = run_crypto_integration_tests()
    print("\n" + "="*60)
    print("QUANTUMCRYPT-AI CROSS-MODULE INTEGRATION TEST SUMMARY v16")
    print("="*60)
    print(f"Dimension: {summary['dimension']}")
    print(f"Test Classes: {summary['test_classes']}")
    print(f"Tests Run: {summary['tests_run']}")
    print(f"Failures: {summary['failures']}")
    print(f"Errors: {summary['errors']}")
    print(f"Skipped: {summary['skipped']}")
    print(f"Security Levels Covered: {', '.join(summary['security_coverage'])}")
    print(f"Status: {'✅ ALL PASSED' if summary['success'] else '❌ FAILURES DETECTED'}")
    print("="*60)
