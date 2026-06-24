"""
Test Suite for QuantumCrypt Observability & Instrumentation v23
Dimension D: Observability & Instrumentation
Version: v23

All tests verify ADD-ONLY functionality.
No existing code is modified or broken.
"""

import unittest
import time
import threading
import json
import sys
import io
from typing import Dict, Any
from unittest.mock import patch, MagicMock

# Import the new module
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')
from quantum_crypt.crypto_observability_instrumentation_v23_2026_june import (
    # Config
    CryptoObservabilityConfig,
    configure_crypto_observability,
    get_crypto_config,
    # Key protection
    _redact_key_material,
    get_key_fingerprint,
    # Audit logging
    CryptoOperationType,
    crypto_audit_log,
    audit_info,
    audit_warning,
    audit_error,
    crypto_audit_context,
    get_audit_correlation_id,
    # Metrics
    crypto_operation_timer,
    timed_crypto_operation,
    get_crypto_metrics_snapshot,
    # HSM health
    HSMHealthStatus,
    HSMHealthCheckResult,
    register_hsm_health_check,
    run_hsm_health_checks,
    # PQ performance
    PQAlgorithmClass,
    record_pq_performance,
    get_pq_performance_summary,
    # Constant time
    record_constant_time_sample,
    analyze_constant_time_safety,
    # Instrumentation
    instrument_crypto_operation,
    # Metadata
    CRYPTO_OBSERVABILITY_VERSION,
    CRYPTO_OBSERVABILITY_DIMENSION,
    get_crypto_observability_metadata,
)


class TestCryptoObservabilityConfig(unittest.TestCase):
    """Test crypto observability configuration."""
    
    def test_default_config_all_disabled(self):
        """ALL FEATURES DISABLED BY DEFAULT - critical requirement."""
        config = get_crypto_config()
        self.assertFalse(config.enable_crypto_audit_logging)
        self.assertFalse(config.enable_crypto_metrics)
        self.assertFalse(config.enable_hsm_health_checks)
        self.assertFalse(config.enable_key_lifecycle_tracing)
        self.assertFalse(config.enable_side_channel_monitoring)
        self.assertFalse(config.enable_constant_time_verification)
        self.assertFalse(config.is_any_enabled())
    
    def test_key_material_redaction_enabled_by_default(self):
        """Key material redaction ENABLED by default for security."""
        config = get_crypto_config()
        self.assertTrue(config.redact_all_key_material)
        self.assertTrue(config.log_key_hashes_only)
    
    def test_configure_crypto_observability(self):
        """Test enabling specific features."""
        configure_crypto_observability(enable_crypto_audit_logging=True)
        config = get_crypto_config()
        self.assertTrue(config.enable_crypto_audit_logging)
        # Reset
        configure_crypto_observability(enable_crypto_audit_logging=False)


class TestKeyMaterialProtection(unittest.TestCase):
    """Test key material protection and redaction."""
    
    def test_bytes_key_material_redaction(self):
        """Test bytes key material is redacted."""
        key_data = b'\x00\x01\x02\x03' * 10  # 40 bytes of key material
        result = _redact_key_material(key_data)
        self.assertIn("KEY_MATERIAL", result)
        self.assertNotEqual(result, key_data)
    
    def test_long_string_key_redaction(self):
        """Test long base64-like strings are redacted."""
        key_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        result = _redact_key_material(key_str)
        self.assertEqual(result, "[KEY_MATERIAL REDACTED]")
    
    def test_dict_key_redaction(self):
        """Test nested dict key material is redacted."""
        data = {
            'private_key': b'secret-key-data-here-12345',
            'public_info': 'ok',
            'nested': {'hsm_key': b'more-secret-data'}
        }
        redacted = _redact_key_material(data)
        self.assertIn("KEY_MATERIAL", redacted['private_key'])
        self.assertEqual(redacted['public_info'], 'ok')
        self.assertIn("KEY_MATERIAL", redacted['nested']['hsm_key'])
    
    def test_get_key_fingerprint(self):
        """Test key fingerprint generation."""
        key = b'test-key-material-12345'
        fp = get_key_fingerprint(key)
        self.assertEqual(len(fp), 32)  # First 32 chars of SHA256
        self.assertTrue(all(c in '0123456789abcdef' for c in fp))


class TestCryptoAuditLogging(unittest.TestCase):
    """Test crypto audit logging functionality."""
    
    def setUp(self):
        configure_crypto_observability(enable_crypto_audit_logging=True, audit_log_level="DEBUG")
    
    def tearDown(self):
        configure_crypto_observability(enable_crypto_audit_logging=False)
    
    def test_crypto_audit_log_format(self):
        """Test audit log produces valid JSON with crypto-specific fields."""
        captured_output = io.StringIO()
        with patch('sys.stdout', new=captured_output):
            crypto_audit_log("INFO", CryptoOperationType.KEY_GENERATION, 
                           "Key generation complete", algorithm="RSA", key_id="key-123")
        
        output = captured_output.getvalue().strip()
        log_entry = json.loads(output)
        
        self.assertIn('timestamp', log_entry)
        self.assertIn('operation_type', log_entry)
        self.assertEqual(log_entry['operation_type'], "key_generation")
        self.assertIn('algorithm', log_entry)
        self.assertIn('key_id', log_entry)
        self.assertTrue(log_entry.get('crypto_audit', False))
    
    def test_audit_context_manager(self):
        """Test crypto audit correlation context."""
        with crypto_audit_context("op-456") as cid:
            self.assertEqual(cid, "op-456")
            self.assertEqual(get_audit_correlation_id(), "op-456")
        self.assertIsNone(get_audit_correlation_id())
    
    def test_audit_logging_disabled_by_default(self):
        """Test audit logging does nothing when disabled."""
        configure_crypto_observability(enable_crypto_audit_logging=False)
        
        captured_output = io.StringIO()
        with patch('sys.stdout', new=captured_output):
            audit_info(CryptoOperationType.ENCRYPTION, "This should not appear")
        
        output = captured_output.getvalue().strip()
        self.assertEqual(output, "")


class TestCryptoOperationMetrics(unittest.TestCase):
    """Test crypto operation metrics collection."""
    
    def setUp(self):
        configure_crypto_observability(enable_crypto_metrics=True)
    
    def tearDown(self):
        configure_crypto_observability(enable_crypto_metrics=False)
    
    def test_crypto_operation_timer_context(self):
        """Test crypto operation timer context manager."""
        with crypto_operation_timer(CryptoOperationType.SIGNATURE, algorithm="ECDSA"):
            time.sleep(0.001)
        
        metrics = get_crypto_metrics_snapshot()
        self.assertIn('signature', metrics['operation_counts'])
        self.assertGreater(metrics['operation_counts']['signature'], 0)
    
    def test_timed_crypto_operation_decorator(self):
        """Test timed crypto operation decorator."""
        @timed_crypto_operation(CryptoOperationType.ENCRYPTION, algorithm="AES")
        def encrypt_data():
            time.sleep(0.001)
            return "encrypted"
        
        result = encrypt_data()
        self.assertEqual(result, "encrypted")
        
        metrics = get_crypto_metrics_snapshot()
        self.assertIn('encryption', metrics['operation_counts'])
    
    def test_algorithm_performance_tracking(self):
        """Test algorithm-specific performance tracking."""
        with crypto_operation_timer(CryptoOperationType.KEY_GENERATION, algorithm="RSA-4096"):
            time.sleep(0.001)
        
        metrics = get_crypto_metrics_snapshot()
        self.assertIn('RSA-4096', metrics['algorithm_performance'])
        self.assertGreater(metrics['algorithm_performance']['RSA-4096']['count'], 0)
    
    def test_metrics_disabled_by_default(self):
        """Test metrics do nothing when disabled."""
        configure_crypto_observability(enable_crypto_metrics=False)
        
        with crypto_operation_timer(CryptoOperationType.HASH):
            pass
        
        metrics = get_crypto_metrics_snapshot()
        self.assertEqual(metrics, {})


class TestHSMHealthMonitoring(unittest.TestCase):
    """Test HSM health monitoring."""
    
    def setUp(self):
        configure_crypto_observability(enable_hsm_health_checks=True)
    
    def tearDown(self):
        configure_crypto_observability(enable_hsm_health_checks=False)
    
    def test_hsm_health_check_result(self):
        """Test HSM health check result creation."""
        result = HSMHealthCheckResult(
            hsm_id="hsm-prod-01",
            status=HSMHealthStatus.ONLINE,
            latency_ms=1.5,
            available_keys=100,
            message="HSM operating normally"
        )
        self.assertEqual(result.hsm_id, "hsm-prod-01")
        self.assertEqual(result.status, HSMHealthStatus.ONLINE)
    
    def test_register_and_run_hsm_check(self):
        """Test registering and running HSM health checks."""
        def hsm1_check():
            return HSMHealthCheckResult(
                hsm_id="hsm-1",
                status=HSMHealthStatus.ONLINE,
                latency_ms=2.0
            )
        
        register_hsm_health_check("hsm-1", hsm1_check)
        result = run_hsm_health_checks()
        
        # Verify our check was registered and ran
        self.assertIn("hsm-1", result['hsm_statuses'])
        self.assertEqual(result['hsm_statuses']["hsm-1"]['status'], "online")
    
    def test_hsm_health_unhealthy_propagates(self):
        """Test offline HSM affects overall status."""
        def bad_hsm_check():
            return HSMHealthCheckResult(
                hsm_id="bad-hsm",
                status=HSMHealthStatus.OFFLINE,
                message="Connection failed"
            )
        
        register_hsm_health_check("bad-hsm", bad_hsm_check)
        result = run_hsm_health_checks()
        
        self.assertEqual(result['overall_status'], "offline")
    
    def test_hsm_checks_disabled_by_default(self):
        """Test HSM checks report disabled status."""
        configure_crypto_observability(enable_hsm_health_checks=False)
        result = run_hsm_health_checks()
        self.assertIn("disabled", result['message'].lower())


class TestPQPerformanceTracking(unittest.TestCase):
    """Test Post-Quantum algorithm performance tracking."""
    
    def setUp(self):
        configure_crypto_observability(enable_crypto_metrics=True)
    
    def tearDown(self):
        configure_crypto_observability(enable_crypto_metrics=False)
    
    def test_record_pq_performance(self):
        """Test recording PQ algorithm performance."""
        record_pq_performance(
            algorithm="CRYSTALS-Kyber",
            alg_class=PQAlgorithmClass.LATTICE,
            operation="keygen",
            key_size_bits=1024,
            duration_seconds=0.005
        )
        
        summary = get_pq_performance_summary()
        self.assertGreater(summary['total_samples'], 0)
        self.assertIn("CRYSTALS-Kyber", summary['by_algorithm'])


class TestConstantTimeVerification(unittest.TestCase):
    """Test constant-time execution verification."""
    
    def setUp(self):
        configure_crypto_observability(enable_constant_time_verification=True)
    
    def tearDown(self):
        configure_crypto_observability(enable_constant_time_verification=False)
    
    def test_record_and_analyze_constant_time(self):
        """Test recording and analyzing constant-time samples."""
        # Record samples for different input variants
        for i in range(10):
            record_constant_time_sample("rsa-sign", 0.001 + i*0.0001, f"variant-{i%2}")
        
        analysis = analyze_constant_time_safety("rsa-sign")
        self.assertIn('variants_tested', analysis)
        self.assertIn('risk_assessment', analysis)
        self.assertIn('max_timing_diff_us', analysis)
    
    def test_constant_time_disabled_by_default(self):
        """Test constant-time verification does nothing when disabled."""
        configure_crypto_observability(enable_constant_time_verification=False)
        
        record_constant_time_sample("test-op", 0.001, "var1")
        analysis = analyze_constant_time_safety("test-op")
        self.assertFalse(analysis['enabled'])


class TestCryptoInstrumentationWrappers(unittest.TestCase):
    """Test crypto instrumentation wrappers."""
    
    def setUp(self):
        configure_crypto_observability(
            enable_crypto_audit_logging=True,
            enable_crypto_metrics=True
        )
    
    def tearDown(self):
        configure_crypto_observability(
            enable_crypto_audit_logging=False,
            enable_crypto_metrics=False
        )
    
    def test_instrument_crypto_operation_decorator(self):
        """Test crypto operation instrumentation decorator."""
        @instrument_crypto_operation(CryptoOperationType.DECRYPTION, algorithm="AES-GCM")
        def decrypt_data(ciphertext):
            return "plaintext"
        
        result = decrypt_data("encrypted-data")
        self.assertEqual(result, "plaintext")
        
        metrics = get_crypto_metrics_snapshot()
        self.assertIn('decryption', metrics['operation_counts'])
    
    def test_zero_overhead_when_disabled(self):
        """Test ZERO overhead path when observability disabled."""
        configure_crypto_observability(
            enable_crypto_audit_logging=False,
            enable_crypto_metrics=False
        )
        
        call_count = [0]
        @instrument_crypto_operation(CryptoOperationType.HASH)
        def hash_data():
            call_count[0] += 1
            return "hash-result"
        
        result = hash_data()
        self.assertEqual(result, "hash-result")
        self.assertEqual(call_count[0], 1)
    
    def test_wrapper_preserves_metadata(self):
        """Test wrappers preserve function metadata."""
        def original():
            """Original crypto function"""
            pass
        
        wrapped = instrument_crypto_operation(CryptoOperationType.HASH)(original)
        self.assertEqual(wrapped.__doc__, "Original crypto function")
        self.assertEqual(wrapped.__name__, "original")


class TestVersionAndMetadata(unittest.TestCase):
    """Test version and metadata."""
    
    def test_version_correct(self):
        """Test version is v23."""
        self.assertEqual(CRYPTO_OBSERVABILITY_VERSION, "23.0.0")
    
    def test_dimension_correct(self):
        """Test dimension is D."""
        self.assertEqual(CRYPTO_OBSERVABILITY_DIMENSION, "D")
    
    def test_get_crypto_observability_metadata(self):
        """Test metadata function."""
        metadata = get_crypto_observability_metadata()
        self.assertEqual(metadata['version'], "23.0.0")
        self.assertEqual(metadata['dimension'], "D")
        self.assertIn('features', metadata)
        self.assertIn('config', metadata)
        self.assertTrue(metadata['key_material_protection'])


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of crypto observability components."""
    
    def setUp(self):
        configure_crypto_observability(enable_crypto_metrics=True)
    
    def tearDown(self):
        configure_crypto_observability(enable_crypto_metrics=False)
    
    def test_concurrent_metric_recording(self):
        """Test concurrent metric recording is thread-safe."""
        num_threads = 10
        operations_per_thread = 50
        
        def worker():
            for _ in range(operations_per_thread):
                with crypto_operation_timer(CryptoOperationType.HASH):
                    pass
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        metrics = get_crypto_metrics_snapshot()
        expected = num_threads * operations_per_thread
        self.assertEqual(metrics['operation_counts']['hash'], expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
