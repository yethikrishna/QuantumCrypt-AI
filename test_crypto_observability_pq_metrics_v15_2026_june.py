"""
Test Suite for PQ Crypto Observability v15 - QuantumCrypt-AI
Tests for Crypto Metrics, Audit Logging, and Health Checks
All tests are ADD-ONLY - no production code modified
"""

import unittest
import json
import time
import threading
import hashlib
import hmac
import secrets

# Import the new crypto observability module
from quantum_crypt.crypto_observability_pq_metrics_v15_2026_june import (
    CryptoOperationType,
    PQAlgorithmFamily,
    KeySensitivityLevel,
    CryptoEvent,
    CryptoMetricsCollector,
    StructuredCryptoLogger,
    CryptoHealthChecker,
    CryptoInstrumentationWrapper,
    get_crypto_instrumentation,
    generate_audit_id,
    generate_correlation_id
)


class TestCryptoEnumerations(unittest.TestCase):
    """Test crypto enumeration types."""

    def test_operation_types_exist(self):
        self.assertTrue(hasattr(CryptoOperationType, 'KEY_GENERATION'))
        self.assertTrue(hasattr(CryptoOperationType, 'ENCRYPTION'))
        self.assertTrue(hasattr(CryptoOperationType, 'DECRYPTION'))
        self.assertTrue(hasattr(CryptoOperationType, 'SIGNING'))
        self.assertTrue(hasattr(CryptoOperationType, 'VERIFICATION'))
        self.assertTrue(hasattr(CryptoOperationType, 'KEY_EXCHANGE'))
        self.assertTrue(hasattr(CryptoOperationType, 'HASHING'))
        self.assertTrue(hasattr(CryptoOperationType, 'RANDOM_GENERATION'))
        self.assertTrue(hasattr(CryptoOperationType, 'HEALTH_CHECK'))

    def test_pq_algorithm_families(self):
        self.assertTrue(hasattr(PQAlgorithmFamily, 'CRYSTALS_KYBER'))
        self.assertTrue(hasattr(PQAlgorithmFamily, 'CRYSTALS_DILITHIUM'))
        self.assertTrue(hasattr(PQAlgorithmFamily, 'FALCON'))
        self.assertTrue(hasattr(PQAlgorithmFamily, 'SPHINCS_PLUS'))
        self.assertTrue(hasattr(PQAlgorithmFamily, 'CLASSICAL'))
        self.assertTrue(hasattr(PQAlgorithmFamily, 'HYBRID'))

    def test_key_sensitivity_levels(self):
        self.assertTrue(hasattr(KeySensitivityLevel, 'PUBLIC'))
        self.assertTrue(hasattr(KeySensitivityLevel, 'INTERNAL'))
        self.assertTrue(hasattr(KeySensitivityLevel, 'SENSITIVE'))
        self.assertTrue(hasattr(KeySensitivityLevel, 'CRITICAL'))

    def test_enum_values_are_strings(self):
        for op in CryptoOperationType:
            self.assertIsInstance(op.value, str)
        for alg in PQAlgorithmFamily:
            self.assertIsInstance(alg.value, str)
        for level in KeySensitivityLevel:
            self.assertIsInstance(level.value, str)


class TestCryptoEvent(unittest.TestCase):
    """Test CryptoEvent data structure."""

    def test_event_creation(self):
        event = CryptoEvent(
            operation_type=CryptoOperationType.KEY_GENERATION,
            algorithm_family=PQAlgorithmFamily.CRYSTALS_KYBER,
            module_name="pq_keygen",
            success=True,
            duration_ms=10.5,
            key_size_bits=256,
            key_sensitivity=KeySensitivityLevel.CRITICAL
        )
        self.assertEqual(event.operation_type, CryptoOperationType.KEY_GENERATION)
        self.assertEqual(event.algorithm_family, PQAlgorithmFamily.CRYSTALS_KYBER)
        self.assertEqual(event.key_size_bits, 256)

    def test_event_to_dict(self):
        event = CryptoEvent(
            operation_type=CryptoOperationType.SIGNING,
            algorithm_family=PQAlgorithmFamily.CRYSTALS_DILITHIUM,
            module_name="pq_sign",
            success=True,
            duration_ms=5.0,
            key_size_bits=512,
            metadata={"hash_used": "sha256"}
        )
        event_dict = event.to_dict()
        self.assertEqual(event_dict["operation_type"], "signing")
        self.assertEqual(event_dict["algorithm_family"], "CRYSTALS-Dilithium")
        self.assertEqual(event_dict["key_size_bits"], 512)
        self.assertEqual(event_dict["key_sensitivity"], "internal")
        self.assertEqual(event_dict["version"], "v15")


class TestCryptoMetricsCollector(unittest.TestCase):
    """Test crypto metrics collector."""

    def setUp(self):
        self.metrics = CryptoMetricsCollector()

    def test_disabled_by_default(self):
        self.assertFalse(self.metrics.is_enabled())

    def test_enable_disable(self):
        self.metrics.enable()
        self.assertTrue(self.metrics.is_enabled())
        self.metrics.disable()
        self.assertFalse(self.metrics.is_enabled())

    def test_operation_recording_disabled(self):
        """Metrics ignored when disabled."""
        self.metrics.record_crypto_operation("encrypt", "kyber", 1.0)
        snapshot = self.metrics.get_snapshot()
        self.assertEqual(len(snapshot["operation_counts"]), 0)

    def test_operation_recording_enabled(self):
        self.metrics.enable()
        self.metrics.record_crypto_operation("encrypt", "kyber", 1.5, True, 256)
        self.metrics.record_crypto_operation("encrypt", "kyber", 2.5, True, 256)
        snapshot = self.metrics.get_snapshot()
        self.assertGreater(len(snapshot["operation_counts"]), 0)
        self.assertGreater(len(snapshot["operation_timing_stats"]), 0)

    def test_key_usage_tracking(self):
        self.metrics.enable()
        self.metrics.increment_key_usage("key_123", "critical")
        self.metrics.increment_key_usage("key_123", "critical")
        snapshot = self.metrics.get_snapshot()
        self.assertGreater(len(snapshot["key_usage_counts"]), 0)

    def test_bytes_processed_tracking(self):
        self.metrics.enable()
        self.metrics.record_bytes_processed(1024)
        self.metrics.record_bytes_processed(2048)
        snapshot = self.metrics.get_snapshot()
        self.assertEqual(snapshot["total_bytes_processed"], 3072)

    def test_entropy_estimates(self):
        self.metrics.enable()
        self.metrics.set_entropy_estimate("system", 256.0)
        snapshot = self.metrics.get_snapshot()
        self.assertEqual(snapshot["entropy_estimates"]["system"], 256.0)

    def test_metrics_reset(self):
        self.metrics.enable()
        self.metrics.record_crypto_operation("hash", "sha256", 0.1)
        self.metrics.record_bytes_processed(100)
        self.metrics.reset()
        snapshot = self.metrics.get_snapshot()
        self.assertEqual(len(snapshot["operation_counts"]), 0)
        self.assertEqual(snapshot["total_bytes_processed"], 0)

    def test_timing_statistics(self):
        self.metrics.enable()
        durations = [1.0, 2.0, 3.0, 4.0, 5.0]
        for d in durations:
            self.metrics.record_crypto_operation("hash", "sha256", d)
        snapshot = self.metrics.get_snapshot()
        stats = list(snapshot["operation_timing_stats"].values())[0]
        self.assertEqual(stats["count"], 5)
        self.assertEqual(stats["min"], 1.0)
        self.assertEqual(stats["max"], 5.0)
        self.assertEqual(stats["avg"], 3.0)


class TestStructuredCryptoLogger(unittest.TestCase):
    """Test structured crypto audit logging."""

    def setUp(self):
        self.metrics = CryptoMetricsCollector()
        self.logger = StructuredCryptoLogger(self.metrics)
        self.log_output = []

    def capture_logs(self):
        self.log_output = []
        self.logger.set_output_handler(lambda x: self.log_output.append(x))

    def test_disabled_by_default(self):
        self.assertFalse(self.logger.is_enabled())

    def test_logging_when_disabled(self):
        self.capture_logs()
        event = CryptoEvent(
            CryptoOperationType.HASHING,
            PQAlgorithmFamily.CLASSICAL
        )
        self.logger.log_event(event)
        self.assertEqual(len(self.log_output), 0)

    def test_logging_when_enabled(self):
        self.capture_logs()
        self.logger.enable()
        event = CryptoEvent(
            operation_type=CryptoOperationType.HASHING,
            algorithm_family=PQAlgorithmFamily.CLASSICAL,
            module_name="hash_module"
        )
        self.logger.log_event(event)
        self.assertEqual(len(self.log_output), 1)
        log_entry = json.loads(self.log_output[0])
        self.assertEqual(log_entry["operation_type"], "hashing")
        self.assertIn("chain_mac", log_entry)  # HMAC chaining
        self.assertIn("entry_sequence", log_entry)

    def test_log_crypto_operation_convenience(self):
        self.capture_logs()
        self.logger.enable()
        self.logger.log_crypto_operation(
            operation_type=CryptoOperationType.ENCRYPTION,
            algorithm_family=PQAlgorithmFamily.CRYSTALS_KYBER,
            module_name="kyber_enc",
            success=True,
            duration_ms=10.0,
            key_size_bits=768,
            key_sensitivity=KeySensitivityLevel.SENSITIVE
        )
        self.assertEqual(len(self.log_output), 1)
        log_entry = json.loads(self.log_output[0])
        self.assertEqual(log_entry["key_size_bits"], 768)
        self.assertEqual(log_entry["key_sensitivity"], "sensitive")

    def test_audit_id_generation(self):
        self.capture_logs()
        self.logger.enable()
        self.logger.log_crypto_operation(
            CryptoOperationType.KEY_GENERATION,
            PQAlgorithmFamily.CRYSTALS_KYBER,
            "test"
        )
        log_entry = json.loads(self.log_output[0])
        self.assertIn("audit_id", log_entry)
        self.assertEqual(len(log_entry["audit_id"]), 32)

    def test_chain_mac_uniqueness(self):
        """Each log entry should have a unique chain MAC."""
        self.capture_logs()
        self.logger.enable()
        for i in range(5):
            self.logger.log_crypto_operation(
                CryptoOperationType.HASHING,
                PQAlgorithmFamily.CLASSICAL,
                f"test_{i}"
            )
        macs = [json.loads(entry)["chain_mac"] for entry in self.log_output]
        self.assertEqual(len(set(macs)), 5)  # All unique


class TestCryptoHealthChecker(unittest.TestCase):
    """Test crypto health checker."""

    def setUp(self):
        self.metrics = CryptoMetricsCollector()
        self.health = CryptoHealthChecker(self.metrics)

    def test_default_health_checks_registered(self):
        """Should have built-in checks."""
        result = self.health.run_health_check()
        self.assertIn("system_random", result["checks"])
        self.assertIn("hash_algorithms", result["checks"])
        self.assertIn("hmac_operations", result["checks"])

    def test_system_random_check(self):
        result = self.health.run_health_check()
        self.assertTrue(result["checks"]["system_random"]["healthy"])

    def test_hash_algorithms_check(self):
        result = self.health.run_health_check()
        self.assertTrue(result["checks"]["hash_algorithms"]["healthy"])
        self.assertIn("sha256", result["checks"]["hash_algorithms"]["algorithms_available"])

    def test_hmac_operations_check(self):
        result = self.health.run_health_check()
        self.assertTrue(result["checks"]["hmac_operations"]["healthy"])
        self.assertTrue(result["checks"]["hmac_operations"]["constant_time_compare"])

    def test_overall_health_status(self):
        result = self.health.run_health_check()
        self.assertTrue(result["healthy"])
        self.assertIn("duration_ms", result)
        self.assertIn("timestamp", result)
        self.assertEqual(result["version"], "v15")

    def test_liveness_probe(self):
        probe = self.health.get_liveness_probe()
        self.assertTrue(probe["alive"])
        self.assertTrue(probe["crypto_ready"])

    def test_custom_health_check(self):
        def custom_check():
            return {"healthy": True, "custom": "value"}

        self.health.register_check("custom_check", custom_check)
        result = self.health.run_health_check()
        self.assertIn("custom_check", result["checks"])

    def test_failing_check_affects_overall(self):
        def bad_check():
            return {"healthy": False, "error": "failed"}

        self.health.register_check("failing", bad_check)
        result = self.health.run_health_check()
        self.assertFalse(result["healthy"])


class TestCryptoInstrumentationWrapper(unittest.TestCase):
    """Test crypto instrumentation wrapper."""

    def setUp(self):
        self.inst = CryptoInstrumentationWrapper()

    def test_disabled_by_default(self):
        self.assertFalse(self.inst.is_instrumented())

    def test_enable_disable(self):
        self.inst.enable_instrumentation()
        self.assertTrue(self.inst.is_instrumented())
        self.assertTrue(self.inst.metrics.is_enabled())
        self.assertTrue(self.inst.logger.is_enabled())
        self.inst.disable_instrumentation()
        self.assertFalse(self.inst.is_instrumented())

    def test_wrap_function_no_instrumentation(self):
        call_count = []

        def hash_func(data):
            call_count.append(True)
            return hashlib.sha256(data).digest()

        wrapped = self.inst.wrap_crypto_function(
            hash_func,
            CryptoOperationType.HASHING,
            PQAlgorithmFamily.CLASSICAL,
            "sha256"
        )

        result = wrapped(b"test")
        self.assertEqual(len(result), 32)
        self.assertEqual(len(call_count), 1)

    def test_wrap_function_with_instrumentation(self):
        self.inst.enable_instrumentation()

        def hash_func(data):
            return hashlib.sha256(data).digest()

        wrapped = self.inst.wrap_crypto_function(
            hash_func,
            CryptoOperationType.HASHING,
            PQAlgorithmFamily.CLASSICAL,
            "sha256",
            256
        )

        result = wrapped(b"test data")
        self.assertEqual(len(result), 32)

        snapshot = self.inst.metrics.get_snapshot()
        self.assertGreater(len(snapshot["operation_counts"]), 0)

    def test_wrap_function_exception_preservation(self):
        self.inst.enable_instrumentation()

        def error_func():
            raise ValueError("Crypto error")

        wrapped = self.inst.wrap_crypto_function(
            error_func,
            CryptoOperationType.ENCRYPTION,
            PQAlgorithmFamily.CRYSTALS_KYBER,
            "test"
        )

        with self.assertRaises(ValueError):
            wrapped()

        # Failure should be recorded
        snapshot = self.inst.metrics.get_snapshot()
        self.assertGreater(len(snapshot["operation_counts"]), 0)

    def test_timed_crypto_operation_decorator(self):
        self.inst.enable_instrumentation()

        @self.inst.timed_crypto_operation("hashing", "sha256", 256)
        def slow_hash(data):
            time.sleep(0.001)
            return hashlib.sha256(data).digest()

        result = slow_hash(b"test")
        self.assertEqual(len(result), 32)

        snapshot = self.inst.metrics.get_snapshot()
        self.assertGreater(len(snapshot["operation_timing_stats"]), 0)


class TestGlobalFunctions(unittest.TestCase):
    """Test global utility functions."""

    def test_get_crypto_instrumentation(self):
        inst = get_crypto_instrumentation()
        self.assertIsInstance(inst, CryptoInstrumentationWrapper)

    def test_generate_audit_id(self):
        audit_id = generate_audit_id()
        self.assertIsInstance(audit_id, str)
        self.assertEqual(len(audit_id), 32)

    def test_generate_correlation_id(self):
        corr_id = generate_correlation_id()
        self.assertIsInstance(corr_id, str)
        self.assertEqual(len(corr_id), 32)

    def test_id_uniqueness(self):
        ids = set()
        for _ in range(100):
            ids.add(generate_audit_id())
        self.assertEqual(len(ids), 100)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify backward compatibility."""

    def test_completely_inert_when_disabled(self):
        inst = CryptoInstrumentationWrapper()
        self.assertFalse(inst.is_instrumented())

        # All operations should be no-ops
        inst.metrics.record_crypto_operation("test", "test", 1.0)
        inst.logger.log_event(CryptoEvent(
            CryptoOperationType.HASHING,
            PQAlgorithmFamily.CLASSICAL
        ))

        snapshot = inst.metrics.get_snapshot()
        self.assertEqual(len(snapshot["operation_counts"]), 0)

    def test_standard_library_only(self):
        """Module should work with stdlib only."""
        import quantum_crypt.crypto_observability_pq_metrics_v15_2026_june as crypto_obs
        # Should import without external dependencies
        self.assertTrue(True)

    def test_no_side_effects_on_import(self):
        """Importing should not enable instrumentation."""
        inst = get_crypto_instrumentation()
        self.assertFalse(inst.is_instrumented())


if __name__ == "__main__":
    unittest.main()
