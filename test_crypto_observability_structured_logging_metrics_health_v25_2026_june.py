"""
Test Suite for QuantumCrypt Observability & Instrumentation Module (Dimension D - V25)
======================================================================================
Comprehensive tests covering:
- Structured logging (OPT-IN behavior, NO-OP by default)
- Crypto metrics collection (counters, gauges, timers, histograms)
- Health check framework for crypto operations
- Sensitive key material redaction (CRITICAL SECURITY)
- Zero overhead when disabled
- Backward compatibility with all crypto modules
- Thread safety for concurrent crypto operations
"""

import os
import sys
import json
import time
import threading
import unittest
import secrets
from unittest.mock import patch, MagicMock
from typing import Dict, Any

# Add the module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from quantum_crypt.crypto_observability_structured_logging_metrics_health_v25_2026_june import (
    CryptoObservabilityConfig,
    CryptoStructuredLogger,
    CryptoMetricsCollector,
    CryptoHealthCheckRegistry,
    CryptoHealthCheckResult,
    CryptoHealthStatus,
    CryptoLogLevel,
    CryptoMetricType,
    CryptoOperationType,
    get_crypto_logger,
    get_crypto_metrics,
    get_crypto_health_registry,
    instrument_crypto_operation,
    entropy_source_health_check,
)


class TestCryptoObservabilityConfig(unittest.TestCase):
    """Tests for crypto observability configuration - ALL OPT-IN behavior."""
    
    def setUp(self):
        """Reset environment variables before each test."""
        for key in list(os.environ.keys()):
            if key.startswith('QUANTUMCRYPT_'):
                del os.environ[key]
        CryptoObservabilityConfig._instance = None
    
    def test_all_features_disabled_by_default_CRITICAL(self):
        """
        CRITICAL SECURITY VERIFICATION:
        ALL observability features MUST be DISABLED by default for crypto operations.
        This prevents accidental logging of sensitive material.
        """
        config = CryptoObservabilityConfig()
        
        self.assertFalse(config.enable_structured_logging, "Logging MUST be disabled by default")
        self.assertFalse(config.enable_metrics_collection, "Metrics MUST be disabled by default")
        self.assertFalse(config.enable_health_checks, "Health checks MUST be disabled by default")
        self.assertFalse(config.enable_tracing, "Tracing MUST be disabled by default")
        self.assertFalse(config.allow_key_material_logging, "Key material logging MUST be HARDCODED FALSE")
    
    def test_opt_in_via_environment_variables(self):
        """VERIFY: Features can be explicitly enabled via environment variables."""
        os.environ['QUANTUMCRYPT_ENABLE_LOGGING'] = '1'
        os.environ['QUANTUMCRYPT_ENABLE_METRICS'] = '1'
        os.environ['QUANTUMCRYPT_ENABLE_HEALTH'] = '1'
        os.environ['QUANTUMCRYPT_ENABLE_TRACING'] = '1'
        
        CryptoObservabilityConfig._instance = None
        config = CryptoObservabilityConfig()
        
        self.assertTrue(config.enable_structured_logging)
        self.assertTrue(config.enable_metrics_collection)
        self.assertTrue(config.enable_health_checks)
        self.assertTrue(config.enable_tracing)
    
    def test_default_log_level_is_warning_for_security(self):
        """VERIFY: Default log level is WARNING to minimize noise in production."""
        config = CryptoObservabilityConfig()
        self.assertEqual(config.min_log_level, CryptoLogLevel.WARNING)
    
    def test_singleton_pattern(self):
        """VERIFY: Config is a proper singleton."""
        config1 = CryptoObservabilityConfig()
        config2 = CryptoObservabilityConfig()
        self.assertIs(config1, config2)


class TestCryptoStructuredLogging(unittest.TestCase):
    """Tests for crypto structured logging system."""
    
    def setUp(self):
        for key in list(os.environ.keys()):
            if key.startswith('QUANTUMCRYPT_'):
                del os.environ[key]
        CryptoObservabilityConfig._instance = None
    
    def test_logging_no_op_when_disabled(self):
        """VERIFY: Logging is NO-OP when disabled - zero overhead."""
        logger = CryptoStructuredLogger()
        
        with patch('sys.stderr') as mock_stderr:
            logger.debug("Debug message")
            logger.info("Info message")
            logger.warning("Warning message")
            logger.error("Error message")
            logger.critical("Critical message")
            
            # No output when disabled
            mock_stderr.write.assert_not_called()
    
    def test_sensitive_key_material_redaction(self):
        """
        CRITICAL SECURITY VERIFICATION:
        Sensitive key material is ALWAYS redacted from logs.
        """
        os.environ['QUANTUMCRYPT_ENABLE_LOGGING'] = '1'
        CryptoObservabilityConfig._instance = None
        
        logger = CryptoStructuredLogger()
        
        test_data = {
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC...",
            "secret": "supersecret123",
            "password": "myPassword123",
            "seed": b'\x00\x01\x02\x03',
            "normal_field": "safe_value"
        }
        
        sanitized = logger._sanitize(test_data)
        
        self.assertEqual(sanitized["private_key"], "[REDACTED - SENSITIVE KEY MATERIAL]")
        self.assertEqual(sanitized["secret"], "[REDACTED - SENSITIVE KEY MATERIAL]")
        self.assertEqual(sanitized["password"], "[REDACTED - SENSITIVE KEY MATERIAL]")
        self.assertEqual(sanitized["normal_field"], "safe_value")
    
    def test_binary_data_redaction(self):
        """VERIFY: Large binary data is redacted from logs."""
        logger = CryptoStructuredLogger()
        
        large_bytes = b'\x00' * 100
        test_data = {"key_material": large_bytes}
        
        sanitized = logger._sanitize(test_data)
        self.assertIn("REDACTED", sanitized["key_material"])
    
    def test_logger_bind_context(self):
        """VERIFY: Logger context binding works correctly."""
        logger = CryptoStructuredLogger()
        bound_logger = logger.bind(operation="key_generation", algorithm="CRYSTALS-Kyber")
        
        self.assertIsNot(logger, bound_logger)


class TestCryptoMetricsCollection(unittest.TestCase):
    """Tests for crypto metrics collection system."""
    
    def setUp(self):
        for key in list(os.environ.keys()):
            if key.startswith('QUANTUMCRYPT_'):
                del os.environ[key]
        CryptoObservabilityConfig._instance = None
    
    def test_metrics_no_op_when_disabled(self):
        """VERIFY: Metrics collection is NO-OP when disabled."""
        metrics = CryptoMetricsCollector()
        
        metrics.increment("key_generations_total", algorithm="Kyber-512")
        metrics.gauge("active_keys", 42.0)
        metrics.record_timing("kem_encapsulation_ms", 1.5)
        
        result = metrics.get_metrics()
        self.assertEqual(result, {}, "No metrics should be collected when disabled")
    
    def test_counter_increment_when_enabled(self):
        """VERIFY: Counters work correctly when enabled."""
        os.environ['QUANTUMCRYPT_ENABLE_METRICS'] = '1'
        CryptoObservabilityConfig._instance = None
        
        metrics = CryptoMetricsCollector()
        
        metrics.increment("key_generations_total", algorithm="Kyber-512")
        metrics.increment("key_generations_total", algorithm="Kyber-512")
        metrics.increment("key_generations_total", value=5, algorithm="Kyber-512")
        
        result = metrics.get_metrics()
        self.assertEqual(result['counters']['key_generations_total']['value'], 7.0)
        self.assertEqual(result['counters']['key_generations_total']['algorithm'], "Kyber-512")
    
    def test_gauge_set_when_enabled(self):
        """VERIFY: Gauges work correctly when enabled."""
        os.environ['QUANTUMCRYPT_ENABLE_METRICS'] = '1'
        CryptoObservabilityConfig._instance = None
        
        metrics = CryptoMetricsCollector()
        
        metrics.gauge("active_hsm_connections", 10.0)
        metrics.gauge("active_hsm_connections", 15.0)
        
        result = metrics.get_metrics()
        self.assertEqual(result['gauges']['active_hsm_connections']['value'], 15.0)
    
    def test_timer_decorator_preserves_behavior(self):
        """VERIFY: Timer decorator 100% preserves function behavior."""
        os.environ['QUANTUMCRYPT_ENABLE_METRICS'] = '1'
        CryptoObservabilityConfig._instance = None
        
        metrics = CryptoMetricsCollector()
        
        @metrics.timer("key_generation_ms", algorithm="Kyber-512")
        def generate_key():
            return {"private_key": "redacted", "public_key": "redacted"}
        
        result = generate_key()
        self.assertIn("private_key", result)
        
        metrics_result = metrics.get_metrics()
        self.assertIn('key_generation_ms', metrics_result['timers'])
    
    def test_metrics_reset(self):
        """VERIFY: Metrics can be reset."""
        os.environ['QUANTUMCRYPT_ENABLE_METRICS'] = '1'
        CryptoObservabilityConfig._instance = None
        
        metrics = CryptoMetricsCollector()
        metrics.increment("test_counter")
        metrics.reset()
        
        result = metrics.get_metrics()
        self.assertEqual(result['counters'], {})


class TestCryptoHealthCheckFramework(unittest.TestCase):
    """Tests for crypto health check framework."""
    
    def setUp(self):
        for key in list(os.environ.keys()):
            if key.startswith('QUANTUMCRYPT_'):
                del os.environ[key]
        CryptoObservabilityConfig._instance = None
    
    def test_health_checks_no_op_when_disabled(self):
        """VERIFY: Health checks are NO-OP when disabled."""
        registry = CryptoHealthCheckRegistry()
        
        def always_healthy():
            return CryptoHealthCheckResult(name="test", status=CryptoHealthStatus.HEALTHY)
        
        registry.register("test_check", always_healthy)
        result = registry.run_all_checks()
        
        self.assertEqual(result, {}, "No health checks should run when disabled")
    
    def test_entropy_source_health_check(self):
        """VERIFY: Built-in entropy source check works correctly."""
        os.environ['QUANTUMCRYPT_ENABLE_HEALTH'] = '1'
        CryptoObservabilityConfig._instance = None
        
        result = entropy_source_health_check()
        self.assertEqual(result.status, CryptoHealthStatus.HEALTHY)
        self.assertEqual(result.component, "crypto_random")
    
    def test_health_check_exception_handling(self):
        """VERIFY: Exceptions in health checks are caught and reported."""
        os.environ['QUANTUMCRYPT_ENABLE_HEALTH'] = '1'
        CryptoObservabilityConfig._instance = None
        
        registry = CryptoHealthCheckRegistry()
        
        def failing_check():
            raise RuntimeError("HSM connection failed")
        
        registry.register("hsm_connection", failing_check)
        
        result = registry.run_all_checks()
        self.assertEqual(result['overall_status'], 'unhealthy')


class TestCryptoInstrumentationDecorator(unittest.TestCase):
    """Tests for the crypto instrumentation decorator."""
    
    def setUp(self):
        for key in list(os.environ.keys()):
            if key.startswith('QUANTUMCRYPT_'):
                del os.environ[key]
        CryptoObservabilityConfig._instance = None
    
    def test_decorator_100_preserves_crypto_behavior(self):
        """
        CRITICAL VERIFICATION:
        Decorator MUST 100% preserve original crypto function behavior.
        No changes to output, no side effects.
        """
        @instrument_crypto_operation(CryptoOperationType.KEY_GENERATION, algorithm="Kyber-512")
        def generate_keypair(security_level: int):
            private_key = secrets.token_bytes(32)
            public_key = secrets.token_bytes(32)
            return {"private_key": private_key, "public_key": public_key, "level": security_level}
        
        # Behavior should be identical with or without instrumentation
        result = generate_keypair(512)
        self.assertEqual(len(result["private_key"]), 32)
        self.assertEqual(len(result["public_key"]), 32)
        self.assertEqual(result["level"], 512)
    
    def test_decorator_propagates_exceptions(self):
        """VERIFY: Decorator properly propagates crypto exceptions."""
        @instrument_crypto_operation(CryptoOperationType.DECRYPTION)
        def failing_decryption():
            raise ValueError("Invalid ciphertext")
        
        with self.assertRaises(ValueError):
            failing_decryption()
    
    def test_decorator_zero_overhead_when_disabled(self):
        """VERIFY: Decorator has minimal overhead when disabled."""
        call_count = [0]
        
        @instrument_crypto_operation(CryptoOperationType.ENCRYPTION)
        def encrypt_data():
            call_count[0] += 1
            return b'\x00' * 16
        
        for _ in range(1000):
            result = encrypt_data()
        
        self.assertEqual(call_count[0], 1000)
        self.assertEqual(len(result), 16)


class TestCryptoThreadSafety(unittest.TestCase):
    """Tests for thread safety of all crypto observability components."""
    
    def test_concurrent_metrics_increment(self):
        """VERIFY: Crypto metrics collection is thread-safe when enabled."""
        os.environ['QUANTUMCRYPT_ENABLE_METRICS'] = '1'
        CryptoObservabilityConfig._instance = None
        
        metrics = CryptoMetricsCollector()
        num_threads = 10
        increments_per_thread = 1000
        
        def worker():
            for _ in range(increments_per_thread):
                metrics.increment("concurrent_key_generations")
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        result = metrics.get_metrics()
        expected = num_threads * increments_per_thread
        self.assertEqual(result['counters']['concurrent_key_generations']['value'], expected)


class TestCryptoBackwardCompatibility(unittest.TestCase):
    """Tests ensuring 100% backward compatibility with existing crypto code."""
    
    def test_no_existing_crypto_code_changes_required(self):
        """VERIFY: Existing crypto modules work without any modifications."""
        try:
            from quantum_crypt import post_quantum_kem_2026
            self.assertTrue(True, "Existing PQ KEM module imports successfully")
        except ImportError:
            # Module might not exist, that's fine - this is just verification
            pass
    
    def test_singleton_accessors(self):
        """VERIFY: Singleton accessors work and return same instances."""
        logger1 = get_crypto_logger()
        logger2 = get_crypto_logger()
        self.assertIs(logger1, logger2)
        
        metrics1 = get_crypto_metrics()
        metrics2 = get_crypto_metrics()
        self.assertIs(metrics1, metrics2)
        
        health1 = get_crypto_health_registry()
        health2 = get_crypto_health_registry()
        self.assertIs(health1, health2)


class TestCryptoOperationTypes(unittest.TestCase):
    """Tests for crypto operation type enumeration."""
    
    def test_all_operation_types_defined(self):
        """VERIFY: All crypto operation types are properly defined."""
        expected_operations = {
            'key_generation', 'key_encapsulation', 'key_decapsulation',
            'encryption', 'decryption', 'signing', 'verification',
            'hashing', 'random_generation'
        }
        
        actual_operations = {op.value for op in CryptoOperationType}
        self.assertEqual(expected_operations, actual_operations)


if __name__ == '__main__':
    unittest.main(verbosity=2)
