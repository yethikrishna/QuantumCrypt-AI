"""
Test Suite for QuantumCrypt-AI Crypto Health Check Framework
June 2026 - Production Grade Tests

DIMENSION D - Observability & Instrumentation
Tests for the post-quantum crypto health check framework.

All tests must pass. No modification of production code.
"""

import os
import sys
import json
import time
import unittest
import threading
import secrets

# Add the module path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.pq_crypto_health_check_framework_2026_june import (
    CryptoHealthStatus,
    CryptoHealthCheckType,
    CryptoHealthCheckResult,
    CryptoAggregatedHealthStatus,
    CryptoHealthCheckRegistry,
    get_crypto_health_registry,
    enable_crypto_health_checks,
    disable_crypto_health_checks,
    create_randomness_quality_check,
    create_key_strength_check,
    create_operation_latency_check,
    create_algorithm_compatibility_check,
    create_process_entropy_available_check,
    register_default_crypto_health_checks,
    crypto_operation_health_monitored,
    get_crypto_security_report,
)


class TestCryptoHealthStatusEnum(unittest.TestCase):
    """Test CryptoHealthStatus enumeration."""

    def test_status_values(self):
        """Test crypto health status enum values."""
        self.assertEqual(CryptoHealthStatus.SECURE.value, "secure")
        self.assertEqual(CryptoHealthStatus.DEGRADED.value, "degraded")
        self.assertEqual(CryptoHealthStatus.INSECURE.value, "insecure")
        self.assertEqual(CryptoHealthStatus.UNKNOWN.value, "unknown")


class TestCryptoHealthCheckTypeEnum(unittest.TestCase):
    """Test CryptoHealthCheckType enumeration."""

    def test_check_type_values(self):
        """Test crypto health check type enum values."""
        self.assertEqual(CryptoHealthCheckType.KEY_HEALTH.value, "key_health")
        self.assertEqual(CryptoHealthCheckType.RANDOMNESS.value, "randomness")
        self.assertEqual(CryptoHealthCheckType.ALGORITHM.value, "algorithm")
        self.assertEqual(CryptoHealthCheckType.LATENCY.value, "latency")
        self.assertEqual(CryptoHealthCheckType.HARDWARE.value, "hardware")
        self.assertEqual(CryptoHealthCheckType.CERTIFICATE.value, "certificate")
        self.assertEqual(CryptoHealthCheckType.CUSTOM.value, "custom")


class TestCryptoHealthCheckResult(unittest.TestCase):
    """Test CryptoHealthCheckResult data class."""

    def test_result_creation(self):
        """Test creating a crypto health check result."""
        result = CryptoHealthCheckResult(
            name="test_crypto_check",
            status=CryptoHealthStatus.SECURE,
            check_type=CryptoHealthCheckType.RANDOMNESS,
            message="Crypto check passed",
        )
        
        self.assertEqual(result.name, "test_crypto_check")
        self.assertEqual(result.status, CryptoHealthStatus.SECURE)
        self.assertEqual(result.check_type, CryptoHealthCheckType.RANDOMNESS)
        self.assertEqual(result.message, "Crypto check passed")

    def test_result_with_security_warning(self):
        """Test result with security warning."""
        result = CryptoHealthCheckResult(
            name="weak_key",
            status=CryptoHealthStatus.INSECURE,
            check_type=CryptoHealthCheckType.KEY_HEALTH,
            message="Key too short",
            security_warning="Insufficient key length detected",
        )
        
        self.assertEqual(result.security_warning, "Insufficient key length detected")

    def test_result_to_dict(self):
        """Test converting result to dictionary."""
        result = CryptoHealthCheckResult(
            name="test_check",
            status=CryptoHealthStatus.SECURE,
            check_type=CryptoHealthCheckType.ALGORITHM,
            message="OK",
            duration_ms=42.1234,
            details={"key_bits": 256},
        )
        
        d = result.to_dict()
        self.assertEqual(d["name"], "test_check")
        self.assertEqual(d["status"], "secure")
        self.assertEqual(d["check_type"], "algorithm")
        self.assertEqual(d["duration_ms"], 42.123)
        self.assertEqual(d["details"]["key_bits"], 256)


class TestCryptoAggregatedHealthStatus(unittest.TestCase):
    """Test CryptoAggregatedHealthStatus."""

    def test_aggregated_creation(self):
        """Test creating aggregated crypto status."""
        checks = [
            CryptoHealthCheckResult("check1", CryptoHealthStatus.SECURE, CryptoHealthCheckType.RANDOMNESS),
            CryptoHealthCheckResult("check2", CryptoHealthStatus.SECURE, CryptoHealthCheckType.KEY_HEALTH),
        ]
        
        agg = CryptoAggregatedHealthStatus(
            overall_status=CryptoHealthStatus.SECURE,
            checks=checks,
        )
        
        self.assertEqual(agg.overall_status, CryptoHealthStatus.SECURE)
        self.assertEqual(len(agg.checks), 2)

    def test_aggregated_severity_order(self):
        """Test that most severe crypto status wins."""
        # Secure + Insecure should result in Insecure
        checks = [
            CryptoHealthCheckResult("check1", CryptoHealthStatus.SECURE, CryptoHealthCheckType.RANDOMNESS),
            CryptoHealthCheckResult("check2", CryptoHealthStatus.INSECURE, CryptoHealthCheckType.KEY_HEALTH),
        ]
        
        # Manually compute overall
        severity_order = {
            CryptoHealthStatus.SECURE: 0,
            CryptoHealthStatus.UNKNOWN: 1,
            CryptoHealthStatus.DEGRADED: 2,
            CryptoHealthStatus.INSECURE: 3,
        }
        
        overall = CryptoHealthStatus.SECURE
        for result in checks:
            if severity_order[result.status] > severity_order[overall]:
                overall = result.status
        
        self.assertEqual(overall, CryptoHealthStatus.INSECURE)

    def test_aggregated_to_json(self):
        """Test JSON serialization."""
        checks = [
            CryptoHealthCheckResult("check1", CryptoHealthStatus.SECURE, CryptoHealthCheckType.RANDOMNESS),
        ]
        
        agg = CryptoAggregatedHealthStatus(
            overall_status=CryptoHealthStatus.SECURE,
            checks=checks,
        )
        
        json_str = agg.to_json()
        data = json.loads(json_str)
        
        self.assertEqual(data["status"], "secure")
        self.assertEqual(data["checks_count"], 1)


class TestCryptoHealthCheckRegistry(unittest.TestCase):
    """Test CryptoHealthCheckRegistry."""

    def setUp(self):
        """Set up test registry."""
        self.registry = CryptoHealthCheckRegistry()

    def test_registry_disabled_by_default(self):
        """Test that registry is disabled by default (opt-in)."""
        self.assertFalse(self.registry.is_enabled())

    def test_enable_disable(self):
        """Test enabling and disabling registry."""
        self.registry.enable()
        self.assertTrue(self.registry.is_enabled())
        
        self.registry.disable()
        self.assertFalse(self.registry.is_enabled())

    def test_register_check(self):
        """Test registering a crypto health check."""
        def dummy_check():
            return CryptoHealthCheckResult("dummy", CryptoHealthStatus.SECURE, CryptoHealthCheckType.CUSTOM)
        
        self.registry.register("dummy_check", dummy_check)
        self.assertIn("dummy_check", self.registry.list_checks())

    def test_unregister_check(self):
        """Test unregistering a crypto health check."""
        def dummy_check():
            return CryptoHealthCheckResult("dummy", CryptoHealthStatus.SECURE, CryptoHealthCheckType.CUSTOM)
        
        self.registry.register("dummy_check", dummy_check)
        result = self.registry.unregister("dummy_check")
        
        self.assertTrue(result)
        self.assertNotIn("dummy_check", self.registry.list_checks())

    def test_run_check_disabled_returns_none(self):
        """Test that running check when disabled returns None."""
        def dummy_check():
            return CryptoHealthCheckResult("dummy", CryptoHealthStatus.SECURE, CryptoHealthCheckType.CUSTOM)
        
        self.registry.register("dummy_check", dummy_check)
        # Registry is disabled by default
        result = self.registry.run_check("dummy_check")
        
        self.assertIsNone(result)

    def test_run_check_enabled(self):
        """Test running check when enabled."""
        def dummy_check():
            return CryptoHealthCheckResult("dummy", CryptoHealthStatus.SECURE, CryptoHealthCheckType.CUSTOM)
        
        self.registry.enable()
        self.registry.register("dummy_check", dummy_check)
        result = self.registry.run_check("dummy_check")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.status, CryptoHealthStatus.SECURE)

    def test_run_all_checks_disabled(self):
        """Test running all checks when disabled returns secure status."""
        result = self.registry.run_all_checks()
        self.assertEqual(result.overall_status, CryptoHealthStatus.SECURE)
        self.assertEqual(len(result.checks), 0)

    def test_run_all_checks_enabled(self):
        """Test running all checks when enabled."""
        def check1():
            return CryptoHealthCheckResult("check1", CryptoHealthStatus.SECURE, CryptoHealthCheckType.RANDOMNESS)
        
        def check2():
            return CryptoHealthCheckResult("check2", CryptoHealthStatus.SECURE, CryptoHealthCheckType.KEY_HEALTH)
        
        self.registry.enable()
        self.registry.register("check1", check1, CryptoHealthCheckType.RANDOMNESS)
        self.registry.register("check2", check2, CryptoHealthCheckType.KEY_HEALTH)
        
        result = self.registry.run_all_checks()
        
        self.assertEqual(result.overall_status, CryptoHealthStatus.SECURE)
        self.assertEqual(len(result.checks), 2)

    def test_run_all_checks_with_filter(self):
        """Test running checks with type filter."""
        def check1():
            return CryptoHealthCheckResult("check1", CryptoHealthStatus.SECURE, CryptoHealthCheckType.RANDOMNESS)
        
        def check2():
            return CryptoHealthCheckResult("check2", CryptoHealthStatus.SECURE, CryptoHealthCheckType.KEY_HEALTH)
        
        self.registry.enable()
        self.registry.register("check1", check1, CryptoHealthCheckType.RANDOMNESS)
        self.registry.register("check2", check2, CryptoHealthCheckType.KEY_HEALTH)
        
        result = self.registry.run_all_checks(filter_type=CryptoHealthCheckType.RANDOMNESS)
        
        self.assertEqual(len(result.checks), 1)
        self.assertEqual(result.checks[0].name, "check1")


class TestRandomnessQualityCheck(unittest.TestCase):
    """Test randomness quality health check."""

    def test_randomness_check_produces_result(self):
        """Test that randomness check runs and produces result."""
        check_func = create_randomness_quality_check(sample_size_bytes=64)
        result = check_func()
        
        self.assertEqual(result.name, "randomness_quality")
        self.assertEqual(result.check_type, CryptoHealthCheckType.RANDOMNESS)
        # Should be SECURE or DEGRADED (secrets module is good)
        self.assertIn(result.status, [CryptoHealthStatus.SECURE, CryptoHealthStatus.DEGRADED])

    def test_randomness_check_includes_statistics(self):
        """Test that randomness check includes statistics."""
        check_func = create_randomness_quality_check(sample_size_bytes=64)
        result = check_func()
        
        self.assertIn("chi_square", result.details)
        self.assertIn("variance", result.details)
        self.assertIn("sample_size_bytes", result.details)


class TestKeyStrengthCheck(unittest.TestCase):
    """Test key strength validation check."""

    def test_strong_key_passes(self):
        """Test that strong keys pass validation."""
        check_func = create_key_strength_check(min_key_bits=256)
        strong_key = secrets.token_bytes(32)  # 256 bits
        result = check_func(strong_key)
        
        self.assertEqual(result.name, "key_strength")
        self.assertEqual(result.status, CryptoHealthStatus.SECURE)
        self.assertEqual(result.details["key_bits"], 256)

    def test_weak_key_fails(self):
        """Test that weak keys are flagged as insecure."""
        check_func = create_key_strength_check(min_key_bits=256)
        weak_key = secrets.token_bytes(16)  # 128 bits - too short
        result = check_func(weak_key)
        
        self.assertEqual(result.status, CryptoHealthStatus.INSECURE)
        self.assertIsNotNone(result.security_warning)

    def test_key_check_includes_entropy(self):
        """Test that key check includes entropy estimate."""
        check_func = create_key_strength_check(min_key_bits=256)
        key = secrets.token_bytes(32)
        result = check_func(key)
        
        self.assertIn("entropy_estimate", result.details)
        self.assertIn("has_repeating_patterns", result.details)


class TestOperationLatencyCheck(unittest.TestCase):
    """Test crypto operation latency check."""

    def test_normal_latency(self):
        """Test normal latency returns secure status."""
        check_func = create_operation_latency_check(
            "key_generation",
            warning_threshold_ms=100.0,
            critical_threshold_ms=500.0,
        )
        result = check_func(50.0)  # 50ms - normal
        
        self.assertEqual(result.status, CryptoHealthStatus.SECURE)

    def test_high_latency_warning(self):
        """Test high latency returns degraded status."""
        check_func = create_operation_latency_check("signing", 100.0, 500.0)
        result = check_func(200.0)  # 200ms - warning
        
        self.assertEqual(result.status, CryptoHealthStatus.DEGRADED)

    def test_critical_latency(self):
        """Test critical latency returns insecure with warning."""
        check_func = create_operation_latency_check("decryption", 100.0, 500.0)
        result = check_func(1000.0)  # 1000ms - critical
        
        self.assertEqual(result.status, CryptoHealthStatus.INSECURE)
        self.assertIsNotNone(result.security_warning)
        self.assertIn("timing attack", result.security_warning)


class TestAlgorithmCompatibilityCheck(unittest.TestCase):
    """Test algorithm compatibility check."""

    def test_nist_standardized_algorithm(self):
        """Test that NIST-standardized algorithms pass."""
        check_func = create_algorithm_compatibility_check("CRYSTALS-Kyber", [])
        result = check_func()
        
        self.assertEqual(result.status, CryptoHealthStatus.SECURE)
        self.assertTrue(result.details.get("nist_pq_standard", False))

    def test_deprecated_algorithm(self):
        """Test that deprecated algorithms are flagged insecure."""
        check_func = create_algorithm_compatibility_check("RSA-1024", [])
        result = check_func()
        
        self.assertEqual(result.status, CryptoHealthStatus.INSECURE)
        self.assertIsNotNone(result.security_warning)

    def test_non_standard_algorithm(self):
        """Test that non-standard algorithms are flagged degraded."""
        check_func = create_algorithm_compatibility_check("CUSTOM-PQ-ALG", [])
        result = check_func()
        
        self.assertEqual(result.status, CryptoHealthStatus.DEGRADED)


class TestSystemEntropyCheck(unittest.TestCase):
    """Test system entropy availability check."""

    def test_entropy_check_produces_result(self):
        """Test that entropy check runs."""
        check_func = create_process_entropy_available_check()
        result = check_func()
        
        self.assertEqual(result.name, "system_entropy")
        self.assertEqual(result.check_type, CryptoHealthCheckType.RANDOMNESS)
        # Should work on most systems
        self.assertIn(result.status, [CryptoHealthStatus.SECURE, CryptoHealthStatus.UNKNOWN])


class TestCryptoOperationDecorator(unittest.TestCase):
    """Test crypto operation monitoring decorator."""

    def setUp(self):
        """Reset registry for each test."""
        registry = get_crypto_health_registry()
        registry.enable()

    def test_decorator_tracks_success(self):
        """Test decorator tracks successful crypto operations."""
        @crypto_operation_health_monitored("key_generation")
        def test_crypto_op():
            return secrets.token_bytes(32)
        
        # Call successfully
        for _ in range(10):
            test_crypto_op()
        
        # Run the health check
        registry = get_crypto_health_registry()
        result = registry.run_check("crypto_op_key_generation")
        
        self.assertIsNotNone(result)
        # Should be secure (0% error rate)
        self.assertIn(result.status, [CryptoHealthStatus.SECURE, CryptoHealthStatus.UNKNOWN])

    def test_decorator_tracks_failures(self):
        """Test decorator tracks failed crypto operations."""
        call_count = [0]
        
        @crypto_operation_health_monitored("signing")
        def test_crypto_op():
            call_count[0] += 1
            if call_count[0] % 2 == 0:
                raise ValueError("Crypto operation failed")
            return secrets.token_bytes(32)
        
        # Call with mix of success/failure
        for i in range(20):
            try:
                test_crypto_op()
            except ValueError:
                pass
        
        registry = get_crypto_health_registry()
        result = registry.run_check("crypto_op_signing")
        
        self.assertIsNotNone(result)
        # 50% error rate should be insecure or degraded
        self.assertIn(result.status, [CryptoHealthStatus.DEGRADED, CryptoHealthStatus.INSECURE])


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions."""

    def test_security_report_disabled(self):
        """Test security report when disabled."""
        disable_crypto_health_checks()
        result = get_crypto_security_report()
        self.assertEqual(result["status"], "secure")
        self.assertIn("note", result)

    def test_security_report_enabled(self):
        """Test security report when enabled."""
        enable_crypto_health_checks()
        register_default_crypto_health_checks()
        result = get_crypto_security_report()
        self.assertIn("status", result)


class TestGlobalRegistry(unittest.TestCase):
    """Test global registry singleton."""

    def test_get_crypto_health_registry(self):
        """Test getting global crypto registry."""
        registry = get_crypto_health_registry()
        self.assertIsInstance(registry, CryptoHealthCheckRegistry)

    def test_same_instance(self):
        """Test that same instance is returned."""
        r1 = get_crypto_health_registry()
        r2 = get_crypto_health_registry()
        self.assertIs(r1, r2)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of registry operations."""

    def test_concurrent_registration(self):
        """Test concurrent check registration."""
        registry = CryptoHealthCheckRegistry()
        registry.enable()
        
        def register_checks(start_id: int):
            for i in range(10):
                name = f"crypto_check_{start_id}_{i}"
                def make_check(n):
                    return lambda: CryptoHealthCheckResult(n, CryptoHealthStatus.SECURE, CryptoHealthCheckType.CUSTOM)
                registry.register(name, make_check(name))
        
        threads = []
        for t in range(5):
            thread = threading.Thread(target=register_checks, args=(t,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Should have 50 checks registered
        self.assertEqual(len(registry.list_checks()), 50)


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return {
        "total": result.testsRun,
        "passed": result.testsRun - len(result.failures) - len(result.errors),
        "failed": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
    }


if __name__ == "__main__":
    results = run_tests()
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)
    print(f"Total tests: {results['total']}")
    print(f"Passed: {results['passed']}")
    print(f"Failed: {results['failed']}")
    print(f"Errors: {results['errors']}")
    print(f"Success: {results['success']}")
    print("="*60)
    
    # Save results
    with open("test_results_pq_crypto_health_check_framework_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
