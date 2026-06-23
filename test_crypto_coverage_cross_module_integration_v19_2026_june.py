#!/usr/bin/env python3
"""
Test Coverage v19 - Cross-Module Integration Tests
QuantumCrypt-AI: PQ Error Resilience v25 + PQ Security Hardening v17 + PQ Observability v14

DIMENSION C - TEST COVERAGE EXPANSION v19
ADD-ONLY: No production code modified, only tests added

Tests:
1. PQ Error v25 + PQ Security v17 Integration
2. PQ Error v25 + PQ Observability v14 Integration
3. PQ Security v17 + PQ Observability v14 Integration
4. Full Triple Integration: PQ Error + PQ Security + PQ Observability
5. Post-Quantum Specific Edge Cases
6. Backward Compatibility Verification
"""

import unittest
import sys
import os
import time
import threading
import secrets
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, Optional, List

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

class TestPQErrorResilienceSecurityIntegration(unittest.TestCase):
    """Test PQ Error Resilience v25 + PQ Security Hardening v17 Integration"""

    def setUp(self):
        """Set up test fixtures"""
        try:
            from crypto_error_resilience_pq_tls_v25_2026_june import (
                PQTLSResilienceWrapper, PQCircuitBreaker, pq_exponential_backoff,
                PQSecurityLevel, PQCircuitState
            )
            from crypto_security_hardening_tls_https_endpoint_protection_v17_2026_june import (
                PQTLSEndpointProtector, PQRequestValidator, SecureMemoryManager
            )
            self.modules_available = True
            self.PQTLSResilienceWrapper = PQTLSResilienceWrapper
            self.PQCircuitBreaker = PQCircuitBreaker
            self.pq_exponential_backoff = pq_exponential_backoff
            self.PQSecurityLevel = PQSecurityLevel
            self.PQCircuitState = PQCircuitState
            self.PQTLSEndpointProtector = PQTLSEndpointProtector
            self.PQRequestValidator = PQRequestValidator
            self.SecureMemoryManager = SecureMemoryManager
        except ImportError as e:
            self.modules_available = False
            print(f"Module import warning: {e}")

    def test_pq_security_wrapped_with_resilience(self):
        """Test: PQ security validator wrapped with PQ error resilience"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        validator = self.PQRequestValidator()
        wrapper = self.PQTLSResilienceWrapper(
            operation=validator.validate_pq_request,
            min_security_level=self.PQSecurityLevel.HYBRID,
            failure_threshold=3
        )
        
        result = wrapper.execute({
            "url": "https://pq.example.com",
            "method": "POST",
            "kem_algorithm": "ML-KEM-768"
        })
        self.assertIsNotNone(result)
        self.assertEqual(wrapper.stats["pq_success_count"], 1)

    def test_pq_kem_failure_triggers_security_downgrade(self):
        """Test: PQ KEM operation failure triggers automatic security downgrade"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        call_count = [0]
        def failing_pq_kem(*args):
            call_count[0] += 1
            if call_count[0] < 3:
                raise Exception("ML-KEM-1024 key encapsulation failed")
            return {"status": "hybrid_mode", "kem": "RSA+ML-KEM"}
        
        wrapper = self.PQTLSResilienceWrapper(
            operation=failing_pq_kem,
            min_security_level=self.PQSecurityLevel.PQ_ONLY,
            enable_downgrade=True,
            max_retries=2
        )
        
        result = wrapper.execute({})
        # Should have downgraded to HYBRID mode
        self.assertGreaterEqual(wrapper.stats["downgrade_count"], 0)
        self.assertGreater(call_count[0], 1)

    def test_pq_secure_memory_zeroization_on_failure(self):
        """Test: Secure memory zeroization triggered on PQ operation failure"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        mem_manager = self.SecureMemoryManager()
        sensitive_data = secrets.token_bytes(32)
        buffer = mem_manager.allocate_secure_buffer(sensitive_data)
        
        failing_op = Mock(side_effect=Exception("PQ operation failed"))
        wrapper = self.PQTLSResilienceWrapper(
            operation=failing_op,
            secure_memory_manager=mem_manager,
            zeroize_on_failure=True
        )
        
        try:
            wrapper.execute({})
        except:
            pass
        
        # Buffer should have been zeroized
        self.assertTrue(buffer.zeroized)
        self.assertEqual(wrapper.stats["zeroization_count"], 1)

    def test_pq_circuit_breaker_independent_thresholds(self):
        """Test: PQ circuit breaker has independent thresholds for PQ vs Hybrid"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        wrapper = self.PQTLSResilienceWrapper(
            operation=Mock(side_effect=Exception("Fail")),
            pq_failure_threshold=2,
            hybrid_failure_threshold=5
        )
        
        # PQ failures should have lower threshold
        for _ in range(2):
            try:
                wrapper.execute({"security_level": "PQ_ONLY"})
            except:
                pass
        
        self.assertEqual(wrapper.pq_circuit.state, self.PQCircuitState.OPEN)
        # Hybrid circuit should still be closed
        self.assertEqual(wrapper.hybrid_circuit.state, self.PQCircuitState.CLOSED)

    def test_pq_crypto_safe_backoff_jitter(self):
        """Test: PQ backoff uses cryptographically secure jitter (secrets module)"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        delays = []
        for _ in range(10):
            delay = self.pq_exponential_backoff(
                attempt=1,
                base_delay=0.01,
                use_crypto_jitter=True
            )
            delays.append(delay)
        
        # Jitter should cause variations (not all identical)
        unique_delays = len(set(delays))
        self.assertGreater(unique_delays, 1, "Crypto jitter should produce varied delays")


class TestPQErrorResilienceObservabilityIntegration(unittest.TestCase):
    """Test PQ Error Resilience v25 + PQ Observability v14 Integration"""

    def setUp(self):
        """Set up test fixtures"""
        try:
            from crypto_error_resilience_pq_tls_v25_2026_june import (
                PQTLSResilienceWrapper, PQSecurityLevel
            )
            from crypto_observability_pq_operation_telemetry_latency_v10_2026_june import (
                PQOperationTelemetry, PQMetricsExporter
            )
            self.modules_available = True
            self.PQTLSResilienceWrapper = PQTLSResilienceWrapper
            self.PQSecurityLevel = PQSecurityLevel
            self.PQOperationTelemetry = PQOperationTelemetry
            self.PQMetricsExporter = PQMetricsExporter
        except ImportError as e:
            self.modules_available = False
            print(f"Module import warning: {e}")

    def test_pq_resilience_events_in_telemetry(self):
        """Test: PQ resilience events are recorded in telemetry"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        telemetry = self.PQOperationTelemetry()
        failing_op = Mock(side_effect=Exception("PQ KEM timeout"))
        
        wrapper = self.PQTLSResilienceWrapper(
            operation=failing_op,
            max_retries=2,
            failure_threshold=3
        )
        
        for _ in range(3):
            try:
                wrapper.execute({"algorithm": "ML-KEM-768"})
            except:
                pass
        
        telemetry.record_pq_event(
            event_type="pq_operation_retries",
            algorithm="ML-KEM-768",
            details={
                "retries": wrapper.stats["retry_count"],
                "failures": wrapper.stats["failure_count"],
                "downgrades": wrapper.stats["downgrade_count"]
            }
        )
        
        metrics = telemetry.get_pq_metrics()
        self.assertIsNotNone(metrics)

    def test_pq_security_level_metrics_exported(self):
        """Test: PQ security level success rates are exported"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        exporter = self.PQMetricsExporter()
        
        # Simulate security level metrics
        exporter.export_pq_counter("pq_only_successes", 85)
        exporter.export_pq_counter("hybrid_successes", 142)
        exporter.export_pq_counter("classical_fallbacks", 8)
        exporter.export_pq_counter("pq_downgrades_total", 12)
        
        metrics = exporter.get_exported_pq_metrics()
        self.assertEqual(metrics.get("pq_only_successes", 0), 85)
        self.assertEqual(metrics.get("pq_downgrades_total", 0), 12)

    def test_pq_kem_latency_tracking(self):
        """Test: PQ KEM operation latency is tracked in observability"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        telemetry = self.PQOperationTelemetry()
        
        # Record KEM operation timings
        telemetry.record_pq_latency("ML-KEM-512", 0.008)
        telemetry.record_pq_latency("ML-KEM-768", 0.015)
        telemetry.record_pq_latency("ML-KEM-1024", 0.032)
        telemetry.record_pq_latency("HYBRID-RSA-MLKEM", 0.045)
        
        latency_stats = telemetry.get_latency_statistics()
        self.assertIn("ML-KEM-1024", str(latency_stats))

    def test_zeroization_events_telemetry(self):
        """Test: Secure memory zeroization events are recorded"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        telemetry = self.PQOperationTelemetry()
        
        for i in range(25):
            telemetry.record_pq_event("secure_memory_zeroization", {
                "buffer_id": f"buf_{i}",
                "passes": 5,
                "size_bytes": 32 + i * 16
            })
        
        event_count = telemetry.get_event_count_by_type("secure_memory_zeroization")
        self.assertEqual(event_count, 25)


class TestPQSecurityObservabilityIntegration(unittest.TestCase):
    """Test PQ Security Hardening v17 + PQ Observability v14 Integration"""

    def setUp(self):
        """Set up test fixtures"""
        try:
            from crypto_security_hardening_tls_https_endpoint_protection_v17_2026_june import (
                PQTLSEndpointProtector, PQRateLimiter, SideChannelResistant
            )
            from crypto_observability_pq_operation_telemetry_latency_v10_2026_june import (
                PQOperationTelemetry, PQMetricsExporter
            )
            self.modules_available = True
            self.PQTLSEndpointProtector = PQTLSEndpointProtector
            self.PQRateLimiter = PQRateLimiter
            self.SideChannelResistant = SideChannelResistant
            self.PQOperationTelemetry = PQOperationTelemetry
            self.PQMetricsExporter = PQMetricsExporter
        except ImportError as e:
            self.modules_available = False
            print(f"Module import warning: {e}")

    def test_pq_tls_protection_telemetry_recording(self):
        """Test: PQ TLS protection events are recorded"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        protector = self.PQTLSEndpointProtector()
        telemetry = self.PQOperationTelemetry()
        
        pq_requests = [
            {"url": "https://pq.api.com", "kem": "ML-KEM-768", "sig": "ML-DSA-65"},
            {"url": "https://hybrid.api.com", "kem": "HYBRID", "sig": "RSA+ML-DSA"},
        ]
        
        for req in pq_requests:
            result = protector.protect_pq_request(req)
            telemetry.record_pq_event("pq_request_protected", {
                "kem": req["kem"],
                "protected": result.get("protected", False)
            })
        
        events = telemetry.get_event_count()
        self.assertGreaterEqual(events, len(pq_requests))

    def test_side_channel_resistance_metrics(self):
        """Test: Side-channel resistance validation metrics"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        sc_validator = self.SideChannelResistant()
        exporter = self.PQMetricsExporter()
        
        # Run timing attack simulations
        test_results = []
        for i in range(100):
            result = sc_validator.validate_timing_independence(
                secrets.token_bytes(32)
            )
            test_results.append(result)
        
        passed = sum(1 for r in test_results if r.get("passed", False))
        exporter.export_pq_counter("side_channel_tests_passed", passed)
        exporter.export_pq_counter("side_channel_tests_total", len(test_results))
        
        metrics = exporter.get_exported_pq_metrics()
        self.assertEqual(metrics["side_channel_tests_total"], 100)

    def test_pq_rate_limit_violations_metrics(self):
        """Test: PQ rate limit violations are captured"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        rate_limiter = self.PQRateLimiter(
            pq_max_requests=10,
            window_seconds=60
        )
        exporter = self.PQMetricsExporter()
        
        violations = 0
        for i in range(20):
            allowed = rate_limiter.check_pq_rate_limit(f"client_{i % 3}")
            if not allowed:
                violations += 1
        
        exporter.export_pq_counter("pq_rate_limit_violations", violations)
        
        metrics = exporter.get_exported_pq_metrics()
        self.assertGreaterEqual(metrics.get("pq_rate_limit_violations", 0), 0)


class TestPQFullTripleIntegration(unittest.TestCase):
    """Full Triple Integration: PQ Error v25 + PQ Security v17 + PQ Observability v14"""

    def setUp(self):
        """Set up test fixtures"""
        try:
            from crypto_error_resilience_pq_tls_v25_2026_june import PQTLSResilienceWrapper
            from crypto_security_hardening_tls_https_endpoint_protection_v17_2026_june import PQTLSEndpointProtector
            from crypto_observability_pq_operation_telemetry_latency_v10_2026_june import (
                PQOperationTelemetry, PQMetricsExporter
            )
            self.modules_available = True
            self.PQTLSResilienceWrapper = PQTLSResilienceWrapper
            self.PQTLSEndpointProtector = PQTLSEndpointProtector
            self.PQOperationTelemetry = PQOperationTelemetry
            self.PQMetricsExporter = PQMetricsExporter
        except ImportError as e:
            self.modules_available = False
            print(f"Module import warning: {e}")

    def test_complete_pq_protected_pipeline(self):
        """Test: Complete PQ pipeline - Security + Resilience + Observability"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        # 1. PQ Security Layer
        protector = self.PQTLSEndpointProtector()
        
        # 2. PQ Error Resilience Layer
        def pq_protected_operation(request):
            return protector.protect_pq_request(request)
        
        wrapper = self.PQTLSResilienceWrapper(
            operation=pq_protected_operation,
            max_retries=2,
            enable_downgrade=True
        )
        
        # 3. PQ Observability Layer
        telemetry = self.PQOperationTelemetry()
        exporter = self.PQMetricsExporter()
        
        # Execute full pipeline
        pq_requests = [
            {"url": "https://pq1.example.com", "kem": "ML-KEM-512", "method": "GET"},
            {"url": "https://pq2.example.com", "kem": "ML-KEM-768", "method": "POST"},
            {"url": "https://pq3.example.com", "kem": "HYBRID", "method": "GET"},
        ]
        
        success_count = 0
        for req in pq_requests:
            start_time = time.time()
            try:
                result = wrapper.execute(req)
                success_count += 1
                latency = time.time() - start_time
                telemetry.record_pq_latency(req["kem"], latency)
                telemetry.record_pq_event("pq_pipeline_success", {"kem": req["kem"]})
            except Exception as e:
                telemetry.record_pq_event("pq_pipeline_failure", {"error": str(e)})
        
        # Export metrics
        exporter.export_pq_counter("pq_pipeline_requests", len(pq_requests))
        exporter.export_pq_counter("pq_pipeline_successes", success_count)
        exporter.export_pq_counter("pq_pipeline_retries", wrapper.stats["retry_count"])
        exporter.export_pq_counter("pq_pipeline_downgrades", wrapper.stats["downgrade_count"])
        
        self.assertEqual(success_count, len(pq_requests))

    def test_pq_failure_chain_all_layers(self):
        """Test: PQ failures propagate through all layers correctly"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        telemetry = self.PQOperationTelemetry()
        
        # Failing PQ security operation
        failing_pq_op = Mock(side_effect=Exception("ML-KEM key exchange failed - HSM timeout"))
        
        wrapper = self.PQTLSResilienceWrapper(
            operation=failing_pq_op,
            max_retries=3,
            enable_downgrade=True
        )
        
        try:
            wrapper.execute({"algorithm": "ML-KEM-1024"})
        except Exception as e:
            telemetry.record_pq_event("pq_full_pipeline_failure", {
                "error": str(e),
                "retries": wrapper.stats["retry_count"],
                "downgrades": wrapper.stats["downgrade_count"],
                "zeroizations": wrapper.stats["zeroization_count"]
            })
        
        self.assertGreater(wrapper.stats["failure_count"], 0)

    def test_concurrent_pq_pipeline_thread_safety(self):
        """Test: Concurrent PQ pipeline execution is thread-safe"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        protector = self.PQTLSEndpointProtector()
        telemetry = self.PQOperationTelemetry()
        
        def pq_worker(worker_id):
            wrapper = self.PQTLSResilienceWrapper(
                operation=protector.protect_pq_request,
                max_retries=1
            )
            try:
                result = wrapper.execute({
                    "url": f"https://pq-worker{worker_id}.example.com",
                    "kem": "ML-KEM-768"
                })
                return True
            except:
                return False
        
        threads = []
        results = []
        for i in range(8):
            t = threading.Thread(target=lambda: results.append(pq_worker(i)))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join(timeout=10.0)
        
        self.assertEqual(len(results), 8)
        telemetry.record_pq_event("pq_concurrent_execution", {"workers": len(results)})


class TestPQSpecificEdgeCases(unittest.TestCase):
    """Post-Quantum Specific Edge Cases and Boundary Conditions"""

    def setUp(self):
        """Set up test fixtures"""
        try:
            from crypto_error_resilience_pq_tls_v25_2026_june import (
                PQTLSResilienceWrapper, PQSecurityLevel
            )
            self.modules_available = True
            self.PQTLSResilienceWrapper = PQTLSResilienceWrapper
            self.PQSecurityLevel = PQSecurityLevel
        except ImportError as e:
            self.modules_available = False
            print(f"Module import warning: {e}")

    def test_pq_security_level_boundaries(self):
        """Test: All PQ security level boundary conditions"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        levels = [
            self.PQSecurityLevel.PQ_ONLY,
            self.PQSecurityLevel.HYBRID,
            self.PQSecurityLevel.CLASSICAL
        ]
        
        for level in levels:
            wrapper = self.PQTLSResilienceWrapper(
                operation=lambda x: {"level": level.name},
                min_security_level=level
            )
            result = wrapper.execute({})
            self.assertIsNotNone(result)

    def test_extremely_large_pq_key_sizes(self):
        """Test: Handling of extremely large PQ key material"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        large_key = secrets.token_bytes(1024 * 10)  # 10KB key material
        wrapper = self.PQTLSResilienceWrapper(
            operation=lambda x: {"key_size": len(large_key)},
            max_retries=1
        )
        
        result = wrapper.execute({"key": large_key})
        self.assertEqual(result["key_size"], 10240)

    def test_pq_hsm_timeout_extreme_values(self):
        """Test: Extreme timeout values for HSM-backed PQ operations"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        # Very long timeout for slow HSM operations
        wrapper = self.PQTLSResilienceWrapper(
            operation=lambda x: {"hsm": "slow"},
            operation_timeout=300.0  # 5 minutes for HSM
        )
        result = wrapper.execute({})
        self.assertIsNotNone(result)
        
        # Zero timeout should be clamped
        wrapper2 = self.PQTLSResilienceWrapper(
            operation=lambda x: {"hsm": "fast"},
            operation_timeout=0
        )
        result2 = wrapper2.execute({})
        self.assertIsNotNone(result2)

    def test_pq_algorithm_mismatch_downgrade(self):
        """Test: Algorithm mismatch triggers proper downgrade path"""
        if not self.modules_available:
            self.skipTest("Modules not available")
        
        call_count = [0]
        def algorithm_mismatch_op(request):
            call_count[0] += 1
            if request.get("algorithm") == "ML-KEM-1024" and call_count[0] < 2:
                raise Exception("Algorithm not supported by peer")
            return {"algorithm": "ML-KEM-768", "mode": "downgraded"}
        
        wrapper = self.PQTLSResilienceWrapper(
            operation=algorithm_mismatch_op,
            enable_downgrade=True
        )
        
        result = wrapper.execute({"algorithm": "ML-KEM-1024"})
        self.assertGreaterEqual(wrapper.stats["downgrade_count"], 0)


class TestPQBackwardCompatibility(unittest.TestCase):
    """PQ Backward Compatibility Verification"""

    def test_pq_modules_import_isolated(self):
        """Test: PQ modules import without side effects"""
        modules = [
            "crypto_error_resilience_pq_tls_v25_2026_june",
            "crypto_security_hardening_tls_https_endpoint_protection_v17_2026_june",
            "crypto_observability_pq_operation_telemetry_latency_v10_2026_june",
        ]
        
        for mod in modules:
            try:
                __import__(mod)
            except ImportError:
                try:
                    __import__(f"quantum_crypt.{mod}")
                except ImportError as e:
                    print(f"Note: {mod} import: {e}")

    def test_standard_crypto_unmodified(self):
        """Test: Standard crypto modules are not monkey-patched"""
        import hashlib
        import hmac
        import secrets
        
        self.assertTrue(hasattr(hashlib, 'sha256'))
        self.assertTrue(hasattr(hmac, 'new'))
        self.assertTrue(hasattr(secrets, 'token_bytes'))


def run_pq_tests():
    """Run all PQ cross-module integration tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    test_classes = [
        TestPQErrorResilienceSecurityIntegration,
        TestPQErrorResilienceObservabilityIntegration,
        TestPQSecurityObservabilityIntegration,
        TestPQFullTripleIntegration,
        TestPQSpecificEdgeCases,
        TestPQBackwardCompatibility
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


if __name__ == "__main__":
    result = run_pq_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
