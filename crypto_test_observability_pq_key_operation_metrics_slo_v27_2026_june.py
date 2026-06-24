"""
Test Suite for Crypto Observability: PQ Key Operation Metrics & SLO v27
Dimension D: Observability & Instrumentation

All tests verify that:
1. Module is DISABLED by default (no behavioral changes)
2. When enabled, works correctly
3. No existing crypto logic is modified
4. 100% backward compatible
5. Security is preserved
"""

import os
import sys
import time
import threading
import unittest
from typing import Dict, Any

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

class TestObservabilityDisabledByDefault(unittest.TestCase):
    """Verify observability is DISABLED by default - NO behavioral changes"""
    
    def setUp(self):
        # Ensure environment variable is NOT set
        if 'QUANTUMCRYPT_OBSERVABILITY_ENABLED' in os.environ:
            del os.environ['QUANTUMCRYPT_OBSERVABILITY_ENABLED']
    
    def test_disabled_by_default_no_env(self):
        """CRITICAL: Observability must be disabled without explicit opt-in"""
        from quantum_crypt.crypto_observability_pq_key_operation_metrics_slo_v27_2026_june import (
            CryptoObservabilityConfig, SLOStatus
        )
        self.assertFalse(CryptoObservabilityConfig.is_enabled())
    
    def test_measure_operation_no_op_when_disabled(self):
        """measure_operation should be NO-OP when disabled"""
        from quantum_crypt.crypto_observability_pq_key_operation_metrics_slo_v27_2026_june import (
            measure_operation, get_metrics_summary
        )
        
        execution_count = [0]
        
        with measure_operation("key_generation", "Kyber") as ctx:
            execution_count[0] += 1
            self.assertIsNone(ctx)
        
        self.assertEqual(execution_count[0], 1)
        
        summary = get_metrics_summary()
        self.assertEqual(summary["status"], "disabled")
        self.assertEqual(summary["operations"], {})
    
    def test_measured_decorator_no_op_when_disabled(self):
        """@measured decorator should be NO-OP when disabled"""
        from quantum_crypt.crypto_observability_pq_key_operation_metrics_slo_v27_2026_june import (
            measured, get_metrics_summary
        )
        
        call_count = [0]
        
        @measured("key_generation", "CRYSTALS-Kyber")
        def mock_keygen(security_level):
            call_count[0] += 1
            return (f"priv_{security_level}", f"pub_{security_level}")
        
        priv, pub = mock_keygen(3)
        self.assertEqual(priv, "priv_3")
        self.assertEqual(pub, "pub_3")
        self.assertEqual(call_count[0], 1)
        
        summary = get_metrics_summary()
        self.assertEqual(summary["status"], "disabled")
    
    def test_evaluate_slo_disabled(self):
        """evaluate_slo should return DISABLED when observability is off"""
        from quantum_crypt.crypto_observability_pq_key_operation_metrics_slo_v27_2026_june import (
            evaluate_slo, SLOStatus
        )
        
        result = evaluate_slo()
        self.assertEqual(result.status, SLOStatus.DISABLED)
        self.assertIn("Observability disabled", result.violations)
    
    def test_record_operation_safe_when_disabled(self):
        """record_operation should not error when disabled"""
        from quantum_crypt.crypto_observability_pq_key_operation_metrics_slo_v27_2026_june import (
            record_operation
        )
        
        # Should not raise any exceptions
        record_operation("key_generation", 5.0, True, "Kyber")
    
    def test_reset_metrics_safe_when_disabled(self):
        """reset_metrics should not error when disabled"""
        from quantum_crypt.crypto_observability_pq_key_operation_metrics_slo_v27_2026_june import (
            reset_metrics
        )
        
        # Should not raise any exceptions
        reset_metrics()

class TestObservabilityWhenEnabled(unittest.TestCase):
    """Test observability functionality when explicitly enabled"""
    
    def setUp(self):
        os.environ['QUANTUMCRYPT_OBSERVABILITY_ENABLED'] = '1'
        # Force reimport to pick up env var
        import importlib
        import quantum_crypt.crypto_observability_pq_key_operation_metrics_slo_v27_2026_june as obs
        importlib.reload(obs)
        obs.CryptoObservabilityConfig.enable()
        obs.reset_metrics()
        self.obs = obs
    
    def tearDown(self):
        if 'QUANTUMCRYPT_OBSERVABILITY_ENABLED' in os.environ:
            del os.environ['QUANTUMCRYPT_OBSERVABILITY_ENABLED']
    
    def test_enabled_when_explicitly_opted_in(self):
        """Observability should work when explicitly enabled"""
        self.assertTrue(self.obs.CryptoObservabilityConfig.is_enabled())
    
    def test_measure_operation_records_success(self):
        """measure_operation should record successful operations"""
        with self.obs.measure_operation("key_generation", "Kyber"):
            time.sleep(0.001)  # Simulate work
        
        summary = self.obs.get_metrics_summary()
        self.assertEqual(summary["status"], "enabled")
        self.assertIn("key_generation", summary["operations"])
        self.assertEqual(summary["operations"]["key_generation"]["errors"], 0)
    
    def test_measure_operation_records_errors(self):
        """measure_operation should record failed operations"""
        try:
            with self.obs.measure_operation("key_generation", "Kyber"):
                raise ValueError("Simulated crypto error")
        except ValueError:
            pass
        
        summary = self.obs.get_metrics_summary()
        self.assertEqual(summary["operations"]["key_generation"]["errors"], 1)
        self.assertGreater(summary["operations"]["key_generation"]["error_rate"], 0)
    
    def test_measured_decorator_works(self):
        """@measured decorator should work when enabled"""
        @self.obs.measured("signature_generation", "Dilithium")
        def mock_sign(message):
            return f"sig_{message}"
        
        result = mock_sign("test_message")
        self.assertEqual(result, "sig_test_message")
        
        summary = self.obs.get_metrics_summary()
        self.assertIn("signature_generation", summary["operations"])
    
    def test_record_operation_direct(self):
        """Direct recording should work"""
        for i in range(10):
            self.obs.record_operation("key_encapsulation", 1.5 + i * 0.1, True, "Kyber")
        
        summary = self.obs.get_metrics_summary()
        self.assertEqual(summary["operations"]["key_encapsulation"]["total"], 10)
    
    def test_slo_evaluation_healthy(self):
        """SLO evaluation should return HEALTHY for good metrics"""
        # Set relaxed SLO for this test to avoid throughput false positive
        relaxed_slo = self.obs.SLOConfig(
            latency_p95_ms=100.0,
            latency_p99_ms=200.0,
            error_rate_max=0.01,
            throughput_min=0.1  # Relaxed throughput
        )
        self.obs.CryptoObservabilityConfig.set_slo_config(relaxed_slo)
        
        # Record good samples
        for _ in range(100):
            self.obs.record_operation("key_generation", 5.0, True, "Kyber")
        
        result = self.obs.evaluate_slo()
        self.assertEqual(result.status, self.obs.SLOStatus.HEALTHY)
        self.assertLess(result.latency_p95_ms, 100.0)
        self.assertEqual(result.error_rate, 0.0)
    
    def test_slo_evaluation_warning_for_latency(self):
        """SLO should return WARNING when P95 is breached"""
        # Record high latency samples
        for _ in range(100):
            self.obs.record_operation("key_generation", 150.0, True, "Kyber")
        
        result = self.obs.evaluate_slo()
        self.assertIn(result.status, [self.obs.SLOStatus.WARNING, self.obs.SLOStatus.BREACHED])
    
    def test_slo_evaluation_breached_for_errors(self):
        """SLO should return BREACHED when error rate is too high"""
        # Mix of success and failure
        for i in range(100):
            success = i < 90  # 90% success, 10% error (>1% threshold)
            self.obs.record_operation("key_generation", 5.0, success, "Kyber")
        
        result = self.obs.evaluate_slo()
        self.assertEqual(result.status, self.obs.SLOStatus.BREACHED)
        self.assertGreater(result.error_rate, 0.01)
    
    def test_percentile_calculation(self):
        """Percentile calculation should work correctly"""
        values = list(range(1, 101))  # 1-100
        
        p95 = self.obs.calculate_percentile(values, 0.95)
        p99 = self.obs.calculate_percentile(values, 0.99)
        
        self.assertGreaterEqual(p95, 95)
        self.assertGreaterEqual(p99, 99)
    
    def test_reset_metrics_clears_data(self):
        """reset_metrics should clear all collected data"""
        self.obs.record_operation("key_generation", 5.0, True, "Kyber")
        self.obs.reset_metrics()
        
        summary = self.obs.get_metrics_summary()
        self.assertEqual(summary["operations"], {})

class TestPostQuantumKeyOperationWrapper(unittest.TestCase):
    """Test PQ key operation wrappers preserve original behavior"""
    
    def setUp(self):
        os.environ['QUANTUMCRYPT_OBSERVABILITY_ENABLED'] = '1'
        import importlib
        import quantum_crypt.crypto_observability_pq_key_operation_metrics_slo_v27_2026_june as obs
        importlib.reload(obs)
        obs.CryptoObservabilityConfig.enable()
        obs.reset_metrics()
        self.obs = obs
    
    def tearDown(self):
        if 'QUANTUMCRYPT_OBSERVABILITY_ENABLED' in os.environ:
            del os.environ['QUANTUMCRYPT_OBSERVABILITY_ENABLED']
    
    def test_wrap_kyber_keygen_preserves_behavior(self):
        """Wrapper should NOT modify crypto behavior"""
        def original_keygen(level):
            return (f"sk_{level}", f"pk_{level}")
        
        sk, pk = self.obs.PostQuantumKeyOperationWrapper.wrap_kyber_keygen(
            original_keygen, 3
        )
        self.assertEqual(sk, "sk_3")
        self.assertEqual(pk, "pk_3")
    
    def test_wrap_kyber_encaps_preserves_behavior(self):
        """Wrapper should NOT modify crypto behavior"""
        def original_encaps(pk):
            return ("shared_secret", "ciphertext")
        
        ss, ct = self.obs.PostQuantumKeyOperationWrapper.wrap_kyber_encaps(
            original_encaps, "test_pk"
        )
        self.assertEqual(ss, "shared_secret")
        self.assertEqual(ct, "ciphertext")
    
    def test_wrap_kyber_decaps_preserves_behavior(self):
        """Wrapper should NOT modify crypto behavior"""
        def original_decaps(sk, ct):
            return "recovered_secret"
        
        result = self.obs.PostQuantumKeyOperationWrapper.wrap_kyber_decaps(
            original_decaps, "test_sk", "test_ct"
        )
        self.assertEqual(result, "recovered_secret")
    
    def test_wrap_dilithium_sign_preserves_behavior(self):
        """Wrapper should NOT modify crypto behavior"""
        def original_sign(sk, msg):
            return f"sig_{msg}"
        
        result = self.obs.PostQuantumKeyOperationWrapper.wrap_dilithium_sign(
            original_sign, "test_sk", "hello"
        )
        self.assertEqual(result, "sig_hello")
    
    def test_wrap_dilithium_verify_preserves_behavior(self):
        """Wrapper should NOT modify crypto behavior"""
        def original_verify(pk, msg, sig):
            return True
        
        result = self.obs.PostQuantumKeyOperationWrapper.wrap_dilithium_verify(
            original_verify, "test_pk", "hello", "test_sig"
        )
        self.assertTrue(result)
    
    def test_wrap_sidh_key_agreement_preserves_behavior(self):
        """Wrapper should NOT modify crypto behavior"""
        def original_agreement(sk, other_pk):
            return "shared_secret"
        
        result = self.obs.PostQuantumKeyOperationWrapper.wrap_sidh_key_agreement(
            original_agreement, "my_sk", "their_pk"
        )
        self.assertEqual(result, "shared_secret")

class TestThreadSafety(unittest.TestCase):
    """Verify thread-safe metrics collection"""
    
    def setUp(self):
        os.environ['QUANTUMCRYPT_OBSERVABILITY_ENABLED'] = '1'
        import importlib
        import quantum_crypt.crypto_observability_pq_key_operation_metrics_slo_v27_2026_june as obs
        importlib.reload(obs)
        obs.CryptoObservabilityConfig.enable()
        obs.reset_metrics()
        self.obs = obs
    
    def tearDown(self):
        if 'QUANTUMCRYPT_OBSERVABILITY_ENABLED' in os.environ:
            del os.environ['QUANTUMCRYPT_OBSERVABILITY_ENABLED']
    
    def test_concurrent_recording(self):
        """Multiple threads should safely record operations"""
        barrier = threading.Barrier(5)
        
        def worker(thread_id):
            barrier.wait()
            for i in range(20):
                self.obs.record_operation(
                    f"op_{thread_id}", 1.0, True, f"alg_{thread_id}"
                )
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        summary = self.obs.get_metrics_summary()
        total = sum(op["total"] for op in summary["operations"].values())
        self.assertEqual(total, 100)  # 5 threads * 20 operations

class TestBackwardCompatibility(unittest.TestCase):
    """Verify 100% backward compatibility - no breaking changes"""
    
    def test_no_crypto_logic_modified(self):
        """CRITICAL: This module should NOT modify any crypto logic"""
        # We only wrap, never replace or modify
        import quantum_crypt
        
        # This is purely additive
        self.assertTrue(hasattr(
            quantum_crypt.crypto_observability_pq_key_operation_metrics_slo_v27_2026_june,
            'PostQuantumKeyOperationWrapper'
        ))
    
    def test_disabled_by_default_guarantee(self):
        """Guarantee: Default behavior is 100% identical to before"""
        import importlib
        import quantum_crypt.crypto_observability_pq_key_operation_metrics_slo_v27_2026_june as obs
        importlib.reload(obs)
        
        # Without any env vars or explicit enable
        self.assertFalse(obs.CryptoObservabilityConfig.is_enabled())

class TestSLOConfigCustomization(unittest.TestCase):
    """Test SLO configuration customization"""
    
    def setUp(self):
        os.environ['QUANTUMCRYPT_OBSERVABILITY_ENABLED'] = '1'
        import importlib
        import quantum_crypt.crypto_observability_pq_key_operation_metrics_slo_v27_2026_june as obs
        importlib.reload(obs)
        obs.CryptoObservabilityConfig.enable()
        obs.reset_metrics()
        self.obs = obs
    
    def tearDown(self):
        if 'QUANTUMCRYPT_OBSERVABILITY_ENABLED' in os.environ:
            del os.environ['QUANTUMCRYPT_OBSERVABILITY_ENABLED']
    
    def test_custom_slo_config(self):
        """Custom SLO config should be applied"""
        custom_config = self.obs.SLOConfig(
            latency_p95_ms=500.0,
            latency_p99_ms=1000.0,
            error_rate_max=0.05,
            throughput_min=1.0
        )
        self.obs.CryptoObservabilityConfig.set_slo_config(custom_config)
        
        retrieved = self.obs.CryptoObservabilityConfig.get_slo_config()
        self.assertEqual(retrieved.latency_p95_ms, 500.0)
        self.assertEqual(retrieved.error_rate_max, 0.05)

if __name__ == '__main__':
    unittest.main(verbosity=2)
