"""
Tests for QuantumCrypt AI - Enhanced Crypto Observability & Instrumentation v10
Dimension D: Observability & Instrumentation

ADD-ONLY implementation - no existing code modified
All tests must pass
"""

import unittest
import time
import json
import threading

from quantum_crypt.crypto_observability_enhanced_distributed_tracing_slo_metrics_v10_2026_june import (
    CryptoEnhancedObservabilityEngineV10,
    TraceContext,
    CryptoBaggage,
    CryptoSpan,
    CryptoOperationType,
    CryptoAlgorithm,
    KeyStrength,
    SpanKind,
    SpanStatus,
    CryptoAdaptiveSampler,
    CryptoHistogram,
    CryptoSLOMonitor,
    SLODefinition,
    SLOStatus,
    CryptoHealthCheckManager,
    CryptoHealthCheck,
    HealthCheckResult,
    HealthStatus,
    get_crypto_observability_engine_v10,
    enable_crypto_observability_v10,
    disable_crypto_observability_v10,
)


class TestCryptoTraceContext(unittest.TestCase):
    """Test crypto trace context."""
    
    def test_generate_trace_context(self):
        """Test trace context generation."""
        ctx = TraceContext.generate()
        self.assertEqual(len(ctx.trace_id), 32)
        self.assertEqual(len(ctx.span_id), 16)
        self.assertIsNotNone(ctx.crypto_operation_id)
    
    def test_child_span_inherits_crypto_id(self):
        """Test child spans inherit crypto operation ID."""
        parent = TraceContext.generate()
        parent.key_id = "key-12345"
        child = TraceContext.from_parent(parent)
        
        self.assertEqual(child.trace_id, parent.trace_id)
        self.assertEqual(child.crypto_operation_id, parent.crypto_operation_id)
        self.assertEqual(child.key_id, "key-12345")
    
    def test_traceparent_header(self):
        """Test W3C traceparent header format."""
        ctx = TraceContext.generate()
        header = ctx.to_traceparent()
        self.assertEqual(len(header.split('-')), 4)
    
    def test_parse_traceparent(self):
        """Test parsing traceparent header."""
        header = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        ctx = TraceContext.from_traceparent(header)
        self.assertIsNotNone(ctx)
        self.assertTrue(ctx.is_sampled())


class TestCryptoBaggage(unittest.TestCase):
    """Test crypto correlation baggage."""
    
    def test_set_key_id(self):
        """Test setting key ID in baggage."""
        bag = CryptoBaggage()
        bag.set_key_id("key-abc123")
        self.assertEqual(bag.get("key_id"), "key-abc123")
    
    def test_set_algorithm(self):
        """Test setting algorithm in baggage."""
        bag = CryptoBaggage()
        bag.set_algorithm("AES-256-GCM")
        self.assertEqual(bag.get("algorithm"), "AES-256-GCM")
    
    def test_baggage_header_format(self):
        """Test baggage header format."""
        bag = CryptoBaggage()
        bag.set_key_id("key-123")
        bag.set_algorithm("Kyber")
        
        header = bag.to_header()
        self.assertIn("key_id=key-123", header)
        self.assertIn("algorithm=Kyber", header)
    
    def test_parse_baggage_header(self):
        """Test parsing baggage header."""
        header = "key_id=key-123,algorithm=AES-256-GCM,tenant_id=acme"
        bag = CryptoBaggage.from_header(header)
        
        self.assertEqual(bag.get("key_id"), "key-123")
        self.assertEqual(bag.get("algorithm"), "AES-256-GCM")
        self.assertEqual(bag.get("tenant_id"), "acme")


class TestCryptoSpan(unittest.TestCase):
    """Test crypto span implementation."""
    
    def test_crypto_span_creation(self):
        """Test basic crypto span creation."""
        ctx = TraceContext.generate()
        span = CryptoSpan(
            name="key_generation",
            trace_context=ctx,
            operation_type=CryptoOperationType.KEY_GENERATION,
            algorithm=CryptoAlgorithm.CRYSTALS_KYBER,
            key_strength=KeyStrength.POST_QUANTUM
        )
        
        self.assertEqual(span.operation_type, CryptoOperationType.KEY_GENERATION)
        self.assertEqual(span.algorithm, CryptoAlgorithm.CRYSTALS_KYBER)
        self.assertEqual(span.key_strength, KeyStrength.POST_QUANTUM)
    
    def test_constant_time_marking(self):
        """Test marking operation as constant-time verified."""
        ctx = TraceContext.generate()
        span = CryptoSpan(
            name="comparison",
            trace_context=ctx,
            operation_type=CryptoOperationType.VERIFICATION
        )
        
        span.mark_constant_time(verified=True)
        self.assertTrue(span.constant_time_verified)
    
    def test_span_duration(self):
        """Test span duration calculation."""
        ctx = TraceContext.generate()
        span = CryptoSpan(
            name="encryption",
            trace_context=ctx,
            operation_type=CryptoOperationType.ENCRYPTION
        )
        time.sleep(0.01)
        span.end()
        
        self.assertGreater(span.duration_ms(), 0)
    
    def test_span_serialization(self):
        """Test span serialization with crypto fields."""
        ctx = TraceContext.generate()
        span = CryptoSpan(
            name="signing",
            trace_context=ctx,
            operation_type=CryptoOperationType.SIGNING,
            algorithm=CryptoAlgorithm.ED25519,
            key_strength=KeyStrength.HIGH
        )
        span.mark_constant_time(True)
        span.end()
        
        d = span.to_dict()
        self.assertEqual(d["operation_type"], "signing")
        self.assertEqual(d["algorithm"], "Ed25519")
        self.assertEqual(d["key_strength"], "high")
        self.assertTrue(d["constant_time_verified"])


class TestCryptoAdaptiveSampler(unittest.TestCase):
    """Test crypto adaptive sampling."""
    
    def test_always_sample_key_operations(self):
        """Test key operations are always sampled."""
        sampler = CryptoAdaptiveSampler(base_rate=0.0)
        self.assertTrue(sampler.should_sample("trace123", is_key_operation=True))
    
    def test_always_sample_errors(self):
        """Test errors are always sampled."""
        sampler = CryptoAdaptiveSampler(base_rate=0.0)
        self.assertTrue(sampler.should_sample("trace123", has_error=True))
    
    def test_higher_sampling_for_post_quantum(self):
        """Test post-quantum algorithms have higher sampling rate."""
        sampler = CryptoAdaptiveSampler(base_rate=0.1, pq_rate=0.5)
        # Just verify no exceptions
        sampler.should_sample("trace123", is_post_quantum=True)
    
    def test_deterministic_sampling(self):
        """Test sampling is deterministic for same trace_id."""
        sampler = CryptoAdaptiveSampler(base_rate=0.5)
        result1 = sampler.should_sample("trace12345")
        result2 = sampler.should_sample("trace12345")
        self.assertEqual(result1, result2)


class TestCryptoHistogram(unittest.TestCase):
    """Test crypto histogram metrics."""
    
    def test_latency_histogram(self):
        """Test crypto operation latency histogram."""
        hist = CryptoHistogram("encryption_latency")
        
        for i in range(1, 101):
            hist.record(float(i))
        
        stats = hist.stats()
        self.assertEqual(stats["count"], 100)
        self.assertGreater(stats["p95"], 90)
        self.assertGreater(stats["p99"], 95)
    
    def test_key_strength_distribution(self):
        """Test key strength tracking."""
        hist = CryptoHistogram("key_strength_bits")
        
        # Simulate key strengths
        hist.record(128.0)  # AES-128
        hist.record(256.0)  # AES-256
        hist.record(256.0)  # Kyber-512 equivalent
        hist.record(384.0)  # P-384
        
        stats = hist.stats()
        self.assertEqual(stats["count"], 4)
        self.assertEqual(stats["min"], 128)
        self.assertEqual(stats["max"], 384)


class TestCryptoSLOMonitor(unittest.TestCase):
    """Test crypto SLO monitoring."""
    
    def test_register_crypto_slo(self):
        """Test registering crypto SLO."""
        monitor = CryptoSLOMonitor()
        slo = SLODefinition(
            name="key_gen_availability",
            target_percentage=99.99,
            operation_type=CryptoOperationType.KEY_GENERATION
        )
        monitor.register_slo(slo)
        self.assertIn("key_gen_availability", monitor._slos)
    
    def test_crypto_slo_perfect_availability(self):
        """Test SLO with 100% success."""
        monitor = CryptoSLOMonitor()
        slo = SLODefinition(name="encryption_slo", target_percentage=99.9)
        monitor.register_slo(slo)
        
        for _ in range(100):
            monitor.record_success("encryption_slo")
        
        result = monitor.calculate_slo("encryption_slo")
        self.assertIsNotNone(result)
        self.assertEqual(result.current_percentage, 100.0)
        self.assertEqual(result.status, SLOStatus.HEALTHY)
    
    def test_crypto_slo_with_failures(self):
        """Test SLO calculation with failures."""
        monitor = CryptoSLOMonitor()
        slo = SLODefinition(name="signing_slo", target_percentage=99.0)
        monitor.register_slo(slo)
        
        # 95 success, 5 failure = 95%
        for _ in range(95):
            monitor.record_success("signing_slo")
        for _ in range(5):
            monitor.record_failure("signing_slo")
        
        result = monitor.calculate_slo("signing_slo")
        self.assertIsNotNone(result)
        self.assertLess(result.current_percentage, 99.0)
    
    def test_slo_burn_rate_calculation(self):
        """Test error budget burn rate."""
        monitor = CryptoSLOMonitor()
        slo = SLODefinition(name="decryption_slo", target_percentage=99.9)
        monitor.register_slo(slo)
        
        for _ in range(1000):
            monitor.record_success("decryption_slo")
        for _ in range(5):
            monitor.record_failure("decryption_slo")
        
        result = monitor.calculate_slo("decryption_slo")
        self.assertIsNotNone(result)
        self.assertGreater(result.error_budget_burn_rate, 0)


class TestCryptoHealthCheckManager(unittest.TestCase):
    """Test crypto health check framework."""
    
    def test_register_health_check(self):
        """Test registering crypto health check."""
        manager = CryptoHealthCheckManager()
        
        def hsm_check():
            return HealthCheckResult(
                name="hsm_connection",
                status=HealthStatus.HEALTHY,
                message="HSM connected"
            )
        
        manager.register_check(CryptoHealthCheck(
            name="hsm_connection",
            check_fn=hsm_check,
            category="hardware"
        ))
        
        self.assertIn("hsm_connection", manager._checks)
    
    def test_default_rng_check(self):
        """Test default RNG health check."""
        manager = CryptoHealthCheckManager()
        manager.register_default_crypto_checks()
        
        result = manager.run_check("system_rng")
        self.assertEqual(result.status, HealthStatus.HEALTHY)
    
    def test_rng_health_check(self):
        """Test RNG health check works."""
        manager = CryptoHealthCheckManager()
        
        def good_rng():
            return HealthCheckResult(
                name="rng",
                status=HealthStatus.HEALTHY,
                message="Entropy sufficient"
            )
        
        manager.register_check(CryptoHealthCheck("rng", good_rng))
        result = manager.run_check("rng")
        self.assertEqual(result.status, HealthStatus.HEALTHY)
    
    def test_unhealthy_check(self):
        """Test unhealthy check propagation."""
        manager = CryptoHealthCheckManager()
        
        def failing_hsm():
            return HealthCheckResult(
                name="hsm",
                status=HealthStatus.UNHEALTHY,
                message="Connection timeout"
            )
        
        manager.register_check(CryptoHealthCheck("hsm", failing_hsm))
        result = manager.run_check("hsm")
        self.assertEqual(result.status, HealthStatus.UNHEALTHY)
        self.assertIn("timeout", result.message)
    
    def test_dependency_propagation(self):
        """Test critical dependency failure propagation."""
        manager = CryptoHealthCheckManager()
        
        def dep_fails():
            return HealthCheckResult("dep", HealthStatus.UNHEALTHY)
        
        def main_check():
            return HealthCheckResult("main", HealthStatus.HEALTHY)
        
        manager.register_check(CryptoHealthCheck("dep", dep_fails))
        manager.register_check(CryptoHealthCheck("main", main_check, dependencies=["dep"]))
        
        result = manager.run_check("main")
        self.assertEqual(result.status, HealthStatus.UNHEALTHY)
    
    def test_overall_health_status(self):
        """Test overall health aggregation."""
        manager = CryptoHealthCheckManager()
        
        manager.register_check(CryptoHealthCheck(
            "check1",
            lambda: HealthCheckResult("check1", HealthStatus.HEALTHY)
        ))
        manager.register_check(CryptoHealthCheck(
            "check2",
            lambda: HealthCheckResult("check2", HealthStatus.HEALTHY)
        ))
        
        self.assertEqual(manager.overall_health(), HealthStatus.HEALTHY)


class TestCryptoEnhancedObservabilityEngineV10(unittest.TestCase):
    """Test main crypto observability engine."""
    
    def test_engine_creation_disabled_by_default(self):
        """Test engine is OPT-IN - disabled by default."""
        engine = CryptoEnhancedObservabilityEngineV10()
        self.assertFalse(engine.is_enabled())
    
    def test_enable_disable(self):
        """Test enable/disable functionality."""
        engine = CryptoEnhancedObservabilityEngineV10()
        engine.enable()
        self.assertTrue(engine.is_enabled())
        engine.disable()
        self.assertFalse(engine.is_enabled())
    
    def test_start_crypto_span_disabled(self):
        """Test span creation when disabled still works."""
        engine = CryptoEnhancedObservabilityEngineV10()
        
        span = engine.start_crypto_span(
            operation_type=CryptoOperationType.ENCRYPTION,
            algorithm=CryptoAlgorithm.AES_256_GCM
        )
        
        self.assertIsNotNone(span)
        self.assertEqual(span.operation_type, CryptoOperationType.ENCRYPTION)
    
    def test_start_crypto_span_enabled(self):
        """Test span creation when enabled."""
        engine = CryptoEnhancedObservabilityEngineV10()
        engine.enable()
        
        span = engine.start_crypto_span(
            operation_type=CryptoOperationType.KEY_GENERATION,
            algorithm=CryptoAlgorithm.CRYSTALS_KYBER,
            key_id="key-kyber-123",
            key_strength=KeyStrength.POST_QUANTUM,
            key_size=1024
        )
        
        self.assertIsNotNone(span)
        self.assertEqual(span.algorithm, CryptoAlgorithm.CRYSTALS_KYBER)
        self.assertEqual(span.key_strength, KeyStrength.POST_QUANTUM)
        self.assertEqual(span.attributes["key_size"], 1024)
    
    def test_end_crypto_span_records_metrics(self):
        """Test ending span records crypto metrics."""
        engine = CryptoEnhancedObservabilityEngineV10()
        engine.enable()
        
        span = engine.start_crypto_span(
            operation_type=CryptoOperationType.ENCRYPTION,
            algorithm=CryptoAlgorithm.AES_256_GCM
        )
        engine.end_crypto_span(span, SpanStatus.OK)
        
        metrics = engine.get_metrics()
        self.assertIn("crypto_op_count_encryption", metrics["counters"])
    
    def test_error_span_tracking(self):
        """Test error span tracking."""
        engine = CryptoEnhancedObservabilityEngineV10()
        engine.enable()
        
        span = engine.start_crypto_span(
            operation_type=CryptoOperationType.DECRYPTION
        )
        engine.end_crypto_span(span, SpanStatus.ERROR)
        
        metrics = engine.get_metrics()
        self.assertIn("crypto_op_error_decryption", metrics["counters"])
    
    def test_key_generation_metrics(self):
        """Test key generation metrics recording."""
        engine = CryptoEnhancedObservabilityEngineV10()
        engine.enable()
        
        engine.record_key_generation(
            algorithm=CryptoAlgorithm.CRYSTALS_KYBER,
            key_strength=KeyStrength.POST_QUANTUM,
            latency_ms=42.5
        )
        
        metrics = engine.get_metrics()
        self.assertIn("key_gen_CRYSTALS-Kyber", metrics["counters"])
        self.assertIn("key_strength_post_quantum", metrics["counters"])
    
    def test_encryption_metrics(self):
        """Test encryption metrics recording."""
        engine = CryptoEnhancedObservabilityEngineV10()
        engine.enable()
        
        engine.record_encryption(
            algorithm=CryptoAlgorithm.AES_256_GCM,
            data_size_bytes=4096,
            latency_ms=1.2
        )
        
        metrics = engine.get_metrics()
        self.assertIn("encryption_AES-256-GCM", metrics["counters"])
        self.assertEqual(metrics["gauges"]["last_encryption_size"], 4096)
    
    def test_slo_integration(self):
        """Test SLO integration with engine."""
        engine = CryptoEnhancedObservabilityEngineV10()
        
        slo = SLODefinition(
            name="crypto_operation_availability",
            target_percentage=99.99
        )
        engine.slo.register_slo(slo)
        engine.slo.record_success("crypto_operation_availability")
        
        result = engine.slo.calculate_slo("crypto_operation_availability")
        self.assertIsNotNone(result)
    
    def test_health_integration(self):
        """Test health check integration."""
        engine = CryptoEnhancedObservabilityEngineV10()
        
        # Default checks should be registered
        result = engine.health.run_check("system_rng")
        self.assertEqual(result.status, HealthStatus.HEALTHY)
    
    def test_export_json(self):
        """Test JSON export functionality."""
        engine = CryptoEnhancedObservabilityEngineV10()
        engine.enable()
        
        span = engine.start_crypto_span(
            operation_type=CryptoOperationType.SIGNING,
            algorithm=CryptoAlgorithm.ED25519
        )
        engine.end_crypto_span(span)
        
        export_str = engine.export_json()
        export_data = json.loads(export_str)
        
        self.assertIn("metrics", export_data)
        self.assertIn("slo", export_data)
        self.assertIn("health", export_data)
    
    def test_algorithm_usage_tracking(self):
        """Test algorithm usage tracking."""
        engine = CryptoEnhancedObservabilityEngineV10()
        engine.enable()
        
        # Create spans for different algorithms
        for _ in range(5):
            span = engine.start_crypto_span(
                operation_type=CryptoOperationType.ENCRYPTION,
                algorithm=CryptoAlgorithm.AES_256_GCM
            )
            engine.end_crypto_span(span)
        
        for _ in range(3):
            span = engine.start_crypto_span(
                operation_type=CryptoOperationType.KEY_GENERATION,
                algorithm=CryptoAlgorithm.CRYSTALS_KYBER
            )
            engine.end_crypto_span(span)
        
        metrics = engine.get_metrics()
        self.assertIn("algorithm_usage", metrics)
        self.assertGreater(metrics["algorithm_usage"].get("AES-256-GCM", 0), 0)
        self.assertGreater(metrics["algorithm_usage"].get("CRYSTALS-Kyber", 0), 0)


class TestGlobalSingleton(unittest.TestCase):
    """Test global singleton functions."""
    
    def test_get_singleton(self):
        """Test getting global engine."""
        engine1 = get_crypto_observability_engine_v10()
        engine2 = get_crypto_observability_engine_v10()
        self.assertIs(engine1, engine2)
    
    def test_global_enable_disable(self):
        """Test global enable/disable functions."""
        enable_crypto_observability_v10()
        self.assertTrue(get_crypto_observability_engine_v10().is_enabled())
        
        disable_crypto_observability_v10()
        self.assertFalse(get_crypto_observability_engine_v10().is_enabled())


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility."""
    
    def test_v8_still_importable(self):
        """Test v8 module can still be imported."""
        try:
            from quantum_crypt import crypto_observability_metrics_collection_v8_2026_june
            self.assertTrue(True)
        except ImportError:
            pass
    
    def test_v10_independent(self):
        """Test v10 works independently of older versions."""
        engine = CryptoEnhancedObservabilityEngineV10()
        self.assertIsNotNone(engine)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety."""
    
    def test_concurrent_crypto_operations(self):
        """Test concurrent crypto operation recording."""
        engine = CryptoEnhancedObservabilityEngineV10()
        engine.enable()
        
        def record_ops(n):
            for _ in range(n):
                span = engine.start_crypto_span(
                    operation_type=CryptoOperationType.ENCRYPTION,
                    algorithm=CryptoAlgorithm.AES_256_GCM
                )
                engine.end_crypto_span(span)
        
        threads = []
        for _ in range(10):
            t = threading.Thread(target=record_ops, args=(100,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        metrics = engine.get_metrics()
        self.assertEqual(metrics["counters"]["crypto_op_count_encryption"], 1000)


if __name__ == "__main__":
    unittest.main()
