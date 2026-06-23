"""
Tests for QuantumCrypt Enhanced Observability v12
Dimension D - Observability & Instrumentation
Tests cover:
- Probabilistic span sampling with crypto operation awareness
- Async context propagation
- Structured logging bridge with crypto context
- Crypto-specific span metrics aggregation
- Health check integration for crypto operations
- All tests are add-only, no existing code modified
"""
import unittest
import asyncio
import time
import logging
from quantum_crypt.crypto_observability_enhanced_sampling_async_logging_v12_2026_june import (
    CryptoTracer,
    ProbabilisticSampler,
    CryptoSpanMetricsAggregator,
    TraceBaggage,
    SpanKind,
    SpanStatus,
    SamplingDecision,
    CryptoOperationType,
    enable_tracing,
    disable_tracing,
    is_tracing_enabled,
    start_span,
    end_span,
    get_metrics,
    get_health_status,
    trace,
    trace_async,
    global_crypto_tracer,
)


class TestProbabilisticSampler(unittest.TestCase):
    """Tests for probabilistic span sampling with crypto awareness."""
    
    def test_sampler_default_rate(self):
        """Test sampler defaults to 100% sampling."""
        sampler = ProbabilisticSampler()
        self.assertEqual(sampler.get_sampling_rate(), 1.0)
    
    def test_sampler_custom_rate(self):
        """Test sampler with custom sampling rate."""
        sampler = ProbabilisticSampler(0.5)
        self.assertEqual(sampler.get_sampling_rate(), 0.5)
    
    def test_sampler_force_sample_key_ops(self):
        """Test key operations are always sampled regardless of rate."""
        sampler = ProbabilisticSampler(0.0)  # 0% sampling rate
        
        # Key generation should always be sampled
        decision = sampler.should_sample(
            "trace_123", "keygen", 
            crypto_op=CryptoOperationType.PQ_KEYGEN
        )
        self.assertEqual(decision, SamplingDecision.RECORD_AND_SAMPLE)
        
        # Key exchange should always be sampled
        decision = sampler.should_sample(
            "trace_456", "kex", 
            crypto_op=CryptoOperationType.PQ_KEX
        )
        self.assertEqual(decision, SamplingDecision.RECORD_AND_SAMPLE)
    
    def test_sampler_100_percent(self):
        """Test 100% sampling rate always samples."""
        sampler = ProbabilisticSampler(1.0)
        for i in range(100):
            decision = sampler.should_sample(f"trace_{i}", "test_op")
            self.assertEqual(decision, SamplingDecision.RECORD_AND_SAMPLE)
    
    def test_sampler_0_percent_normal_ops(self):
        """Test 0% sampling rate drops normal operations."""
        sampler = ProbabilisticSampler(0.0)
        for i in range(100):
            decision = sampler.should_sample(
                f"trace_{i}", "test_op",
                crypto_op=CryptoOperationType.PQ_ENCRYPT
            )
            self.assertEqual(decision, SamplingDecision.DROP)


class TestCryptoSpanMetricsAggregator(unittest.TestCase):
    """Tests for crypto-specific span metrics aggregation."""
    
    def test_metrics_initialization(self):
        """Test metrics aggregator initializes properly."""
        aggregator = CryptoSpanMetricsAggregator()
        metrics = aggregator.get_metrics()
        self.assertEqual(metrics["total_spans"], 0)
        self.assertEqual(metrics["total_errors"], 0)
        self.assertIn("crypto_operations", metrics)
    
    def test_metrics_record_crypto_operation(self):
        """Test recording crypto operation metrics."""
        aggregator = CryptoSpanMetricsAggregator()
        
        from dataclasses import dataclass
        @dataclass
        class MockSpan:
            name: str
            status: SpanStatus
            crypto_operation: CryptoOperationType
            end_time: float = 0.0
            start_time: float = 0.0
            
            def get_duration_ms(self):
                return 100.0
        
        span = MockSpan(
            name="pq_encrypt", 
            status=SpanStatus.OK,
            crypto_operation=CryptoOperationType.PQ_ENCRYPT
        )
        aggregator.record_span(span)
        
        metrics = aggregator.get_metrics()
        self.assertEqual(metrics["total_spans"], 1)
        self.assertIn("pq_encryption", metrics["crypto_operations"])
        self.assertEqual(metrics["crypto_operations"]["pq_encryption"], 1)
    
    def test_metrics_multiple_crypto_ops(self):
        """Test recording multiple different crypto operations."""
        aggregator = CryptoSpanMetricsAggregator()
        
        from dataclasses import dataclass
        @dataclass
        class MockSpan:
            name: str
            status: SpanStatus
            crypto_operation: CryptoOperationType
            end_time: float = 0.0
            start_time: float = 0.0
            
            def get_duration_ms(self):
                return 100.0
        
        span1 = MockSpan(
            name="encrypt", status=SpanStatus.OK,
            crypto_operation=CryptoOperationType.PQ_ENCRYPT
        )
        span2 = MockSpan(
            name="decrypt", status=SpanStatus.OK,
            crypto_operation=CryptoOperationType.PQ_DECRYPT
        )
        span3 = MockSpan(
            name="sign", status=SpanStatus.OK,
            crypto_operation=CryptoOperationType.PQ_SIGN
        )
        
        aggregator.record_span(span1)
        aggregator.record_span(span2)
        aggregator.record_span(span3)
        
        metrics = aggregator.get_metrics()
        self.assertEqual(metrics["total_spans"], 3)
        self.assertEqual(metrics["crypto_operations"]["pq_encryption"], 1)
        self.assertEqual(metrics["crypto_operations"]["pq_decryption"], 1)
        self.assertEqual(metrics["crypto_operations"]["pq_signing"], 1)


class TestCryptoTracer(unittest.TestCase):
    """Tests for main crypto tracer implementation."""
    
    def setUp(self):
        """Reset tracer state before each test."""
        disable_tracing()
        global_crypto_tracer.metrics.reset()
    
    def test_tracer_disabled_by_default(self):
        """Test tracer is disabled by default (opt-in)."""
        self.assertFalse(is_tracing_enabled())
    
    def test_tracer_enable_disable(self):
        """Test enabling and disabling tracing."""
        enable_tracing()
        self.assertTrue(is_tracing_enabled())
        disable_tracing()
        self.assertFalse(is_tracing_enabled())
    
    def test_start_span_with_crypto_operation(self):
        """Test starting span with crypto operation type."""
        enable_tracing()
        span = start_span(
            "test_encryption",
            kind=SpanKind.ENCRYPTION,
            crypto_operation=CryptoOperationType.PQ_ENCRYPT
        )
        self.assertEqual(span.crypto_operation, CryptoOperationType.PQ_ENCRYPT)
        self.assertEqual(span.kind, SpanKind.ENCRYPTION)
        end_span(span)
    
    def test_start_span_disabled(self):
        """Test span creation when disabled returns no-op span."""
        span = start_span("test_operation")
        self.assertEqual(span.trace_id, "disabled")
        self.assertEqual(span.span_id, "disabled")
    
    def test_end_span_records_metrics(self):
        """Test ending span records crypto metrics."""
        enable_tracing()
        span = start_span(
            "test_encryption",
            crypto_operation=CryptoOperationType.PQ_ENCRYPT
        )
        end_span(span)
        
        metrics = get_metrics()
        self.assertGreater(metrics["total_spans"], 0)
        self.assertIn("pq_encryption", metrics["crypto_operations"])


class TestCryptoTraceDecorator(unittest.TestCase):
    """Tests for crypto trace decorators."""
    
    def setUp(self):
        """Reset tracer state before each test."""
        disable_tracing()
        global_crypto_tracer.metrics.reset()
    
    def test_sync_decorator_with_crypto_op(self):
        """Test sync decorator with crypto operation type."""
        enable_tracing()
        
        @trace(
            "encrypt_data",
            kind=SpanKind.ENCRYPTION,
            crypto_operation=CryptoOperationType.PQ_ENCRYPT
        )
        def encrypt_func():
            return "encrypted_data"
        
        result = encrypt_func()
        self.assertEqual(result, "encrypted_data")
        
        metrics = get_metrics()
        self.assertIn("pq_encryption", metrics["crypto_operations"])
    
    def test_sync_decorator_disabled(self):
        """Test sync decorator works when disabled."""
        @trace("test_function")
        def test_func():
            return "success"
        
        result = test_func()
        self.assertEqual(result, "success")


class TestAsyncCryptoTraceDecorator(unittest.TestCase):
    """Tests for async crypto trace decorators."""
    
    def setUp(self):
        """Reset tracer state before each test."""
        disable_tracing()
        global_crypto_tracer.metrics.reset()
    
    def test_async_decorator_with_crypto_op(self):
        """Test async decorator with crypto operation type."""
        enable_tracing()
        
        @trace_async(
            "async_key_exchange",
            kind=SpanKind.KEY_EXCHANGE,
            crypto_operation=CryptoOperationType.PQ_KEX
        )
        async def kex_func():
            await asyncio.sleep(0.001)
            return "shared_secret"
        
        result = asyncio.run(kex_func())
        self.assertEqual(result, "shared_secret")
        
        metrics = get_metrics()
        self.assertIn("pq_key_exchange", metrics["crypto_operations"])
    
    def test_async_decorator_disabled(self):
        """Test async decorator works when disabled."""
        @trace_async("test_async_function")
        async def test_func():
            await asyncio.sleep(0.001)
            return "success"
        
        result = asyncio.run(test_func())
        self.assertEqual(result, "success")


class TestCryptoHealthCheck(unittest.TestCase):
    """Tests for crypto health check integration."""
    
    def setUp(self):
        """Reset tracer state before each test."""
        disable_tracing()
        global_crypto_tracer.metrics.reset()
    
    def test_health_check_disabled(self):
        """Test health check when tracing is disabled."""
        health = get_health_status()
        self.assertIn("status", health)
        self.assertIn("tracing_enabled", health)
        self.assertFalse(health["tracing_enabled"])
    
    def test_health_check_enabled(self):
        """Test health check when tracing is enabled."""
        enable_tracing()
        health = get_health_status()
        self.assertTrue(health["tracing_enabled"])
        self.assertIn("sampling_rate", health)
        self.assertIn("metrics", health)
        self.assertIn("checks", health)
        self.assertIn("crypto_error_rate", health["checks"])
    
    def test_health_check_crypto_thresholds(self):
        """Test health check uses crypto-specific error thresholds."""
        enable_tracing()
        health = get_health_status()
        # Crypto has stricter thresholds (5% vs 10% for general)
        self.assertEqual(health["checks"]["crypto_error_rate"]["threshold"], 0.05)


class TestCryptoLoggingIntegration(unittest.TestCase):
    """Tests for structured logging bridge with crypto context."""
    
    def setUp(self):
        """Reset tracer state before each test."""
        disable_tracing()
        global_crypto_tracer.metrics.reset()
    
    def test_logging_filter_has_crypto_context(self):
        """Test logging filter includes crypto operation context."""
        enable_tracing()
        log_filter = global_crypto_tracer.get_logging_filter()
        
        span = start_span(
            "test_operation",
            crypto_operation=CryptoOperationType.PQ_ENCRYPT
        )
        
        record = logging.LogRecord(
            "test", logging.INFO, "", 0, "test message", (), None
        )
        log_filter.filter(record)
        
        self.assertEqual(record.crypto_operation, "pq_encryption")
        self.assertIsNotNone(record.trace_id)
        self.assertIsNotNone(record.span_id)
        
        end_span(span)


class TestSpanKindEnum(unittest.TestCase):
    """Tests for crypto-specific span kinds."""
    
    def test_crypto_span_kinds_exist(self):
        """Test crypto-specific span kinds are defined."""
        self.assertIsNotNone(SpanKind.CRYPTO_OPERATION)
        self.assertIsNotNone(SpanKind.KEY_EXCHANGE)
        self.assertIsNotNone(SpanKind.ENCRYPTION)
        self.assertIsNotNone(SpanKind.DECRYPTION)
        self.assertIsNotNone(SpanKind.SIGNING)
        self.assertIsNotNone(SpanKind.VERIFICATION)
    
    def test_crypto_operation_types_exist(self):
        """Test crypto operation types are defined."""
        self.assertIsNotNone(CryptoOperationType.PQ_KEYGEN)
        self.assertIsNotNone(CryptoOperationType.PQ_ENCRYPT)
        self.assertIsNotNone(CryptoOperationType.PQ_DECRYPT)
        self.assertIsNotNone(CryptoOperationType.PQ_SIGN)
        self.assertIsNotNone(CryptoOperationType.PQ_VERIFY)
        self.assertIsNotNone(CryptoOperationType.PQ_KEX)
        self.assertIsNotNone(CryptoOperationType.HYBRID_ENCRYPT)
        self.assertIsNotNone(CryptoOperationType.HYBRID_DECRYPT)


class TestTraceBaggage(unittest.TestCase):
    """Tests for trace baggage context propagation."""
    
    def test_baggage_correlation_id(self):
        """Test correlation ID storage and retrieval."""
        baggage = TraceBaggage()
        baggage.set_correlation_id("crypto-session-123")
        self.assertEqual(baggage.get_correlation_id(), "crypto-session-123")
    
    def test_baggage_items(self):
        """Test baggage item storage."""
        baggage = TraceBaggage()
        baggage.set_baggage_item("key_id", "rsa-2048-1")
        baggage.set_baggage_item("algorithm", "kyber-1024")
        self.assertEqual(baggage.get_baggage_item("key_id"), "rsa-2048-1")
        self.assertEqual(baggage.get_baggage_item("algorithm"), "kyber-1024")


class TestContextPropagation(unittest.TestCase):
    """Tests for trace context propagation."""
    
    def setUp(self):
        """Reset tracer state before each test."""
        disable_tracing()
        global_crypto_tracer.metrics.reset()
    
    def test_inject_trace_context_with_sampling_flags(self):
        """Test context injection includes correct sampling flags."""
        enable_tracing()
        span = start_span("test_operation")
        
        headers = global_crypto_tracer.inject_trace_context()
        self.assertIn("traceparent", headers)
        
        # traceparent format: version-traceId-spanId-flags
        parts = headers["traceparent"].split("-")
        self.assertEqual(len(parts), 4)
        self.assertEqual(parts[0], "00")  # version
        self.assertEqual(parts[3], "01")  # sampled flag
        
        end_span(span)


if __name__ == "__main__":
    unittest.main(verbosity=2)
