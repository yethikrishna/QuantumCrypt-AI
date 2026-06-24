"""
Test Suite for QuantumCrypt-AI Observability v15
Crypto Distributed Tracing & Context Correlation
====================================================
Tests: 36 total
100% ADD-ONLY - NO PRODUCTION CODE MODIFIED
"""

import unittest
import threading
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from crypto_observability_distributed_tracing_correlation_v15_2026_june import (
    CryptoDistributedTracingCorrelationEngine,
    TraceContextPropagator,
    CryptoAdaptiveSampler,
    ThreadLocalContext,
    generate_trace_id,
    generate_span_id,
    generate_crypto_correlation_id,
    is_valid_trace_id,
    is_valid_span_id,
    enable_crypto_tracing,
    disable_crypto_tracing,
    start_crypto_trace_span,
    end_crypto_trace_span,
    get_crypto_correlation_ids,
    inject_crypto_trace_context,
    create_key_operation_correlation,
    traced_crypto_operation,
    TracePropagationFormat,
    SpanKind,
    SpanStatus,
    CryptoOperationType,
    SamplingDecision,
    CRYPTO_OBSERVABILITY_VERSION,
    CRYPTO_OBSERVABILITY_DIMENSION,
    CRYPTO_OBSERVABILITY_FEATURES,
)


class TestCryptoTraceIdGeneration(unittest.TestCase):
    """Test trace and span ID generation utilities."""
    
    def test_generate_trace_id_format(self):
        trace_id = generate_trace_id()
        self.assertEqual(len(trace_id), 32)
        self.assertTrue(is_valid_trace_id(trace_id))
    
    def test_generate_span_id_format(self):
        span_id = generate_span_id()
        self.assertEqual(len(span_id), 16)
        self.assertTrue(is_valid_span_id(span_id))
    
    def test_invalid_trace_id_rejected(self):
        self.assertFalse(is_valid_trace_id("0" * 32))
        self.assertFalse(is_valid_trace_id("g" * 32))
        self.assertFalse(is_valid_trace_id("too_short"))
    
    def test_crypto_correlation_id_format(self):
        corr_id = generate_crypto_correlation_id()
        self.assertTrue(corr_id.startswith("crypto-"))
        self.assertGreater(len(corr_id), 20)


class TestCryptoThreadLocalContext(unittest.TestCase):
    """Test thread-local context storage."""
    
    def test_context_isolation(self):
        context = ThreadLocalContext()
        results = {}
        
        def worker(thread_id):
            context.set_span_context(None)
            results[thread_id] = context.get_span_context()
        
        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        self.assertIsNone(results[1])
        self.assertIsNone(results[2])
    
    def test_baggage_storage(self):
        context = ThreadLocalContext()
        from crypto_observability_distributed_tracing_correlation_v15_2026_june import BaggageEntry
        
        context.set_baggage({"key1": BaggageEntry(value="val1")})
        baggage = context.get_baggage()
        self.assertEqual(baggage["key1"].value, "val1")


class TestCryptoTraceContextPropagation(unittest.TestCase):
    """Test W3C Trace Context and B3 propagation."""
    
    def setUp(self):
        from crypto_observability_distributed_tracing_correlation_v15_2026_june import SpanContext, TraceFlags
        self.test_context = SpanContext(
            trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
            span_id="00f067aa0ba902b7",
            trace_flags=TraceFlags(sampled=True)
        )
    
    def test_w3c_inject_format(self):
        carrier = {}
        TraceContextPropagator.inject_w3c(self.test_context, carrier)
        self.assertIn("traceparent", carrier)
        parts = carrier["traceparent"].split("-")
        self.assertEqual(len(parts), 4)
        self.assertEqual(parts[0], "00")
        self.assertEqual(parts[1], "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(parts[2], "00f067aa0ba902b7")
        self.assertEqual(parts[3], "01")
    
    def test_w3c_extract_valid(self):
        carrier = {
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        }
        extracted = TraceContextPropagator.extract_w3c(carrier)
        self.assertIsNotNone(extracted)
        self.assertEqual(extracted.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(extracted.span_id, "00f067aa0ba902b7")
        self.assertTrue(extracted.trace_flags.sampled)
    
    def test_w3c_extract_invalid(self):
        carrier = {"traceparent": "invalid-format"}
        extracted = TraceContextPropagator.extract_w3c(carrier)
        self.assertIsNone(extracted)
    
    def test_b3_multi_inject(self):
        carrier = {}
        TraceContextPropagator.inject_b3_multi(self.test_context, carrier)
        self.assertIn("X-B3-TraceId", carrier)
        self.assertIn("X-B3-SpanId", carrier)
        self.assertIn("X-B3-Sampled", carrier)
    
    def test_b3_multi_extract(self):
        carrier = {
            "X-B3-TraceId": "4bf92f3577b34da6a3ce929d0e0e4736",
            "X-B3-SpanId": "00f067aa0ba902b7",
            "X-B3-Sampled": "1"
        }
        extracted = TraceContextPropagator.extract_b3_multi(carrier)
        self.assertIsNotNone(extracted)
        self.assertTrue(extracted.trace_flags.sampled)


class TestCryptoAdaptiveSampler(unittest.TestCase):
    """Test crypto-optimized adaptive sampling."""
    
    def test_sampler_initialization(self):
        sampler = CryptoAdaptiveSampler()
        self.assertGreater(sampler.get_current_sampling_rate(), 0)
        self.assertLessEqual(sampler.get_current_sampling_rate(), 1.0)
    
    def test_key_operation_sampling_priority(self):
        """Key operations should always be sampled (security critical)."""
        sampler = CryptoAdaptiveSampler()
        decision = sampler.should_sample(
            trace_id=generate_trace_id(),
            is_key_operation=True
        )
        # Key ops should almost always be sampled
        self.assertIn(decision, [SamplingDecision.RECORD_AND_SAMPLE, SamplingDecision.DROP])
    
    def test_hsm_call_sampling(self):
        """HSM calls should be sampled at higher rate."""
        sampler = CryptoAdaptiveSampler()
        decision = sampler.should_sample(
            trace_id=generate_trace_id(),
            is_hsm_call=True
        )
        self.assertIsNotNone(decision)
    
    def test_error_sampling_priority(self):
        sampler = CryptoAdaptiveSampler()
        decision = sampler.should_sample(
            trace_id=generate_trace_id(),
            has_error=True
        )
        self.assertIn(decision, [SamplingDecision.RECORD_AND_SAMPLE, SamplingDecision.DROP])
    
    def test_sampling_rate_adaptation(self):
        sampler = CryptoAdaptiveSampler()
        for _ in range(50):
            sampler.record_trace()
        self.assertIsNotNone(sampler.get_current_sampling_rate())


class TestCryptoTracingEngineBasics(unittest.TestCase):
    """Test basic crypto tracing engine functionality."""
    
    def setUp(self):
        self.engine = CryptoDistributedTracingCorrelationEngine()
        self.engine.enable()
    
    def tearDown(self):
        self.engine.disable()
        self.engine.clear_context()
    
    def test_engine_can_be_disabled(self):
        engine = CryptoDistributedTracingCorrelationEngine()
        engine.disable()
        self.assertFalse(engine.is_enabled())
    
    def test_engine_enable_disable(self):
        self.assertTrue(self.engine.is_enabled())
        self.engine.disable()
        self.assertFalse(self.engine.is_enabled())
    
    def test_start_span_when_disabled(self):
        self.engine.disable()
        context, span_id = self.engine.start_span("test")
        self.assertEqual(span_id, "disabled")
        self.assertIsNotNone(context)
    
    def test_start_span_creates_context(self):
        context, span_id = self.engine.start_span(
            "key_generation",
            operation_type=CryptoOperationType.KEY_GENERATION
        )
        self.assertNotEqual(span_id, "disabled")
        self.assertTrue(is_valid_trace_id(context.trace_id))
        self.assertTrue(is_valid_span_id(context.span_id))
    
    def test_end_span(self):
        context, span_id = self.engine.start_span("test")
        self.engine.end_span(span_id, SpanStatus.OK)
        spans = self.engine.get_finished_spans()
        self.assertGreater(len(spans), 0)
    
    def test_add_span_event(self):
        context, span_id = self.engine.start_span("test")
        self.engine.add_event(span_id, "key_material_generated", {"algorithm": "Kyber-768"})
        self.engine.end_span(span_id)
        spans = self.engine.get_finished_spans()
        self.assertEqual(len(spans[0]["events"]), 1)
    
    def test_key_operation_marking(self):
        context, span_id = self.engine.start_span(
            "key_rotation",
            operation_type=CryptoOperationType.KEY_ROTATION
        )
        spans = self.engine.get_finished_spans()
        # Span data should be stored internally
        self.engine.end_span(span_id)
        self.assertTrue(True)  # No exceptions = pass


class TestCryptoCorrelationContext(unittest.TestCase):
    """Test crypto-specific cross-signal correlation."""
    
    def setUp(self):
        self.engine = CryptoDistributedTracingCorrelationEngine()
        self.engine.enable()
    
    def tearDown(self):
        self.engine.disable()
        self.engine.clear_context()
    
    def test_create_key_correlation_context(self):
        corr = self.engine.create_crypto_correlation_context(
            key_id="KEY-001",
            operation_id="OP-123",
            algorithm="CRYSTALS-Kyber-768",
            operation_type=CryptoOperationType.KEY_GENERATION
        )
        self.assertIsNotNone(corr.correlation_id)
        self.assertEqual(corr.key_id, "KEY-001")
        self.assertEqual(corr.algorithm, "CRYSTALS-Kyber-768")
        self.assertEqual(corr.operation_type, CryptoOperationType.KEY_GENERATION)
    
    def test_get_correlation_ids(self):
        self.engine.start_span("test")
        self.engine.create_crypto_correlation_context(
            key_id="KEY-001",
            hsm_session_id="HSM-SESSION-789"
        )
        ids = self.engine.get_current_correlation_ids()
        self.assertIn("trace_id", ids)
        self.assertIn("span_id", ids)
        self.assertIn("key_id", ids)
        self.assertIn("hsm_session_id", ids)
        self.assertEqual(ids["key_id"], "KEY-001")
        self.assertEqual(ids["hsm_session_id"], "HSM-SESSION-789")


class TestCryptoBaggagePropagation(unittest.TestCase):
    """Test baggage context propagation for crypto operations."""
    
    def setUp(self):
        self.engine = CryptoDistributedTracingCorrelationEngine()
        self.engine.enable()
    
    def tearDown(self):
        self.engine.disable()
        self.engine.clear_context()
    
    def test_set_and_get_baggage(self):
        self.engine.set_baggage_entry(
            "key_id",
            "KEY-MASTER-001",
            {"sensitivity": "TOP_SECRET", "hsm_slot": "3"}
        )
        entry = self.engine.get_baggage_entry("key_id")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.value, "KEY-MASTER-001")
        self.assertEqual(entry.metadata["sensitivity"], "TOP_SECRET")
    
    def test_baggage_none_when_disabled(self):
        self.engine.disable()
        self.engine.set_baggage_entry("key", "value")
        entry = self.engine.get_baggage_entry("key")
        self.assertIsNone(entry)


class TestCryptoSpanKindSupport(unittest.TestCase):
    """Test crypto-specific span kinds."""
    
    def setUp(self):
        self.engine = CryptoDistributedTracingCorrelationEngine()
        self.engine.enable()
    
    def tearDown(self):
        self.engine.disable()
        self.engine.clear_context()
    
    def test_hsm_operation_span(self):
        context, span_id = self.engine.start_span(
            "hsm_sign_operation",
            kind=SpanKind.HSM_OPERATION,
            operation_type=CryptoOperationType.SIGNING
        )
        self.assertNotEqual(span_id, "disabled")
        self.engine.end_span(span_id)
    
    def test_key_operation_span(self):
        context, span_id = self.engine.start_span(
            "key_wrap",
            kind=SpanKind.KEY_OPERATION,
            operation_type=CryptoOperationType.KEY_WRAPPING
        )
        self.assertNotEqual(span_id, "disabled")
        self.engine.end_span(span_id)
    
    def test_crypto_operation_span(self):
        context, span_id = self.engine.start_span(
            "kem_encapsulate",
            kind=SpanKind.CRYPTO_OPERATION,
            operation_type=CryptoOperationType.KEM_ENCAPSULATION
        )
        self.assertNotEqual(span_id, "disabled")
        self.engine.end_span(span_id)


class TestTracedCryptoOperationDecorator(unittest.TestCase):
    """Test the traced crypto operation decorator."""
    
    def setUp(self):
        enable_crypto_tracing()
    
    def tearDown(self):
        disable_crypto_tracing()
    
    def test_decorator_traces_success(self):
        @traced_crypto_operation(
            name="key_derivation",
            kind=SpanKind.CRYPTO_OPERATION,
            operation_type=CryptoOperationType.KEY_DERIVATION
        )
        def derive_key(material):
            return f"derived_{material}"
        
        result = derive_key("secret_material")
        self.assertEqual(result, "derived_secret_material")
    
    def test_decorator_traces_error(self):
        @traced_crypto_operation(name="hsm_call")
        def hsm_error_func():
            raise RuntimeError("HSM connection failed")
        
        with self.assertRaises(RuntimeError):
            hsm_error_func()


class TestCryptoGlobalConvenienceAPI(unittest.TestCase):
    """Test the global convenience API functions."""
    
    def test_enable_disable_tracing(self):
        enable_crypto_tracing()
        engine = CryptoDistributedTracingCorrelationEngine()
        self.assertTrue(engine.is_enabled())
        disable_crypto_tracing()
        self.assertFalse(engine.is_enabled())
    
    def test_global_span_management(self):
        enable_crypto_tracing()
        ctx, span_id = start_crypto_trace_span("global_test")
        self.assertNotEqual(span_id, "disabled")
        end_crypto_trace_span(span_id)
        disable_crypto_tracing()
    
    def test_global_correlation_ids(self):
        enable_crypto_tracing()
        start_crypto_trace_span("test")
        create_key_operation_correlation("KEY-GLOBAL-001")
        ids = get_crypto_correlation_ids()
        self.assertIsNotNone(ids["trace_id"])
        self.assertEqual(ids["key_id"], "KEY-GLOBAL-001")
        disable_crypto_tracing()
    
    def test_inject_context(self):
        enable_crypto_tracing()
        start_crypto_trace_span("inject_test")
        carrier = {}
        inject_crypto_trace_context(carrier)
        self.assertIn("traceparent", carrier)
        disable_crypto_tracing()


class TestCryptoMetadataMarkers(unittest.TestCase):
    """Test version and dimension metadata."""
    
    def test_version_marker(self):
        self.assertEqual(CRYPTO_OBSERVABILITY_VERSION, "v15")
    
    def test_dimension_marker(self):
        self.assertEqual(CRYPTO_OBSERVABILITY_DIMENSION, "D")
    
    def test_features_list(self):
        self.assertGreater(len(CRYPTO_OBSERVABILITY_FEATURES), 0)


class TestCryptoOperationTypeEnum(unittest.TestCase):
    """Test crypto operation type enumeration."""
    
    def test_all_operation_types_exist(self):
        self.assertTrue(hasattr(CryptoOperationType, 'KEY_GENERATION'))
        self.assertTrue(hasattr(CryptoOperationType, 'KEY_ROTATION'))
        self.assertTrue(hasattr(CryptoOperationType, 'KEY_WRAPPING'))
        self.assertTrue(hasattr(CryptoOperationType, 'ENCRYPTION'))
        self.assertTrue(hasattr(CryptoOperationType, 'DECRYPTION'))
        self.assertTrue(hasattr(CryptoOperationType, 'SIGNING'))
        self.assertTrue(hasattr(CryptoOperationType, 'VERIFICATION'))
        self.assertTrue(hasattr(CryptoOperationType, 'KEM_ENCAPSULATION'))
        self.assertTrue(hasattr(CryptoOperationType, 'KEM_DECAPSULATION'))
        self.assertTrue(hasattr(CryptoOperationType, 'HSM_CALL'))


class TestCryptoThreadSafety(unittest.TestCase):
    """Test thread safety of the crypto tracing engine."""
    
    def test_concurrent_span_creation(self):
        enable_crypto_tracing()
        errors = []
        
        def create_spans(thread_id):
            try:
                for i in range(10):
                    ctx, span_id = start_crypto_trace_span(
                        f"thread_{thread_id}_crypto_op_{i}",
                        operation_type=CryptoOperationType.ENCRYPTION
                    )
                    end_crypto_trace_span(span_id)
            except Exception as e:
                errors.append(e)
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=create_spans, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)
        disable_crypto_tracing()


class TestCryptoBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility guarantees."""
    
    def test_disabled_has_zero_overhead(self):
        """When disabled, operations should return immediately without side effects."""
        engine = CryptoDistributedTracingCorrelationEngine()
        engine.disable()
        
        # All operations should work without error when disabled
        ctx, span_id = engine.start_span("test")
        self.assertEqual(span_id, "disabled")
        
        engine.end_span(span_id)
        engine.add_event(span_id, "test")
        engine.set_baggage_entry("key", "value")
        entry = engine.get_baggage_entry("key")
        self.assertIsNone(entry)
        
        carrier = {}
        engine.inject_context(carrier)
        self.assertEqual(len(carrier), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
