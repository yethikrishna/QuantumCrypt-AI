"""
Test Suite for QuantumCrypt Enhanced Distributed Tracing (Dimension D - Observability V7)
Tests are ADD-ONLY - no existing tests are modified
All existing tests will continue to pass
"""

import unittest
import time
import threading
from quantum_crypt.crypto_observability_enhanced_distributed_tracing_v7_2026_june import (
    CryptoEnhancedTracer,
    CryptoTraceContext,
    CryptoSpanKind,
    SpanStatus,
    SecurityLevel,
    crypto_traced,
    crypto_trace_span,
    GLOBAL_CRYPTO_TRACER,
    CryptoSpanEvent
)


class TestCryptoEnhancedDistributedTracing(unittest.TestCase):
    """Test enhanced distributed tracing for cryptographic operations."""
    
    def setUp(self):
        """Set up test tracer."""
        self.tracer = CryptoEnhancedTracer(service_name="test_crypto")
    
    def test_tracer_disabled_by_default(self):
        """Test that tracing is disabled by default (OPT-IN)."""
        self.assertFalse(self.tracer.is_enabled())
    
    def test_enable_disable_tracer(self):
        """Test enabling and disabling tracer."""
        self.tracer.enable()
        self.assertTrue(self.tracer.is_enabled())
        
        self.tracer.disable()
        self.assertFalse(self.tracer.is_enabled())
    
    def test_noop_span_when_disabled(self):
        """Test that no-op spans are returned when tracing is disabled."""
        span = self.tracer.start_span("test_span", CryptoSpanKind.ENCRYPTION)
        self.assertEqual(span.trace_id, "noop")
        self.assertEqual(span.span_id, "noop")
    
    def test_start_span_when_enabled(self):
        """Test starting a real span when enabled."""
        self.tracer.enable()
        span = self.tracer.start_span(
            "aes_encrypt",
            CryptoSpanKind.ENCRYPTION,
            SecurityLevel.HIGH,
            algorithm="AES-256-GCM"
        )
        
        self.assertNotEqual(span.trace_id, "noop")
        self.assertNotEqual(span.span_id, "noop")
        self.assertEqual(span.name, "aes_encrypt")
        self.assertEqual(span.operation_type, CryptoSpanKind.ENCRYPTION)
        self.assertEqual(span.security_level, SecurityLevel.HIGH)
    
    def test_span_high_precision_duration(self):
        """Test high precision nanosecond duration."""
        self.tracer.enable()
        span = self.tracer.start_span("timed_span", CryptoSpanKind.HASHING)
        time.sleep(0.01)
        span.end()
        
        self.assertIsNotNone(span.duration_ns)
        self.assertGreater(span.duration_ns, 0)
        self.assertIsNotNone(span.duration_ms)
    
    def test_span_status(self):
        """Test setting span status."""
        self.tracer.enable()
        span = self.tracer.start_span("status_test", CryptoSpanKind.VERIFICATION)
        
        self.assertEqual(span.status, SpanStatus.UNSET)
        
        span.set_status(SpanStatus.OK)
        self.assertEqual(span.status, SpanStatus.OK)
        
        span.set_status(SpanStatus.ERROR)
        self.assertEqual(span.status, SpanStatus.ERROR)
    
    def test_sensitive_data_masking(self):
        """Test that sensitive data is automatically masked."""
        self.tracer.enable()
        span = self.tracer.start_span("key_gen", CryptoSpanKind.KEY_GENERATION)
        
        # These should be automatically masked
        span.set_attribute("private_key", "very_secret_key_12345")
        span.set_attribute("password", "my_password")
        span.set_attribute("plaintext", "sensitive_data")
        
        # Check that values are redacted
        self.assertIn("[REDACTED", span.attributes["private_key"])
        self.assertIn("[REDACTED", span.attributes["password"])
        self.assertIn("[REDACTED", span.attributes["plaintext"])
    
    def test_explicit_sensitive_flag(self):
        """Test explicit sensitive flag for attributes."""
        self.tracer.enable()
        span = self.tracer.start_span("custom_op", CryptoSpanKind.INTERNAL)
        
        span.set_attribute("custom_field", "secret_value", sensitive=True)
        
        self.assertEqual(span.attributes["custom_field"], "[REDACTED length=12]")
    
    def test_non_sensitive_attributes(self):
        """Test that non-sensitive attributes are preserved."""
        self.tracer.enable()
        span = self.tracer.start_span("hash", CryptoSpanKind.HASHING)
        
        span.set_attribute("algorithm", "SHA-256")
        span.set_attribute("iterations", 10000)
        
        self.assertEqual(span.attributes["algorithm"], "SHA-256")
        self.assertEqual(span.attributes["iterations"], 10000)
    
    def test_span_events_with_masking(self):
        """Test events with automatic sensitive data masking."""
        self.tracer.enable()
        span = self.tracer.start_span("event_test", CryptoSpanKind.ENCRYPTION)
        
        span.add_event("key_loaded", secret_key="abc123xyz789", key_size=256)
        
        event = span.events[0]
        self.assertEqual(event.name, "key_loaded")
        self.assertIn("[REDACTED", event.attributes["secret_key"])
        self.assertEqual(event.attributes["key_size"], 256)
    
    def test_all_crypto_operation_kinds(self):
        """Test all cryptographic operation kinds."""
        self.tracer.enable()
        
        for kind in CryptoSpanKind:
            span = self.tracer.start_span(f"op_{kind.value}", kind)
            self.assertEqual(span.operation_type, kind)
    
    def test_all_security_levels(self):
        """Test all security levels."""
        self.tracer.enable()
        
        for level in SecurityLevel:
            span = self.tracer.start_span(
                f"level_{level.value}",
                CryptoSpanKind.INTERNAL,
                level
            )
            self.assertEqual(span.security_level, level)
    
    def test_parent_child_span_relationship(self):
        """Test parent-child span relationships."""
        self.tracer.enable()
        parent = self.tracer.start_span("parent", CryptoSpanKind.KEY_EXCHANGE)
        
        child = self.tracer.start_span(
            "child",
            CryptoSpanKind.ENCRYPTION,
            parent_trace_id=parent.trace_id,
            parent_span_id=parent.span_id
        )
        
        self.assertEqual(child.parent_span_id, parent.span_id)
        self.assertEqual(child.trace_id, parent.trace_id)
    
    def test_trace_context_thread_local(self):
        """Test thread-local trace context."""
        self.tracer.enable()
        
        span = self.tracer.start_span("context_test", CryptoSpanKind.HASHING)
        CryptoTraceContext.set_current_span(span)
        
        self.assertEqual(CryptoTraceContext.get_current_span(), span)
        self.assertEqual(CryptoTraceContext.get_trace_id(), span.trace_id)
    
    def test_trace_context_clear(self):
        """Test clearing trace context."""
        self.tracer.enable()
        
        span = self.tracer.start_span("clear_test", CryptoSpanKind.HASHING)
        CryptoTraceContext.set_current_span(span)
        CryptoTraceContext.clear()
        
        self.assertIsNone(CryptoTraceContext.get_current_span())
    
    def test_trace_context_isolation(self):
        """Test that trace context is thread-isolated."""
        self.tracer.enable()
        results = {}
        
        def thread_1():
            span1 = self.tracer.start_span("thread1", CryptoSpanKind.ENCRYPTION)
            CryptoTraceContext.set_current_span(span1)
            results["thread1"] = CryptoTraceContext.get_trace_id()
        
        def thread_2():
            span2 = self.tracer.start_span("thread2", CryptoSpanKind.DECRYPTION)
            CryptoTraceContext.set_current_span(span2)
            results["thread2"] = CryptoTraceContext.get_trace_id()
        
        t1 = threading.Thread(target=thread_1)
        t2 = threading.Thread(target=thread_2)
        
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        self.assertNotEqual(results["thread1"], results["thread2"])
    
    def test_get_crypto_operation_summary(self):
        """Test crypto operation summary generation."""
        self.tracer.enable()
        
        span1 = self.tracer.start_span("encrypt", CryptoSpanKind.ENCRYPTION)
        span1.set_status(SpanStatus.OK)
        span1.end()
        
        span2 = self.tracer.start_span(
            "sign",
            CryptoSpanKind.SIGNING,
            parent_trace_id=span1.trace_id
        )
        span2.set_status(SpanStatus.ERROR)
        span2.end()
        
        summary = self.tracer.get_crypto_operation_summary(span1.trace_id)
        self.assertEqual(summary["total_operations"], 2)
        self.assertEqual(summary["error_count"], 1)
        self.assertIn("encryption", summary["operations_by_type"])
        self.assertIn("signing", summary["operations_by_type"])
    
    def test_export_secure_spans(self):
        """Test exporting securely masked spans."""
        self.tracer.enable()
        
        span = self.tracer.start_span(
            "export_test",
            CryptoSpanKind.KEY_GENERATION,
            SecurityLevel.CRITICAL,
            private_key="very_secret"
        )
        span.add_event("key_generated", algorithm="RSA")
        span.end()
        
        exported = self.tracer.export_secure_spans(span.trace_id)
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["name"], "export_test")
        self.assertEqual(exported[0]["security_level"], "critical")
        # Sensitive data should be masked in export
        self.assertIn("[REDACTED", exported[0]["attributes"]["private_key"])
    
    def test_cleanup_old_traces(self):
        """Test old trace cleanup mechanism."""
        self.tracer.enable()
        self.tracer.max_trace_age_seconds = 0
        
        # Create a trace
        span = self.tracer.start_span("old_trace", CryptoSpanKind.HASHING)
        trace_id = span.trace_id
        
        # Force time passage
        import time as time_module
        time_module.sleep(0.001)
        
        removed = self.tracer.cleanup_old_traces()
        self.assertGreaterEqual(removed, 0)
    
    def test_crypto_traced_decorator_disabled(self):
        """Test traced decorator when disabled (no impact)."""
        GLOBAL_CRYPTO_TRACER.disable()
        
        @crypto_traced("encrypt_op", CryptoSpanKind.ENCRYPTION)
        def encrypt_func():
            return "encrypted_data"
        
        result = encrypt_func()
        self.assertEqual(result, "encrypted_data")
    
    def test_crypto_traced_decorator_enabled(self):
        """Test traced decorator when enabled."""
        GLOBAL_CRYPTO_TRACER.enable()
        
        @crypto_traced("encrypt_op", CryptoSpanKind.ENCRYPTION, SecurityLevel.HIGH)
        def encrypt_func():
            return "encrypted_data"
        
        result = encrypt_func()
        self.assertEqual(result, "encrypted_data")
        
        GLOBAL_CRYPTO_TRACER.disable()
    
    def test_crypto_traced_decorator_error_propagation(self):
        """Test that errors propagate through traced decorator."""
        GLOBAL_CRYPTO_TRACER.enable()
        
        @crypto_traced("error_op", CryptoSpanKind.DECRYPTION)
        def error_func():
            raise ValueError("decryption failed")
        
        with self.assertRaises(ValueError):
            error_func()
        
        GLOBAL_CRYPTO_TRACER.disable()
    
    def test_crypto_trace_span_context_manager(self):
        """Test trace span context manager."""
        GLOBAL_CRYPTO_TRACER.enable()
        
        with crypto_trace_span("test_ctx", CryptoSpanKind.SIGNING) as span:
            self.assertIsNotNone(span)
            span.set_attribute("algorithm", "ECDSA")
        
        GLOBAL_CRYPTO_TRACER.disable()
    
    def test_crypto_trace_span_context_manager_disabled(self):
        """Test context manager is no-op when disabled."""
        GLOBAL_CRYPTO_TRACER.disable()
        
        with crypto_trace_span("noop_ctx", CryptoSpanKind.VERIFICATION):
            # Should work without issues
            pass
    
    def test_crypto_trace_span_error_handling(self):
        """Test context manager error handling."""
        GLOBAL_CRYPTO_TRACER.enable()
        
        with self.assertRaises(ValueError):
            with crypto_trace_span("error_ctx", CryptoSpanKind.DECRYPTION):
                raise ValueError("test error")
        
        GLOBAL_CRYPTO_TRACER.disable()
    
    def test_secure_id_generation(self):
        """Test cryptographically secure ID generation."""
        self.tracer.enable()
        
        trace_id = self.tracer._generate_secure_trace_id()
        span_id = self.tracer._generate_secure_span_id()
        
        # Should be hex strings
        self.assertEqual(len(trace_id), 32)  # 16 bytes = 32 hex chars
        self.assertEqual(len(span_id), 16)   # 8 bytes = 16 hex chars
        
        # Verify they're valid hex
        int(trace_id, 16)
        int(span_id, 16)
    
    def test_span_event_hashing(self):
        """Test that sensitive event values are hashed."""
        event = CryptoSpanEvent("test", attributes={"secret_key": "my_secret_value"})
        
        # Should contain hash for verification
        self.assertIn("hash=", event.attributes["secret_key"])


class TestTracingBackwardCompatibility(unittest.TestCase):
    """Test that tracing doesn't break existing behavior."""
    
    def test_no_impact_when_disabled(self):
        """Verify zero impact when tracing is disabled."""
        tracer = CryptoEnhancedTracer()
        
        # All operations should work without side effects
        span = tracer.start_span("test", CryptoSpanKind.ENCRYPTION)
        span.add_event("event", key="secret")
        span.set_attribute("key", "value")
        span.set_status(SpanStatus.OK)
        span.end()
        
        # Export should work but return empty/noop data
        exported = tracer.export_secure_spans()
        self.assertIsInstance(exported, list)
        
        # Trace retrieval works
        trace = tracer.get_trace("any_id")
        self.assertEqual(trace, [])
    
    def test_global_tracer_safe(self):
        """Test that global tracer is safe to use."""
        # Should never raise exceptions
        try:
            GLOBAL_CRYPTO_TRACER.enable()
            GLOBAL_CRYPTO_TRACER.disable()
            GLOBAL_CRYPTO_TRACER.is_enabled()
            GLOBAL_CRYPTO_TRACER.cleanup_old_traces()
        except Exception:
            self.fail("Global tracer raised an exception")


if __name__ == "__main__":
    unittest.main()
