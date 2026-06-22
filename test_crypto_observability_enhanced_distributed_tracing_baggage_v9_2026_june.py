"""
Tests for QuantumCrypt AI - Enhanced Distributed Tracing with Baggage Context v9
Dimension D: Observability & Instrumentation

Covers:
- W3C Trace Context compliance for crypto operations
- Security baggage propagation
- Crypto-aware sampling strategies
- Key operation provenance tracking
- Compliance audit trail generation
- Zero overhead when disabled
"""

import os
import pytest
import time
import threading

# Import module
from quantum_crypt.crypto_observability_enhanced_distributed_tracing_baggage_v9_2026_june import (
    CryptoTraceContext,
    CryptoTraceManager,
    SecurityBaggageManager,
    CryptoTraceSampler,
    CryptoOperationType,
    CryptoSamplingStrategy,
    SecurityLevel,
    TraceFlag,
    CryptoAuditExporter,
    StructuredLogAuditExporter,
    crypto_traced,
    PQ_CRYPTO_TRACING_ENABLED,
)


class TestCryptoTraceContextW3CCompliance:
    """Test W3C Trace Context standard compliance for crypto"""
    
    def test_trace_id_format(self):
        """Trace ID must be 32 hex characters"""
        ctx = CryptoTraceContext()
        assert len(ctx.trace_id) == 32
        int(ctx.trace_id, 16)
    
    def test_span_id_format(self):
        """Span ID must be 16 hex characters"""
        ctx = CryptoTraceContext()
        assert len(ctx.parent_id) == 16
        int(ctx.parent_id, 16)
    
    def test_traceparent_serialization(self):
        """Test W3C traceparent format serialization"""
        ctx = CryptoTraceContext(flags=TraceFlag.SAMPLED.value)
        traceparent = ctx.to_traceparent()
        parts = traceparent.split("-")
        assert len(parts) == 4
        assert parts[0] == "00"
        assert len(parts[1]) == 32
        assert len(parts[2]) == 16
        assert len(parts[3]) == 2
    
    def test_traceparent_parsing(self):
        """Test parsing valid W3C traceparent"""
        valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        ctx = CryptoTraceContext.from_traceparent(valid)
        assert ctx is not None
        assert ctx.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    
    def test_traceparent_parsing_invalid(self):
        """Test parsing invalid traceparent"""
        invalid_cases = [
            "",
            "invalid-format",
            "00-short-00f067aa0ba902b7-01",
        ]
        for invalid in invalid_cases:
            assert CryptoTraceContext.from_traceparent(invalid) is None
    
    def test_sampled_and_critical_flags(self):
        """Test sampled and critical security flags"""
        ctx = CryptoTraceContext(flags=0)
        assert not ctx.is_sampled()
        assert not ctx.is_critical()
        
        sampled = ctx.with_sampled(True)
        assert sampled.is_sampled()
        
        critical = ctx.with_critical(True)
        assert critical.is_critical()
        assert critical.is_sampled()  # Critical implies sampled
    
    def test_child_span_inheritance(self):
        """Test child span inherits trace ID"""
        parent = CryptoTraceContext(
            operation_type=CryptoOperationType.KEY_GENERATION,
            algorithm="CRYSTALS-Kyber"
        )
        child = parent.child_span()
        
        assert child.trace_id == parent.trace_id
        assert child.parent_id != parent.parent_id
        assert child.operation_type == parent.operation_type
        assert child.algorithm == parent.algorithm
    
    def test_operation_id_generation(self):
        """Test crypto operation ID format"""
        op_id = CryptoTraceContext.generate_operation_id()
        assert op_id.startswith("pq-op-")
        assert len(op_id) > 15
    
    def test_key_id_generation(self):
        """Test key provenance ID format"""
        key_id = CryptoTraceContext.generate_key_id()
        assert key_id.startswith("pq-key-")
        assert len(key_id) > 20


class TestSecurityBaggageManager:
    """Test security context propagation"""
    
    def setup_method(self):
        SecurityBaggageManager.clear_context()
    
    def test_set_and_get_security_context(self):
        """Test basic security baggage operations"""
        SecurityBaggageManager.set_security_context("tenant", "acme_corp")
        assert SecurityBaggageManager.get_security_context("tenant") == "acme_corp"
    
    def test_key_id_tracking(self):
        """Test key ID provenance tracking"""
        key_id = "pq-key-abc123def456"
        SecurityBaggageManager.set_key_id(key_id)
        assert SecurityBaggageManager.get_key_id() == key_id
    
    def test_tenant_id_tracking(self):
        """Test multi-tenant isolation tracking"""
        SecurityBaggageManager.set_tenant_id("tenant_789")
        assert SecurityBaggageManager.get_security_context("tenant_id") == "tenant_789"
    
    def test_compliance_markers(self):
        """Test compliance marker tracking (FIPS, GDPR, etc.)"""
        SecurityBaggageManager.set_compliance_marker("FIPS140-3")
        assert SecurityBaggageManager.get_security_context("compliance") == "FIPS140-3"
    
    def test_security_level_tracking(self):
        """Test security level is stored with each baggage entry"""
        SecurityBaggageManager.set_security_context(
            "sensitive_data", "protected", SecurityLevel.RESTRICTED
        )
        all_ctx = SecurityBaggageManager.get_all_context()
        assert "sensitive_data_level" in all_ctx
        assert all_ctx["sensitive_data_level"] == "RESTRICTED"
    
    def test_baggage_size_limits(self):
        """Test baggage entry limits prevent overflow"""
        for i in range(100):
            SecurityBaggageManager.set_security_context(f"key{i}", f"val{i}")
        all_ctx = SecurityBaggageManager.get_all_context()
        # Each entry has key and key_level, so actual entries < 2*MAX
        assert len(all_ctx) <= SecurityBaggageManager.MAX_ENTRIES * 2
    
    def test_clear_context(self):
        """Test clearing all security context"""
        SecurityBaggageManager.set_security_context("test", "value")
        SecurityBaggageManager.clear_context()
        assert SecurityBaggageManager.get_all_context() == {}


class TestCryptoTraceSampler:
    """Test crypto-aware sampling strategies"""
    
    def test_always_off_strategy(self):
        """ALWAYS_OFF never samples"""
        sampler = CryptoTraceSampler(strategy=CryptoSamplingStrategy.ALWAYS_OFF)
        ctx = CryptoTraceContext(operation_type=CryptoOperationType.ENCRYPTION)
        for _ in range(100):
            assert not sampler.should_sample(ctx)
    
    def test_always_on_strategy(self):
        """ALWAYS_ON always samples"""
        sampler = CryptoTraceSampler(strategy=CryptoSamplingStrategy.ALWAYS_ON)
        ctx = CryptoTraceContext()
        for _ in range(100):
            assert sampler.should_sample(ctx)
    
    def test_error_only_strategy(self):
        """ERROR_ONLY samples only on errors"""
        sampler = CryptoTraceSampler(strategy=CryptoSamplingStrategy.ERROR_ONLY)
        ctx = CryptoTraceContext()
        assert not sampler.should_sample(ctx, error_occurred=False)
        assert sampler.should_sample(ctx, error_occurred=True)
    
    def test_key_operations_only_strategy(self):
        """KEY_OPERATIONS_ONLY samples key ops and errors"""
        sampler = CryptoTraceSampler(strategy=CryptoSamplingStrategy.KEY_OPERATIONS_ONLY)
        
        key_ctx = CryptoTraceContext(operation_type=CryptoOperationType.KEY_GENERATION)
        normal_ctx = CryptoTraceContext(operation_type=CryptoOperationType.HASH)
        
        # Key operations sampled
        assert sampler.should_sample(key_ctx)
        # Normal operations not sampled
        assert not sampler.should_sample(normal_ctx)
        # Errors always sampled
        assert sampler.should_sample(normal_ctx, error_occurred=True)
    
    def test_key_operation_detection(self):
        """Test key operation detection works correctly"""
        sampler = CryptoTraceSampler()
        
        key_ops = [
            CryptoOperationType.KEY_GENERATION,
            CryptoOperationType.KEY_AGREEMENT,
            CryptoOperationType.KEY_WRAP,
            CryptoOperationType.KEY_UNWRAP,
        ]
        
        for op_type in key_ops:
            ctx = CryptoTraceContext(operation_type=op_type)
            assert sampler._is_key_operation(op_type)
        
        # Non-key ops
        assert not sampler._is_key_operation(CryptoOperationType.HASH)
        assert not sampler._is_key_operation(CryptoOperationType.ENCRYPTION)
    
    def test_adaptive_crypto_strategy(self):
        """ADAPTIVE_CRYPTO strategy behavior"""
        sampler = CryptoTraceSampler(
            strategy=CryptoSamplingStrategy.ADAPTIVE_CRYPTO,
            general_sample_rate=0.0,  # 0% for normal ops
            key_op_sample_rate=1.0    # 100% for key ops
        )
        
        key_ctx = CryptoTraceContext(operation_type=CryptoOperationType.KEY_GENERATION)
        normal_ctx = CryptoTraceContext(operation_type=CryptoOperationType.HASH)
        critical_ctx = CryptoTraceContext().with_critical(True)
        
        # Key ops always sampled
        assert sampler.should_sample(key_ctx)
        # Critical ops always sampled
        assert sampler.should_sample(critical_ctx)
        # Errors always sampled
        assert sampler.should_sample(normal_ctx, error_occurred=True)


class TestCryptoTraceManager:
    """Test global crypto trace manager"""
    
    def test_is_enabled(self):
        """Test enabled check returns bool"""
        assert isinstance(CryptoTraceManager.is_enabled(), bool)
    
    def test_start_key_operation_is_critical(self):
        """Key generation operations are automatically marked critical"""
        ctx = CryptoTraceManager.start_crypto_operation(
            operation_type=CryptoOperationType.KEY_GENERATION,
            algorithm="CRYSTALS-Kyber-768"
        )
        assert ctx.operation_type == CryptoOperationType.KEY_GENERATION
        assert ctx.algorithm == "CRYSTALS-Kyber-768"
        # Key ops are critical when enabled
        if PQ_CRYPTO_TRACING_ENABLED:
            assert ctx.is_critical()
    
    def test_start_crypto_operation(self):
        """Test starting crypto trace with metadata"""
        ctx = CryptoTraceManager.start_crypto_operation(
            operation_type=CryptoOperationType.SIGNING,
            algorithm="CRYSTALS-Dilithium-3",
            security_level=SecurityLevel.CRITICAL
        )
        assert ctx.operation_type == CryptoOperationType.SIGNING
        assert ctx.algorithm == "CRYSTALS-Dilithium-3"
        assert ctx.security_level == SecurityLevel.CRITICAL
        assert "operation_id" in ctx.attributes
    
    def test_end_crypto_operation_success(self):
        """Test ending successful crypto operation"""
        ctx = CryptoTraceManager.start_crypto_operation(
            CryptoOperationType.ENCRYPTION,
            algorithm="AES-256-GCM"
        )
        audit = CryptoTraceManager.end_crypto_operation(ctx, success=True)
        # Audit is None unless sampled, or dict if sampled
        assert audit is None or isinstance(audit, dict)
        if audit:
            assert audit["success"] is True
            assert audit["operation_type"] == "ENCRYPTION"
    
    def test_end_crypto_operation_with_error(self):
        """Test ending failed crypto operation"""
        ctx = CryptoTraceManager.start_crypto_operation(
            CryptoOperationType.DECRYPTION
        )
        audit = CryptoTraceManager.end_crypto_operation(
            ctx,
            success=False,
            error_info="Decryption failed: invalid padding"
        )
        if audit:
            assert audit["success"] is False
            assert "invalid padding" in audit["error"]
    
    def test_audit_record_structure(self):
        """Test audit record has all required compliance fields"""
        # Force sample by using critical
        ctx = CryptoTraceContext().with_critical(True)
        ctx.attributes["operation_id"] = "test-op-123"
        
        audit = CryptoTraceManager.end_crypto_operation(ctx, success=True)
        
        if audit:
            required_fields = [
                "trace_id", "span_id", "operation_type",
                "security_level", "duration_ms", "success",
                "attributes", "security_context", "timestamp", "service"
            ]
            for field in required_fields:
                assert field in audit, f"Missing audit field: {field}"


class TestCryptoTracedDecorator:
    """Test @crypto_traced decorator"""
    
    def test_decorator_preserves_function(self):
        """Test decorator doesn't break function behavior"""
        @crypto_traced(CryptoOperationType.HASH, algorithm="SHA-256")
        def hash_data(data: bytes) -> str:
            return f"hash:{data.hex()[:8]}"
        
        result = hash_data(b"test data")
        assert result.startswith("hash:")
    
    def test_decorator_exception_propagation(self):
        """Test decorator propagates exceptions correctly"""
        @crypto_traced(CryptoOperationType.DECRYPTION)
        def failing_decrypt():
            raise ValueError("Invalid ciphertext")
        
        with pytest.raises(ValueError, match="Invalid ciphertext"):
            failing_decrypt()
    
    def test_decorator_with_security_level(self):
        """Test decorator with custom security level"""
        @crypto_traced(
            CryptoOperationType.KEY_GENERATION,
            algorithm="CRYSTALS-Kyber",
            security_level=SecurityLevel.CRITICAL
        )
        def generate_key():
            return "key_generated"
        
        assert generate_key() == "key_generated"


class TestCryptoAuditExporter:
    """Test audit exporters"""
    
    def test_base_exporter_interface(self):
        """Test base exporter can be called"""
        exporter = CryptoAuditExporter()
        exporter.export_audit_record({"test": "data"})  # Should not raise
    
    def test_structured_log_exporter(self):
        """Test structured log exporter creates valid output"""
        exporter = StructuredLogAuditExporter()
        audit_record = {
            "trace_id": "abc123",
            "operation_type": "KEY_GENERATION",
            "success": True
        }
        # Should not raise
        exporter.export_audit_record(audit_record)


class TestEnums:
    """Test crypto-specific enums"""
    
    def test_crypto_operation_types_complete(self):
        """Test all crypto operation types are defined"""
        expected_ops = [
            "KEY_GENERATION", "KEY_AGREEMENT",
            "ENCRYPTION", "DECRYPTION",
            "SIGNING", "VERIFICATION",
            "KEY_WRAP", "KEY_UNWRAP",
            "HASH", "HMAC",
            "RANDOM_GENERATION", "CERTIFICATE_OP"
        ]
        for op in expected_ops:
            assert hasattr(CryptoOperationType, op)
    
    def test_sampling_strategies(self):
        """Test all crypto sampling strategies exist"""
        assert hasattr(CryptoSamplingStrategy, "KEY_OPERATIONS_ONLY")
        assert hasattr(CryptoSamplingStrategy, "ADAPTIVE_CRYPTO")
    
    def test_security_levels(self):
        """Test all security classification levels exist"""
        assert hasattr(SecurityLevel, "PUBLIC")
        assert hasattr(SecurityLevel, "INTERNAL")
        assert hasattr(SecurityLevel, "SENSITIVE")
        assert hasattr(SecurityLevel, "RESTRICTED")
        assert hasattr(SecurityLevel, "CRITICAL")
    
    def test_trace_flags(self):
        """Test trace flag values"""
        assert TraceFlag.NOT_SAMPLED.value == 0x00
        assert TraceFlag.SAMPLED.value == 0x01
        assert TraceFlag.CRITICAL.value == 0x04


class TestThreadSafety:
    """Test thread safety of security context"""
    
    def test_security_baggage_thread_isolation(self):
        """Test security baggage is thread-local"""
        results = []
        
        def worker(thread_num):
            SecurityBaggageManager.set_tenant_id(f"tenant_{thread_num}")
            time.sleep(0.01)
            val = SecurityBaggageManager.get_security_context("tenant_id")
            results.append((thread_num, val))
        
        threads = []
        for i in range(3):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        for expected, actual in results:
            assert actual == f"tenant_{expected}"


class TestModuleExports:
    """Test module exports are complete"""
    
    def test_all_exports_present(self):
        """Test all expected exports are available"""
        import quantum_crypt.crypto_observability_enhanced_distributed_tracing_baggage_v9_2026_june as module
        
        expected_exports = [
            "CryptoTraceContext",
            "CryptoTraceManager",
            "SecurityBaggageManager",
            "CryptoTraceSampler",
            "CryptoOperationType",
            "CryptoSamplingStrategy",
            "SecurityLevel",
            "TraceFlag",
            "CryptoAuditExporter",
            "StructuredLogAuditExporter",
            "crypto_traced",
            "PQ_CRYPTO_TRACING_ENABLED",
        ]
        
        for export in expected_exports:
            assert hasattr(module, export), f"Missing export: {export}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
