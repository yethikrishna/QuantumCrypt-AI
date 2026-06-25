"""
Test Suite for Error Resilience - PQ Key Operation Deadline v36
Dimension E: Error Resilience
ADD-ONLY tests - no production code modified
All existing tests must continue to pass
"""
import pytest
import time
import threading
from quantum_crypt.crypto_error_resilience_pq_key_operation_deadline_v36_2026_june import (
    QuantumCryptError,
    KeyOperationError,
    KeyOperationDeadlineExceeded,
    KeyOperationCancelled,
    CryptoCancellationToken,
    KeyOperationDeadlineManager,
    DeadlineAwarePQKeyPipeline,
    get_crypto_deadline_manager,
    CancellationReason,
    KeyOperationType,
    KeyAlgorithm,
)


class TestCryptoCancellationToken:
    """Test crypto cancellation token functionality"""
    
    def test_token_creation_basic(self):
        """Test basic token creation"""
        token = CryptoCancellationToken(
            timeout_ms=5000,
            operation_name="test_keygen",
            operation_type=KeyOperationType.KEY_GENERATION,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER
        )
        assert not token.cancelled
        assert token.remaining_ms is not None
        assert token.remaining_ms > 0
    
    def test_token_expires_after_timeout(self):
        """Test token expires after timeout"""
        token = CryptoCancellationToken(
            timeout_ms=100,
            operation_name="fast_test",
            operation_type=KeyOperationType.KEY_GENERATION,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER
        )
        assert not token.cancelled
        time.sleep(0.15)
        assert token.cancelled
        assert token.cancellation_reason == CancellationReason.DEADLINE_EXCEEDED
    
    def test_throw_if_cancelled_raises(self):
        """Test throw_if_cancelled raises when cancelled"""
        token = CryptoCancellationToken(
            timeout_ms=100,
            operation_name="test",
            operation_type=KeyOperationType.KEY_GENERATION,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER
        )
        time.sleep(0.15)
        
        with pytest.raises(KeyOperationDeadlineExceeded):
            token.throw_if_cancelled()
    
    def test_explicit_cancel(self):
        """Test explicit cancellation"""
        token = CryptoCancellationToken(
            timeout_ms=30000,
            operation_name="test",
            operation_type=KeyOperationType.KEY_GENERATION,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER
        )
        assert not token.cancelled
        
        token.cancel(CancellationReason.USER_REQUESTED)
        assert token.cancelled
        assert token.cancellation_reason == CancellationReason.USER_REQUESTED
        
        with pytest.raises(KeyOperationCancelled):
            token.throw_if_cancelled()
    
    def test_child_token_inherits_cancellation(self):
        """Test child token inherits parent cancellation"""
        parent = CryptoCancellationToken(
            timeout_ms=30000,
            operation_name="parent",
            operation_type=KeyOperationType.KEY_GENERATION,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER
        )
        child = parent.create_child_token("child_op")
        
        assert not parent.cancelled
        assert not child.cancelled
        
        parent.cancel(CancellationReason.USER_REQUESTED)
        
        # Give callback time to propagate
        time.sleep(0.01)
        assert child.cancelled
    
    def test_cleanup_callback_invoked_on_cancel(self):
        """Test cleanup callbacks are invoked on cancellation"""
        cleaned_up = []
        
        def cleanup():
            cleaned_up.append(True)
        
        token = CryptoCancellationToken(
            timeout_ms=30000,
            operation_name="test",
            operation_type=KeyOperationType.KEY_GENERATION,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER
        )
        token.register_cleanup(cleanup)
        
        token.cancel(CancellationReason.USER_REQUESTED)
        
        assert len(cleaned_up) == 1
    
    def test_cleanup_on_deadline(self):
        """Test cleanup is executed on deadline expiration"""
        cleaned_up = []
        
        def cleanup():
            cleaned_up.append(True)
        
        token = CryptoCancellationToken(
            timeout_ms=100,
            operation_name="test",
            operation_type=KeyOperationType.KEY_GENERATION,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER
        )
        token.register_cleanup(cleanup)
        
        time.sleep(0.15)
        _ = token.cancelled  # Trigger expiration check
        
        assert len(cleaned_up) == 1


class TestKeyOperationDeadlineManager:
    """Test key operation deadline manager"""
    
    def test_create_token(self):
        """Test creating token"""
        manager = KeyOperationDeadlineManager(default_timeout_ms=10000)
        token = manager.create_token(
            "test_op",
            timeout_ms=5000,
            operation_type=KeyOperationType.KEY_GENERATION,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER
        )
        
        assert not token.cancelled
        assert token.remaining_ms is not None
    
    def test_key_operation_scope_context_manager(self):
        """Test key operation scope context manager"""
        manager = KeyOperationDeadlineManager()
        
        with manager.key_operation_scope(
            "test_scope", 1000, KeyOperationType.KEY_GENERATION, KeyAlgorithm.CRYSTALS_KYBER
        ) as token:
            assert not token.cancelled
            assert token.remaining_ms is not None
        
        # Token should be cancelled after scope exit
        assert token.cancelled
    
    def test_key_operation_scope_with_parent(self):
        """Test scope with parent token"""
        manager = KeyOperationDeadlineManager()
        parent = CryptoCancellationToken(
            timeout_ms=10000,
            operation_name="parent",
            operation_type=KeyOperationType.KEY_GENERATION,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER
        )
        
        with manager.key_operation_scope("child_scope", parent_token=parent) as child:
            assert not child.cancelled
        
        assert child.cancelled
    
    def test_global_manager_instance(self):
        """Test global manager singleton"""
        manager1 = get_crypto_deadline_manager()
        manager2 = get_crypto_deadline_manager()
        assert manager1 is manager2


class TestDeadlineAwarePQKeyPipeline:
    """Test deadline-aware PQ key pipeline"""
    
    def test_pipeline_successful_generation(self):
        """Test successful key generation through pipeline"""
        pipeline = DeadlineAwarePQKeyPipeline()
        
        def mock_gen(algorithm, key_size, token):
            return b"mock_key_material_12345"
        
        result = pipeline.execute_key_generation(
            mock_gen,
            KeyAlgorithm.CRYSTALS_KYBER,
            key_size=1024,
            timeout_ms=5000
        )
        
        assert result["success"] == True
        assert result["degraded"] == False
        assert result["key_material"] == b"mock_key_material_12345"
    
    def test_pipeline_cancellation_returns_safe_result(self):
        """Test pipeline returns safe result on cancellation"""
        pipeline = DeadlineAwarePQKeyPipeline()
        
        def cancelling_gen(algorithm, key_size, token):
            token.cancel(CancellationReason.SECURITY_POLICY)
            token.throw_if_cancelled()
            return b"should_not_reach"
        
        result = pipeline.execute_key_generation(
            cancelling_gen,
            KeyAlgorithm.CRYSTALS_KYBER,
            key_size=1024,
            timeout_ms=5000
        )
        
        assert result["success"] == False
        assert result["key_material"] is None  # No partial key material exposed
        assert result["cancelled"] == True
    
    def test_pipeline_partial_key_zeroized(self):
        """Test partial key material is zeroized on cancellation"""
        pipeline = DeadlineAwarePQKeyPipeline()
        
        # This test verifies the cleanup mechanism exists
        # The actual zeroization happens in the generation function
        token = CryptoCancellationToken(
            timeout_ms=5000,
            operation_name="test",
            operation_type=KeyOperationType.KEY_GENERATION,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER
        )
        
        partial_key = bytearray(b"sensitive_data_here")
        original_id = id(partial_key)
        
        def cleanup():
            for i in range(len(partial_key)):
                partial_key[i] = 0
            partial_key.clear()
        
        token.register_cleanup(cleanup)
        token.cancel(CancellationReason.USER_REQUESTED)
        
        # Verify buffer was cleared
        assert len(partial_key) == 0
        assert id(partial_key) == original_id  # Same buffer, just cleared


class TestExceptionHierarchy:
    """Test custom exception hierarchy"""
    
    def test_key_operation_error_inherits_base(self):
        """Test KeyOperationError inheritance"""
        error = KeyOperationDeadlineExceeded("Test message")
        assert isinstance(error, QuantumCryptError)
        assert isinstance(error, KeyOperationError)
        assert error.retryable == True
        assert error.fallback_available == True
    
    def test_key_operation_cancelled_not_retryable(self):
        """Test KeyOperationCancelled properties"""
        error = KeyOperationCancelled("Cancelled")
        assert isinstance(error, KeyOperationError)
        assert error.retryable == False
        assert error.sensitive == True


class TestIntegration:
    """Integration tests"""
    
    def test_deadline_across_threads(self):
        """Test deadline works across threads"""
        token = CryptoCancellationToken(
            timeout_ms=200,
            operation_name="thread_test",
            operation_type=KeyOperationType.KEY_GENERATION,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER
        )
        
        errors = []
        
        def worker():
            try:
                time.sleep(0.3)
                token.throw_if_cancelled()
            except KeyOperationDeadlineExceeded as e:
                errors.append(e)
        
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        
        assert len(errors) == 1
    
    def test_nested_key_operations(self):
        """Test nested key operation scopes"""
        manager = KeyOperationDeadlineManager()
        
        with manager.key_operation_scope("outer", 5000) as outer:
            with manager.key_operation_scope("inner", parent_token=outer) as inner:
                assert not inner.cancelled
        
        assert inner.cancelled
        assert outer.cancelled


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
