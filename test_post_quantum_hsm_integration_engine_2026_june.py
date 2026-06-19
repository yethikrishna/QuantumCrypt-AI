"""
Test Suite for Post-Quantum HSM Integration Engine - June 2026
Production-grade tests for HSM integration, key management, and audit logging
"""

import pytest
from datetime import datetime, timedelta
from quantum_crypt.post_quantum_hsm_integration_engine_2026_june import (
    PostQuantumHSMIntegrationEngine,
    HSMProviderType,
    KeyType,
    KeyState,
    KeyUsage,
    HSMOperationStatus,
    create_post_quantum_hsm_engine
)


class TestPostQuantumHSMIntegrationEngine:
    """Test suite for Post-Quantum HSM Integration Engine"""

    def test_engine_initialization_default(self):
        """Test default engine initialization"""
        engine = PostQuantumHSMIntegrationEngine()
        assert engine.provider_type == HSMProviderType.EMULATED
        assert engine.enable_audit_logging is True

    def test_engine_initialization_custom_provider(self):
        """Test engine initialization with custom provider"""
        engine = PostQuantumHSMIntegrationEngine(
            provider_type=HSMProviderType.PKCS11,
            enable_audit_logging=False
        )
        assert engine.provider_type == HSMProviderType.PKCS11
        assert engine.enable_audit_logging is False

    def test_factory_function(self):
        """Test factory function creates engine correctly"""
        engine = create_post_quantum_hsm_engine(provider_type="aws_cloudhsm")
        assert engine.provider_type == HSMProviderType.AWS_CLOUDHSM
        
        engine_default = create_post_quantum_hsm_engine()
        assert engine_default.provider_type == HSMProviderType.EMULATED

    def test_create_session_unauthenticated(self):
        """Test creating an unauthenticated session"""
        engine = PostQuantumHSMIntegrationEngine()
        session = engine.create_session(authenticated=False)
        
        assert session.session_id is not None
        assert session.authenticated is False
        assert session.provider_type == HSMProviderType.EMULATED
        assert session.operations_count == 0

    def test_create_session_authenticated(self):
        """Test creating an authenticated session"""
        engine = PostQuantumHSMIntegrationEngine()
        session = engine.create_session(authenticated=True, user_role="admin")
        
        assert session.session_id is not None
        assert session.authenticated is True
        assert session.user_role == "admin"

    def test_close_session(self):
        """Test closing a session"""
        engine = PostQuantumHSMIntegrationEngine()
        session = engine.create_session()
        
        result = engine.close_session(session.session_id)
        assert result is True

    def test_close_nonexistent_session(self):
        """Test closing a non-existent session"""
        engine = PostQuantumHSMIntegrationEngine()
        result = engine.close_session("nonexistent_session")
        assert result is False

    def test_session_is_valid(self):
        """Test session validity check"""
        engine = PostQuantumHSMIntegrationEngine()
        session = engine.create_session(authenticated=True)
        
        # Valid session
        assert session.is_valid(timeout_minutes=30) is True
        
        # Unauthenticated session should be invalid
        session_unauth = engine.create_session(authenticated=False)
        assert session_unauth.is_valid() is False

    def test_generate_key_basic(self):
        """Test basic key generation"""
        engine = PostQuantumHSMIntegrationEngine()
        
        result = engine.generate_key(
            key_type=KeyType.KYBER768,
            label="Test Kyber Key",
            key_usages=[KeyUsage.ENCRYPT, KeyUsage.DECRYPT]
        )
        
        assert result.status == HSMOperationStatus.SUCCESS
        assert result.key_id is not None
        assert result.error_message is None
        assert result.execution_time_ms >= 0

    def test_generate_key_different_types(self):
        """Test generating different post-quantum key types"""
        engine = PostQuantumHSMIntegrationEngine()
        
        key_types = [
            KeyType.KYBER512,
            KeyType.KYBER768,
            KeyType.KYBER1024,
            KeyType.DILITHIUM2,
            KeyType.DILITHIUM3,
            KeyType.DILITHIUM5,
            KeyType.AES_256,
            KeyType.HMAC_SHA256
        ]
        
        for key_type in key_types:
            result = engine.generate_key(
                key_type=key_type,
                label=f"Test {key_type.value}",
                key_usages=[KeyUsage.SIGN, KeyUsage.VERIFY]
            )
            assert result.status == HSMOperationStatus.SUCCESS
            assert result.key_id is not None

    def test_generate_key_with_session(self):
        """Test key generation with valid session"""
        engine = PostQuantumHSMIntegrationEngine()
        session = engine.create_session(authenticated=True)
        
        result = engine.generate_key(
            key_type=KeyType.KYBER768,
            label="Session Key",
            key_usages=[KeyUsage.ENCRYPT],
            session_id=session.session_id
        )
        
        assert result.status == HSMOperationStatus.SUCCESS

    def test_generate_key_with_invalid_session(self):
        """Test key generation fails with invalid session"""
        engine = PostQuantumHSMIntegrationEngine()
        
        result = engine.generate_key(
            key_type=KeyType.KYBER768,
            label="Fail Key",
            key_usages=[KeyUsage.ENCRYPT],
            session_id="invalid_session_id"
        )
        
        assert result.status == HSMOperationStatus.UNAUTHORIZED

    def test_get_key_attributes_exists(self):
        """Test getting attributes for existing key"""
        engine = PostQuantumHSMIntegrationEngine()
        
        gen_result = engine.generate_key(
            key_type=KeyType.DILITHIUM3,
            label="Attr Test Key",
            key_usages=[KeyUsage.SIGN, KeyUsage.VERIFY]
        )
        
        attrs = engine.get_key_attributes(gen_result.key_id)
        assert attrs is not None
        assert attrs.key_id == gen_result.key_id
        assert attrs.key_type == KeyType.DILITHIUM3
        assert attrs.key_state == KeyState.ACTIVE
        assert attrs.label == "Attr Test Key"
        assert KeyUsage.SIGN in attrs.key_usages
        assert KeyUsage.VERIFY in attrs.key_usages

    def test_get_key_attributes_not_exists(self):
        """Test getting attributes for non-existent key"""
        engine = PostQuantumHSMIntegrationEngine()
        attrs = engine.get_key_attributes("nonexistent_key")
        assert attrs is None

    def test_list_keys_empty(self):
        """Test listing keys when none exist"""
        engine = PostQuantumHSMIntegrationEngine()
        keys = engine.list_keys()
        assert len(keys) == 0

    def test_list_keys_multiple(self):
        """Test listing multiple keys"""
        engine = PostQuantumHSMIntegrationEngine()
        
        key_ids = []
        for i in range(5):
            result = engine.generate_key(
                key_type=KeyType.AES_256,
                label=f"Key {i}",
                key_usages=[KeyUsage.ENCRYPT]
            )
            key_ids.append(result.key_id)
        
        listed = engine.list_keys()
        assert len(listed) == 5
        assert all(kid in listed for kid in key_ids)

    def test_change_key_state(self):
        """Test changing key lifecycle state"""
        engine = PostQuantumHSMIntegrationEngine()
        
        gen_result = engine.generate_key(
            key_type=KeyType.KYBER768,
            label="State Test Key",
            key_usages=[KeyUsage.ENCRYPT, KeyUsage.DECRYPT]
        )
        
        # Change to SUSPENDED
        result = engine.change_key_state(gen_result.key_id, KeyState.SUSPENDED)
        assert result.status == HSMOperationStatus.SUCCESS
        
        # Verify state changed
        attrs = engine.get_key_attributes(gen_result.key_id)
        assert attrs.key_state == KeyState.SUSPENDED

    def test_change_key_state_not_exists(self):
        """Test changing state for non-existent key"""
        engine = PostQuantumHSMIntegrationEngine()
        result = engine.change_key_state("nonexistent", KeyState.DEACTIVATED)
        assert result.status == HSMOperationStatus.KEY_NOT_FOUND

    def test_destroy_key(self):
        """Test destroying a key"""
        engine = PostQuantumHSMIntegrationEngine()
        
        gen_result = engine.generate_key(
            key_type=KeyType.KYBER768,
            label="Destroy Test Key",
            key_usages=[KeyUsage.ENCRYPT]
        )
        
        # Key should exist before destroy
        assert len(engine.list_keys()) == 1
        
        # Destroy key
        result = engine.destroy_key(gen_result.key_id)
        assert result.status == HSMOperationStatus.SUCCESS
        
        # Key should be gone
        assert len(engine.list_keys()) == 0

    def test_destroy_key_not_exists(self):
        """Test destroying non-existent key"""
        engine = PostQuantumHSMIntegrationEngine()
        result = engine.destroy_key("nonexistent_key")
        assert result.status == HSMOperationStatus.KEY_NOT_FOUND

    def test_wrap_key_success(self):
        """Test successful key wrapping"""
        engine = PostQuantumHSMIntegrationEngine()
        
        # Create wrapping key
        wrap_key_result = engine.generate_key(
            key_type=KeyType.AES_256,
            label="Wrapping Key",
            key_usages=[KeyUsage.WRAP, KeyUsage.UNWRAP]
        )
        
        # Create target key (extractable)
        target_key_result = engine.generate_key(
            key_type=KeyType.KYBER768,
            label="Target Key",
            key_usages=[KeyUsage.ENCRYPT, KeyUsage.EXPORT],
            extractable=True
        )
        
        # Wrap the target key
        wrap_result = engine.wrap_key(
            target_key_id=target_key_result.key_id,
            wrapping_key_id=wrap_key_result.key_id
        )
        
        assert wrap_result.status == HSMOperationStatus.SUCCESS
        assert wrap_result.output_data is not None
        assert len(wrap_result.output_data) > 16  # Salt + wrapped data

    def test_wrap_key_no_export_permission(self):
        """Test wrapping fails when key not exportable"""
        engine = PostQuantumHSMIntegrationEngine()
        
        wrap_key_result = engine.generate_key(
            key_type=KeyType.AES_256,
            label="Wrapping Key",
            key_usages=[KeyUsage.WRAP]
        )
        
        # Target key without EXPORT permission
        target_key_result = engine.generate_key(
            key_type=KeyType.KYBER768,
            label="Non-exportable Key",
            key_usages=[KeyUsage.ENCRYPT],  # No EXPORT
            extractable=False
        )
        
        wrap_result = engine.wrap_key(
            target_key_id=target_key_result.key_id,
            wrapping_key_id=wrap_key_result.key_id
        )
        
        assert wrap_result.status == HSMOperationStatus.OPERATION_NOT_ALLOWED

    def test_wrap_key_no_wrap_permission(self):
        """Test wrapping fails when wrapping key lacks WRAP permission"""
        engine = PostQuantumHSMIntegrationEngine()
        
        # Wrapping key without WRAP permission
        wrap_key_result = engine.generate_key(
            key_type=KeyType.AES_256,
            label="Bad Wrapping Key",
            key_usages=[KeyUsage.ENCRYPT]  # No WRAP
        )
        
        target_key_result = engine.generate_key(
            key_type=KeyType.KYBER768,
            label="Target Key",
            key_usages=[KeyUsage.ENCRYPT, KeyUsage.EXPORT],
            extractable=True
        )
        
        wrap_result = engine.wrap_key(
            target_key_id=target_key_result.key_id,
            wrapping_key_id=wrap_key_result.key_id
        )
        
        assert wrap_result.status == HSMOperationStatus.OPERATION_NOT_ALLOWED

    def test_audit_logging_enabled(self):
        """Test audit logging captures operations"""
        engine = PostQuantumHSMIntegrationEngine(enable_audit_logging=True)
        
        # Perform operations
        engine.generate_key(KeyType.AES_256, "Audit Test", [KeyUsage.ENCRYPT])
        engine.list_keys()
        
        logs = engine.get_audit_log()
        assert len(logs) >= 2
        
        # Check log structure
        for log in logs:
            assert "log_id" in log
            assert "timestamp" in log
            assert "operation_type" in log
            assert "status" in log

    def test_audit_logging_disabled(self):
        """Test no audit logs when disabled"""
        engine = PostQuantumHSMIntegrationEngine(enable_audit_logging=False)
        
        engine.generate_key(KeyType.AES_256, "No Audit", [KeyUsage.ENCRYPT])
        
        logs = engine.get_audit_log()
        assert len(logs) == 0

    def test_audit_log_filter_by_key(self):
        """Test filtering audit log by key ID"""
        engine = PostQuantumHSMIntegrationEngine()
        
        result1 = engine.generate_key(KeyType.AES_256, "Key 1", [KeyUsage.ENCRYPT])
        result2 = engine.generate_key(KeyType.AES_256, "Key 2", [KeyUsage.ENCRYPT])
        
        logs_for_key1 = engine.get_audit_log(key_id=result1.key_id)
        assert len(logs_for_key1) >= 1
        assert all(log["key_id"] == result1.key_id for log in logs_for_key1)

    def test_get_hsm_statistics(self):
        """Test HSM statistics reporting"""
        engine = PostQuantumHSMIntegrationEngine()
        
        # Generate some keys
        for i in range(3):
            engine.generate_key(KeyType.AES_256, f"Stat Key {i}", [KeyUsage.ENCRYPT])
        
        stats = engine.get_hsm_statistics()
        
        assert stats["provider_type"] == "emulated"
        assert stats["total_keys"] == 3
        assert stats["total_operations"] >= 3
        assert "keys_by_state" in stats
        assert "keys_by_type" in stats
        assert "audit_log_entries" in stats

    def test_key_state_policy_enforcement(self):
        """Test that key state policies are enforced"""
        engine = PostQuantumHSMIntegrationEngine()
        
        # Create and suspend a key
        gen_result = engine.generate_key(
            key_type=KeyType.KYBER768,
            label="Suspended Key",
            key_usages=[KeyUsage.ENCRYPT, KeyUsage.EXPORT],
            extractable=True
        )
        
        engine.change_key_state(gen_result.key_id, KeyState.SUSPENDED)
        
        # Create wrapping key
        wrap_result = engine.generate_key(
            key_type=KeyType.AES_256,
            label="Wrapper",
            key_usages=[KeyUsage.WRAP]
        )
        
        # Wrapping should fail on SUSPENDED key
        wrap_result = engine.wrap_key(gen_result.key_id, wrap_result.key_id)
        assert wrap_result.status == HSMOperationStatus.OPERATION_NOT_ALLOWED

    def test_extractable_key_flag(self):
        """Test extractable flag is properly set"""
        engine = PostQuantumHSMIntegrationEngine()
        
        # Extractable key
        result_extractable = engine.generate_key(
            key_type=KeyType.KYBER768,
            label="Extractable",
            key_usages=[KeyUsage.ENCRYPT],
            extractable=True
        )
        
        # Non-extractable key
        result_not_extractable = engine.generate_key(
            key_type=KeyType.KYBER768,
            label="Not Extractable",
            key_usages=[KeyUsage.ENCRYPT],
            extractable=False
        )
        
        attrs_ext = engine.get_key_attributes(result_extractable.key_id)
        attrs_not_ext = engine.get_key_attributes(result_not_extractable.key_id)
        
        assert attrs_ext.extractable is True
        assert attrs_ext.never_exportable is False
        assert attrs_not_ext.extractable is False
        assert attrs_not_ext.never_exportable is True

    def test_key_attributes_to_dict(self):
        """Test key attributes serialization"""
        engine = PostQuantumHSMIntegrationEngine()
        
        gen_result = engine.generate_key(
            key_type=KeyType.DILITHIUM3,
            label="Serialize Test",
            key_usages=[KeyUsage.SIGN]
        )
        
        attrs = engine.get_key_attributes(gen_result.key_id)
        attr_dict = attrs.to_dict()
        
        assert isinstance(attr_dict, dict)
        assert attr_dict["key_id"] == gen_result.key_id
        assert attr_dict["key_type"] == "dilithium3"
        assert attr_dict["key_state"] == "active"
        assert "created_at" in attr_dict


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
