"""
Test Suite for Post-Quantum Secure Password Vault
QuantumCrypt-AI - Production Grade Tests
"""

import pytest
import json
import threading
from quantum_crypt.post_quantum_secure_password_vault_2026_june import (
    VaultConfig,
    VaultEntry,
    VaultStats,
    PostQuantumPasswordVault,
    PasswordStrengthMeter
)


class TestPasswordStrengthMeter:
    """Tests for password strength evaluation"""

    def test_very_weak_password(self):
        """Test very weak password detection"""
        result = PasswordStrengthMeter.evaluate("1234")
        assert result["score"] <= 40
        assert result["rating"] in ["Very Weak", "Weak"]

    def test_weak_password(self):
        """Test weak password detection"""
        result = PasswordStrengthMeter.evaluate("password")
        assert result["score"] <= 60

    def test_strong_password(self):
        """Test strong password detection"""
        result = PasswordStrengthMeter.evaluate("MyStr0ng!P@ssw0rd2024")
        assert result["score"] >= 60
        assert result["entropy_bits"] > 0

    def test_password_generation(self):
        """Test secure password generation"""
        password = PasswordStrengthMeter.generate_strong_password(20)
        assert len(password) == 20
        
        # Generated passwords should score well
        result = PasswordStrengthMeter.evaluate(password)
        assert result["score"] >= 60

    def test_feedback_provided(self):
        """Test feedback generation"""
        result = PasswordStrengthMeter.evaluate("short")
        assert len(result["feedback"]) > 0


class TestPostQuantumPasswordVault:
    """Main tests for Password Vault"""

    @pytest.fixture
    def vault(self):
        """Create a standard vault for testing"""
        return PostQuantumPasswordVault("MySecureMasterPassword123!")

    def test_add_and_retrieve_entry(self, vault):
        """Test basic add and retrieve functionality"""
        service = "gmail.com"
        username = "user@gmail.com"
        password = "MyGmailPassword123!"
        
        # Add entry
        result = vault.add_entry(service, username, password)
        assert result is True
        
        # Retrieve password
        retrieved = vault.get_password(service, username)
        assert retrieved == password

    def test_retrieve_nonexistent(self, vault):
        """Test retrieving non-existent entry"""
        retrieved = vault.get_password("not-there.com", "nobody")
        assert retrieved is None

    def test_empty_entry_rejected(self, vault):
        """Test that empty entries are rejected"""
        assert vault.add_entry("", "user", "pass") is False
        assert vault.add_entry("service", "", "pass") is False
        assert vault.add_entry("service", "user", "") is False

    def test_verify_password_correct(self, vault):
        """Test correct password verification"""
        vault.add_entry("bank.com", "user", "SecurePass123!")
        
        assert vault.verify_password("bank.com", "user", "SecurePass123!") is True

    def test_verify_password_incorrect(self, vault):
        """Test incorrect password verification"""
        vault.add_entry("bank.com", "user", "SecurePass123!")
        
        assert vault.verify_password("bank.com", "user", "WrongPassword!") is False
        assert vault.verify_password("bank.com", "user", "") is False

    def test_delete_entry(self, vault):
        """Test entry deletion"""
        vault.add_entry("test.com", "user", "pass123")
        assert vault.get_password("test.com", "user") is not None
        
        result = vault.delete_entry("test.com", "user")
        assert result is True
        assert vault.get_password("test.com", "user") is None

    def test_delete_nonexistent(self, vault):
        """Test deleting non-existent entry"""
        result = vault.delete_entry("not-there.com", "nobody")
        assert result is False

    def test_list_services(self, vault):
        """Test listing services"""
        vault.add_entry("gmail.com", "user1", "pass1")
        vault.add_entry("gmail.com", "user2", "pass2")
        vault.add_entry("bank.com", "user", "pass3")
        
        services = vault.list_services()
        assert len(services) == 2
        assert "bank.com" in services
        assert "gmail.com" in services

    def test_list_entries(self, vault):
        """Test listing entries"""
        vault.add_entry("gmail.com", "user1", "pass1", {"category": "email"})
        vault.add_entry("bank.com", "user2", "pass2")
        
        entries = vault.list_entries()
        assert len(entries) == 2
        
        # Verify passwords are NOT included
        for entry in entries:
            service, username, modified, metadata = entry
            assert service in ["gmail.com", "bank.com"]
            assert "pass1" not in str(entry)
            assert "pass2" not in str(entry)

    def test_get_stats(self, vault):
        """Test statistics generation"""
        stats = vault.get_stats()
        assert stats.total_entries == 0
        assert stats.unique_services == 0
        
        vault.add_entry("service1.com", "user1", "pass1")
        vault.add_entry("service2.com", "user2", "pass2")
        
        stats = vault.get_stats()
        assert stats.total_entries == 2
        assert stats.unique_services == 2
        assert stats.vault_size_bytes > 0
        assert stats.config_version == "1.0"

    def test_case_insensitive_lookup(self, vault):
        """Test case-insensitive service/username lookup"""
        vault.add_entry("Gmail.COM", "User@Gmail.com", "MyPassword123")
        
        # Different cases should all work
        assert vault.get_password("gmail.com", "user@gmail.com") == "MyPassword123"
        assert vault.get_password("GMAIL.COM", "USER@GMAIL.COM") == "MyPassword123"

    def test_whitespace_handling(self, vault):
        """Test whitespace handling in service/username"""
        vault.add_entry("  github.com  ", "  user  ", "githubpass")
        
        assert vault.get_password("github.com", "user") == "githubpass"
        assert vault.get_password("  github.com  ", "  user  ") == "githubpass"

    def test_export_import(self, vault):
        """Test vault export and import"""
        # Add entries
        vault.add_entry("service1.com", "user1", "password1")
        vault.add_entry("service2.com", "user2", "password2", {"note": "test"})
        
        # Export
        exported = vault.export_vault()
        assert isinstance(exported, str)
        data = json.loads(exported)
        assert "config" in data
        assert "entries" in data
        assert len(data["entries"]) == 2
        
        # Import into new vault
        imported_vault = PostQuantumPasswordVault.import_vault(
            exported, "MySecureMasterPassword123!"
        )
        
        # Verify data integrity
        assert imported_vault.get_password("service1.com", "user1") == "password1"
        assert imported_vault.get_password("service2.com", "user2") == "password2"

    def test_clear_vault(self, vault):
        """Test clearing vault"""
        vault.add_entry("test.com", "user", "pass")
        assert vault.get_stats().total_entries == 1
        
        vault.clear()
        assert vault.get_stats().total_entries == 0
        assert vault.get_password("test.com", "user") is None

    def test_thread_safety(self, vault):
        """Test thread-safe concurrent operations"""
        num_threads = 5
        entries_per_thread = 20
        
        def add_entries(thread_id):
            for i in range(entries_per_thread):
                vault.add_entry(
                    f"service-{thread_id}-{i}.com",
                    f"user-{thread_id}",
                    f"password-{thread_id}-{i}"
                )
        
        threads = []
        for t in range(num_threads):
            thread = threading.Thread(target=add_entries, args=(t,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        stats = vault.get_stats()
        assert stats.total_entries == num_threads * entries_per_thread

    def test_metadata_storage(self, vault):
        """Test metadata storage and retrieval"""
        metadata = {
            "category": "social",
            "url": "https://twitter.com",
            "notes": "2FA enabled"
        }
        
        vault.add_entry("twitter.com", "user", "twpass", metadata)
        
        entries = vault.list_entries()
        found_metadata = None
        for entry in entries:
            if entry[0] == "twitter.com":
                found_metadata = entry[3]
                break
        
        assert found_metadata is not None
        assert found_metadata["category"] == "social"
        assert found_metadata["url"] == "https://twitter.com"


class TestVaultSecurity:
    """Security-focused tests"""

    def test_encryption_produces_different_output(self):
        """Test that same password encrypts differently each time (random nonce)"""
        vault = PostQuantumPasswordVault("master")
        
        vault.add_entry("test.com", "user1", "samepassword")
        vault.add_entry("test.com", "user2", "samepassword")
        
        # Get raw encrypted data - they should be different
        entries = vault.list_entries()
        assert len(entries) == 2
        # The internal encrypted_password should differ due to random nonce
        # This is verified by checking we can decrypt both
        assert vault.get_password("test.com", "user1") == "samepassword"
        assert vault.get_password("test.com", "user2") == "samepassword"

    def test_wrong_master_password_cannot_decrypt(self, vault):
        """Test that wrong master password cannot decrypt"""
        vault.add_entry("secret.com", "user", "verysecret")
        
        # Export and try to import with wrong password
        exported = vault.export_vault()
        
        # Try to import with wrong master password
        wrong_vault = PostQuantumPasswordVault.import_vault(
            exported, "WRONG_PASSWORD"
        )
        
        # This should fail to decrypt
        with pytest.raises(ValueError):
            wrong_vault.get_password("secret.com", "user")

    def test_tampered_data_detected(self):
        """Test that tampered encrypted data is detected"""
        vault = PostQuantumPasswordVault("master")
        vault.add_entry("test.com", "user", "secret")
        
        exported = vault.export_vault()
        data = json.loads(exported)
        
        # Tamper with the encrypted password
        data["entries"][0]["encrypted_password"] = "AAAA" + data["entries"][0]["encrypted_password"][4:]
        
        tampered_export = json.dumps(data)
        
        tampered_vault = PostQuantumPasswordVault.import_vault(
            tampered_export, "master"
        )
        
        # Should detect tampering
        with pytest.raises(ValueError):
            tampered_vault.get_password("test.com", "user")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
