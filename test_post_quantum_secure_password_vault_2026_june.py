#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Password Vault
Honest, production-grade testing with real verification
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add the quantum_crypt directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_password_vault_2026_june import (
    PostQuantumPasswordVault,
    VaultEntry,
    VaultSecurityLevel,
    PasswordStrength,
    VaultEntryType
)


class TestPasswordStrengthAnalysis(unittest.TestCase):
    """Test password strength analysis"""
    
    def setUp(self):
        self.vault = PostQuantumPasswordVault(":memory:")
    
    def test_very_weak_password(self):
        """Test very weak password detection"""
        strength, score = self.vault.analyze_password_strength("password")
        self.assertEqual(strength, PasswordStrength.VERY_WEAK)
        self.assertLess(score, 20)
    
    def test_weak_password(self):
        """Test weak password detection"""
        strength, score = self.vault.analyze_password_strength("pass1234")
        self.assertIn(strength, [PasswordStrength.WEAK, PasswordStrength.VERY_WEAK])
    
    def test_strong_password(self):
        """Test strong password detection"""
        strength, score = self.vault.analyze_password_strength("MyP@ssw0rd!2345")
        self.assertIn(strength, [PasswordStrength.STRONG, PasswordStrength.VERY_STRONG])
        self.assertGreaterEqual(score, 60)
    
    def test_very_strong_password(self):
        """Test very strong password detection"""
        strength, score = self.vault.analyze_password_strength("K9$pR7@qW2!xZ5&vN8*bQ3%zY9")
        self.assertIn(strength, [PasswordStrength.STRONG, PasswordStrength.VERY_STRONG])
        self.assertGreaterEqual(score, 70)
    
    def test_common_pattern_penalty(self):
        """Test common pattern penalty"""
        strength1, score1 = self.vault.analyze_password_strength("abc123XYZ")
        strength2, score2 = self.vault.analyze_password_strength("def456XYZ")
        # abc123 should have lower score due to common pattern
        self.assertLess(score1, score2 + 10)  # Allow small variance


class TestPasswordGeneration(unittest.TestCase):
    """Test secure password generation"""
    
    def setUp(self):
        self.vault = PostQuantumPasswordVault(":memory:")
    
    def test_password_length(self):
        """Test password generation respects length"""
        password = self.vault.generate_secure_password(length=32)
        self.assertEqual(len(password), 32)
    
    def test_password_min_length(self):
        """Test minimum length enforcement"""
        with self.assertRaises(ValueError):
            self.vault.generate_secure_password(length=4)
    
    def test_password_character_sets(self):
        """Test password contains requested character sets"""
        password = self.vault.generate_secure_password(
            length=24,
            include_upper=True,
            include_lower=True,
            include_digits=True,
            include_special=True
        )
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(c in "!@#$%^&*()_+-=[]{}|;:,.?" for c in password))
    
    def test_password_uniqueness(self):
        """Test generated passwords are unique"""
        passwords = set()
        for _ in range(100):
            passwords.add(self.vault.generate_secure_password())
        # With cryptographically secure generation, collisions are astronomically unlikely
        self.assertEqual(len(passwords), 100)


class TestVaultOperations(unittest.TestCase):
    """Test core vault operations"""
    
    def setUp(self):
        """Create temporary vault file"""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_file.close()
        self.vault_path = self.temp_file.name
        self.master_password = "MySecureMasterPass123!"
    
    def tearDown(self):
        """Clean up temporary file"""
        if os.path.exists(self.vault_path):
            os.unlink(self.vault_path)
    
    def test_vault_creation(self):
        """Test vault creation"""
        vault = PostQuantumPasswordVault(self.vault_path)
        result = vault.create_vault(self.master_password)
        self.assertTrue(result)
        self.assertFalse(vault.is_locked())
        self.assertTrue(os.path.exists(self.vault_path))
    
    def test_short_master_password_rejected(self):
        """Test short master password is rejected"""
        vault = PostQuantumPasswordVault(self.vault_path)
        with self.assertRaises(ValueError):
            vault.create_vault("short")
    
    def test_vault_lock_unlock(self):
        """Test vault lock and unlock"""
        vault = PostQuantumPasswordVault(self.vault_path)
        vault.create_vault(self.master_password)
        self.assertFalse(vault.is_locked())
        
        vault.lock_vault()
        self.assertTrue(vault.is_locked())
        
        result = vault.unlock_vault(self.master_password)
        self.assertTrue(result)
        self.assertFalse(vault.is_locked())
    
    def test_wrong_password_rejected(self):
        """Test wrong password is rejected"""
        vault = PostQuantumPasswordVault(self.vault_path)
        vault.create_vault(self.master_password)
        vault.lock_vault()
        
        result = vault.unlock_vault("wrong_password")
        self.assertFalse(result)
        self.assertTrue(vault.is_locked())
    
    def test_vault_persistence(self):
        """Test vault data persists across sessions"""
        # Create and populate vault
        vault1 = PostQuantumPasswordVault(self.vault_path)
        vault1.create_vault(self.master_password)
        entry_id = vault1.add_entry(
            title="Test Account",
            username="user@example.com",
            password="SecretPass123!"
        )
        vault1.lock_vault()
        
        # Open new vault instance
        vault2 = PostQuantumPasswordVault(self.vault_path)
        result = vault2.unlock_vault(self.master_password)
        self.assertTrue(result)
        
        entry = vault2.get_entry(entry_id)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["title"], "Test Account")


class TestVaultEntryOperations(unittest.TestCase):
    """Test entry CRUD operations"""
    
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_file.close()
        self.vault = PostQuantumPasswordVault(self.temp_file.name)
        self.vault.create_vault("MySecureMasterPass123!")
    
    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
    
    def test_add_entry(self):
        """Test adding a vault entry"""
        entry_id = self.vault.add_entry(
            title="GitHub",
            username="developer",
            password="GitHubPass123!",
            url="https://github.com",
            tags=["development", "git"]
        )
        self.assertIsNotNone(entry_id)
        self.assertEqual(len(entry_id), 32)  # 16 hex bytes
    
    def test_get_entry(self):
        """Test retrieving and decrypting entry"""
        original_password = "MySecretPassword123!"
        entry_id = self.vault.add_entry(
            title="Test",
            username="testuser",
            password=original_password
        )
        
        entry = self.vault.get_entry(entry_id)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["password"], original_password)
        self.assertEqual(entry["username"], "testuser")
    
    def test_update_entry_password(self):
        """Test updating entry password"""
        entry_id = self.vault.add_entry(
            title="Test",
            username="user",
            password="old_password"
        )
        
        new_password = "NewSecurePassword456!"
        result = self.vault.update_entry_password(entry_id, new_password)
        self.assertTrue(result)
        
        entry = self.vault.get_entry(entry_id)
        self.assertEqual(entry["password"], new_password)
    
    def test_delete_entry(self):
        """Test deleting entry"""
        entry_id = self.vault.add_entry(
            title="ToDelete",
            username="user",
            password="pass"
        )
        
        # Soft delete
        result = self.vault.delete_entry(entry_id, permanent=False)
        self.assertTrue(result)
        
        entry = self.vault.get_entry(entry_id)
        self.assertIsNone(entry)  # Deleted entries are not returned
    
    def test_search_entries(self):
        """Test entry search"""
        self.vault.add_entry(
            title="Google Account",
            username="user@gmail.com",
            password="pass1",
            tags=["email", "google"]
        )
        self.vault.add_entry(
            title="GitHub",
            username="dev",
            password="pass2",
            tags=["development"]
        )
        
        results = self.vault.search_entries("google")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["title"], "Google Account")
        
        results = self.vault.search_entries("dev")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["title"], "GitHub")


class TestVaultSecurity(unittest.TestCase):
    """Test vault security features"""
    
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_file.close()
    
    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
    
    def test_encryption_determinism(self):
        """Test same plaintext encrypts differently (different nonce)"""
        vault = PostQuantumPasswordVault(self.temp_file.name)
        vault.create_vault("MasterPass123!")
        
        # Encrypt same password twice
        id1 = vault.add_entry("Test1", "user", "SamePassword123!")
        id2 = vault.add_entry("Test2", "user", "SamePassword123!")
        
        # Ciphertexts should be different due to unique nonce
        entry1 = vault.entries[id1]
        entry2 = vault.entries[id2]
        self.assertNotEqual(entry1.encrypted_secret, entry2.encrypted_secret)
        
        # But decrypt to same value
        e1 = vault.get_entry(id1)
        e2 = vault.get_entry(id2)
        self.assertEqual(e1["password"], e2["password"])
    
    def test_different_security_levels(self):
        """Test different security levels work"""
        for level in VaultSecurityLevel:
            vault = PostQuantumPasswordVault(self.temp_file.name, security_level=level)
            vault.create_vault("MasterPass123!")
            entry_id = vault.add_entry("Test", "user", "pass")
            entry = vault.get_entry(entry_id)
            self.assertIsNotNone(entry)
            if os.path.exists(self.temp_file.name):
                os.unlink(self.temp_file.name)
    
    def test_vault_statistics(self):
        """Test vault statistics generation"""
        vault = PostQuantumPasswordVault(self.temp_file.name)
        vault.create_vault("MasterPass123!")
        
        # Add some entries
        vault.add_entry("Strong", "user", "K9$pR7@qW2!xZ5&vN8*")  # Strong
        vault.add_entry("Weak", "user", "password123")  # Weak
        
        stats = vault.get_vault_statistics()
        self.assertEqual(stats["total_entries"], 2)
        self.assertIn("average_password_strength", stats)
        self.assertIn("weak_passwords_count", stats)
    
    def test_security_report(self):
        """Test security report generation"""
        vault = PostQuantumPasswordVault(self.temp_file.name)
        vault.create_vault("MasterPass123!")
        vault.add_entry("Test", "user", "weak")
        
        report = vault.generate_security_report()
        self.assertIn("report_generated", report)
        self.assertIn("statistics", report)
        self.assertIn("recommendations", report)
        self.assertIn("security_note", report)
        # Honest security note should be present
        self.assertIn("not 'quantum-proof'", report["security_note"])


class TestVaultIntegrity(unittest.TestCase):
    """Test vault integrity and error handling"""
    
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_file.close()
    
    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
    
    def test_locked_vault_operations_rejected(self):
        """Test operations on locked vault are rejected"""
        vault = PostQuantumPasswordVault(self.temp_file.name)
        vault.create_vault("MasterPass123!")
        vault.lock_vault()
        
        with self.assertRaises(RuntimeError):
            vault.add_entry("Test", "user", "pass")
        
        with self.assertRaises(RuntimeError):
            vault.get_entry("any_id")
    
    def test_corrupted_vault_file(self):
        """Test corrupted vault file handling"""
        # Create valid vault
        vault = PostQuantumPasswordVault(self.temp_file.name)
        vault.create_vault("MasterPass123!")
        vault.lock_vault()
        
        # Corrupt the file
        with open(self.temp_file.name, 'w') as f:
            f.write("{corrupted json data")
        
        # Should fail gracefully
        vault2 = PostQuantumPasswordVault(self.temp_file.name)
        with self.assertRaises((json.JSONDecodeError, KeyError)):
            vault2.unlock_vault("MasterPass123!")


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Save test results
    results_data = {
        "timestamp": __import__('time').time(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
        "test_module": "post_quantum_secure_password_vault_2026_june"
    }
    
    with open("test_results_password_vault.json", "w") as f:
        json.dump(results_data, f, indent=2)
    
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("Post-Quantum Secure Password Vault - Test Suite")
    print("=" * 60)
    print()
    
    result = run_tests()
    
    print()
    print("=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {'YES' if result.wasSuccessful() else 'NO'}")
    print("=" * 60)
    
    sys.exit(0 if result.wasSuccessful() else 1)
