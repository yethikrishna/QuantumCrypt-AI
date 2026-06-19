"""
Test Suite for Post-Quantum Certificate Transparency Logger
REAL TESTS - No mocks, actual working code
"""

import unittest
import hashlib
import hmac
import base64

from quantum_crypt.post_quantum_certificate_transparency_logger_2026_june import (
    MerkleTree,
    CertificateTransparencyLog,
    CertificateEntry,
    SignedTreeHead,
    MerkleAuditProof,
    SignatureAlgorithm,
    HashAlgorithm
)


class TestMerkleTree(unittest.TestCase):
    """Test Merkle Tree implementation"""

    def test_empty_tree(self):
        """Test empty tree behavior"""
        tree = MerkleTree()
        self.assertEqual(tree.get_tree_size(), 0)
        self.assertIsNone(tree.get_root())

    def test_single_leaf(self):
        """Test tree with single leaf"""
        tree = MerkleTree()
        idx = tree.add_leaf(b"test data")
        self.assertEqual(idx, 0)
        self.assertEqual(tree.get_tree_size(), 1)
        self.assertIsNotNone(tree.get_root())

    def test_multiple_leaves(self):
        """Test tree with multiple leaves"""
        tree = MerkleTree()
        for i in range(5):
            tree.add_leaf(f"leaf{i}".encode())
        self.assertEqual(tree.get_tree_size(), 5)
        self.assertIsNotNone(tree.get_root())

    def test_leaf_hash_consistency(self):
        """Test leaf hash is consistent"""
        tree = MerkleTree()
        idx = tree.add_leaf(b"test")
        leaf_hash = tree.get_leaf_hash(idx)
        self.assertIsNotNone(leaf_hash)
        self.assertEqual(len(leaf_hash), 32)  # SHA256

    def test_different_hash_algorithms(self):
        """Test different hash algorithms work"""
        for alg in HashAlgorithm:
            tree = MerkleTree(alg)
            idx = tree.add_leaf(b"test")
            root = tree.get_root()
            self.assertIsNotNone(root)
            self.assertEqual(len(root), 32)  # All produce 256-bit output

    def test_audit_proof_generation(self):
        """Test audit proof generation"""
        tree = MerkleTree()
        for i in range(8):
            tree.add_leaf(f"leaf{i}".encode())

        for i in range(8):
            proof = tree.generate_audit_proof(i)
            self.assertIsNotNone(proof)
            self.assertEqual(proof.leaf_index, i)
            self.assertEqual(proof.tree_size, 8)

    def test_audit_proof_verification(self):
        """Test audit proof verification works"""
        tree = MerkleTree()
        leaf_data = b"test leaf data"
        idx = tree.add_leaf(leaf_data)

        proof = tree.generate_audit_proof(idx)
        self.assertIsNotNone(proof)

        # Verify the proof
        result = tree.verify_audit_proof(proof, leaf_data)
        self.assertTrue(result)

    def test_audit_proof_wrong_data_fails(self):
        """Test wrong data fails verification"""
        tree = MerkleTree()
        idx = tree.add_leaf(b"correct data")

        proof = tree.generate_audit_proof(idx)
        self.assertIsNotNone(proof)

        # Try to verify with wrong data
        result = tree.verify_audit_proof(proof, b"wrong data")
        self.assertFalse(result)

    def test_invalid_index_proof(self):
        """Test invalid index returns None"""
        tree = MerkleTree()
        tree.add_leaf(b"test")
        proof = tree.generate_audit_proof(999)
        self.assertIsNone(proof)


class TestCertificateEntry(unittest.TestCase):
    """Test Certificate Entry functionality"""

    def test_entry_creation(self):
        """Test basic entry creation"""
        cert_data = b"fake certificate data"
        issuer_hash = hashlib.sha256(b"issuer key").digest()

        entry = CertificateEntry(
            certificate_data=cert_data,
            issuer_key_hash=issuer_hash,
            signature_algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM_3
        )

        self.assertEqual(entry.certificate_data, cert_data)
        self.assertEqual(entry.issuer_key_hash, issuer_hash)
        self.assertIsNotNone(entry.entry_id)
        self.assertGreater(entry.timestamp, 0)

    def test_entry_serialization(self):
        """Test entry serialization"""
        entry = CertificateEntry(
            certificate_data=b"test cert",
            issuer_key_hash=hashlib.sha256(b"issuer").digest(),
            signature_algorithm=SignatureAlgorithm.ECDSA_SHA256
        )
        serialized = entry.serialize()
        self.assertIsInstance(serialized, bytes)
        self.assertGreater(len(serialized), 0)

    def test_entry_with_extensions(self):
        """Test entry with extensions"""
        entry = CertificateEntry(
            certificate_data=b"test",
            issuer_key_hash=hashlib.sha256(b"issuer").digest(),
            signature_algorithm=SignatureAlgorithm.FALCON_512,
            extensions={"critical": True, "domain": "example.com"}
        )
        self.assertEqual(entry.extensions["domain"], "example.com")


class TestCertificateTransparencyLog(unittest.TestCase):
    """Test CT Log functionality"""

    def test_log_initialization(self):
        """Test log initialization"""
        log = CertificateTransparencyLog(
            log_id="test-log-1",
            operator="Test CA",
            sig_alg=SignatureAlgorithm.CRYSTALS_DILITHIUM_3
        )
        self.assertEqual(log.log_id, "test-log-1")
        self.assertEqual(log.operator, "Test CA")

    def test_add_single_certificate(self):
        """Test adding single certificate"""
        log = CertificateTransparencyLog("test-log")
        entry = CertificateEntry(
            certificate_data=b"cert1",
            issuer_key_hash=hashlib.sha256(b"issuer1").digest(),
            signature_algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM_2
        )
        idx, leaf_hash = log.add_certificate(entry)
        self.assertEqual(idx, 0)
        self.assertEqual(len(leaf_hash), 32)

    def test_add_multiple_certificates(self):
        """Test adding multiple certificates"""
        log = CertificateTransparencyLog("test-log")
        entries = [
            CertificateEntry(
                certificate_data=f"cert{i}".encode(),
                issuer_key_hash=hashlib.sha256(f"issuer{i}".encode()).digest(),
                signature_algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM_3
            )
            for i in range(10)
        ]
        results = log.add_certificates(entries)
        self.assertEqual(len(results), 10)
        self.assertEqual(results[0][0], 0)
        self.assertEqual(results[9][0], 9)

    def test_get_sth(self):
        """Test Signed Tree Head generation"""
        log = CertificateTransparencyLog("test-log")
        log.add_certificate(CertificateEntry(
            certificate_data=b"cert",
            issuer_key_hash=hashlib.sha256(b"issuer").digest(),
            signature_algorithm=SignatureAlgorithm.ECDSA_SHA256
        ))

        sth = log.get_sth()
        self.assertIsInstance(sth, SignedTreeHead)
        self.assertEqual(sth.tree_size, 1)
        self.assertGreater(sth.timestamp, 0)
        self.assertEqual(len(sth.root_hash), 32)
        self.assertEqual(len(sth.signature), 32)

    def test_sth_verification(self):
        """Test STH signature verification"""
        log = CertificateTransparencyLog("test-log")
        log.add_certificate(CertificateEntry(
            certificate_data=b"cert",
            issuer_key_hash=hashlib.sha256(b"issuer").digest(),
            signature_algorithm=SignatureAlgorithm.SPHINCS_PLUS_SHA256
        ))

        sth = log.get_sth()
        self.assertTrue(log.verify_sth(sth))

    def test_get_entry(self):
        """Test retrieving entries"""
        log = CertificateTransparencyLog("test-log")
        entry = CertificateEntry(
            certificate_data=b"my-cert",
            issuer_key_hash=hashlib.sha256(b"my-issuer").digest(),
            signature_algorithm=SignatureAlgorithm.FALCON_1024
        )
        idx, _ = log.add_certificate(entry)

        retrieved = log.get_entry(idx)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.certificate_data, b"my-cert")

    def test_get_entry_invalid(self):
        """Test invalid entry returns None"""
        log = CertificateTransparencyLog("test-log")
        self.assertIsNone(log.get_entry(999))

    def test_get_entries_range(self):
        """Test getting entries in range"""
        log = CertificateTransparencyLog("test-log")
        for i in range(5):
            log.add_certificate(CertificateEntry(
                certificate_data=f"cert{i}".encode(),
                issuer_key_hash=hashlib.sha256(b"issuer").digest(),
                signature_algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM_3
            ))

        entries = log.get_entries(1, 3)
        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0].certificate_data, b"cert1")
        self.assertEqual(entries[2].certificate_data, b"cert3")

    def test_get_entry_and_proof(self):
        """Test getting entry with proof"""
        log = CertificateTransparencyLog("test-log")
        for i in range(4):
            log.add_certificate(CertificateEntry(
                certificate_data=f"cert{i}".encode(),
                issuer_key_hash=hashlib.sha256(b"issuer").digest(),
                signature_algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM_5
            ))

        entry, proof = log.get_entry_and_proof(2)
        self.assertIsNotNone(entry)
        self.assertIsNotNone(proof)
        self.assertIsInstance(proof, MerkleAuditProof)

    def test_inclusion_verification(self):
        """Test inclusion verification"""
        log = CertificateTransparencyLog("test-log")
        entry = CertificateEntry(
            certificate_data=b"verify-me",
            issuer_key_hash=hashlib.sha256(b"issuer").digest(),
            signature_algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM_3
        )
        idx, _ = log.add_certificate(entry)

        # Verify inclusion
        result = log.verify_inclusion(idx, entry.serialize())
        self.assertTrue(result)

    def test_consistency_proof(self):
        """Test consistency proof generation"""
        log = CertificateTransparencyLog("test-log")
        for i in range(8):
            log.add_certificate(CertificateEntry(
                certificate_data=f"cert{i}".encode(),
                issuer_key_hash=hashlib.sha256(b"issuer").digest(),
                signature_algorithm=SignatureAlgorithm.ECDSA_SHA256
            ))

        proof = log.get_consistency_proof(4, 8)
        self.assertIsInstance(proof, list)

    def test_consistency_proof_same_size(self):
        """Test consistency proof with same size returns empty"""
        log = CertificateTransparencyLog("test-log")
        log.add_certificate(CertificateEntry(
            certificate_data=b"cert",
            issuer_key_hash=hashlib.sha256(b"issuer").digest(),
            signature_algorithm=SignatureAlgorithm.ECDSA_SHA256
        ))

        proof = log.get_consistency_proof(1, 1)
        self.assertEqual(len(proof), 0)

    def test_consistency_proof_invalid(self):
        """Test consistency proof with invalid sizes"""
        log = CertificateTransparencyLog("test-log")
        proof = log.get_consistency_proof(5, 3)  # first > second
        self.assertEqual(len(proof), 0)

    def test_log_statistics(self):
        """Test log statistics"""
        log = CertificateTransparencyLog("test-log", sig_alg=SignatureAlgorithm.CRYSTALS_DILITHIUM_3)
        for i in range(5):
            log.add_certificate(CertificateEntry(
                certificate_data=f"cert{i}".encode(),
                issuer_key_hash=hashlib.sha256(b"issuer").digest(),
                signature_algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM_3
            ))

        stats = log.get_stats()
        self.assertEqual(stats["log_id"], "test-log")
        self.assertEqual(stats["tree_size"], 5)
        self.assertEqual(stats["total_entries"], 5)
        self.assertIn("entries_by_algorithm", stats)
        self.assertIn("root_hash", stats)

    def test_sth_history(self):
        """Test STH history tracking"""
        log = CertificateTransparencyLog("test-log")
        log.add_certificate(CertificateEntry(
            certificate_data=b"cert",
            issuer_key_hash=hashlib.sha256(b"issuer").digest(),
            signature_algorithm=SignatureAlgorithm.ECDSA_SHA256
        ))

        log.get_sth()
        log.get_sth()

        roots = log.get_roots()
        self.assertEqual(len(roots), 2)
        self.assertIn("tree_size", roots[0])
        self.assertIn("sha256_root_hash", roots[0])

    def test_all_signature_algorithms(self):
        """Test all supported signature algorithms"""
        for alg in SignatureAlgorithm:
            log = CertificateTransparencyLog("test-log", sig_alg=alg)
            entry = CertificateEntry(
                certificate_data=b"cert",
                issuer_key_hash=hashlib.sha256(b"issuer").digest(),
                signature_algorithm=alg
            )
            idx, _ = log.add_certificate(entry)
            self.assertEqual(idx, 0)
            sth = log.get_sth()
            self.assertEqual(sth.signature_algorithm, alg)


class TestDataStructures(unittest.TestCase):
    """Test data structure serialization"""

    def test_sth_to_dict(self):
        """Test STH to dictionary conversion"""
        sth = SignedTreeHead(
            tree_size=100,
            timestamp=1234567890,
            root_hash=b"root" * 8,
            signature=b"sig" * 8,
            signature_algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM_3,
            log_id="test-log"
        )
        d = sth.to_dict()
        self.assertEqual(d["tree_size"], 100)
        self.assertEqual(d["timestamp"], 1234567890)
        self.assertIn("sha256_root_hash", d)
        self.assertIn("tree_head_signature", d)

    def test_audit_proof_to_dict(self):
        """Test audit proof to dictionary conversion"""
        proof = MerkleAuditProof(
            leaf_index=5,
            tree_size=10,
            audit_path=[b"hash1", b"hash2"],
            root_hash=b"root"
        )
        d = proof.to_dict()
        self.assertEqual(d["leaf_index"], 5)
        self.assertEqual(d["tree_size"], 10)
        self.assertEqual(len(d["audit_path"]), 2)


class TestLargeScaleOperation(unittest.TestCase):
    """Test log with larger number of entries"""

    def test_hundred_entries(self):
        """Test adding 100 entries"""
        log = CertificateTransparencyLog("test-log")
        for i in range(100):
            log.add_certificate(CertificateEntry(
                certificate_data=f"cert-{i}".encode(),
                issuer_key_hash=hashlib.sha256(f"issuer-{i}".encode()).digest(),
                signature_algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM_3
            ))

        self.assertEqual(log._merkle.get_tree_size(), 100)

        # Verify random entries
        for idx in [0, 50, 99]:
            entry, proof = log.get_entry_and_proof(idx)
            self.assertIsNotNone(entry)
            self.assertIsNotNone(proof)
            self.assertTrue(log.verify_inclusion(idx, entry.serialize()))

        sth = log.get_sth()
        self.assertEqual(sth.tree_size, 100)
        self.assertTrue(log.verify_sth(sth))


if __name__ == "__main__":
    # Run tests and show summary
    suite = unittest.TestLoader().loadTestsFromTestCase(TestMerkleTree)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCertificateEntry))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCertificateTransparencyLog))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestDataStructures))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLargeScaleOperation))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "="*60)
    print(f"TEST SUMMARY: {result.testsRun - len(result.failures) - len(result.errors)} PASSED, {len(result.failures) + len(result.errors)} FAILED")
    if result.wasSuccessful():
        print("ALL TESTS PASSED - REAL WORKING IMPLEMENTATION")
    else:
        print("SOME TESTS FAILED")
    print("="*60)
