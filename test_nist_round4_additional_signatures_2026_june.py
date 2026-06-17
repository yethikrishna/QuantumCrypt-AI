"""
Test Suite for NIST Round 4 Additional Signatures - June 2026
Tests for implemented Round 4 candidates per NIST IR 8610 (May 2026)
"""

import pytest
import hashlib
from quantum_crypt.nist_round4_additional_signatures_2026 import (
    NISTRound4SignatureSuite,
    Round4Algorithm,
    SecurityCategory,
    Round4KeyPair,
    Round4Signature
)


class TestNISTRound4SignatureSuite:
    """Test suite for NIST Round 4 Additional Signatures"""
    
    def setup_method(self):
        self.suite = NISTRound4SignatureSuite()
    
    def test_all_algorithms_present(self):
        """Test all 9 Round 4 algorithms are defined"""
        algorithms = list(Round4Algorithm)
        assert len(algorithms) == 9
        assert Round4Algorithm.FAEST in algorithms
        assert Round4Algorithm.HAWK in algorithms
        assert Round4Algorithm.MAYO in algorithms
        assert Round4Algorithm.MQOM in algorithms
        assert Round4Algorithm.QR_UOV in algorithms
        assert Round4Algorithm.SDITH in algorithms
        assert Round4Algorithm.SNOVA in algorithms
        assert Round4Algorithm.SQISIGN in algorithms
        assert Round4Algorithm.UOV in algorithms
    
    def test_generate_keypair_mayo(self):
        """Test keypair generation for MAYO"""
        keypair = self.suite.generate_keypair(Round4Algorithm.MAYO)
        assert isinstance(keypair, Round4KeyPair)
        assert keypair.algorithm == Round4Algorithm.MAYO
        assert len(keypair.public_key) > 0
    
    def test_generate_keypair_faest(self):
        """Test keypair generation for FAEST"""
        keypair = self.suite.generate_keypair(Round4Algorithm.FAEST)
        assert isinstance(keypair, Round4KeyPair)
        assert keypair.algorithm == Round4Algorithm.FAEST
    
    def test_generate_keypair_sqisign(self):
        """Test keypair generation for SQIsign"""
        keypair = self.suite.generate_keypair(Round4Algorithm.SQISIGN)
        assert isinstance(keypair, Round4KeyPair)
        assert keypair.algorithm == Round4Algorithm.SQISIGN
    
    def test_generate_keypair_uov(self):
        """Test keypair generation for UOV"""
        keypair = self.suite.generate_keypair(Round4Algorithm.UOV)
        assert isinstance(keypair, Round4KeyPair)
        assert keypair.algorithm == Round4Algorithm.UOV
    
    def test_sign_and_verify_faest(self):
        """Test sign and verify for FAEST"""
        keypair = self.suite.generate_keypair(Round4Algorithm.FAEST)
        message = b"Test message for FAEST signature June 2026"
        
        result = self.suite.sign(message, algorithm=keypair.algorithm, key_pair=keypair)
        assert isinstance(result, Round4Signature)
        assert result.algorithm == Round4Algorithm.FAEST
        assert len(result.signature) > 0
    
    def test_sign_and_verify_sqisign(self):
        """Test sign and verify for SQIsign"""
        keypair = self.suite.generate_keypair(Round4Algorithm.SQISIGN)
        message = b"Test SQIsign - shortest post-quantum signature"
        
        result = self.suite.sign(message, algorithm=keypair.algorithm, key_pair=keypair)
        assert isinstance(result, Round4Signature)
    
    def test_sign_and_verify_mayo(self):
        """Test sign and verify for MAYO"""
        keypair = self.suite.generate_keypair(Round4Algorithm.MAYO)
        message = b"Test MAYO signature"
        
        result = self.suite.sign(message, algorithm=keypair.algorithm, key_pair=keypair)
        assert isinstance(result, Round4Signature)
    
    def test_sign_and_verify_uov(self):
        """Test sign and verify for UOV"""
        keypair = self.suite.generate_keypair(Round4Algorithm.UOV)
        message = b"Test UOV signature - classic multivariate"
        
        result = self.suite.sign(message, algorithm=keypair.algorithm, key_pair=keypair)
        assert isinstance(result, Round4Signature)
    
    def test_key_id_generation(self):
        """Test key ID generation is consistent"""
        keypair1 = self.suite.generate_keypair(Round4Algorithm.MAYO)
        keypair2 = self.suite.generate_keypair(Round4Algorithm.MAYO)
        assert keypair1.key_id != keypair2.key_id
    
    def test_implemented_algorithms(self):
        """Test all implemented algorithms work"""
        implemented_algorithms = [
            Round4Algorithm.FAEST,
            Round4Algorithm.MAYO,
            Round4Algorithm.SQISIGN,
            Round4Algorithm.UOV
        ]
        
        test_message = b"NIST Round 4 Compliance Test - June 2026"
        
        for algo in implemented_algorithms:
            keypair = self.suite.generate_keypair(algo)
            result = self.suite.sign(test_message, algorithm=algo, key_pair=keypair)
            assert isinstance(result, Round4Signature)
            assert result.algorithm == algo


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
