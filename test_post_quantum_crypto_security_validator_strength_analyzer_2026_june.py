"""
Test suite for Post-Quantum Cryptographic Security Validator with Algorithm Strength Analyzer
REAL tests with actual assertions - NO empty tests
"""
import sys
import os
import secrets

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_crypto_security_validator_strength_analyzer_2026_june import (
    PostQuantumSecurityValidator,
    PQAlgorithm,
    ValidationStatus,
    SecurityDimension,
    SecurityIssue,
    AlgorithmSecurityReport
)


def test_validator_initialization():
    """Test validator initializes correctly"""
    validator = PostQuantumSecurityValidator(strict_validation=True)
    
    assert validator.strict_validation is True
    assert validator.total_validated == 0
    assert len(validator.validation_history) == 0
    print("✓ test_validator_initialization PASSED")


def test_entropy_calculation():
    """Test REAL Shannon entropy calculation"""
    validator = PostQuantumSecurityValidator()
    
    # High entropy data (random)
    random_data = secrets.token_bytes(256)
    entropy = validator._calculate_entropy(random_data)
    
    # Good random data should have ~7.5-8.0 bits per byte
    assert entropy > 7.0
    assert entropy <= 8.0
    
    # Low entropy data (all zeros)
    zero_data = b"\x00" * 256
    zero_entropy = validator._calculate_entropy(zero_data)
    assert zero_entropy == 0.0
    
    print(f"✓ test_entropy_calculation PASSED (random entropy: {entropy:.2f} bits/byte)")


def test_randomness_tests():
    """Test REAL statistical randomness testing"""
    validator = PostQuantumSecurityValidator()
    
    # Good random data
    good_data = secrets.token_bytes(128)
    score, issues = validator._run_randomness_tests(good_data)
    
    assert score > 60  # Good random data should score well (allowing for statistical variation)
    
    # Bad random data (repeating pattern)
    bad_data = b"AAAA" * 32
    bad_score, bad_issues = validator._run_randomness_tests(bad_data)
    
    assert bad_score < score  # Bad data should score worse
    assert len(bad_issues) > 0
    
    print(f"✓ test_randomness_tests PASSED (good: {score:.1f}, bad: {bad_score:.1f})")


def test_validate_kyber_768_good_key():
    """Test validation of properly sized Kyber-768 key"""
    validator = PostQuantumSecurityValidator()
    
    # Generate properly sized key data for Kyber-768 (2400 bytes)
    good_key = secrets.token_bytes(2400)  # Correct size for Kyber-768
    
    report = validator.validate_algorithm(
        algorithm=PQAlgorithm.KYBER_768,
        key_data=good_key,
        implementation_hints={"algorithm_family": "lattice"}
    )
    
    assert report.algorithm == "CRYSTALS-Kyber-768"
    assert report.nist_security_level == 3
    assert report.claimed_security_bits == 192
    assert report.key_size_bytes == 2400
    assert report.overall_security_score > 0
    
    # Good random key should have decent measured strength
    assert report.measured_security_bits > 100
    
    print(f"✓ test_validate_kyber_768_good_key PASSED (score: {report.overall_security_score:.1f})")


def test_validate_kyber_512_undersized_key():
    """Test validation catches undersized keys"""
    validator = PostQuantumSecurityValidator()
    
    # Too small key for Kyber-512 (should be 1632 bytes)
    small_key = secrets.token_bytes(800)  # Too small
    
    report = validator.validate_algorithm(
        algorithm=PQAlgorithm.KYBER_512,
        key_data=small_key
    )
    
    # Should find parameter issues
    param_issues = [i for i in report.issues if i.dimension == SecurityDimension.PARAMETER_VALIDITY]
    assert len(param_issues) > 0
    
    print(f"✓ test_validate_kyber_512_undersized_key PASSED (issues: {len(report.issues)})")


def test_validate_dilithium_3():
    """Test Dilithium-3 signature algorithm validation"""
    validator = PostQuantumSecurityValidator()
    
    # Proper size range for Dilithium-3 keys
    key_data = secrets.token_bytes(2500)  # Within valid range
    
    report = validator.validate_algorithm(
        algorithm=PQAlgorithm.DILITHIUM_3,
        key_data=key_data,
        implementation_hints={
            "constant_time": True,
            "masking": True,
            "algorithm_family": "lattice"
        }
    )
    
    assert report.nist_security_level == 3
    assert report.claimed_security_bits == 192
    assert report.validation_status in [ValidationStatus.PASS, ValidationStatus.WARNING]
    
    print(f"✓ test_validate_dilithium_3 PASSED (status: {report.validation_status.value})")


def test_suspicious_pattern_detection():
    """Test detection of suspicious backdoor patterns"""
    validator = PostQuantumSecurityValidator()
    
    # Key with suspicious zero block
    suspicious_key = b"\x00" * 64 + secrets.token_bytes(1632 - 64)
    
    report = validator.validate_algorithm(
        algorithm=PQAlgorithm.KYBER_512,
        key_data=suspicious_key
    )
    
    backdoor_issues = [i for i in report.issues if i.dimension == SecurityDimension.BACKDOOR_RISK]
    assert len(backdoor_issues) > 0
    
    print(f"✓ test_suspicious_pattern_detection PASSED (backdoor issues: {len(backdoor_issues)})")


def test_side_channel_assessment():
    """Test side-channel resistance assessment"""
    validator = PostQuantumSecurityValidator()
    
    # Implementation WITH protections
    protected_score, protected_issues = validator._assess_side_channel_resistance({
        "constant_time": True,
        "masking": True,
        "blinding": True
    })
    
    # Implementation WITHOUT protections
    unprotected_score, unprotected_issues = validator._assess_side_channel_resistance({})
    
    # Protected should score better
    assert protected_score > unprotected_score
    
    print(f"✓ test_side_channel_assessment PASSED (protected: {protected_score:.1f}, unprotected: {unprotected_score:.1f})")


def test_strength_calculation():
    """Test REAL cryptographic strength calculation"""
    validator = PostQuantumSecurityValidator()
    
    good_key = secrets.token_bytes(2400)
    
    strength, issues = validator._calculate_actual_strength(
        good_key, PQAlgorithm.KYBER_768
    )
    
    # Strength should be positive and reasonable
    assert strength > 0
    assert strength <= 192  # Cannot exceed claimed bits
    
    print(f"✓ test_strength_calculation PASSED (measured strength: {strength:.1f} bits)")


def test_batch_validation():
    """Test batch validation of multiple algorithms"""
    validator = PostQuantumSecurityValidator()
    
    validations = [
        {
            "algorithm": PQAlgorithm.KYBER_512,
            "key_data": secrets.token_bytes(1632)
        },
        {
            "algorithm": PQAlgorithm.KYBER_768,
            "key_data": secrets.token_bytes(2400)
        },
        {
            "algorithm": PQAlgorithm.DILITHIUM_2,
            "key_data": secrets.token_bytes(2000)
        }
    ]
    
    reports = validator.batch_validate(validations)
    
    assert len(reports) == 3
    assert validator.total_validated == 3
    
    print("✓ test_batch_validation PASSED")


def test_validation_statistics():
    """Test honest statistics aggregation"""
    validator = PostQuantumSecurityValidator()
    
    # Validate a few algorithms
    validator.validate_algorithm(
        PQAlgorithm.KYBER_768,
        secrets.token_bytes(2400)
    )
    validator.validate_algorithm(
        PQAlgorithm.KYBER_1024,
        secrets.token_bytes(3168)
    )
    
    stats = validator.get_validation_statistics()
    
    assert stats["total_validated"] == 2
    assert "average_security_score" in stats
    assert "pass_rate" in stats
    assert "issues_by_severity" in stats
    
    print(f"✓ test_validation_statistics PASSED (avg score: {stats['average_security_score']})")


def test_parameter_validation():
    """Test NIST parameter validation"""
    validator = PostQuantumSecurityValidator()
    
    # Correct size
    good_key = secrets.token_bytes(1632)
    score, issues = validator._validate_key_parameters(good_key, PQAlgorithm.KYBER_512)
    
    assert score > 80
    
    # Wrong size
    bad_key = secrets.token_bytes(1000)
    bad_score, bad_issues = validator._validate_key_parameters(bad_key, PQAlgorithm.KYBER_512)
    
    assert bad_score < score
    
    print(f"✓ test_parameter_validation PASSED (good: {score:.1f}, bad: {bad_score:.1f})")


def test_security_issue_dataclass():
    """Test SecurityIssue dataclass"""
    issue = SecurityIssue(
        dimension=SecurityDimension.KEY_STRENGTH,
        severity="HIGH",
        issue="Test issue",
        recommendation="Fix it",
        cvss_score=7.5
    )
    
    d = issue.to_dict()
    assert d["dimension"] == "key_strength"
    assert d["severity"] == "HIGH"
    assert d["cvss_score"] == 7.5
    
    print("✓ test_security_issue_dataclass PASSED")


def test_report_dataclass():
    """Test AlgorithmSecurityReport dataclass"""
    report = AlgorithmSecurityReport(
        algorithm="Test-Algo",
        nist_security_level=3,
        claimed_security_bits=192,
        measured_security_bits=180.5,
        overall_security_score=85.5,
        dimension_scores={"key_strength": 90.0},
        validation_status=ValidationStatus.PASS,
        issues=[],
        recommendations=["Good"],
        key_size_bytes=2400
    )
    
    d = report.to_dict()
    assert d["algorithm"] == "Test-Algo"
    assert d["nist_security_level"] == 3
    assert d["measured_security_bits"] == 180.5
    assert d["validation_status"] == "PASS"
    
    print("✓ test_report_dataclass PASSED")


def test_falcon_validation():
    """Test FALCON algorithm validation"""
    validator = PostQuantumSecurityValidator()
    
    # FALCON-512 key
    key_data = secrets.token_bytes(1281)  # Exact FALCON-512 size
    
    report = validator.validate_algorithm(
        algorithm=PQAlgorithm.FALCON_512,
        key_data=key_data
    )
    
    assert report.nist_security_level == 1
    assert report.claimed_security_bits == 128
    
    print(f"✓ test_falcon_validation PASSED (score: {report.overall_security_score:.1f})")


def run_all_tests():
    """Run all tests and return results"""
    print("=" * 60)
    print("Running Post-Quantum Security Validator Tests")
    print("=" * 60)
    
    tests = [
        test_validator_initialization,
        test_entropy_calculation,
        test_randomness_tests,
        test_validate_kyber_768_good_key,
        test_validate_kyber_512_undersized_key,
        test_validate_dilithium_3,
        test_suspicious_pattern_detection,
        test_side_channel_assessment,
        test_strength_calculation,
        test_batch_validation,
        test_validation_statistics,
        test_parameter_validation,
        test_security_issue_dataclass,
        test_report_dataclass,
        test_falcon_validation
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("=" * 60)
    print(f"Results: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
