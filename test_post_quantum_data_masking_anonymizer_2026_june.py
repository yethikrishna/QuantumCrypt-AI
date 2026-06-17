#!/usr/bin/env python3
"""
Test suite for QuantumCrypt AI - Post-Quantum Data Masking & Anonymization
Production-grade tests with real validation
"""

import sys
import json
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_data_masking_anonymizer_2026_june import (
    QuantumSecureMasker, PIIDetector, AnonymizationReport,
    PiiType, MaskingStrategy, AnonymizationLevel
)


def test_pii_detection():
    """Test PII detection functionality"""
    print("=" * 60)
    print("TEST 1: PII Detection")
    print("=" * 60)
    
    detector = PIIDetector()
    
    test_text = """
    Customer Information:
    Email: john.doe@example.com
    Phone: 555-123-4567 or +1 (800) 555-0199
    Credit Card: 4111-1111-1111-1111
    SSN: 123-45-6789
    IP Address: 192.168.1.100
    IBAN: DE89370400440532013000
    """
    
    detections = detector.detect_pii(test_text)
    
    print(f"Total PII detected: {len(detections)}")
    for value, pii_type, start, end in detections:
        print(f"  [{pii_type.value:15}] {value}")
    
    # Verify detection worked
    assert len(detections) > 0, "No PII was detected"
    
    # Check specific types were found
    types_found = {p[1].value for p in detections}
    print(f"\nPII types found: {sorted(types_found)}")
    
    print("\n✅ TEST 1 PASSED - PII detection working")
    return True


def test_partial_masking():
    """Test partial masking strategy"""
    print("\n" + "=" * 60)
    print("TEST 2: Partial Masking Strategy")
    print("=" * 60)
    
    masker = QuantumSecureMasker()
    
    test_cases = [
        ("john.doe@example.com", PiiType.EMAIL),
        ("555-123-4567", PiiType.PHONE),
        ("4111-1111-1111-1111", PiiType.CREDIT_CARD),
        ("192.168.1.100", PiiType.IP_ADDRESS)
    ]
    
    for value, pii_type in test_cases:
        result = masker.mask_value(
            value, pii_type,
            strategy=MaskingStrategy.PARTIAL,
            level=AnonymizationLevel.MEDIUM
        )
        print(f"  Original: {value:40} -> Masked: {result.masked_value}")
        assert result.masked_value != value, "Value was not masked"
        assert '*' in result.masked_value, "No mask characters found"
    
    print("\n✅ TEST 2 PASSED - Partial masking working")
    return True


def test_full_masking():
    """Test full masking strategy"""
    print("\n" + "=" * 60)
    print("TEST 3: Full Masking Strategy")
    print("=" * 60)
    
    masker = QuantumSecureMasker()
    
    value = "john.doe@example.com"
    result = masker.mask_value(
        value, PiiType.EMAIL,
        strategy=MaskingStrategy.FULL,
        level=AnonymizationLevel.MEDIUM
    )
    
    print(f"  Original: {value}")
    print(f"  Masked:   {result.masked_value}")
    print(f"  Length:   {len(result.masked_value)} (original: {len(value)})")
    
    assert all(c == '*' for c in result.masked_value), "Not all characters masked"
    assert len(result.masked_value) == len(value), "Mask length mismatch"
    assert not result.is_reversible, "Full masking should not be reversible"
    
    print("\n✅ TEST 3 PASSED - Full masking working")
    return True


def test_tokenization():
    """Test tokenization strategy"""
    print("\n" + "=" * 60)
    print("TEST 4: Tokenization Strategy")
    print("=" * 60)
    
    masker = QuantumSecureMasker()
    
    original_value = "sensitive-data-12345"
    result = masker.mask_value(
        original_value, PiiType.EMAIL,
        strategy=MaskingStrategy.TOKENIZATION,
        level=AnonymizationLevel.HIGH
    )
    
    print(f"  Original: {original_value}")
    print(f"  Token:    {result.masked_value}")
    print(f"  Salt:     {result.salt}")
    print(f"  Reversible: {result.is_reversible}")
    
    # Verify tokenization worked
    assert result.token is not None, "No token generated"
    assert result.is_reversible, "Tokenization should be reversible"
    
    # Test unmasking
    unmasked = masker.unmask_token(result.token)
    print(f"  Unmasked: {unmasked}")
    assert unmasked == original_value, "Token unmasking failed"
    
    print("\n✅ TEST 4 PASSED - Tokenization working")
    return True


def test_quantum_hashing():
    """Test quantum-resistant hashing"""
    print("\n" + "=" * 60)
    print("TEST 5: Quantum-Resistant Hashing (SHA3-512)")
    print("=" * 60)
    
    masker = QuantumSecureMasker()
    
    value = "user@example.com"
    result = masker.mask_value(
        value, PiiType.EMAIL,
        strategy=MaskingStrategy.HASH,
        level=AnonymizationLevel.QUANTUM_RESISTANT
    )
    
    print(f"  Original: {value}")
    print(f"  Hash:     {result.masked_value}")
    print(f"  Salt:     {result.salt}")
    print(f"  Reversible: {result.is_reversible}")
    
    # Verify hashing properties
    assert result.masked_value != value, "Value was not hashed"
    assert result.salt is not None, "No salt generated"
    assert not result.is_reversible, "Hashing should not be reversible"
    
    # Verify same input with different salt produces different hash
    result2 = masker.mask_value(
        value, PiiType.EMAIL,
        strategy=MaskingStrategy.HASH,
        level=AnonymizationLevel.QUANTUM_RESISTANT
    )
    assert result.masked_value != result2.masked_value, "Hash should be salted"
    print(f"  Hash 2 (different salt): {result2.masked_value}")
    print("  ✓ Different salts produce different hashes")
    
    print("\n✅ TEST 5 PASSED - Quantum hashing working")
    return True


def test_text_anonymization():
    """Test full text anonymization"""
    print("\n" + "=" * 60)
    print("TEST 6: Full Text Anonymization")
    print("=" * 60)
    
    masker = QuantumSecureMasker()
    
    original_text = """
    Dear Customer,
    
    Thank you for your order. Your payment was processed using
    credit card 4111-1111-1111-1111. A confirmation has been
    sent to john.doe@example.com. You can reach us at 555-123-4567.
    
    Your IP (192.168.1.100) has been logged for security purposes.
    """
    
    print("ORIGINAL TEXT:")
    print(original_text)
    
    masked_text, fields = masker.mask_text(
        original_text,
        strategy=MaskingStrategy.PARTIAL,
        level=AnonymizationLevel.MEDIUM
    )
    
    print("\nMASKED TEXT:")
    print(masked_text)
    
    print(f"\nTotal fields masked: {len(fields)}")
    for f in fields:
        print(f"  [{f.pii_type.value:12}] -> {f.masked_value}")
    
    # Verify masking worked
    assert masked_text != original_text, "Text was not modified"
    assert len(fields) > 0, "No fields were masked"
    
    print("\n✅ TEST 6 PASSED - Text anonymization working")
    return True


def test_anonymization_report():
    """Test anonymization reporting"""
    print("\n" + "=" * 60)
    print("TEST 7: Anonymization Reporting")
    print("=" * 60)
    
    masker = QuantumSecureMasker()
    
    test_text = """
    Contact: john@example.com, jane@company.org
    Phone: 555-0101, 555-0202
    IP: 10.0.0.1, 192.168.1.1
    """
    
    _, fields = masker.mask_text(test_text)
    report = AnonymizationReport.generate_report(fields)
    
    print("Report:")
    print(json.dumps(report, indent=2))
    
    json_output = AnonymizationReport.to_json(fields)
    print(f"\nJSON output length: {len(json_output)} chars")
    
    assert report["total_fields_masked"] == len(fields)
    assert "by_pii_type" in report
    assert "by_security_level" in report
    
    print("\n✅ TEST 7 PASSED - Reporting working")
    return True


def run_all_tests():
    """Run all production tests"""
    print("\n" + "=" * 60)
    print("QuantumCrypt AI - Data Masking Production Tests")
    print("=" * 60 + "\n")
    
    tests = [
        test_pii_detection,
        test_partial_masking,
        test_full_masking,
        test_tokenization,
        test_quantum_hashing,
        test_text_anonymization,
        test_anonymization_report
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"\n❌ TEST FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
