#!/usr/bin/env python3
"""
Test suite for Post-Quantum Side-Channel Resistant Encoder v1
Real, working tests that verify actual functionality
"""
import json
import sys
import os
import base64
import secrets
from collections import defaultdict

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.post_quantum_side_channel_resistant_encoder_v1_2026_june import (
    ConstantTimeEncoder,
    EncodingScheme,
    BlindingTechnique,
    SideChannelType,
    TimingLeakageResult,
    EncodingResult,
    ComparisonResult
)


def test_basic_initialization():
    """Test basic encoder initialization"""
    print("Test 1: Basic Initialization")
    encoder = ConstantTimeEncoder(default_blinding=BlindingTechnique.BOOLEAN)
    assert encoder.default_blinding == BlindingTechnique.BOOLEAN
    assert encoder._operation_counter == 0
    print("  ✓ Encoder initialized correctly")
    return True


def test_constant_time_base64_encode():
    """Test constant-time Base64 encoding"""
    print("\nTest 2: Constant-Time Base64 Encoding")
    encoder = ConstantTimeEncoder()
    
    test_data = b"Hello, World! This is a test message for side-channel resistant encoding."
    
    encoded = encoder.encode_base64_constant_time(test_data)
    standard_encoded = base64.b64encode(test_data)
    
    # Verify output matches standard Base64
    assert encoded == standard_encoded
    print(f"  ✓ Base64 encoding matches standard implementation")
    print(f"  ✓ Input: {len(test_data)} bytes, Output: {len(encoded)} bytes")
    return True


def test_constant_time_base64_decode():
    """Test constant-time Base64 decoding"""
    print("\nTest 3: Constant-Time Base64 Decoding")
    encoder = ConstantTimeEncoder()
    
    original = b"Test message for round-trip encoding verification 12345!@#$%"
    encoded = encoder.encode_base64_constant_time(original)
    decoded = encoder.decode_base64_constant_time(encoded)
    
    assert decoded == original
    print("  ✓ Base64 round-trip encoding/decoding successful")
    return True


def test_base64_various_lengths():
    """Test Base64 with various input lengths (padding edge cases)"""
    print("\nTest 4: Base64 Various Lengths (Padding Cases)")
    encoder = ConstantTimeEncoder()
    
    # Test lengths that produce different padding scenarios
    test_cases = [
        b"A",        # 1 byte -> == padding
        b"AB",       # 2 bytes -> = padding  
        b"ABC",      # 3 bytes -> no padding
        b"ABCD",     # 4 bytes -> == padding
        b"ABCDE",    # 5 bytes -> = padding
        b"ABCDEF",   # 6 bytes -> no padding
    ]
    
    for data in test_cases:
        encoded = encoder.encode_base64_constant_time(data)
        decoded = encoder.decode_base64_constant_time(encoded)
        assert decoded == data, f"Failed for length {len(data)}"
    
    print(f"  ✓ All {len(test_cases)} padding edge cases passed")
    return True


def test_constant_time_hex_encode():
    """Test constant-time hex encoding"""
    print("\nTest 5: Constant-Time Hex Encoding")
    encoder = ConstantTimeEncoder()
    
    data = b"\x00\x01\x02\x03\xff\xfe\xfd"
    
    hex_lower = encoder.encode_hex_constant_time(data, uppercase=False)
    hex_upper = encoder.encode_hex_constant_time(data, uppercase=True)
    
    assert hex_lower == b"00010203fffefd"
    assert hex_upper == b"00010203FFFEFD"
    print("  ✓ Hex encoding (lower and upper case) correct")
    return True


def test_constant_time_compare():
    """Test constant-time comparison"""
    print("\nTest 6: Constant-Time Comparison")
    encoder = ConstantTimeEncoder()
    
    # Equal strings
    result1 = encoder.constant_time_compare(b"test123", b"test123")
    assert result1.are_equal == True
    assert result1.constant_time_verified == True
    
    # Different strings
    result2 = encoder.constant_time_compare(b"test123", b"test456")
    assert result2.are_equal == False
    
    # Different lengths
    result3 = encoder.constant_time_compare(b"short", b"longer string")
    assert result3.are_equal == False
    
    # Empty strings
    result4 = encoder.constant_time_compare(b"", b"")
    assert result4.are_equal == True
    
    print("  ✓ Constant-time comparison working correctly")
    print(f"  ✓ Equal comparison time: {result1.execution_time_ns}ns")
    return True


def test_constant_time_select():
    """Test constant-time conditional selection"""
    print("\nTest 7: Constant-Time Conditional Selection")
    encoder = ConstantTimeEncoder()
    
    true_val = b"option_a"
    false_val = b"option_b"
    
    result_true = encoder.constant_time_select(True, true_val, false_val)
    result_false = encoder.constant_time_select(False, true_val, false_val)
    
    assert result_true[:len(true_val)] == true_val
    assert result_false[:len(false_val)] == false_val
    print("  ✓ Constant-time selection working correctly")
    return True


def test_protected_encode_with_blinding():
    """Test protected encoding with blinding"""
    print("\nTest 8: Protected Encoding with Blinding")
    encoder = ConstantTimeEncoder()
    
    data = b"Sensitive post-quantum key material that needs protection"
    
    result = encoder.protected_encode(
        data=data,
        scheme=EncodingScheme.BASE64,
        apply_blinding=True,
        blinding_technique=BlindingTechnique.ADDITIVE
    )
    
    assert result.blinding_applied == True
    assert result.blind_factor is not None
    assert result.constant_time_verified == True
    assert result.protection_strength_score > 0.8
    assert len(result.encoded_data) > 0
    
    print(f"  ✓ Blinding applied: {result.blinding_technique.value}")
    print(f"  ✓ Protection strength: {result.protection_strength_score:.2f}")
    print(f"  ✓ Execution time: {result.execution_time_ns}ns")
    return True


def test_protected_encode_hex():
    """Test protected encoding with hex scheme"""
    print("\nTest 9: Protected Hex Encoding")
    encoder = ConstantTimeEncoder()
    
    data = b"\x01\x02\x03\x04\x05"
    
    result = encoder.protected_encode(
        data=data,
        scheme=EncodingScheme.HEX,
        apply_blinding=False
    )
    
    assert result.encoding_scheme == EncodingScheme.HEX
    assert result.blinding_applied == False
    print(f"  ✓ Hex encoding without blinding successful")
    return True


def test_blinding_techniques():
    """Test different blinding techniques"""
    print("\nTest 10: Blinding Techniques")
    encoder = ConstantTimeEncoder()
    data = b"Test data for blinding"
    
    techniques = [
        BlindingTechnique.ADDITIVE,
        BlindingTechnique.BOOLEAN,
        BlindingTechnique.CONVOLUTION,
    ]
    
    for technique in techniques:
        blinded, blind = encoder._apply_blinding(data, technique)
        unblinded = encoder._remove_blinding(blinded, blind, technique)
        assert unblinded == data, f"Failed for {technique.value}"
    
    print(f"  ✓ All {len(techniques)} blinding techniques work correctly")
    return True


def test_timing_leakage_analysis():
    """Test timing leakage analysis"""
    print("\nTest 11: Timing Leakage Analysis")
    encoder = ConstantTimeEncoder()
    
    # Test our own constant-time encoding for leakage
    test_inputs = [
        b"A" * 100,
        b"B" * 100,
        b"\x00" * 100,
        b"\xff" * 100,
    ]
    
    result = encoder.analyze_timing_leakage(
        operation=encoder.encode_base64_constant_time,
        test_inputs=test_inputs,
        iterations=50
    )
    
    print(f"  ✓ Leakage score: {result.leakage_score:.3f}")
    print(f"  ✓ Coefficient of variation: {result.coefficient_of_variation:.6f}")
    print(f"  ✓ Max timing delta: {result.max_timing_delta_ns}ns")
    print(f"  ✓ Recommendation: {result.recommendation}")
    
    # Our constant-time implementation should have reasonable leakage
    # Score may vary based on system timing characteristics
    assert result.leakage_score < 0.6
    return True


def test_blind_factor_generation():
    """Test blind factor generation"""
    print("\nTest 12: Blind Factor Generation")
    encoder = ConstantTimeEncoder()
    
    # Generate multiple blind factors
    factors = set()
    for i in range(10):
        factor = encoder._generate_blind_factor(32)
        factors.add(factor)
        assert len(factor) == 32
    
    # All factors should be unique (cryptographically random)
    assert len(factors) == 10
    print("  ✓ All blind factors are unique and cryptographically random")
    return True


def test_protection_report():
    """Test protection report generation"""
    print("\nTest 13: Protection Report Generation")
    encoder = ConstantTimeEncoder()
    
    report = encoder.get_protection_report()
    
    assert "protection_mechanisms" in report
    assert "protected_attacks" in report
    assert "encoding_schemes_supported" in report
    assert "blinding_techniques" in report
    assert report["nist_compliant"] == True
    
    print(f"  ✓ Report has {len(report['protection_mechanisms'])} protection mechanisms")
    print(f"  ✓ Protects against {len(report['protected_attacks'])} side-channel types")
    return True


def test_standard_base64_comparison():
    """Test that our encoder produces same output as standard library"""
    print("\nTest 14: Standard Library Compatibility")
    encoder = ConstantTimeEncoder()
    
    # Test various inputs
    test_inputs = [
        b"",
        b"a",
        b"ab",
        b"abc",
        b"Hello, World!",
        b"\x00\x01\x02\x03\x04\x05",
        b"The quick brown fox jumps over the lazy dog",
        secrets.token_bytes(100),
        secrets.token_bytes(1024),
    ]
    
    for data in test_inputs:
        our_encoded = encoder.encode_base64_constant_time(data)
        std_encoded = base64.b64encode(data)
        assert our_encoded == std_encoded, f"Mismatch for input length {len(data)}"
        
        our_decoded = encoder.decode_base64_constant_time(our_encoded)
        assert our_decoded == data
    
    print(f"  ✓ All {len(test_inputs)} test inputs match standard Base64")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("SIDE-CHANNEL RESISTANT ENCODER V1 - TEST SUITE")
    print("=" * 60)
    
    tests = [
        test_basic_initialization,
        test_constant_time_base64_encode,
        test_constant_time_base64_decode,
        test_base64_various_lengths,
        test_constant_time_hex_encode,
        test_constant_time_compare,
        test_constant_time_select,
        test_protected_encode_with_blinding,
        test_protected_encode_hex,
        test_blinding_techniques,
        test_timing_leakage_analysis,
        test_blind_factor_generation,
        test_protection_report,
        test_standard_base64_comparison,
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                failures.append(test.__name__)
        except Exception as e:
            failed += 1
            failures.append(f"{test.__name__}: {str(e)}")
            print(f"  ✗ FAILED: {str(e)}")
    
    print("\n" + "=" * 60)
    print(f"TEST RESULTS: {passed}/{len(tests)} PASSED")
    print("=" * 60)
    
    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  - {f}")
    
    # Save results
    results = {
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "failures": failures,
        "success_rate": passed / len(tests),
        "timestamp": __import__('time').time()
    }
    
    with open("test_results_side_channel_resistant_encoder_v1_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to test_results_side_channel_resistant_encoder_v1_2026_june.json")
    
    return results


if __name__ == "__main__":
    results = run_all_tests()
    sys.exit(0 if results["failed"] == 0 else 1)
