#!/usr/bin/env python3
"""
Test suite for Post-Quantum Certificate Revocation Checker
Production-grade testing with real assertions
"""
import sys
import json
sys.path.insert(0, '.')

from quantum_crypt.post_quantum_certificate_revocation_checker_2026_june import (
    CertificateRevocationChecker,
    CertificateInfo,
    RevocationStatus,
    RevocationReason,
    RevocationCheckMethod,
    RevocationCheckResult,
    LRUCache
)
from datetime import datetime, timedelta


def test_checker_initialization():
    """Test checker initialization with default parameters"""
    print("Test 1: Checker initialization...")
    checker = CertificateRevocationChecker()
    assert checker.enable_ocsp == True
    assert checker.enable_crl == True
    assert checker.enable_stapling == True
    assert checker.cache_ttl == 3600
    print("  ✓ PASSED: Default initialization works")


def test_checker_custom_config():
    """Test checker with custom configuration"""
    print("Test 2: Custom configuration...")
    checker = CertificateRevocationChecker(
        cache_ttl_seconds=7200,
        max_cache_size=5000,
        enable_ocsp=True,
        enable_crl=False,
        enable_stapling=True
    )
    assert checker.cache_ttl == 7200
    assert checker.enable_crl == False
    print("  ✓ PASSED: Custom configuration works")


def test_certificate_info_creation():
    """Test CertificateInfo dataclass creation"""
    print("Test 3: Certificate info creation...")
    cert = CertificateInfo(
        serial_number="01:23:45:67:89:AB:CD:EF",
        issuer_dn="CN=Test CA, O=Test Org",
        ocsp_urls=["http://ocsp.test.com"],
        crl_urls=["http://crl.test.com/crl.pem"]
    )
    assert cert.serial_number == "01:23:45:67:89:AB:CD:EF"
    assert cert.get_serial_int() > 0
    assert len(cert.ocsp_urls) == 1
    print("  ✓ PASSED: Certificate info created correctly")


def test_lru_cache_basic():
    """Test LRU cache basic operations"""
    print("Test 4: LRU cache operations...")
    cache = LRUCache(max_size=3)
    
    result = RevocationCheckResult(
        certificate_serial="test",
        status=RevocationStatus.GOOD,
        check_method=RevocationCheckMethod.OCSP
    )
    
    cache.put("key1", result)
    cache.put("key2", result)
    cache.put("key3", result)
    
    assert cache.size() == 3
    
    # Add fourth should evict oldest
    cache.put("key4", result)
    assert cache.size() == 3
    assert cache.get("key1") is None  # Evicted
    print("  ✓ PASSED: LRU cache eviction works")


def test_lru_cache_freshness():
    """Test cache freshness checking"""
    print("Test 5: Cache freshness...")
    cache = LRUCache(max_size=100)
    
    # Create expired result
    expired_result = RevocationCheckResult(
        certificate_serial="expired",
        status=RevocationStatus.GOOD,
        check_method=RevocationCheckMethod.OCSP,
        ttl_seconds=0  # Immediate expiry
    )
    expired_result.check_timestamp = datetime.now() - timedelta(hours=2)
    
    cache.put("expired", expired_result)
    assert cache.get("expired") is None  # Should be expired
    
    fresh_result = RevocationCheckResult(
        certificate_serial="fresh",
        status=RevocationStatus.GOOD,
        check_method=RevocationCheckMethod.OCSP,
        ttl_seconds=3600
    )
    cache.put("fresh", fresh_result)
    assert cache.get("fresh") is not None
    print("  ✓ PASSED: Cache freshness works")


def test_ocsp_check_with_url():
    """Test OCSP check with responder URL"""
    print("Test 6: OCSP check with URL...")
    checker = CertificateRevocationChecker()
    
    cert = CertificateInfo(
        serial_number="00:11:22:33:44:55:66:77",
        issuer_dn="CN=Test CA",
        ocsp_urls=["http://ocsp.example.com/ocsp"]
    )
    
    result = checker.check_ocsp(cert)
    
    assert result.certificate_serial == cert.serial_number
    assert result.check_method == RevocationCheckMethod.OCSP
    assert result.responder_url == "http://ocsp.example.com/ocsp"
    assert result.response_signature_valid == True
    print(f"  ✓ PASSED: OCSP check completed, status={result.status.value}")


def test_crl_check_with_url():
    """Test CRL check with URL"""
    print("Test 7: CRL check with URL...")
    checker = CertificateRevocationChecker()
    
    cert = CertificateInfo(
        serial_number="AA:BB:CC:DD:EE:FF",
        issuer_dn="CN=Test CA",
        crl_urls=["http://crl.example.com/crl.pem"]
    )
    
    result = checker.check_crl(cert)
    
    assert result.certificate_serial == cert.serial_number
    assert result.check_method == RevocationCheckMethod.CRL
    assert result.responder_url == "http://crl.example.com/crl.pem"
    print(f"  ✓ PASSED: CRL check completed, status={result.status.value}")


def test_comprehensive_check():
    """Test comprehensive certificate check (OCSP -> CRL fallback)"""
    print("Test 8: Comprehensive check...")
    checker = CertificateRevocationChecker()
    
    cert = CertificateInfo(
        serial_number="12:34:56:78:90",
        issuer_dn="CN=Test CA",
        ocsp_urls=["http://ocsp.example.com"],
        crl_urls=["http://crl.example.com"]
    )
    
    result = checker.check_certificate(cert)
    
    assert result.certificate_serial == cert.serial_number
    assert result.status in [RevocationStatus.GOOD, RevocationStatus.UNKNOWN]
    print(f"  ✓ PASSED: Comprehensive check, method={result.check_method.value}")


def test_check_no_urls():
    """Test behavior when no OCSP/CRL URLs available"""
    print("Test 9: No URLs handling...")
    checker = CertificateRevocationChecker()
    
    cert = CertificateInfo(
        serial_number="NO:URLS:00",
        issuer_dn="CN=Test CA",
        ocsp_urls=[],
        crl_urls=[]
    )
    
    result = checker.check_certificate(cert)
    assert result.status == RevocationStatus.NOT_CHECKED
    assert "No revocation check" in (result.error_message or "")
    print("  ✓ PASSED: No URLs handled correctly")


def test_cache_hits():
    """Test that repeated checks use cache"""
    print("Test 10: Cache hits...")
    checker = CertificateRevocationChecker()
    
    cert = CertificateInfo(
        serial_number="CACHE:TEST:01",
        issuer_dn="CN=Test CA",
        ocsp_urls=["http://ocsp.example.com"]
    )
    
    # First check - cache miss
    result1 = checker.check_ocsp(cert)
    stats_before = checker.get_stats()
    
    # Second check - should be cache hit
    result2 = checker.check_ocsp(cert)
    stats_after = checker.get_stats()
    
    assert stats_after["cache_hits"] > stats_before["cache_hits"]
    print(f"  ✓ PASSED: Cache working, hits={stats_after['cache_hits']}")


def test_result_serialization():
    """Test result serialization to dict"""
    print("Test 11: Result serialization...")
    result = RevocationCheckResult(
        certificate_serial="SERIAL:TEST:001",
        status=RevocationStatus.GOOD,
        check_method=RevocationCheckMethod.OCSP,
        response_signature_valid=True,
        nonce_matched=True
    )
    
    result_dict = result.to_dict()
    assert "certificate_serial" in result_dict
    assert "status" in result_dict
    assert "is_fresh" in result_dict
    assert result_dict["status"] == "good"
    
    # Verify JSON serializable
    json_str = json.dumps(result_dict)
    assert len(json_str) > 0
    print("  ✓ PASSED: Result JSON serialization works")


def test_revoked_status_detection():
    """Test is_revoked helper method"""
    print("Test 12: Revoked status detection...")
    good_result = RevocationCheckResult(
        certificate_serial="GOOD",
        status=RevocationStatus.GOOD,
        check_method=RevocationCheckMethod.OCSP
    )
    assert good_result.is_revoked() == False
    
    revoked_result = RevocationCheckResult(
        certificate_serial="REVOKED",
        status=RevocationStatus.REVOKED,
        check_method=RevocationCheckMethod.OCSP
    )
    assert revoked_result.is_revoked() == True
    
    expired_result = RevocationCheckResult(
        certificate_serial="EXPIRED",
        status=RevocationStatus.EXPIRED,
        check_method=RevocationCheckMethod.OCSP
    )
    assert expired_result.is_revoked() == True
    print("  ✓ PASSED: Revoked status detection correct")


def test_trusted_responder():
    """Test trusted responder whitelist"""
    print("Test 13: Trusted responders...")
    checker = CertificateRevocationChecker()
    
    assert checker.is_trusted_responder("ocsp.digicert.com") == True
    assert checker.is_trusted_responder("unknown.bad.com") == False
    
    checker.add_trusted_responder("ocsp.mycompany.com")
    assert checker.is_trusted_responder("ocsp.mycompany.com") == True
    print("  ✓ PASSED: Trusted responder whitelist works")


def test_stapled_response_check():
    """Test stapled OCSP response verification"""
    print("Test 14: Stapled response check...")
    checker = CertificateRevocationChecker()
    
    cert = CertificateInfo(
        serial_number="STAPLED:TEST:001",
        issuer_dn="CN=Test CA"
    )
    
    stapled_response = b'\x00' + b'\x00' * 64  # Simulated good response
    result = checker.check_stapled(cert, stapled_response)
    
    assert result.check_method == RevocationCheckMethod.OCSP_STAPLING
    assert result.certificate_serial == cert.serial_number
    print(f"  ✓ PASSED: Stapled check, status={result.status.value}")


def test_checker_statistics():
    """Test checker statistics tracking"""
    print("Test 15: Checker statistics...")
    checker = CertificateRevocationChecker()
    
    cert = CertificateInfo(
        serial_number="STATS:TEST",
        issuer_dn="CN=Test CA",
        ocsp_urls=["http://ocsp.example.com"]
    )
    
    checker.check_ocsp(cert)
    checker.check_ocsp(cert)  # Should be cache hit
    
    stats = checker.get_stats()
    assert stats["total_checks"] >= 2
    assert stats["ocsp_checks"] >= 1
    assert stats["cache_hits"] >= 1
    assert "cache_hit_rate" in stats
    print(f"  ✓ PASSED: Stats tracked, hit_rate={stats['cache_hit_rate']:.2f}")


def test_pem_parsing():
    """Test PEM certificate parsing"""
    print("Test 16: PEM parsing...")
    checker = CertificateRevocationChecker()
    
    sample_pem = """
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 01:23:45:67:89:AB:CD:EF
        Issuer: CN=Test CA, O=Test Organization
        Validity
            Not Before: Jan  1 00:00:00 2024 GMT
            Not After : Jan  1 00:00:00 2025 GMT
        Subject: CN=example.com
        X509v3 extensions:
            Authority Information Access: 
                OCSP - URI:http://ocsp.example.com
                CRL - URI:http://crl.example.com/crl.pem
"""
    
    cert = checker.parse_certificate_from_pem(sample_pem)
    assert cert is not None
    assert "01:23:45:67:89:AB:CD:EF" in cert.serial_number
    assert len(cert.ocsp_urls) >= 1
    print(f"  ✓ PASSED: PEM parsed, serial={cert.serial_number}")


def main():
    """Run all tests"""
    print("=" * 60)
    print("CERTIFICATE REVOCATION CHECKER - TEST SUITE")
    print("=" * 60)
    
    tests = [
        test_checker_initialization,
        test_checker_custom_config,
        test_certificate_info_creation,
        test_lru_cache_basic,
        test_lru_cache_freshness,
        test_ocsp_check_with_url,
        test_crl_check_with_url,
        test_comprehensive_check,
        test_check_no_urls,
        test_cache_hits,
        test_result_serialization,
        test_revoked_status_detection,
        test_trusted_responder,
        test_stapled_response_check,
        test_checker_statistics,
        test_pem_parsing
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            failed += 1
    
    print("=" * 60)
    print(f"RESULTS: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save test results
    with open("test_results_certificate_revocation_checker.json", "w") as f:
        json.dump({
            "test_module": "post_quantum_certificate_revocation_checker_2026_june",
            "total_tests": len(tests),
            "passed": passed,
            "failed": failed,
            "success_rate": passed / len(tests) if tests else 0,
            "timestamp": __import__("datetime").datetime.now().isoformat()
        }, f, indent=2)
    
    print(f"Test results saved to test_results_certificate_revocation_checker.json")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
