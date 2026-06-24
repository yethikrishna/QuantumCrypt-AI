"""
Test Suite for Post-Quantum Certificate Transparency Monitor v26
Dimension A - Feature Expansion
June 2026 - 100% Backward Compatible
35 tests total
"""

import pytest
from datetime import datetime, timedelta
from quantum_crypt.pq_certificate_transparency_monitor_v26_2026_june import (
    PQCertificateTransparencyMonitor,
    CertificateEntry,
    MonitorAlert,
    AlgorithmDetector,
    VulnerabilityScanner,
    PQAlgorithm,
    CertificateStatus,
    VulnerabilityType,
    CTLogProvider
)


class TestPQAlgorithmEnum:
    def test_algorithm_enum_values(self):
        assert PQAlgorithm.CRYSTALS_KYBER.value == "CRYSTALS-Kyber"
        assert PQAlgorithm.KYBER_768.value == "Kyber-768"
        assert PQAlgorithm.CRYSTALS_DILITHIUM.value == "CRYSTALS-Dilithium"

    def test_hybrid_algorithms_exist(self):
        assert PQAlgorithm.HYBRID_RSA_KYBER in list(PQAlgorithm)
        assert PQAlgorithm.HYBRID_ECDSA_DILITHIUM in list(PQAlgorithm)


class TestCertificateEntry:
    def test_certificate_entry_creation(self):
        entry = CertificateEntry(
            serial_number="0123456789abcdef",
            subject="CN=test.com",
            issuer="Let's Encrypt",
            signature_algorithm="RSA",
            public_key_algorithm="RSA",
            key_size_bits=2048,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
            ct_log="Google_Pilot",
            entry_index=123456
        )
        assert len(entry.entry_id) == 20
        assert entry.status == CertificateStatus.VALID

    def test_is_post_quantum_true(self):
        entry = CertificateEntry(
            serial_number="test", subject="CN=test.com", issuer="Issuer",
            signature_algorithm="Kyber-768", public_key_algorithm="Kyber-768",
            key_size_bits=1536,
            not_before=datetime.now(), not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1,
            pq_algorithms=[PQAlgorithm.KYBER_768]
        )
        assert entry.is_post_quantum() is True

    def test_is_post_quantum_false(self):
        entry = CertificateEntry(
            serial_number="test", subject="CN=test.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=2048,
            not_before=datetime.now(), not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1
        )
        assert entry.is_post_quantum() is False

    def test_is_hybrid_detection(self):
        entry = CertificateEntry(
            serial_number="test", subject="CN=test.com", issuer="Issuer",
            signature_algorithm="RSA+Kyber", public_key_algorithm="RSA+Kyber",
            key_size_bits=4096,
            not_before=datetime.now(), not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1,
            pq_algorithms=[PQAlgorithm.HYBRID_RSA_KYBER]
        )
        assert entry.is_hybrid() is True

    def test_days_until_expiry(self):
        entry = CertificateEntry(
            serial_number="test", subject="CN=test.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=2048,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=45),
            ct_log="Test", entry_index=1
        )
        assert 44 <= entry.days_until_expiry() <= 45

    def test_is_expiring_soon(self):
        entry = CertificateEntry(
            serial_number="test", subject="CN=test.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=2048,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=5),
            ct_log="Test", entry_index=1
        )
        assert entry.is_expiring_soon(30) is True

    def test_to_dict_serialization(self):
        entry = CertificateEntry(
            serial_number="test123", subject="CN=test.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=2048,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1,
            domains=["test.com", "www.test.com"]
        )
        d = entry.to_dict()
        assert d["serial_number"] == "test123"
        assert d["entry_id"] == entry.entry_id
        assert len(d["domains"]) == 2


class TestAlgorithmDetector:
    def test_detect_kyber_algorithm(self):
        algs = AlgorithmDetector.detect_algorithms("RSA+Kyber-768")
        assert len(algs) > 0
        assert PQAlgorithm.HYBRID_RSA_KYBER in algs

    def test_detect_dilithium_algorithm(self):
        algs = AlgorithmDetector.detect_algorithms("ECDSA+Dilithium-3")
        assert PQAlgorithm.HYBRID_ECDSA_DILITHIUM in algs

    def test_detect_no_pq_algorithm(self):
        algs = AlgorithmDetector.detect_algorithms("RSA-2048")
        assert len(algs) == 0

    def test_assess_key_strength_weak_rsa(self):
        safe, warnings = AlgorithmDetector.assess_key_strength("RSA", 1024)
        assert safe is False
        assert len(warnings) > 0

    def test_assess_key_strength_ecdsa(self):
        safe, warnings = AlgorithmDetector.assess_key_strength("ECDSA", 256)
        assert safe is False


class TestVulnerabilityScanner:
    def test_scan_small_rsa_key(self):
        entry = CertificateEntry(
            serial_number="test", subject="CN=test.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=1024,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1
        )
        vulns = VulnerabilityScanner.scan_certificate(entry)
        assert VulnerabilityType.SMALL_KEY_SIZE in vulns

    def test_scan_deprecated_rsa_2048(self):
        entry = CertificateEntry(
            serial_number="test", subject="CN=test.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=2048,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1
        )
        vulns = VulnerabilityScanner.scan_certificate(entry)
        assert VulnerabilityType.DEPRECATED_ALGORITHM in vulns

    def test_scan_classical_no_pq(self):
        entry = CertificateEntry(
            serial_number="test", subject="CN=test.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=4096,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1
        )
        vulns = VulnerabilityScanner.scan_certificate(entry)
        assert VulnerabilityType.DEPRECATED_ALGORITHM in vulns


class TestCTMonitor:
    def test_monitor_initialization(self):
        monitor = PQCertificateTransparencyMonitor()
        assert len(monitor.entries) == 0
        assert len(monitor.alerts) == 0

    def test_add_certificate_entry(self):
        monitor = PQCertificateTransparencyMonitor()
        entry = CertificateEntry(
            serial_number="test123", subject="CN=test.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=2048,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
            ct_log="Google_Pilot", entry_index=1,
            domains=["test.com"]
        )
        entry_id = monitor.add_certificate_entry(entry)
        assert entry_id in monitor.entries
        assert "test.com" in monitor.domain_index

    def test_pq_adoption_stats_empty(self):
        monitor = PQCertificateTransparencyMonitor()
        stats = monitor.get_pq_adoption_stats()
        assert stats["total_certificates"] == 0
        assert stats["post_quantum_count"] == 0

    def test_pq_adoption_stats_with_data(self):
        monitor = PQCertificateTransparencyMonitor()
        monitor.simulate_ct_scan(20)
        stats = monitor.get_pq_adoption_stats()
        assert stats["total_certificates"] == 20
        assert "post_quantum_percentage" in stats
        assert "algorithm_distribution" in stats

    def test_get_domain_status_not_found(self):
        monitor = PQCertificateTransparencyMonitor()
        status = monitor.get_domain_pq_status("nonexistent.com")
        assert status["found"] is False

    def test_get_domain_status_found(self):
        monitor = PQCertificateTransparencyMonitor()
        entry = CertificateEntry(
            serial_number="test", subject="CN=mydomain.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=2048,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1,
            domains=["mydomain.com"]
        )
        monitor.add_certificate_entry(entry)
        status = monitor.get_domain_pq_status("mydomain.com")
        assert status["found"] is True
        assert status["total_certificates"] == 1

    def test_get_alerts_empty(self):
        monitor = PQCertificateTransparencyMonitor()
        alerts = monitor.get_alerts()
        assert len(alerts) == 0

    def test_compliance_report(self):
        monitor = PQCertificateTransparencyMonitor()
        monitor.simulate_ct_scan(10)
        report = monitor.get_compliance_report()
        assert "report_generated" in report
        assert "migration_progress" in report
        assert "risk_assessment" in report
        assert "recommendations" in report

    def test_simulate_ct_scan(self):
        monitor = PQCertificateTransparencyMonitor()
        count = monitor.simulate_ct_scan(50)
        assert count == 50
        assert len(monitor.entries) == 50
        assert monitor.last_scan_time is not None


class TestAlertGeneration:
    def test_pq_adoption_alert(self):
        monitor = PQCertificateTransparencyMonitor()
        entry = CertificateEntry(
            serial_number="pqtest", subject="CN=pq-domain.com", issuer="Issuer",
            signature_algorithm="Kyber-768", public_key_algorithm="Kyber-768",
            key_size_bits=1536,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1,
            domains=["pq-domain.com"],
            pq_algorithms=[PQAlgorithm.KYBER_768]
        )
        monitor.add_certificate_entry(entry)
        alerts = monitor.get_alerts("info")
        pq_alerts = [a for a in alerts if a["type"] == "PQ_ADOPTION"]
        assert len(pq_alerts) >= 1

    def test_vulnerability_alert(self):
        monitor = PQCertificateTransparencyMonitor()
        entry = CertificateEntry(
            serial_number="vulntest", subject="CN=weak.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=1024,  # Small key
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1,
            domains=["weak.com"]
        )
        monitor.add_certificate_entry(entry)
        alerts = monitor.get_alerts("medium")
        vuln_alerts = [a for a in alerts if a["type"] == "VULNERABILITY"]
        assert len(vuln_alerts) >= 1

    def test_expiry_alert(self):
        monitor = PQCertificateTransparencyMonitor()
        entry = CertificateEntry(
            serial_number="expiretest", subject="CN=expiring.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=2048,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=3),  # Expiring soon
            ct_log="Test", entry_index=1,
            domains=["expiring.com"]
        )
        monitor.add_certificate_entry(entry)
        alerts = monitor.get_alerts("medium")
        expiry_alerts = [a for a in alerts if a["type"] == "EXPIRING_SOON"]
        assert len(expiry_alerts) >= 1

    def test_alert_severity_filtering(self):
        monitor = PQCertificateTransparencyMonitor()
        # Add entries that generate different severity alerts
        entry1 = CertificateEntry(
            serial_number="high", subject="CN=vuln.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=1024,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1,
            domains=["vuln.com"]
        )
        monitor.add_certificate_entry(entry1)
        
        high_alerts = monitor.get_alerts("high")
        medium_alerts = monitor.get_alerts("medium")
        info_alerts = monitor.get_alerts("info")
        
        assert len(info_alerts) >= len(medium_alerts) >= len(high_alerts)


class TestIntegration:
    def test_full_monitoring_workflow(self):
        """Test complete monitoring workflow."""
        monitor = PQCertificateTransparencyMonitor()
        
        # 1. Simulate CT log scan
        monitor.simulate_ct_scan(100)
        
        # 2. Get adoption statistics
        stats = monitor.get_pq_adoption_stats()
        assert stats["total_certificates"] == 100
        
        # 3. Check specific domain status
        status = monitor.get_domain_pq_status("example.com")
        assert status["found"] is True
        
        # 4. Get compliance report
        report = monitor.get_compliance_report()
        assert report["risk_assessment"] in ["LOW", "MEDIUM", "HIGH"]
        
        # 5. Get alerts
        alerts = monitor.get_alerts("medium")
        assert isinstance(alerts, list)

    def test_hybrid_certificate_tracking(self):
        """Test hybrid certificate detection and tracking."""
        monitor = PQCertificateTransparencyMonitor()
        
        hybrid_entry = CertificateEntry(
            serial_number="hybrid123", subject="CN=secure-bank.io", issuer="DigiCert",
            signature_algorithm="RSA+Kyber-768", public_key_algorithm="RSA+Kyber-768",
            key_size_bits=4096,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=365),
            ct_log="Google_Pilot", entry_index=999999,
            domains=["secure-bank.io", "www.secure-bank.io"],
            pq_algorithms=[PQAlgorithm.HYBRID_RSA_KYBER, PQAlgorithm.KYBER_768]
        )
        
        monitor.add_certificate_entry(hybrid_entry)
        
        stats = monitor.get_pq_adoption_stats()
        assert stats["hybrid_count"] >= 1
        assert stats["post_quantum_count"] >= 1
        
        status = monitor.get_domain_pq_status("secure-bank.io")
        assert status["has_pq_adoption"] is True
        assert "RSA+Kyber" in status["algorithms_used"]


class TestEdgeCases:
    def test_empty_domains_list(self):
        monitor = PQCertificateTransparencyMonitor()
        entry = CertificateEntry(
            serial_number="nodomain", subject="CN=test", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=2048,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1,
            domains=[]
        )
        monitor.add_certificate_entry(entry)
        assert entry.entry_id in monitor.entries

    def test_expired_certificate(self):
        monitor = PQCertificateTransparencyMonitor()
        entry = CertificateEntry(
            serial_number="expired", subject="CN=old.com", issuer="Issuer",
            signature_algorithm="RSA", public_key_algorithm="RSA",
            key_size_bits=2048,
            not_before=datetime.now() - timedelta(days=365),
            not_after=datetime.now() - timedelta(days=1),
            ct_log="Test", entry_index=1
        )
        monitor.add_certificate_entry(entry)
        assert entry.days_until_expiry() == 0

    def test_zero_key_size(self):
        monitor = PQCertificateTransparencyMonitor()
        entry = CertificateEntry(
            serial_number="zerokey", subject="CN=test.com", issuer="Issuer",
            signature_algorithm="Unknown", public_key_algorithm="Unknown",
            key_size_bits=0,
            not_before=datetime.now(),
            not_after=datetime.now() + timedelta(days=90),
            ct_log="Test", entry_index=1
        )
        # Should not crash
        monitor.add_certificate_entry(entry)
        assert entry.entry_id in monitor.entries


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
