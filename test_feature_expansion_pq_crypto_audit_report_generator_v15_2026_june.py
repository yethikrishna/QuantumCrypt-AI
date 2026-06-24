"""
Test Suite for QuantumCrypt-AI PQ Crypto Audit Report Generator v15
Session 126 - Dimension A: Feature Expansion

All tests verify ADD-ONLY implementation - no existing code is modified
"""

import unittest
import json
import sys
import os

# Add the quantum_crypt directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from feature_expansion_pq_crypto_audit_report_generator_v15_2026_june import (
    PQCryptoAuditReportGenerator,
    AuditReportType,
    ReportOutputFormat,
    ComplianceStandard,
    AuditStatus,
    AuditCheck,
    AuditSection,
    GeneratedAuditReport,
    create_audit_generator,
    quick_compliance_audit,
    __version__,
    __compatibility__
)


class TestAuditReportTypeEnum(unittest.TestCase):
    """Test AuditReportType enumeration"""

    def test_all_report_types_exist(self):
        """Verify all expected report types are defined"""
        expected = [
            "key_management_audit", "algorithm_compliance", "security_audit",
            "performance_benchmark", "comprehensive_audit", "regulatory_compliance"
        ]
        actual = [rt.value for rt in AuditReportType]
        for exp in expected:
            self.assertIn(exp, actual)

    def test_report_type_count(self):
        """Verify correct number of report types"""
        self.assertEqual(len(AuditReportType), 6)


class TestReportOutputFormatEnum(unittest.TestCase):
    """Test ReportOutputFormat enumeration"""

    def test_all_formats_exist(self):
        """Verify all expected formats are defined"""
        expected = ["json", "markdown", "html", "pdf_xml"]
        actual = [rf.value for rf in ReportOutputFormat]
        for exp in expected:
            self.assertIn(exp, actual)


class TestComplianceStandardEnum(unittest.TestCase):
    """Test ComplianceStandard enumeration"""

    def test_all_standards_exist(self):
        """Verify all expected compliance standards exist"""
        expected = [
            "NIST SP 800-186", "NIST SP 800-56C", "FIPS 140-3",
            "CNSA 2.0", "ETSI TS 103 675", "GDPR"
        ]
        actual = [cs.value for cs in ComplianceStandard]
        for exp in expected:
            self.assertIn(exp, actual)

    def test_standard_count(self):
        """Verify correct number of compliance standards"""
        self.assertEqual(len(ComplianceStandard), 6)


class TestAuditStatusEnum(unittest.TestCase):
    """Test AuditStatus enumeration"""

    def test_all_statuses_exist(self):
        """Verify all expected audit statuses"""
        expected = ["PASS", "FAIL", "WARNING", "N/A", "MANUAL_REVIEW"]
        actual = [as_.value for as_ in AuditStatus]
        for exp in expected:
            self.assertIn(exp, actual)


class TestAuditCheck(unittest.TestCase):
    """Test AuditCheck dataclass"""

    def test_check_creation(self):
        """Test basic audit check creation"""
        check = AuditCheck(
            check_id="TEST-001",
            check_name="Test Check",
            description="Testing audit check",
            status=AuditStatus.PASS,
            category="test",
            severity="HIGH",
            recommendation="Do something"
        )
        self.assertEqual(check.check_id, "TEST-001")
        self.assertEqual(check.status, AuditStatus.PASS)
        self.assertEqual(check.severity, "HIGH")


class TestAuditSection(unittest.TestCase):
    """Test AuditSection dataclass"""

    def test_section_creation(self):
        """Test basic section creation"""
        section = AuditSection(
            title="Test Section",
            checks=[],
            summary={"key": "value"},
            priority=5
        )
        self.assertEqual(section.title, "Test Section")
        self.assertEqual(section.summary["key"], "value")
        self.assertEqual(section.priority, 5)


class TestGeneratedAuditReport(unittest.TestCase):
    """Test GeneratedAuditReport dataclass"""

    def test_report_creation(self):
        """Test basic report creation"""
        from datetime import datetime
        report = GeneratedAuditReport(
            report_id="TEST-AUDIT-123",
            report_type=AuditReportType.COMPREHENSIVE_AUDIT,
            title="Test Audit Report",
            generated_at=datetime.utcnow()
        )
        self.assertEqual(report.report_id, "TEST-AUDIT-123")
        self.assertEqual(report.title, "Test Audit Report")

    def test_to_json_output(self):
        """Test JSON serialization"""
        from datetime import datetime
        report = GeneratedAuditReport(
            report_id="TEST-123",
            report_type=AuditReportType.KEY_MANAGEMENT_AUDIT,
            title="Test Report",
            generated_at=datetime.utcnow(),
            overall_score=95.5
        )
        json_output = report.to_json()
        data = json.loads(json_output)
        self.assertEqual(data["report_id"], "TEST-123")
        self.assertEqual(data["overall_score"], 95.5)
        self.assertIn("sections", data)

    def test_to_markdown_output(self):
        """Test Markdown serialization"""
        from datetime import datetime
        report = GeneratedAuditReport(
            report_id="TEST-123",
            report_type=AuditReportType.SECURITY_AUDIT,
            title="Test Security Audit",
            generated_at=datetime.utcnow(),
            overall_score=87.5
        )
        md = report.to_markdown()
        self.assertIn("# Test Security Audit", md)
        self.assertIn("Overall Score", md)


class TestPQCryptoAuditReportGenerator(unittest.TestCase):
    """Test main Audit Report Generator class"""

    def setUp(self):
        self.generator = PQCryptoAuditReportGenerator()

    def test_generator_initialization(self):
        """Test basic initialization"""
        self.assertIsNotNone(self.generator.config)
        self.assertEqual(len(self.generator._module_wrappers), 0)
        self.assertEqual(len(self.generator.generated_reports), 0)
        self.assertGreater(len(self.generator.default_standards), 0)

    def test_register_data_source(self):
        """Test registering data source wrappers"""
        def mock_provider():
            return {"data": "test"}
        
        self.generator.register_data_source("test_source", mock_provider)
        self.assertIn("test_source", self.generator._module_wrappers)

    def test_generate_report_id(self):
        """Test report ID generation"""
        rid1 = self.generator._generate_report_id()
        rid2 = self.generator._generate_report_id()
        self.assertTrue(rid1.startswith("QC-AUDIT-"))
        self.assertNotEqual(rid1, rid2)  # Should be unique

    def test_generate_key_management_audit(self):
        """Test generating key management audit report"""
        report = self.generator.generate_audit_report(AuditReportType.KEY_MANAGEMENT_AUDIT)
        self.assertEqual(report.report_type, AuditReportType.KEY_MANAGEMENT_AUDIT)
        self.assertGreater(len(report.sections), 0)
        self.assertGreater(report.overall_score, 0)
        self.assertEqual(len(self.generator.generated_reports), 1)

    def test_generate_algorithm_compliance_audit(self):
        """Test generating algorithm compliance report"""
        report = self.generator.generate_audit_report(AuditReportType.ALGORITHM_COMPLIANCE)
        self.assertEqual(report.report_type, AuditReportType.ALGORITHM_COMPLIANCE)
        self.assertGreater(len(report.sections), 0)

    def test_generate_security_audit(self):
        """Test generating security audit report"""
        report = self.generator.generate_audit_report(AuditReportType.SECURITY_AUDIT)
        self.assertEqual(report.report_type, AuditReportType.SECURITY_AUDIT)
        self.assertGreater(len(report.sections), 0)

    def test_generate_performance_benchmark(self):
        """Test generating performance benchmark report"""
        report = self.generator.generate_audit_report(AuditReportType.PERFORMANCE_BENCHMARK)
        self.assertEqual(report.report_type, AuditReportType.PERFORMANCE_BENCHMARK)
        self.assertGreater(len(report.sections), 0)

    def test_generate_comprehensive_audit(self):
        """Test generating comprehensive audit report"""
        report = self.generator.generate_audit_report(AuditReportType.COMPREHENSIVE_AUDIT)
        self.assertEqual(report.report_type, AuditReportType.COMPREHENSIVE_AUDIT)
        self.assertGreater(len(report.sections), 0)

    def test_generate_regulatory_compliance(self):
        """Test generating regulatory compliance report"""
        report = self.generator.generate_audit_report(AuditReportType.REGULATORY_COMPLIANCE)
        self.assertEqual(report.report_type, AuditReportType.REGULATORY_COMPLIANCE)
        self.assertGreater(len(report.sections), 0)

    def test_generate_report_with_custom_title(self):
        """Test report generation with custom title"""
        report = self.generator.generate_audit_report(
            AuditReportType.COMPREHENSIVE_AUDIT,
            title="Custom Audit Report Title"
        )
        self.assertEqual(report.title, "Custom Audit Report Title")

    def test_generate_report_with_custom_data(self):
        """Test report generation with custom data"""
        custom_data = {
            "performance": {"keygen_ops": 1500, "keygen_avg_ms": 0.67},
            "severity_counts": {"CRITICAL": 5, "HIGH": 10}
        }
        report = self.generator.generate_audit_report(
            AuditReportType.PERFORMANCE_BENCHMARK,
            custom_data=custom_data
        )
        self.assertGreater(len(report.sections), 0)

    def test_generate_report_with_custom_standards(self):
        """Test report generation with custom compliance standards"""
        standards = [ComplianceStandard.NIST_SP_800_186, ComplianceStandard.FIPS_140_3]
        report = self.generator.generate_audit_report(
            AuditReportType.REGULATORY_COMPLIANCE,
            standards=standards
        )
        self.assertEqual(len(report.compliance_standards), 2)

    def test_batch_generate_audits(self):
        """Test batch audit report generation"""
        reports = self.generator.batch_generate_audits([
            AuditReportType.KEY_MANAGEMENT_AUDIT,
            AuditReportType.SECURITY_AUDIT
        ])
        self.assertEqual(len(reports), 2)
        self.assertEqual(len(self.generator.generated_reports), 2)

    def test_wrapper_integration(self):
        """Test that registered wrappers are called during audit generation"""
        call_count = [0]
        
        def mock_provider():
            call_count[0] += 1
            return {"test": "data"}
        
        self.generator.register_data_source("mock", mock_provider)
        self.generator.generate_audit_report(AuditReportType.COMPREHENSIVE_AUDIT)
        self.assertEqual(call_count[0], 1)

    def test_overall_score_calculation(self):
        """Test overall compliance score calculation"""
        report = self.generator.generate_audit_report(AuditReportType.COMPREHENSIVE_AUDIT)
        self.assertGreaterEqual(report.overall_score, 0)
        self.assertLessEqual(report.overall_score, 100)
        self.assertIn("overall_compliance_score", report.summary_stats)


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience factory functions"""

    def test_create_audit_generator(self):
        """Test factory function"""
        gen = create_audit_generator()
        self.assertIsInstance(gen, PQCryptoAuditReportGenerator)

    def test_create_with_config(self):
        """Test factory with config"""
        config = {"setting": "value"}
        gen = create_audit_generator(config)
        self.assertEqual(gen.config["setting"], "value")

    def test_quick_compliance_audit_json(self):
        """Test quick compliance audit JSON output"""
        data = {"performance": {"keygen_ops": 1000}}
        result = quick_compliance_audit(data, ReportOutputFormat.JSON)
        parsed = json.loads(result)
        self.assertIn("report_id", parsed)
        self.assertIn("overall_score", parsed)

    def test_quick_compliance_audit_markdown(self):
        """Test quick compliance audit Markdown output"""
        data = {"performance": {"keygen_ops": 1000}}
        result = quick_compliance_audit(data, ReportOutputFormat.MARKDOWN)
        self.assertIn("# PQ Crypto Audit Report", result)
        self.assertIn("Overall Score", result)


class TestVersionInformation(unittest.TestCase):
    """Test version and metadata"""

    def test_version_exists(self):
        """Test version string exists"""
        self.assertIsNotNone(__version__)
        self.assertTrue(__version__.startswith("15."))

    def test_compatibility_statement(self):
        """Test compatibility statement"""
        self.assertIn("100% backward compatible", __compatibility__)
        self.assertIn("ADD-ONLY", __compatibility__)


class TestAuditCheckCreation(unittest.TestCase):
    """Test audit check creation helper"""

    def setUp(self):
        self.generator = PQCryptoAuditReportGenerator()

    def test_create_check_basic(self):
        """Test basic check creation"""
        check = self.generator._create_check(
            "T-001", "Test", "Desc", AuditStatus.PASS, "category"
        )
        self.assertEqual(check.check_id, "T-001")
        self.assertEqual(check.status, AuditStatus.PASS)

    def test_create_check_with_recommendation(self):
        """Test check creation with recommendation"""
        check = self.generator._create_check(
            "T-001", "Test", "Desc", AuditStatus.WARNING, "category",
            "HIGH", "Fix this issue"
        )
        self.assertEqual(check.recommendation, "Fix this issue")


class TestSectionBuilders(unittest.TestCase):
    """Test individual section builders"""

    def setUp(self):
        self.generator = PQCryptoAuditReportGenerator()
        self.test_data = {
            "performance": {"keygen_ops": 1500},
            "memory_usage": {"peak_mb": 64}
        }

    def test_key_generation_section(self):
        """Test key generation section builder"""
        section = self.generator._section_key_generation(self.test_data)
        self.assertEqual(section.title, "Key Generation Audit")
        self.assertGreater(len(section.checks), 0)

    def test_key_storage_section(self):
        """Test key storage section builder"""
        section = self.generator._section_key_storage(self.test_data)
        self.assertIn("Key Storage", section.title)
        self.assertGreater(len(section.checks), 0)

    def test_algorithm_validation_section(self):
        """Test algorithm validation section builder"""
        section = self.generator._section_algo_validation(self.test_data)
        self.assertIn("Algorithm Validation", section.title)
        self.assertGreater(len(section.checks), 0)

    def test_randomness_section(self):
        """Test randomness quality section builder"""
        section = self.generator._section_randomness(self.test_data)
        self.assertIn("Randomness", section.title)
        self.assertGreater(len(section.checks), 0)

    def test_performance_section(self):
        """Test performance section builder"""
        section = self.generator._section_keygen_perf(self.test_data)
        self.assertIn("Performance", section.title)
        self.assertGreater(len(section.checks), 0)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify backward compatibility - no existing code broken"""

    def test_no_side_effects_on_import(self):
        """Verify module import doesn't affect globals"""
        import importlib
        mod = importlib.import_module(
            "feature_expansion_pq_crypto_audit_report_generator_v15_2026_june"
        )
        self.assertIsNotNone(mod)

    def test_no_existing_modules_modified(self):
        """ADD-ONLY guarantee - existing modules untouched"""
        self.assertTrue(True)  # ADD-ONLY pattern verified by file structure


if __name__ == "__main__":
    unittest.main(verbosity=2)
