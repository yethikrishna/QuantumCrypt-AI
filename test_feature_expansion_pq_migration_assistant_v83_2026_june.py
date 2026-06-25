"""
Test Suite for PQC Migration Assistant v83
Dimension A: Feature Expansion - Test Coverage
All tests verify production-grade functionality
"""
import pytest
import json
from quantum_crypt.feature_expansion_pq_migration_assistant_v83_2026_june import (
    PQCMigrationAssistant,
    assess_algorithm_vulnerability,
    create_migration_roadmap,
    AlgorithmType,
    MigrationPriority,
    RiskLevel,
    UseCaseCategory,
    CryptoInventoryItem,
    MigrationRecommendation,
    MigrationRoadmap
)


class TestPQCMigrationAssistant:
    """Test suite for PQCMigrationAssistant class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.assistant = PQCMigrationAssistant()
    
    def test_initialization(self):
        """Test assistant initialization"""
        assert self.assistant.algorithm_mappings is not None
        assert self.assistant.use_case_recommendations is not None
        assert self.assistant.compliance_standards is not None
        assert self.assistant.inventory == []
        assert len(self.assistant.algorithm_mappings) > 0
    
    def test_add_inventory_item(self):
        """Test adding single inventory item"""
        item = CryptoInventoryItem(
            item_id="TEST-001",
            name="Test TLS Cert",
            algorithm="RSA-2048",
            algorithm_type=AlgorithmType.CLASSICAL,
            key_size=2048,
            use_case=UseCaseCategory.TLS,
            location="Test Server",
            owner="Test Team"
        )
        
        result_id = self.assistant.add_inventory_item(item)
        assert result_id == "TEST-001"
        assert len(self.assistant.inventory) == 1
    
    def test_add_inventory_items_bulk(self):
        """Test adding multiple inventory items"""
        items = [
            CryptoInventoryItem(
                item_id=f"TEST-{i:03d}",
                name=f"Item {i}",
                algorithm="RSA-2048",
                algorithm_type=AlgorithmType.CLASSICAL,
                key_size=2048,
                use_case=UseCaseCategory.TLS,
                location=f"Server {i}",
                owner="Team"
            )
            for i in range(3)
        ]
        
        ids = self.assistant.add_inventory_items_bulk(items)
        assert len(ids) == 3
        assert len(self.assistant.inventory) == 3
    
    def test_clear_inventory(self):
        """Test clearing inventory"""
        item = CryptoInventoryItem(
            item_id="TEST-001",
            name="Test",
            algorithm="RSA-2048",
            algorithm_type=AlgorithmType.CLASSICAL,
            key_size=2048,
            use_case=UseCaseCategory.TLS,
            location="Test",
            owner="Test"
        )
        self.assistant.add_inventory_item(item)
        assert len(self.assistant.inventory) == 1
        
        self.assistant.clear_inventory()
        assert len(self.assistant.inventory) == 0


class TestVulnerabilityAssessment:
    """Test suite for quantum vulnerability assessment"""
    
    def setup_method(self):
        self.assistant = PQCMigrationAssistant()
    
    def test_rsa_2048_vulnerability(self):
        """Test RSA-2048 vulnerability assessment"""
        vulnerable, risk, security = self.assistant.assess_quantum_vulnerability("RSA-2048")
        assert vulnerable is True
        assert risk == RiskLevel.CRITICAL
        assert security == 112
    
    def test_ecdsa_p256_vulnerability(self):
        """Test ECDSA-P256 vulnerability assessment"""
        vulnerable, risk, security = self.assistant.assess_quantum_vulnerability("ECDSA-P256")
        assert vulnerable is True
        assert risk == RiskLevel.HIGH
        assert security == 128
    
    def test_aes_256_not_vulnerable(self):
        """Test AES-256 is not quantum vulnerable"""
        vulnerable, risk, security = self.assistant.assess_quantum_vulnerability("AES-256")
        assert vulnerable is False
        assert risk == RiskLevel.LOW
        assert security == 256
    
    def test_sha_256_not_vulnerable(self):
        """Test SHA-256 is not quantum vulnerable"""
        vulnerable, risk, security = self.assistant.assess_quantum_vulnerability("SHA-256")
        assert vulnerable is False
        assert risk == RiskLevel.LOW
        assert security == 128
    
    def test_unknown_algorithm_assumes_vulnerable(self):
        """Test unknown algorithm defaults to vulnerable"""
        vulnerable, risk, security = self.assistant.assess_quantum_vulnerability("UNKNOWN-ALG")
        assert vulnerable is True
        assert risk == RiskLevel.UNKNOWN
        assert security == 0
    
    def test_algorithm_case_insensitive(self):
        """Test algorithm matching is case insensitive"""
        v1, r1, s1 = self.assistant.assess_quantum_vulnerability("rsa-2048")
        v2, r2, s2 = self.assistant.assess_quantum_vulnerability("RSA-2048")
        assert v1 == v2
        assert r1 == r2
        assert s1 == s2


class TestMigrationPriority:
    """Test suite for migration priority calculation"""
    
    def setup_method(self):
        self.assistant = PQCMigrationAssistant()
    
    def test_immediate_priority_for_critical_risk(self):
        """Test critical risk items get immediate priority"""
        item = CryptoInventoryItem(
            item_id="TEST-001",
            name="Critical Item",
            algorithm="RSA-2048",
            algorithm_type=AlgorithmType.CLASSICAL,
            key_size=2048,
            use_case=UseCaseCategory.KEY_EXCHANGE,
            location="Prod",
            owner="Security"
        )
        priority = self.assistant.calculate_migration_priority(item)
        assert priority == MigrationPriority.IMMEDIATE
    
    def test_high_priority_for_high_risk(self):
        """Test high risk items get high priority"""
        item = CryptoInventoryItem(
            item_id="TEST-001",
            name="High Risk Item",
            algorithm="ECDSA-P256",
            algorithm_type=AlgorithmType.CLASSICAL,
            key_size=256,
            use_case=UseCaseCategory.TLS,
            location="Prod",
            owner="Network"
        )
        priority = self.assistant.calculate_migration_priority(item)
        assert priority in (MigrationPriority.HIGH, MigrationPriority.IMMEDIATE)
    
    def test_deferred_priority_for_non_vulnerable(self):
        """Test non-vulnerable algorithms get deferred priority"""
        item = CryptoInventoryItem(
            item_id="TEST-001",
            name="Safe Item",
            algorithm="AES-256",
            algorithm_type=AlgorithmType.CLASSICAL,
            key_size=256,
            use_case=UseCaseCategory.DATA_ENCRYPTION,
            location="Prod",
            owner="Ops"
        )
        priority = self.assistant.calculate_migration_priority(item)
        assert priority == MigrationPriority.DEFERRED


class TestMigrationRecommendation:
    """Test suite for migration recommendation generation"""
    
    def setup_method(self):
        self.assistant = PQCMigrationAssistant()
    
    def test_generate_recommendation_structure(self):
        """Test recommendation has correct structure"""
        item = CryptoInventoryItem(
            item_id="TEST-001",
            name="Test TLS Cert",
            algorithm="RSA-2048",
            algorithm_type=AlgorithmType.CLASSICAL,
            key_size=2048,
            use_case=UseCaseCategory.TLS,
            location="Prod",
            owner="Network"
        )
        
        rec = self.assistant.generate_migration_recommendation(item)
        
        assert isinstance(rec, MigrationRecommendation)
        assert rec.item_id == "TEST-001"
        assert rec.current_algorithm == "RSA-2048"
        assert "Kyber" in rec.recommended_algorithm
        assert isinstance(rec.priority, MigrationPriority)
        assert isinstance(rec.risk_level, RiskLevel)
        assert rec.estimated_effort_hours > 0
        assert rec.timeline_weeks > 0
        assert len(rec.dependencies) >= 0
        assert len(rec.fallback_strategy) > 0
        assert len(rec.verification_steps) > 0
    
    def test_recommendation_has_verification_steps(self):
        """Test all recommendations have verification steps"""
        item = CryptoInventoryItem(
            item_id="TEST-001",
            name="Test",
            algorithm="RSA-3072",
            algorithm_type=AlgorithmType.CLASSICAL,
            key_size=3072,
            use_case=UseCaseCategory.CODE_SIGNING,
            location="Build",
            owner="DevOps"
        )
        
        rec = self.assistant.generate_migration_recommendation(item)
        assert len(rec.verification_steps) >= 5


class TestMigrationRoadmap:
    """Test suite for migration roadmap generation"""
    
    def setup_method(self):
        self.assistant = PQCMigrationAssistant()
        self._populate_test_inventory()
    
    def _populate_test_inventory(self):
        """Add test inventory items"""
        items = [
            CryptoInventoryItem(
                item_id="TLS-001",
                name="Web Server TLS",
                algorithm="RSA-2048",
                algorithm_type=AlgorithmType.CLASSICAL,
                key_size=2048,
                use_case=UseCaseCategory.TLS,
                location="DMZ",
                owner="Network"
            ),
            CryptoInventoryItem(
                item_id="SIGN-001",
                name="Code Signing",
                algorithm="ECDSA-P256",
                algorithm_type=AlgorithmType.CLASSICAL,
                key_size=256,
                use_case=UseCaseCategory.CODE_SIGNING,
                location="Build",
                owner="DevOps"
            ),
            CryptoInventoryItem(
                item_id="ENC-001",
                name="Data Encryption",
                algorithm="AES-256",
                algorithm_type=AlgorithmType.CLASSICAL,
                key_size=256,
                use_case=UseCaseCategory.DATA_ENCRYPTION,
                location="DB",
                owner="Ops"
            )
        ]
        self.assistant.add_inventory_items_bulk(items)
    
    def test_generate_roadmap_structure(self):
        """Test roadmap generation produces valid structure"""
        roadmap = self.assistant.generate_migration_roadmap("Test Roadmap")
        
        assert isinstance(roadmap, MigrationRoadmap)
        assert roadmap.roadmap_id.startswith("PQC-ROADMAP-")
        assert roadmap.title == "Test Roadmap"
        assert roadmap.total_assets == 3
        assert roadmap.vulnerable_assets == 2  # RSA and ECDSA are vulnerable
        assert roadmap.estimated_total_effort_hours > 0
        assert len(roadmap.recommendations) == 3
        assert len(roadmap.phases) > 0
        assert len(roadmap.compliance_notes) > 0
    
    def test_roadmap_recommendations_sorted_by_priority(self):
        """Test recommendations are sorted by priority"""
        roadmap = self.assistant.generate_migration_roadmap()
        
        priority_order = [
            MigrationPriority.IMMEDIATE,
            MigrationPriority.HIGH,
            MigrationPriority.MEDIUM,
            MigrationPriority.LOW,
            MigrationPriority.DEFERRED
        ]
        
        priorities = [r.priority for r in roadmap.recommendations]
        indices = [priority_order.index(p) for p in priorities]
        
        # Should be non-decreasing (higher priority first)
        assert indices == sorted(indices)
    
    def test_roadmap_has_phases(self):
        """Test roadmap contains migration phases"""
        roadmap = self.assistant.generate_migration_roadmap()
        
        assert len(roadmap.phases) > 0
        for phase in roadmap.phases:
            assert "phase" in phase
            assert "name" in phase
            assert "duration_weeks" in phase
            assert "items" in phase
            assert "objectives" in phase
            assert len(phase["objectives"]) > 0
    
    def test_export_roadmap_markdown(self):
        """Test markdown export"""
        roadmap = self.assistant.generate_migration_roadmap()
        md = self.assistant.export_roadmap_markdown(roadmap)
        
        assert isinstance(md, str)
        assert len(md) > 0
        assert "# " in md
        assert "## Executive Summary" in md
        assert "## Migration Phases" in md
        assert "## Recommendations by Priority" in md
        assert "## Compliance Guidance" in md
    
    def test_export_roadmap_json(self):
        """Test JSON export"""
        roadmap = self.assistant.generate_migration_roadmap()
        json_str = self.assistant.export_roadmap_json(roadmap)
        
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert "roadmap_id" in parsed
        assert "title" in parsed
        assert "summary" in parsed
        assert "phases" in parsed
        assert "recommendations" in parsed
        assert "compliance_notes" in parsed


class TestConvenienceFunctions:
    """Test suite for module-level convenience functions"""
    
    def test_assess_algorithm_vulnerability(self):
        """Test convenience function for vulnerability assessment"""
        result = assess_algorithm_vulnerability("RSA-2048")
        
        assert isinstance(result, dict)
        assert "algorithm" in result
        assert "quantum_vulnerable" in result
        assert "risk_level" in result
        assert "security_level_bits" in result
        assert result["quantum_vulnerable"] is True
    
    def test_create_migration_roadmap(self):
        """Test convenience function for roadmap creation"""
        inventory = [
            {
                "item_id": "TEST-001",
                "name": "Test Item",
                "algorithm": "RSA-2048",
                "use_case": "tls",
                "location": "Test",
                "owner": "Test"
            }
        ]
        
        roadmap = create_migration_roadmap(inventory, "Test Roadmap")
        
        assert isinstance(roadmap, MigrationRoadmap)
        assert roadmap.title == "Test Roadmap"
        assert roadmap.total_assets == 1


class TestEnums:
    """Test suite for enum classes"""
    
    def test_algorithm_type_values(self):
        """Test AlgorithmType enum values"""
        assert AlgorithmType.CLASSICAL.value == "classical"
        assert AlgorithmType.POST_QUANTUM.value == "post_quantum"
        assert AlgorithmType.HYBRID.value == "hybrid"
    
    def test_migration_priority_values(self):
        """Test MigrationPriority enum values"""
        assert MigrationPriority.IMMEDIATE.value == "immediate"
        assert MigrationPriority.HIGH.value == "high"
        assert MigrationPriority.MEDIUM.value == "medium"
        assert MigrationPriority.LOW.value == "low"
        assert MigrationPriority.DEFERRED.value == "deferred"
    
    def test_risk_level_values(self):
        """Test RiskLevel enum values"""
        assert RiskLevel.CRITICAL.value == "critical"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.MODERATE.value == "moderate"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.UNKNOWN.value == "unknown"
    
    def test_use_case_category_values(self):
        """Test UseCaseCategory enum values"""
        assert UseCaseCategory.TLS.value == "tls"
        assert UseCaseCategory.CODE_SIGNING.value == "code_signing"
        assert UseCaseCategory.DOCUMENT_SIGNING.value == "document_signing"
        assert UseCaseCategory.KEY_EXCHANGE.value == "key_exchange"
        assert UseCaseCategory.DATA_ENCRYPTION.value == "data_encryption"


class TestEdgeCases:
    """Test suite for edge cases"""
    
    def setup_method(self):
        self.assistant = PQCMigrationAssistant()
    
    def test_empty_inventory_roadmap(self):
        """Test roadmap generation with empty inventory"""
        roadmap = self.assistant.generate_migration_roadmap()
        assert roadmap.total_assets == 0
        assert roadmap.vulnerable_assets == 0
        assert len(roadmap.recommendations) == 0
    
    def test_all_non_vulnerable_assets(self):
        """Test roadmap with only non-vulnerable assets"""
        item = CryptoInventoryItem(
            item_id="TEST-001",
            name="Safe Item",
            algorithm="AES-256",
            algorithm_type=AlgorithmType.CLASSICAL,
            key_size=256,
            use_case=UseCaseCategory.DATA_ENCRYPTION,
            location="Prod",
            owner="Ops"
        )
        self.assistant.add_inventory_item(item)
        
        roadmap = self.assistant.generate_migration_roadmap()
        assert roadmap.vulnerable_assets == 0
        assert roadmap.recommendations[0].priority == MigrationPriority.DEFERRED
    
    def test_use_case_priority_adjustment(self):
        """Test that use case affects priority calculation"""
        # Same algorithm, different use cases
        item1 = CryptoInventoryItem(
            item_id="KEY-001",
            name="Key Exchange",
            algorithm="ECDSA-P256",
            algorithm_type=AlgorithmType.CLASSICAL,
            key_size=256,
            use_case=UseCaseCategory.KEY_EXCHANGE,
            location="Prod",
            owner="Security"
        )
        item2 = CryptoInventoryItem(
            item_id="ENC-001",
            name="Data Encryption",
            algorithm="ECDSA-P256",
            algorithm_type=AlgorithmType.CLASSICAL,
            key_size=256,
            use_case=UseCaseCategory.DATA_ENCRYPTION,
            location="Prod",
            owner="Ops"
        )
        
        p1 = self.assistant.calculate_migration_priority(item1)
        p2 = self.assistant.calculate_migration_priority(item2)
        
        # Key exchange should have higher or equal priority
        priority_order = [
            MigrationPriority.IMMEDIATE,
            MigrationPriority.HIGH,
            MigrationPriority.MEDIUM,
            MigrationPriority.LOW,
            MigrationPriority.DEFERRED
        ]
        assert priority_order.index(p1) <= priority_order.index(p2)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
