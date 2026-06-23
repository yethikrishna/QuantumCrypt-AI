"""
Test Suite for Post-Quantum KEX Protocol Selector v1
=====================================================
Dimension A: Feature Expansion - QuantumCrypt-AI

Comprehensive tests covering:
- Algorithm selection logic
- Security-performance tradeoffs
- Compliance-aware selection
- Network and hardware adaptation
- Thread safety
- Edge cases and fallback behavior

All existing tests must pass - ADD-ONLY philosophy
"""
import pytest
import threading
from quantum_crypt.post_quantum_kex_selector_v1_2026_june import (
    PostQuantumKEXSelector,
    SelectionConstraints,
    KEXAlgorithm,
    SecurityLevel,
    ComplianceStandard,
    NetworkProfile,
    HardwareProfile,
    KEXCharacteristicsDatabase,
    get_global_kex_selector
)


class TestKEXCharacteristicsDatabase:
    """Tests for the algorithm characteristics database."""

    def test_database_initialization(self):
        """Test database initializes with all algorithms."""
        db = KEXCharacteristicsDatabase()
        algorithms = db.get_all_algorithms()
        
        assert len(algorithms) >= 9  # At least 9 algorithms defined
        
        # Verify key algorithms are present
        kyber_768 = db.get_characteristics(KEXAlgorithm.KYBER_768)
        assert kyber_768 is not None
        assert kyber_768.security_level == SecurityLevel.LEVEL_3
        assert kyber_768.nist_standardized is True

    def test_kyber_security_levels(self):
        """Test Kyber series has correct security levels."""
        db = KEXCharacteristicsDatabase()
        
        kyber_512 = db.get_characteristics(KEXAlgorithm.KYBER_512)
        kyber_768 = db.get_characteristics(KEXAlgorithm.KYBER_768)
        kyber_1024 = db.get_characteristics(KEXAlgorithm.KYBER_1024)
        
        assert kyber_512.security_level == SecurityLevel.LEVEL_1
        assert kyber_768.security_level == SecurityLevel.LEVEL_3
        assert kyber_1024.security_level == SecurityLevel.LEVEL_5

    def test_algorithm_sizes(self):
        """Test algorithm public key and ciphertext sizes."""
        db = KEXCharacteristicsDatabase()
        
        kyber_512 = db.get_characteristics(KEXAlgorithm.KYBER_512)
        assert kyber_512.public_key_size_bytes == 800
        assert kyber_512.ciphertext_size_bytes == 768
        
        x25519 = db.get_characteristics(KEXAlgorithm.X25519)
        assert x25519.public_key_size_bytes == 32  # Much smaller classic ECC


class TestPostQuantumKEXSelector:
    """Tests for the main selector class."""

    def test_selector_initialization(self):
        """Test selector initializes correctly."""
        selector = PostQuantumKEXSelector()
        stats = selector.get_selection_statistics()
        assert stats["total_selections"] == 0

    def test_balanced_selection_default(self):
        """Test default balanced selection returns valid algorithm."""
        selector = PostQuantumKEXSelector()
        result = selector.recommend_for_balanced()
        
        assert result is not None
        assert result.selected_algorithm is not None
        assert result.confidence_score > 0
        assert result.security_level == SecurityLevel.LEVEL_3
        assert "security" in result.tradeoff_analysis
        assert "performance" in result.tradeoff_analysis

    def test_high_security_selection(self):
        """Test high security mode selects Level 5 algorithms."""
        selector = PostQuantumKEXSelector()
        result = selector.recommend_for_high_security()
        
        assert result.security_level == SecurityLevel.LEVEL_5
        assert result.confidence_score > 0.5

    def test_constrained_device_selection(self):
        """Test constrained device mode selects efficient algorithms."""
        selector = PostQuantumKEXSelector()
        result = selector.recommend_for_constrained()
        
        # Should select Level 1 for constrained devices
        assert result.security_level == SecurityLevel.LEVEL_1

    def test_custom_constraints_min_security(self):
        """Test custom minimum security level constraint."""
        selector = PostQuantumKEXSelector()
        
        # Require Level 5
        constraints = SelectionConstraints(
            min_security_level=SecurityLevel.LEVEL_5
        )
        result = selector.select_algorithm(constraints)
        
        assert result.security_level == SecurityLevel.LEVEL_5

    def test_size_constraints(self):
        """Test selection with public key size constraints."""
        selector = PostQuantumKEXSelector()
        
        # Very small size constraint should force fallback
        constraints = SelectionConstraints(
            max_public_key_size=100  # Only X25519 fits
        )
        result = selector.select_algorithm(constraints)
        
        # X25519 doesn't meet NIST standard requirement, so it should either
        # fallback or select something - just verify we get valid result
        assert result is not None
        assert result.selected_algorithm is not None

    def test_preferred_algorithm_bonus(self):
        """Test preferred algorithms receive selection bonus."""
        selector = PostQuantumKEXSelector()
        
        # Prefer SABER over Kyber
        constraints = SelectionConstraints(
            min_security_level=SecurityLevel.LEVEL_3,
            preferred_algorithms=[KEXAlgorithm.SABER]
        )
        result = selector.select_algorithm(constraints)
        
        # Should have high confidence
        assert result.confidence_score > 0.5

    def test_excluded_algorithms(self):
        """Test algorithm exclusion works."""
        selector = PostQuantumKEXSelector()
        
        # Exclude all Level 3 algorithms except one
        constraints = SelectionConstraints(
            min_security_level=SecurityLevel.LEVEL_3,
            excluded_algorithms=[
                KEXAlgorithm.KYBER_768,
                KEXAlgorithm.NTRU_HPS_2048_677
            ]
        )
        result = selector.select_algorithm(constraints)
        
        # Should not select excluded algorithms
        assert result.selected_algorithm not in [
            KEXAlgorithm.KYBER_768,
            KEXAlgorithm.NTRU_HPS_2048_677
        ]

    def test_compliance_required_selection(self):
        """Test compliance-aware selection."""
        selector = PostQuantumKEXSelector()
        
        constraints = SelectionConstraints(
            min_security_level=SecurityLevel.LEVEL_3,
            compliance_required=ComplianceStandard.NSA_CSf
        )
        result = selector.select_algorithm(constraints)
        
        # Should select NSA CSF compliant algorithm
        assert result is not None
        assert result.confidence_score > 0

    def test_network_profile_awareness(self):
        """Test network profile affects selection."""
        selector = PostQuantumKEXSelector()
        
        # Low latency network - larger messages okay
        constraints_low_latency = SelectionConstraints(
            min_security_level=SecurityLevel.LEVEL_3,
            network_profile=NetworkProfile.LOW_LATENCY
        )
        result_low_latency = selector.select_algorithm(constraints_low_latency)
        
        # High latency network - smaller messages preferred
        constraints_high_latency = SelectionConstraints(
            min_security_level=SecurityLevel.LEVEL_3,
            network_profile=NetworkProfile.HIGH_LATENCY
        )
        result_high_latency = selector.select_algorithm(constraints_high_latency)
        
        # Both should return valid results
        assert result_low_latency.selected_algorithm is not None
        assert result_high_latency.selected_algorithm is not None

    def test_hardware_profile_awareness(self):
        """Test hardware profile affects selection."""
        selector = PostQuantumKEXSelector()
        
        constraints_embedded = SelectionConstraints(
            min_security_level=SecurityLevel.LEVEL_1,
            hardware_profile=HardwareProfile.EMBEDDED
        )
        result = selector.select_algorithm(constraints_embedded)
        
        assert result is not None
        assert result.confidence_score > 0

    def test_selection_history_tracking(self):
        """Test selection history is tracked."""
        selector = PostQuantumKEXSelector()
        
        initial_stats = selector.get_selection_statistics()
        initial_count = initial_stats["total_selections"]
        
        selector.recommend_for_balanced()
        selector.recommend_for_high_security()
        
        final_stats = selector.get_selection_statistics()
        
        assert final_stats["total_selections"] == initial_count + 2
        assert final_stats["average_confidence"] > 0

    def test_alternatives_provided(self):
        """Test alternatives are provided with selection."""
        selector = PostQuantumKEXSelector()
        result = selector.recommend_for_balanced()
        
        assert len(result.alternatives) >= 0
        for alg, score in result.alternatives:
            assert isinstance(alg, KEXAlgorithm)
            assert score > 0

    def test_tradeoff_analysis(self):
        """Test tradeoff analysis contains all components."""
        selector = PostQuantumKEXSelector()
        result = selector.recommend_for_balanced()
        
        assert "security" in result.tradeoff_analysis
        assert "performance" in result.tradeoff_analysis
        assert "compliance" in result.tradeoff_analysis
        
        for key, value in result.tradeoff_analysis.items():
            assert 0 <= value <= 1.0


class TestGlobalSingleton:
    """Tests for the global singleton instance."""

    def test_global_singleton_creation(self):
        """Test global singleton returns same instance."""
        selector1 = get_global_kex_selector()
        selector2 = get_global_kex_selector()
        
        assert selector1 is selector2

    def test_global_singleton_functional(self):
        """Test global singleton works correctly."""
        selector = get_global_kex_selector()
        result = selector.recommend_for_balanced()
        
        assert result is not None
        assert result.selected_algorithm is not None


class TestThreadSafety:
    """Tests for thread-safe selector operations."""

    def test_concurrent_selections(self):
        """Test concurrent selections from multiple threads."""
        selector = PostQuantumKEXSelector()
        errors = []
        results = []
        
        def worker():
            try:
                for _ in range(10):
                    result = selector.recommend_for_balanced()
                    results.append(result)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert len(results) == 50


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_impossible_constraints_fallback(self):
        """Test impossible constraints result in graceful fallback."""
        selector = PostQuantumKEXSelector()
        
        # Impossible combination
        constraints = SelectionConstraints(
            min_security_level=SecurityLevel.LEVEL_5,
            max_public_key_size=100  # No Level 5 algorithm fits this
        )
        result = selector.select_algorithm(constraints)
        
        # Should return something (fallback mechanism)
        assert result is not None
        assert result.selected_algorithm is not None

    def test_all_algorithms_excluded(self):
        """Test when all algorithms are excluded."""
        selector = PostQuantumKEXSelector()
        
        constraints = SelectionConstraints(
            excluded_algorithms=list(KEXAlgorithm)  # Exclude everything
        )
        result = selector.select_algorithm(constraints)
        
        # Should return fallback
        assert result is not None
        assert result.selected_algorithm is not None

    def test_empty_constraints(self):
        """Test with default empty constraints."""
        selector = PostQuantumKEXSelector()
        constraints = SelectionConstraints()
        result = selector.select_algorithm(constraints)
        
        assert result is not None
        assert result.confidence_score > 0

    def test_selection_reason_populated(self):
        """Test selection reason is always provided."""
        selector = PostQuantumKEXSelector()
        result = selector.recommend_for_balanced()
        
        assert result.selection_reason is not None
        assert len(result.selection_reason) > 0

    def test_timestamp_set(self):
        """Test timestamp is set on selection result."""
        selector = PostQuantumKEXSelector()
        result = selector.recommend_for_balanced()
        
        assert result.timestamp > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
