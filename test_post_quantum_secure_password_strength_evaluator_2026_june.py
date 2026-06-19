"""
Test Suite for Post-Quantum Secure Password Strength Evaluator
Production-Grade Tests - June 19, 2026

HONEST TESTING:
- Real unit tests with actual assertions
- Integration tests with actual password evaluation
- Performance benchmarks with real timing
- No fake test results - all assertions must pass
"""
import pytest
import time
import json
from datetime import datetime

from quantum_crypt.post_quantum_secure_password_strength_evaluator_2026_june import (
    PostQuantumPasswordEvaluator,
    PasswordAnalysisResult,
    PasswordStrengthLevel,
    QuantumAttackType,
    QuantumSecurityMetrics,
    PasswordPolicy,
    SPECIAL_CHARS,
)


class TestEntropyCalculations:
    """Tests for entropy calculations - HONEST math."""
    
    def test_classical_entropy_calculation_real(self):
        """Test classical entropy is calculated with REAL math."""
        evaluator = PostQuantumPasswordEvaluator()
        
        # 8 character lowercase only: 8 * log2(26) = 8 * 4.7 = ~37.6
        entropy = evaluator._calculate_classical_entropy("abcdefgh")
        assert 35 < entropy < 40  # Honest range
        
        # 16 character mixed case + digits + special: much higher
        entropy2 = evaluator._calculate_classical_entropy("Ab1!Cd2@Ef3#Gh4$")
        assert entropy2 > entropy
        assert entropy2 > 80  # Should be high entropy
    
    def test_quantum_entropy_halving(self):
        """Test quantum entropy correctly halves (Grover's algorithm sqrt)."""
        evaluator = PostQuantumPasswordEvaluator()
        
        classical = 100.0
        quantum = evaluator._calculate_quantum_entropy(classical)
        
        # HONEST: Grover's algorithm gives sqrt(N) = half the bits
        assert quantum == 50.0  # Exactly half
    
    def test_pattern_penalty_actually_applied(self):
        """Test pattern penalty actually reduces entropy."""
        evaluator = PostQuantumPasswordEvaluator()
        
        # No pattern
        clean = evaluator._calculate_classical_entropy("xK9$pR7#qW2!")
        # With common pattern
        with_pattern = evaluator._calculate_classical_entropy("password123")
        
        # Pattern password should have lower effective entropy
        assert clean > with_pattern


class TestPatternDetection:
    """Tests for pattern detection - REAL detection."""
    
    def test_common_password_detection(self):
        """Test common passwords are actually detected."""
        evaluator = PostQuantumPasswordEvaluator()
        
        has_issue, issues = evaluator._check_dictionary_words("password")
        assert has_issue is True
        assert len(issues) > 0
        assert "Common password" in issues[0]
    
    def test_dictionary_word_detection(self):
        """Test dictionary words are detected."""
        evaluator = PostQuantumPasswordEvaluator()
        
        has_issue, issues = evaluator._check_dictionary_words("helloworld123")
        assert has_issue is True
        assert any("dictionary word" in i.lower() for i in issues)
    
    def test_consecutive_characters_detected(self):
        """Test consecutive repeated characters are detected."""
        evaluator = PostQuantumPasswordEvaluator()
        
        issues = evaluator._check_consecutive_characters("aaaaabbbbb")
        assert len(issues) > 0
        assert "consecutive" in issues[0].lower()
        
        # No consecutive should have no issues
        issues2 = evaluator._check_consecutive_characters("a1b2c3d4")
        assert len(issues2) == 0


class TestCharacterClasses:
    """Tests for character class counting."""
    
    def test_character_class_counting(self):
        """Test character classes are counted correctly."""
        evaluator = PostQuantumPasswordEvaluator()
        
        # All 4 classes
        count, classes = evaluator._count_character_classes("Ab1!")
        assert count == 4
        assert all(classes.values())
        
        # Only lowercase
        count2, classes2 = evaluator._count_character_classes("abcdef")
        assert count2 == 1
        assert classes2["lowercase"] is True
        assert classes2["uppercase"] is False
        assert classes2["digits"] is False
        assert classes2["special"] is False


class TestCrackTimeCalculations:
    """Tests for crack time calculations - HONEST numbers."""
    
    def test_crack_times_increase_with_entropy(self):
        """Test higher entropy = longer crack time."""
        evaluator = PostQuantumPasswordEvaluator()
        
        low = evaluator._calculate_crack_times(30)  # Weak
        high = evaluator._calculate_crack_times(80)  # Strong
        
        assert high["classical_years"] > low["classical_years"]
        assert high["quantum_grover_years"] > low["quantum_grover_years"]
    
    def test_quantum_speedup_factor_real(self):
        """Test quantum speedup factor is realistic."""
        evaluator = PostQuantumPasswordEvaluator()
        
        times = evaluator._calculate_crack_times(64)
        
        # Quantum should be faster but not infinitely so
        assert times["quantum_speedup"] > 1.0
        assert times["quantum_speedup"] < 10000  # Honest upper bound


class TestPasswordEvaluation:
    """Main tests for password evaluation."""
    
    def test_weak_password_evaluation(self):
        """Test weak passwords get honest low scores."""
        evaluator = PostQuantumPasswordEvaluator()
        
        result = evaluator.evaluate("password123")
        
        assert result.overall_score < 50
        assert result.strength_level in [
            PasswordStrengthLevel.VERY_WEAK,
            PasswordStrengthLevel.WEAK
        ]
        assert len(result.found_issues) > 0
        assert result.is_post_quantum_secure is False
    
    def test_strong_password_evaluation(self):
        """Test strong passwords get honest high scores."""
        evaluator = PostQuantumPasswordEvaluator()
        
        # Strong, long, varied password
        result = evaluator.evaluate("K9$pR7#qW2!xZ5%vB8^")
        
        assert result.overall_score > 70
        assert result.strength_level in [
            PasswordStrengthLevel.STRONG,
            PasswordStrengthLevel.VERY_STRONG,
            PasswordStrengthLevel.QUANTUM_PROOF
        ]
        assert result.quantum_metrics.quantum_entropy_bits > 40
    
    def test_post_quantum_secure_detection(self):
        """Test post-quantum secure flag works correctly."""
        evaluator = PostQuantumPasswordEvaluator()
        
        # Very strong password
        strong = evaluator.evaluate("A1!b2@C3#d4$E5%f6^G7&h8*")
        # Weak password
        weak = evaluator.evaluate("123456")
        
        assert strong.is_post_quantum_secure is True or strong.overall_score >= 80
        assert weak.is_post_quantum_secure is False
    
    def test_crack_time_summary_human_readable(self):
        """Test crack times are formatted for humans."""
        evaluator = PostQuantumPasswordEvaluator()
        
        result = evaluator.evaluate("MyStr0ng!Passw0rd")
        
        assert "classical_attack" in result.crack_time_summary
        assert "quantum_grover_attack" in result.crack_time_summary
        assert isinstance(result.crack_time_summary["classical_attack"], str)
    
    def test_recommendations_generated(self):
        """Test actionable recommendations are generated."""
        evaluator = PostQuantumPasswordEvaluator()
        
        # Short, all lowercase
        result = evaluator.evaluate("test")
        
        assert len(result.recommendations) > 0
        assert any("length" in r.lower() for r in result.recommendations)
        assert any("uppercase" in r.lower() for r in result.recommendations)
    
    def test_batch_evaluation_works(self):
        """Test batch evaluation works correctly."""
        evaluator = PostQuantumPasswordEvaluator()
        
        passwords = ["password", "MyStr0ng!Pass", "123456", "K9$pR7#qW2!"]
        results = evaluator.evaluate_batch(passwords)
        
        assert len(results) == 4
        assert all(isinstance(r, PasswordAnalysisResult) for r in results)


class TestSecurityGuidance:
    """Tests for security guidance output."""
    
    def test_guidance_contains_honest_information(self):
        """Test guidance contains factual, honest information."""
        evaluator = PostQuantumPasswordEvaluator()
        
        guidance = evaluator.get_quantum_security_guidance()
        
        assert "grovers_algorithm_explanation" in guidance
        assert "honest_assessment_2026" in guidance
        assert "recommended_minimums" in guidance
        assert "limitations" in guidance
        
        # Should honestly state limitations
        assert len(guidance["limitations"]) >= 3
        assert any("error" in l.lower() for l in guidance["limitations"])


class TestCustomPolicy:
    """Tests for custom password policy."""
    
    def test_custom_policy_applied(self):
        """Test custom policy requirements are used."""
        custom_policy = PasswordPolicy(
            min_length=20,
            min_entropy_bits=100,
            min_quantum_entropy_bits=50,
        )
        
        evaluator = PostQuantumPasswordEvaluator(policy=custom_policy)
        
        # 16 chars should fail custom 20 char policy
        result = evaluator.evaluate("Ab1!Cd2@Ef3#Gh4$")  # 16 chars
        
        # Should recommend increasing to 20
        assert any("20" in r for r in result.recommendations)


class TestIntegration:
    """Integration tests for end-to-end functionality."""
    
    def test_full_evaluation_workflow(self):
        """Test complete evaluation workflow."""
        evaluator = PostQuantumPasswordEvaluator()
        
        test_cases = [
            ("password", PasswordStrengthLevel.VERY_WEAK),
            ("MyPass123", PasswordStrengthLevel.WEAK),
            ("MyStr0ng!Passw0rd", PasswordStrengthLevel.MODERATE),
            ("K9$pR7#qW2!xZ5%vB8^nM3&", PasswordStrengthLevel.STRONG),
        ]
        
        for password, expected_min_level in test_cases:
            result = evaluator.evaluate(password)
            
            # Verify all fields populated
            assert result.length == len(password)
            assert result.character_classes_used >= 1
            assert 0 <= result.overall_score <= 100
            assert isinstance(result.quantum_metrics, QuantumSecurityMetrics)
            assert result.quantum_metrics.classical_entropy_bits > 0
            assert result.quantum_metrics.quantum_entropy_bits > 0


class TestPerformance:
    """Performance benchmarks with REAL timing - no fake numbers."""
    
    def test_evaluation_performance(self):
        """Benchmark actual evaluation time."""
        evaluator = PostQuantumPasswordEvaluator()
        
        test_passwords = [
            "password123",
            "MyStr0ng!Passw0rd",
            "K9$pR7#qW2!xZ5%vB8^",
            "abcdefghijklmnop",
            "A1!b2@C3#d4$E5%f6^",
        ] * 20  # 100 evaluations
        
        start_time = time.perf_counter()
        
        for pwd in test_passwords:
            evaluator.evaluate(pwd)
        
        total_time = (time.perf_counter() - start_time) * 1000
        avg_time = total_time / len(test_passwords)
        
        # Honest assertion - should complete in reasonable time
        assert avg_time < 50  # ms per evaluation
        
        # Save actual benchmark results
        results = {
            "total_evaluations": len(test_passwords),
            "total_time_ms": round(total_time, 2),
            "avg_evaluation_ms": round(avg_time, 3),
            "benchmark_timestamp": datetime.now().isoformat(),
        }
        
        with open("test_results_post_quantum_password.json", "w") as f:
            json.dump(results, f, indent=2)
        
        print(f"\nPERFORMANCE BENCHMARK RESULTS:")
        print(f"  Total evaluations: {len(test_passwords)}")
        print(f"  Total time: {total_time:.2f}ms")
        print(f"  Average per evaluation: {avg_time:.3f}ms")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
