"""
Comprehensive Tests for Policy Engine

Complete test suite for the configurable policy engine including policy management,
evaluation, application, and integration testing.
"""

import pytest
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import uuid

from src.core.services.policy_engine import (
    PolicyEngine, get_policy_engine, PolicyEngineError, PolicyConflictError
)
from src.core.config.policy_manager import PolicyManager, get_policy_manager
from src.core.services.policy_applicator import PolicyApplicator, get_policy_applicator
from src.core.config.policy_models import (
    PolicyContext, PolicyDecision, PolicyConfiguration, PolicyTemplate,
    PolicyScope, PolicyPriority, PolicyStatus, PolicyDecisionType
)
from src.core.config.policies.base import BasePolicy, PolicyRule, PIIType, RedactionMethod
from src.core.config.policies.gdpr import GDPRPolicy
from src.core.config.policies.hipaa import HIPAAPolicy
from src.core.models.ner_models import PIIEntity, EntityConfidence
from src.core.models.visual_models import VisualPIIEntity, VisualPIIType, BoundingBox


class TestPolicyEngine:
    """Test suite for the PolicyEngine class."""
    
    @pytest.fixture
    def policy_engine(self):
        """Create a PolicyEngine instance for testing."""
        return PolicyEngine()
    
    @pytest.fixture
    def mock_text_entities(self):
        """Mock text PII entities for testing."""
        return [
            PIIEntity(
                text="john.doe@email.com",
                entity_type="EMAIL_ADDRESS",
                start_position=10,
                end_position=27,
                confidence=0.95,
                confidence_level=EntityConfidence.VERY_HIGH
            ),
            PIIEntity(
                text="123-45-6789",
                entity_type="US_SSN",
                start_position=50,
                end_position=61,
                confidence=0.92,
                confidence_level=EntityConfidence.VERY_HIGH
            )
        ]
    
    @pytest.fixture
    def mock_visual_entities(self):
        """Mock visual PII entities for testing."""
        return [
            VisualPIIEntity(
                entity_type=VisualPIIType.FACE,
                bounding_box=BoundingBox(x1=10, y1=10, x2=50, y2=50),
                confidence=0.88
            )
        ]
    
    @pytest.fixture
    def sample_context(self):
        """Create a sample policy context."""
        return PolicyContext(
            document_id="test_doc_123",
            user_id="user_456",
            document_type="pdf",
            compliance_standards=["gdpr", "hipaa"]
        )
    
    def test_policy_engine_initialization(self, policy_engine):
        """Test policy engine initialization."""
        assert policy_engine is not None
        assert hasattr(policy_engine, 'policies')
        assert hasattr(policy_engine, 'policy_configurations')
        assert len(policy_engine.policies) >= 3  # GDPR, HIPAA, NDHM
    
    def test_policy_registration(self, policy_engine):
        """Test policy registration functionality."""
        
        # Create a test policy
        test_policy = GDPRPolicy()
        
        # Register policy
        success = policy_engine.register_policy("test_gdpr", test_policy)
        assert success
        assert "test_gdpr" in policy_engine.policies
        assert "test_gdpr" in policy_engine.policy_configurations
    
    def test_policy_unregistration(self, policy_engine):
        """Test policy unregistration functionality."""
        
        # Register and then unregister a policy
        test_policy = GDPRPolicy()
        policy_engine.register_policy("test_remove", test_policy)
        
        success = policy_engine.unregister_policy("test_remove")
        assert success
        assert "test_remove" not in policy_engine.policies
    
    @pytest.mark.asyncio
    async def test_entity_evaluation_async(self, policy_engine, mock_text_entities, sample_context):
        """Test asynchronous entity evaluation."""
        
        result = await policy_engine.evaluate_entities_async(
            entities=mock_text_entities,
            context=sample_context
        )
        
        assert result.success
        assert len(result.decisions) > 0
        assert result.execution_time_ms > 0
        assert result.request_id is not None
    
    def test_entity_evaluation_sync(self, policy_engine, mock_text_entities, sample_context):
        """Test synchronous entity evaluation."""
        
        result = policy_engine.evaluate_entities_sync(
            entities=mock_text_entities,
            context=sample_context
        )
        
        assert result.success
        assert len(result.decisions) > 0
        assert result.execution_time_ms > 0
    
    def test_policy_conflict_resolution(self, policy_engine):
        """Test policy conflict resolution."""
        
        # Create conflicting decisions
        decision1 = PolicyDecision(
            decision_type=PolicyDecisionType.ALLOW,
            pii_type=PIIType.EMAIL,
            entity_text="test@email.com",
            applied_policy="policy1",
            policy_priority=PolicyPriority.LOW
        )
        
        decision2 = PolicyDecision(
            decision_type=PolicyDecisionType.REDACT,
            pii_type=PIIType.EMAIL,
            entity_text="test@email.com",
            applied_policy="policy2",
            policy_priority=PolicyPriority.HIGH
        )
        
        context = PolicyContext()
        decisions = [decision1, decision2]
        
        resolved = policy_engine._resolve_policy_conflicts(decisions, context)
        
        assert len(resolved) == 1
        assert resolved[0].decision_type == PolicyDecisionType.REDACT  # Higher priority wins
        assert resolved[0].policy_priority == PolicyPriority.HIGH
    
    def test_decision_caching(self, policy_engine, mock_text_entities, sample_context):
        """Test decision caching functionality."""
        
        # First evaluation
        result1 = policy_engine.evaluate_entities_sync(mock_text_entities, sample_context)
        
        # Second evaluation (should use cache)
        result2 = policy_engine.evaluate_entities_sync(mock_text_entities, sample_context)
        
        assert result1.success
        assert result2.success
        # Cache should have some entries
        assert len(policy_engine.decision_cache) > 0
    
    def test_policy_statistics(self, policy_engine):
        """Test policy engine statistics."""
        
        stats = policy_engine.get_policy_statistics()
        
        assert "registered_policies" in stats
        assert "total_evaluations" in stats
        assert "cache_size" in stats
        assert "engine_status" in stats
        assert stats["engine_status"] == "active"


class TestPolicyManager:
    """Test suite for the PolicyManager class."""
    
    @pytest.fixture
    def policy_manager(self):
        """Create a PolicyManager instance for testing."""
        # Use a temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            yield PolicyManager(storage_path=temp_dir)
    
    @pytest.fixture
    def sample_policy_config(self):
        """Create a sample policy configuration."""
        return {
            "name": "Test Policy",
            "description": "A test policy for unit testing",
            "policy_type": "test",
            "configuration": {
                "test_setting": "value"
            }
        }
    
    def test_policy_manager_initialization(self, policy_manager):
        """Test policy manager initialization."""
        assert policy_manager is not None
        assert hasattr(policy_manager, 'policies')
        assert hasattr(policy_manager, 'templates')
        assert len(policy_manager.templates) >= 3  # Default templates
    
    def test_create_policy(self, policy_manager, sample_policy_config):
        """Test policy creation."""
        
        policy = policy_manager.create_policy(**sample_policy_config, created_by="test_user")
        
        assert policy is not None
        assert policy.name == sample_policy_config["name"]
        assert policy.policy_type == sample_policy_config["policy_type"]
        assert policy.created_by == "test_user"
        assert policy.policy_id in policy_manager.policies
    
    def test_get_policy(self, policy_manager, sample_policy_config):
        """Test policy retrieval."""
        
        # Create policy
        created_policy = policy_manager.create_policy(**sample_policy_config)
        
        # Retrieve policy
        retrieved_policy = policy_manager.get_policy(created_policy.policy_id)
        
        assert retrieved_policy is not None
        assert retrieved_policy.policy_id == created_policy.policy_id
        assert retrieved_policy.name == created_policy.name
    
    def test_update_policy(self, policy_manager, sample_policy_config):
        """Test policy updates."""
        
        # Create policy
        policy = policy_manager.create_policy(**sample_policy_config)
        
        # Update policy
        updates = {
            "description": "Updated description",
            "priority": PolicyPriority.HIGH
        }
        
        updated_policy = policy_manager.update_policy(
            policy.policy_id, 
            updates, 
            updated_by="test_user"
        )
        
        assert updated_policy.description == "Updated description"
        assert updated_policy.priority == PolicyPriority.HIGH
        assert updated_policy.updated_by == "test_user"
    
    def test_delete_policy(self, policy_manager, sample_policy_config):
        """Test policy deletion (soft delete)."""
        
        # Create policy
        policy = policy_manager.create_policy(**sample_policy_config)
        
        # Delete policy
        success = policy_manager.delete_policy(policy.policy_id, deleted_by="test_user")
        
        assert success
        
        # Policy should still exist but be inactive
        deleted_policy = policy_manager.get_policy(policy.policy_id)
        assert deleted_policy.status == PolicyStatus.INACTIVE
    
    def test_policy_validation(self, policy_manager):
        """Test policy validation."""
        
        # Valid policy
        valid_config = PolicyConfiguration(
            name="Valid Policy",
            policy_type="test",
            description="A valid policy"
        )
        
        errors = policy_manager.validate_policy(valid_config)
        assert len(errors) == 0
        
        # Invalid policy (empty name)
        invalid_config = PolicyConfiguration(
            name="",
            policy_type="test",
            description="Invalid policy"
        )
        
        errors = policy_manager.validate_policy(invalid_config)
        assert len(errors) > 0
    
    def test_policy_export_import(self, policy_manager, sample_policy_config):
        """Test policy export and import functionality."""
        
        # Create policy
        original_policy = policy_manager.create_policy(**sample_policy_config)
        
        # Export policy
        exported_data = policy_manager.export_policy(original_policy.policy_id, format="json")
        assert exported_data is not None
        assert "name" in exported_data
        
        # Import policy
        imported_policy = policy_manager.import_policy(
            exported_data, 
            format="json", 
            imported_by="test_user"
        )
        
        assert imported_policy.name == original_policy.name
        assert imported_policy.policy_type == original_policy.policy_type
        assert imported_policy.policy_id != original_policy.policy_id  # Should have new ID
    
    def test_policy_templates(self, policy_manager):
        """Test policy template functionality."""
        
        templates = policy_manager.get_templates()
        assert len(templates) > 0
        
        # Test creating policy from template
        gdpr_template = None
        for template in templates:
            if template.base_policy_type == "gdpr":
                gdpr_template = template
                break
        
        assert gdpr_template is not None
        
        policy = gdpr_template.create_policy(
            name="GDPR Policy from Template",
            configuration={"retention_period_days": 1095}
        )
        
        assert policy.name == "GDPR Policy from Template"
        assert policy.policy_type == "gdpr"


class TestPolicyApplicator:
    """Test suite for the PolicyApplicator class."""
    
    @pytest.fixture
    def policy_applicator(self):
        """Create a PolicyApplicator instance for testing."""
        return PolicyApplicator()
    
    @pytest.fixture
    def sample_decisions(self):
        """Create sample policy decisions."""
        return [
            PolicyDecision(
                decision_type=PolicyDecisionType.REDACT,
                pii_type=PIIType.EMAIL,
                entity_text="john.doe@email.com",
                applied_policy="gdpr",
                redaction_method=RedactionMethod.BLACKOUT,
                entity_position={"start_position": 10, "end_position": 27}
            ),
            PolicyDecision(
                decision_type=PolicyDecisionType.PSEUDONYMIZE,
                pii_type=PIIType.NAME,
                entity_text="John Doe",
                applied_policy="gdpr",
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                entity_position={"start_position": 0, "end_position": 8}
            )
        ]
    
    def test_policy_applicator_initialization(self, policy_applicator):
        """Test policy applicator initialization."""
        assert policy_applicator is not None
        assert hasattr(policy_applicator, 'visual_redactor')
        assert hasattr(policy_applicator, 'pseudonym_cache')
        assert hasattr(policy_applicator, 'generalization_rules')
    
    @pytest.mark.asyncio
    async def test_text_decisions_application(self, policy_applicator, sample_decisions):
        """Test applying decisions to text content."""
        
        text_content = "John Doe works at john.doe@email.com"
        
        result = await policy_applicator.apply_decisions_async(
            decisions=sample_decisions,
            text_content=text_content
        )
        
        assert result.success
        assert result.text_result is not None
        assert result.text_result.success
        assert result.text_result.entities_processed > 0
        assert result.text_result.redacted_text != text_content  # Text should be changed
    
    def test_text_decisions_application_sync(self, policy_applicator, sample_decisions):
        """Test synchronous text decision application."""
        
        text_content = "John Doe works at john.doe@email.com"
        
        result = policy_applicator.apply_decisions_sync(
            decisions=sample_decisions,
            text_content=text_content
        )
        
        assert result.success
        assert result.text_result is not None
        assert result.text_result.success
    
    def test_pseudonym_generation(self, policy_applicator):
        """Test pseudonym generation functionality."""
        
        # Test name pseudonymization
        name_pseudonym = policy_applicator._generate_pseudonym("John Doe", PIIType.NAME)
        assert name_pseudonym != "John Doe"
        assert isinstance(name_pseudonym, str)
        
        # Test email pseudonymization
        email_pseudonym = policy_applicator._generate_pseudonym("test@email.com", PIIType.EMAIL)
        assert email_pseudonym != "test@email.com"
        assert "@" in email_pseudonym
        
        # Test consistency - same input should give same pseudonym
        name_pseudonym2 = policy_applicator._generate_pseudonym("John Doe", PIIType.NAME)
        assert name_pseudonym == name_pseudonym2
    
    def test_generalization_rules(self, policy_applicator):
        """Test generalization rules for different PII types."""
        
        # Test age generalization
        age_generalized = policy_applicator._generalize_age("25")
        assert age_generalized in ["Under 18", "18-29", "30-49", "50-64", "65+"]
        
        # Test date generalization
        date_generalized = policy_applicator._generalize_date("1990-05-15")
        assert "1990" in date_generalized
        
        # Test phone generalization
        phone_generalized = policy_applicator._generalize_phone("(555) 123-4567")
        assert "(555)" in phone_generalized
        assert "XXX-XXXX" in phone_generalized
    
    def test_application_methods(self, policy_applicator, sample_decisions):
        """Test different application methods."""
        
        from src.core.services.policy_applicator import ApplicationMethod
        
        text_content = "John Doe works at john.doe@email.com"
        
        # Test preview mode
        preview_result = policy_applicator.apply_decisions_sync(
            decisions=sample_decisions,
            text_content=text_content,
            method=ApplicationMethod.PREVIEW
        )
        
        assert preview_result.success
        # In preview mode, text should show what would be changed
        assert "[REDACT:" in preview_result.text_result.redacted_text or "[PSEUDONYMIZE:" in preview_result.text_result.redacted_text


class TestPolicyEngineIntegration:
    """Integration tests for the complete policy engine system."""
    
    @pytest.fixture
    def full_system(self):
        """Set up the complete policy system."""
        policy_engine = PolicyEngine()
        policy_manager = PolicyManager()
        policy_applicator = PolicyApplicator()
        
        return {
            "engine": policy_engine,
            "manager": policy_manager,
            "applicator": policy_applicator
        }
    
    @pytest.mark.asyncio
    async def test_end_to_end_policy_flow(self, full_system):
        """Test complete end-to-end policy flow."""
        
        engine = full_system["engine"]
        manager = full_system["manager"]
        applicator = full_system["applicator"]
        
        # 1. Create a custom policy
        policy_config = manager.create_policy(
            name="Test Integration Policy",
            policy_type="custom",
            description="Policy for integration testing",
            created_by="test_system"
        )
        
        # 2. Create test entities
        entities = [
            PIIEntity(
                text="test@example.com",
                entity_type="EMAIL_ADDRESS",
                start_position=0,
                end_position=16,
                confidence=0.95,
                confidence_level=EntityConfidence.VERY_HIGH
            )
        ]
        
        # 3. Create context
        context = PolicyContext(
            document_id="integration_test_doc",
            user_id="test_user",
            document_type="email"
        )
        
        # 4. Evaluate entities
        evaluation_result = await engine.evaluate_entities_async(
            entities=entities,
            context=context,
            policy_names=[policy_config.name]
        )
        
        # 5. Apply decisions
        if evaluation_result.success and evaluation_result.decisions:
            application_result = await applicator.apply_decisions_async(
                decisions=evaluation_result.decisions,
                text_content="Contact me at test@example.com",
                context=context
            )
            
            assert application_result.success
        
        # 6. Clean up
        manager.delete_policy(policy_config.policy_id)
    
    def test_policy_conflict_scenarios(self, full_system):
        """Test various policy conflict scenarios."""
        
        engine = full_system["engine"]
        
        # Create conflicting decisions
        decisions = [
            PolicyDecision(
                decision_type=PolicyDecisionType.ALLOW,
                pii_type=PIIType.EMAIL,
                entity_text="test@email.com",
                applied_policy="policy_allow",
                policy_priority=PolicyPriority.LOW
            ),
            PolicyDecision(
                decision_type=PolicyDecisionType.REDACT,
                pii_type=PIIType.EMAIL,
                entity_text="test@email.com",
                applied_policy="policy_redact",
                policy_priority=PolicyPriority.HIGH
            ),
            PolicyDecision(
                decision_type=PolicyDecisionType.DENY,
                pii_type=PIIType.EMAIL,
                entity_text="test@email.com",
                applied_policy="policy_deny",
                policy_priority=PolicyPriority.CRITICAL
            )
        ]
        
        context = PolicyContext()
        resolved = engine._resolve_policy_conflicts(decisions, context)
        
        # Highest priority (DENY) should win
        assert len(resolved) == 1
        assert resolved[0].decision_type == PolicyDecisionType.DENY
        assert resolved[0].policy_priority == PolicyPriority.CRITICAL
    
    def test_performance_under_load(self, full_system):
        """Test system performance under load."""
        
        engine = full_system["engine"]
        
        # Create a large number of entities
        entities = []
        for i in range(100):
            entity = PIIEntity(
                text=f"email{i}@test.com",
                entity_type="EMAIL_ADDRESS",
                start_position=i * 20,
                end_position=(i * 20) + 15,
                confidence=0.9,
                confidence_level=EntityConfidence.HIGH
            )
            entities.append(entity)
        
        context = PolicyContext(document_id="load_test")
        
        start_time = datetime.now()
        result = engine.evaluate_entities_sync(entities, context)
        end_time = datetime.now()
        
        processing_time = (end_time - start_time).total_seconds()
        
        assert result.success
        assert len(result.decisions) == len(entities)
        assert processing_time < 5.0  # Should complete within 5 seconds
    
    def test_error_handling_and_recovery(self, full_system):
        """Test error handling and recovery mechanisms."""
        
        engine = full_system["engine"]
        
        # Test with invalid entity
        invalid_entities = [
            Mock(entity_type="INVALID_TYPE", text="invalid", confidence=0.5)
        ]
        
        context = PolicyContext()
        
        # Should handle errors gracefully
        result = engine.evaluate_entities_sync(invalid_entities, context)
        
        # May not be successful, but shouldn't crash
        assert result is not None
        assert hasattr(result, 'success')
    
    def test_cache_performance(self, full_system):
        """Test caching performance improvements."""
        
        engine = full_system["engine"]
        
        entities = [
            PIIEntity(
                text="cached@email.com",
                entity_type="EMAIL_ADDRESS",
                start_position=0,
                end_position=16,
                confidence=0.95,
                confidence_level=EntityConfidence.VERY_HIGH
            )
        ]
        
        context = PolicyContext(document_id="cache_test")
        
        # First evaluation (cache miss)
        start_time = datetime.now()
        result1 = engine.evaluate_entities_sync(entities, context)
        time1 = (datetime.now() - start_time).total_seconds()
        
        # Second evaluation (cache hit)
        start_time = datetime.now()
        result2 = engine.evaluate_entities_sync(entities, context)
        time2 = (datetime.now() - start_time).total_seconds()
        
        assert result1.success
        assert result2.success
        # Second evaluation should be faster (cached)
        assert time2 <= time1


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])