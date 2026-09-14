import os
from datetime import datetime
from unittest.mock import patch, MagicMock
from capss.agent.capss_agent import CAPSSAgent
from capss.schemas.context import RegistrationContext
from capss.schemas.policy import PrivacyPolicy

def run_emergency_scenario(agent):
    """Simulate emergency registration requiring anonymous authentication."""
    ctx = RegistrationContext(
        ue_id="UE-EM-1",
        suci="suci-em-1",
        registration_type="emergency",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime.utcnow()
    )
    policy = agent.process_registration(ctx)
    print(f"Emergency Scenario Policy ID: {policy.policy_id}")
    print(f"Selected Scheme: {getattr(policy, 'applied_scheme', getattr(policy, 'selected_scheme', ''))}")
    assert policy is not None

if __name__ == '__main__':
    with patch('capss.agent.capss_agent.SchemeKnowledgeBase') as MockKB, \
         patch('capss.agent.capss_agent.ExperienceMemory') as MockMemory, \
         patch('capss.agent.capss_agent.ContextAnalyzer') as MockAnalyzer, \
         patch('capss.agent.capss_agent.ReasoningEngine') as MockEngine, \
         patch('capss.agent.capss_agent.PolicyGenerator') as MockGenerator, \
         patch('capss.agent.capss_agent.PolicyValidator') as MockValidator, \
         patch('capss.agent.capss_agent.MemoryUpdater') as MockUpdater:
        
        agent = CAPSSAgent("dummy", experience_path="dummy_exp.json")
        
        mock_req_profile = MagicMock()
        mock_req_profile.anonymous_auth_required = True
        agent.analyzer.analyze.return_value = mock_req_profile
        
        mock_rec = MagicMock()
        mock_rec.recommended_scheme = "ANON-AUTH-SCHEME"
        mock_rec.decision_trace = MagicMock()
        agent.engine.reason.return_value = mock_rec
        
        mock_policy = MagicMock(spec=PrivacyPolicy)
        mock_policy.policy_id = "POL-EM-1"
        mock_policy.applied_scheme = "ANON-AUTH-SCHEME"
        agent.generator.generate.return_value = mock_policy
        
        run_emergency_scenario(agent)
