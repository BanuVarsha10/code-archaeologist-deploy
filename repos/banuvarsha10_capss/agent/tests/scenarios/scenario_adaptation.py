import os
from datetime import datetime
from unittest.mock import patch, MagicMock
from capss.agent.capss_agent import CAPSSAgent
from capss.schemas.context import RegistrationContext
from capss.schemas.policy import PrivacyPolicy

def run_adaptation_scenario(agent):
    """Simulate UE registering multiple times with changing contexts."""
    # First: eMBB
    ctx1 = RegistrationContext(
        ue_id="UE-AD-1",
        suci="suci-ad-1",
        registration_type="initial",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime.utcnow()
    )
    policy1 = agent.process_registration(ctx1)
    
    # Second: URLLC
    ctx2 = RegistrationContext(
        ue_id="UE-AD-1",
        suci="suci-ad-1",
        registration_type="mobility",
        slice_type="URLLC",
        dnn="enterprise",
        timestamp=datetime.utcnow()
    )
    policy2 = agent.process_registration(ctx2)
    
    # Third: mMTC
    ctx3 = RegistrationContext(
        ue_id="UE-AD-1",
        suci="suci-ad-1",
        registration_type="periodic",
        slice_type="mMTC",
        dnn="iot",
        timestamp=datetime.utcnow()
    )
    policy3 = agent.process_registration(ctx3)
    
    print(f"Adaptation completed for {ctx1.ue_id}")
    assert policy1 is not None
    assert policy2 is not None
    assert policy3 is not None

if __name__ == '__main__':
    with patch('capss.agent.capss_agent.SchemeKnowledgeBase') as MockKB, \
         patch('capss.agent.capss_agent.ExperienceMemory') as MockMemory, \
         patch('capss.agent.capss_agent.ContextAnalyzer') as MockAnalyzer, \
         patch('capss.agent.capss_agent.ReasoningEngine') as MockEngine, \
         patch('capss.agent.capss_agent.PolicyGenerator') as MockGenerator, \
         patch('capss.agent.capss_agent.PolicyValidator') as MockValidator, \
         patch('capss.agent.capss_agent.MemoryUpdater') as MockUpdater:
        
        agent = CAPSSAgent("dummy", experience_path="dummy_exp.json")
        
        agent.analyzer.analyze.return_value = MagicMock()
        
        mock_rec = MagicMock()
        mock_rec.recommended_scheme = "ADAPTIVE-SCHEME"
        mock_rec.decision_trace = MagicMock()
        agent.engine.reason.return_value = mock_rec
        
        mock_policy = MagicMock(spec=PrivacyPolicy)
        mock_policy.policy_id = "POL-AD-1"
        mock_policy.applied_scheme = "ADAPTIVE-SCHEME"
        agent.generator.generate.return_value = mock_policy
        
        run_adaptation_scenario(agent)
