import pytest
from datetime import datetime
from capss.schemas.context import RegistrationContext
from capss.context_analyzer.analyzer import ContextAnalyzer
from capss.schemas.experience import Experience

@pytest.fixture
def base_context():
    return RegistrationContext(
        ue_id="UE-1",
        suci="suci-1",
        registration_type="initial",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime.utcnow()
    )

def test_analyze_basic(base_context):
    analyzer = ContextAnalyzer()
    profile = analyzer.analyze(base_context)
    
    assert profile.threat_level == "medium"
    assert profile.latency_requirement == "medium"
    assert profile.resource_profile == "powerful"
    assert profile.tracking_risk == 0.3
    assert profile.anonymous_auth_required is False

def test_emergency_critical_threat():
    ctx = RegistrationContext(
        ue_id="UE-1",
        suci="suci-1",
        registration_type="emergency",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime.utcnow()
    )
    analyzer = ContextAnalyzer()
    profile = analyzer.analyze(ctx)
    
    assert profile.threat_level == "critical"
    assert profile.anonymous_auth_required is True

def test_urllc_ultra_low_latency():
    ctx = RegistrationContext(
        ue_id="UE-1",
        suci="suci-1",
        registration_type="initial",
        slice_type="URLLC",
        dnn="internet",
        timestamp=datetime.utcnow()
    )
    analyzer = ContextAnalyzer()
    profile = analyzer.analyze(ctx)
    
    assert profile.latency_requirement == "ultra_low"
    assert profile.resource_profile == "powerful"

def test_mmtc_constrained_resource():
    ctx = RegistrationContext(
        ue_id="UE-1",
        suci="suci-1",
        registration_type="initial",
        slice_type="mMTC",
        dnn="iot",
        timestamp=datetime.utcnow()
    )
    analyzer = ContextAnalyzer()
    profile = analyzer.analyze(ctx)
    
    assert profile.resource_profile == "constrained"
    assert profile.latency_requirement == "high"

def test_context_completeness(base_context):
    analyzer = ContextAnalyzer()
    # 6 required fields populated out of 17 total fields
    # (6 required + 5 Systems Module + 4 Privacy Module + 2 combined threat)
    profile = analyzer.analyze(base_context)
    assert profile.context_completeness == 6 / 17

def test_tracking_risk_increases_with_experiences(base_context):
    analyzer = ContextAnalyzer()
    
    # 0 experiences
    prof1 = analyzer.analyze(base_context, [])
    assert prof1.tracking_risk == 0.3
    
    # 3 experiences
    experiences = [
        Experience(ue_id="UE-1", context_snapshot={}, requirement_profile={}, selected_scheme="TEST", selected_scheme_id="S1", reason="", confidence=1.0)
        for _ in range(3)
    ]
    prof2 = analyzer.analyze(base_context, experiences)
    assert prof2.tracking_risk == 0.5  # 0.3 + 0.2

def test_custom_config_weights(base_context):
    config = {
        "slice_weights": {"eMBB": 0.9},
        "dnn_weights": {"internet": 0.9},
        "registration_type_weights": {"initial": 0.9},
    }
    analyzer = ContextAnalyzer(config=config)
    profile = analyzer.analyze(base_context)
    # (0.9 + 0.9 + 0.9) / 3 = 0.9
    assert profile.privacy_requirement == 0.9
