"""Tests for SystemsContextLoader — Raw Systems-module CSV ingestion."""

import pytest
import os
import tempfile
from datetime import datetime
from capss.context_loader.systems_loader import SystemsContextLoader, load_systems_contexts
from capss.schemas.context import RegistrationContext


@pytest.fixture
def temp_systems_csvs():
    """Create a temporary pair of valid Systems CSV files."""
    reg_content = (
        "Request_ID,Timestamp,Event,UE_ID,SUCI,Authentication_Result,Registration_Status,Registration_Type,Cause_Code,gNB_IP,DNN,S_NSSAI\n"
        "REQ-001,2024-01-15T08:12:34Z,REG_REQ,UE-001,suci-0-001-01-0001,SUCCESS,SUCCESS,initial,NONE,192.168.1.1,internet,eMBB\n"
        "REQ-002,2024-01-15T09:15:00Z,REG_REQ,UE-002,suci-0-001-01-0002,SUCCESS,SUCCESS,mobility,NONE,192.168.1.2,ims,URLLC\n"
        "REQ-003,2024-01-15T10:20:00Z,REG_REQ,UE-003,suci-0-001-01-0003,FAILED,BLOCKED,initial,AUTH_FAIL,192.168.1.3,enterprise,mMTC\n"
    )

    attack_content = (
        "Request_ID,Experiment,Timestamp,UE_ID,Attack_Detected,Attack_Type,Decision,Severity,Confidence,Risk_Score,Reasons\n"
        "REQ-001,EXP-1,2024-01-15T08:12:34Z,UE-001,False,none,ALLOW,low,0.05,0.1,Header OK; Subscriber OK\n"
        "REQ-002,EXP-1,2024-01-15T09:15:00Z,UE-002,True,replay,TAG,medium,0.75,0.6,Replay pattern detected\n"
        "REQ-003,EXP-1,2024-01-15T10:20:00Z,UE-003,True,flooding,BLOCK,critical,0.95,0.9,DOS flooding attack; Invalid MAC\n"
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f_reg:
        f_reg.write(reg_content)
        reg_path = f_reg.name

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f_att:
        f_att.write(attack_content)
        att_path = f_att.name

    yield reg_path, att_path

    # Cleanup
    if os.path.exists(reg_path):
        os.remove(reg_path)
    if os.path.exists(att_path):
        os.remove(att_path)


def test_systems_loader_valid_ingestion(temp_systems_csvs):
    reg_path, att_path = temp_systems_csvs
    loader = SystemsContextLoader(reg_path, att_path)
    contexts = loader.load_all()

    assert len(contexts) == 3

    # Row 1: REQ-001 (ALLOW)
    c1 = contexts[0]
    assert isinstance(c1, RegistrationContext)
    assert c1.ue_id == "UE-001"
    assert c1.suci == "suci-0-001-01-0001"
    assert c1.registration_type == "initial"
    assert c1.slice_type == "eMBB"
    assert c1.dnn == "internet"
    assert c1.request_classification == "ALLOW"
    assert c1.attack_type == "NONE"  # Attack_Detected = False -> NONE
    assert c1.attack_severity == "low"
    assert c1.detection_confidence == 0.05
    assert c1.threat_score == 0.1
    assert c1.reasons == "Header OK; Subscriber OK"
    # Uncomputed Privacy module fields remain None
    assert c1.privacy_score is None
    assert c1.privacy_risk_level is None
    assert c1.metadata_leakage is None
    assert c1.correlation_score is None

    # Row 2: REQ-002 (TAG)
    c2 = contexts[1]
    assert c2.request_classification == "TAG"
    assert c2.attack_type == "replay"
    assert c2.detection_confidence == 0.75
    assert c2.threat_score == 0.6

    # Row 3: REQ-003 (BLOCK)
    c3 = contexts[2]
    assert c3.request_classification == "BLOCK"
    assert c3.attack_type == "flooding"
    assert c3.attack_severity == "critical"
    assert c3.detection_confidence == 0.95
    assert c3.threat_score == 0.9


def test_systems_loader_fallback_join(temp_systems_csvs):
    """Test joining on (UE_ID, Timestamp) when Request_ID is missing or mismatched."""
    reg_content = (
        "Request_ID,Timestamp,Event,UE_ID,SUCI,Authentication_Result,Registration_Status,Registration_Type,Cause_Code,gNB_IP,DNN,S_NSSAI\n"
        ",2024-01-15T08:12:34Z,REG_REQ,UE-001,suci-0-001-01-0001,SUCCESS,SUCCESS,initial,NONE,192.168.1.1,internet,eMBB\n"
    )
    attack_content = (
        "Request_ID,Experiment,Timestamp,UE_ID,Attack_Detected,Attack_Type,Decision,Severity,Confidence,Risk_Score,Reasons\n"
        ",EXP-1,2024-01-15T08:12:34Z,UE-001,False,none,ALLOW,low,0.05,0.1,Header OK\n"
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f_reg:
        f_reg.write(reg_content)
        reg_path = f_reg.name

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f_att:
        f_att.write(attack_content)
        att_path = f_att.name

    try:
        contexts = load_systems_contexts(reg_path, att_path)
        assert len(contexts) == 1
        assert contexts[0].ue_id == "UE-001"
        assert contexts[0].request_classification == "ALLOW"
    finally:
        os.remove(reg_path)
        os.remove(att_path)


def test_systems_loader_invalid_decision_error():
    """Test invalid Decision raises clear ValueError naming the Request_ID."""
    reg_content = (
        "Request_ID,Timestamp,Event,UE_ID,SUCI,Authentication_Result,Registration_Status,Registration_Type,Cause_Code,gNB_IP,DNN,S_NSSAI\n"
        "REQ-BAD-DECISION,2024-01-15T08:12:34Z,REG_REQ,UE-001,suci-1,SUCCESS,SUCCESS,initial,NONE,192.168.1.1,internet,eMBB\n"
    )
    attack_content = (
        "Request_ID,Experiment,Timestamp,UE_ID,Attack_Detected,Attack_Type,Decision,Severity,Confidence,Risk_Score,Reasons\n"
        "REQ-BAD-DECISION,EXP-1,2024-01-15T08:12:34Z,UE-001,False,none,INVALID_DECISION,low,0.05,0.1,Notes\n"
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f_reg:
        f_reg.write(reg_content)
        reg_path = f_reg.name

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f_att:
        f_att.write(attack_content)
        att_path = f_att.name

    try:
        loader = SystemsContextLoader(reg_path, att_path)
        with pytest.raises(ValueError) as excinfo:
            loader.load_all()
        assert "REQ-BAD-DECISION" in str(excinfo.value)
        assert "ALLOW, TAG, BLOCK" in str(excinfo.value)
    finally:
        os.remove(reg_path)
        os.remove(att_path)


def test_systems_loader_missing_mandatory_field():
    """Test missing mandatory field raises clear ValueError naming the Request_ID."""
    reg_content = (
        "Request_ID,Timestamp,Event,UE_ID,SUCI,Authentication_Result,Registration_Status,Registration_Type,Cause_Code,gNB_IP,DNN,S_NSSAI\n"
        "REQ-MISSING-SUCI,2024-01-15T08:12:34Z,REG_REQ,UE-001,,SUCCESS,SUCCESS,initial,NONE,192.168.1.1,internet,eMBB\n"
    )
    attack_content = (
        "Request_ID,Experiment,Timestamp,UE_ID,Attack_Detected,Attack_Type,Decision,Severity,Confidence,Risk_Score,Reasons\n"
        "REQ-MISSING-SUCI,EXP-1,2024-01-15T08:12:34Z,UE-001,False,none,ALLOW,low,0.05,0.1,Notes\n"
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f_reg:
        f_reg.write(reg_content)
        reg_path = f_reg.name

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f_att:
        f_att.write(attack_content)
        att_path = f_att.name

    try:
        loader = SystemsContextLoader(reg_path, att_path)
        with pytest.raises(ValueError) as excinfo:
            loader.load_all()
        assert "REQ-MISSING-SUCI" in str(excinfo.value)
        assert "SUCI" in str(excinfo.value)
    finally:
        os.remove(reg_path)
        os.remove(att_path)


def test_systems_loader_invalid_numeric_field():
    """Test non-numeric Confidence or Risk_Score raises clear ValueError naming Request_ID."""
    reg_content = (
        "Request_ID,Timestamp,Event,UE_ID,SUCI,Authentication_Result,Registration_Status,Registration_Type,Cause_Code,gNB_IP,DNN,S_NSSAI\n"
        "REQ-BAD-FLOAT,2024-01-15T08:12:34Z,REG_REQ,UE-001,suci-1,SUCCESS,SUCCESS,initial,NONE,192.168.1.1,internet,eMBB\n"
    )
    attack_content = (
        "Request_ID,Experiment,Timestamp,UE_ID,Attack_Detected,Attack_Type,Decision,Severity,Confidence,Risk_Score,Reasons\n"
        "REQ-BAD-FLOAT,EXP-1,2024-01-15T08:12:34Z,UE-001,False,none,ALLOW,low,NOT_A_FLOAT,0.1,Notes\n"
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f_reg:
        f_reg.write(reg_content)
        reg_path = f_reg.name

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f_att:
        f_att.write(attack_content)
        att_path = f_att.name

    try:
        loader = SystemsContextLoader(reg_path, att_path)
        with pytest.raises(ValueError) as excinfo:
            loader.load_all()
        assert "REQ-BAD-FLOAT" in str(excinfo.value)
        assert "Confidence" in str(excinfo.value)
    finally:
        os.remove(reg_path)
        os.remove(att_path)


def test_systems_loader_no_year_timestamp():
    """Test parsing timestamps in 'MM/DD HH:MM:SS.mmm' format with year override (Bug 1)."""
    reg_content = (
        "Request_ID,Timestamp,Event,UE_ID,SUCI,Authentication_Result,Registration_Status,Registration_Type,Cause_Code,gNB_IP,DNN,S_NSSAI\n"
        "REQ-NO-YEAR,07/16 13:16:20.312,REG_REQ,UE-001,suci-0-001-01-0001,SUCCESS,SUCCESS,initial,NONE,192.168.1.1,internet,eMBB\n"
    )
    attack_content = (
        "Request_ID,Experiment,Timestamp,UE_ID,Attack_Detected,Attack_Type,Decision,Severity,Confidence,Risk_Score,Reasons\n"
        "REQ-NO-YEAR,EXP-1,07/16 13:16:20.312,UE-001,False,none,ALLOW,low,0.05,0.1,Notes\n"
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f_reg:
        f_reg.write(reg_content)
        reg_path = f_reg.name

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as f_att:
        f_att.write(attack_content)
        att_path = f_att.name

    try:
        loader = SystemsContextLoader(reg_path, att_path, year=2024)
        contexts = loader.load_all()
        assert len(contexts) == 1
        assert contexts[0].timestamp.year == 2024
        assert contexts[0].timestamp.month == 7
        assert contexts[0].timestamp.day == 16
        assert contexts[0].timestamp.hour == 13
        assert contexts[0].timestamp.minute == 16
        assert contexts[0].timestamp.second == 20
    finally:
        os.remove(reg_path)
        os.remove(att_path)
