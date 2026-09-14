import pytest
import os
from datetime import datetime, timedelta
from capss.context_loader.loader import ContextLoader

def test_load_valid_csv(tmp_path):
    csv_file = tmp_path / "test.csv"
    csv_file.write_text("timestamp,ue_id,suci,registration_type,slice_type,dnn\n"
                        "2024-01-15 10:30:00.123,UE-1,suci-1,initial,eMBB,internet\n"
                        "2024-01-15 10:31:00.123,UE-2,suci-2,mobility,URLLC,ims\n")
    
    loader = ContextLoader(str(csv_file))
    contexts = loader.load_all()
    assert len(contexts) == 2
    assert contexts[0].ue_id == "UE-1"
    assert contexts[1].slice_type == "URLLC"

def test_filter_by_ue(tmp_path):
    csv_file = tmp_path / "test.csv"
    csv_file.write_text("timestamp,ue_id,suci,registration_type,slice_type,dnn\n"
                        "2024-01-15 10:30:00.123,UE-1,suci-1,initial,eMBB,internet\n"
                        "2024-01-15 10:31:00.123,UE-2,suci-2,mobility,URLLC,ims\n"
                        "2024-01-15 10:32:00.123,UE-1,suci-1,periodic,eMBB,internet\n")
    
    loader = ContextLoader(str(csv_file))
    ue_contexts = loader.load_by_ue("UE-1")
    assert len(ue_contexts) == 2
    assert ue_contexts[0].registration_type == "initial"
    assert ue_contexts[1].registration_type == "periodic"

def test_filter_by_slice(tmp_path):
    csv_file = tmp_path / "test.csv"
    csv_file.write_text("timestamp,ue_id,suci,registration_type,slice_type,dnn\n"
                        "2024-01-15 10:30:00.123,UE-1,suci-1,initial,eMBB,internet\n"
                        "2024-01-15 10:31:00.123,UE-2,suci-2,mobility,URLLC,ims\n")
    
    loader = ContextLoader(str(csv_file))
    slice_contexts = loader.load_by_slice("URLLC")
    assert len(slice_contexts) == 1
    assert slice_contexts[0].ue_id == "UE-2"

def test_filter_by_time_range(tmp_path):
    csv_file = tmp_path / "test.csv"
    csv_file.write_text("timestamp,ue_id,suci,registration_type,slice_type,dnn\n"
                        "2024-01-15 10:30:00.123,UE-1,suci-1,initial,eMBB,internet\n"
                        "2024-01-15 10:45:00.123,UE-2,suci-2,mobility,URLLC,ims\n")
    
    loader = ContextLoader(str(csv_file))
    t1 = datetime(2024, 1, 15, 10, 25, 0)
    t2 = datetime(2024, 1, 15, 10, 35, 0)
    time_contexts = loader.load_by_time_range(t1, t2)
    assert len(time_contexts) == 1
    assert time_contexts[0].ue_id == "UE-1"

def test_missing_optional_columns(tmp_path):
    csv_file = tmp_path / "test.csv"
    csv_file.write_text("timestamp,ue_id,suci,registration_type,slice_type,dnn,privacy_score\n"
                        "2024-01-15 10:30:00.123,UE-1,suci-1,initial,eMBB,internet,0.8\n")
    
    loader = ContextLoader(str(csv_file))
    contexts = loader.load_all()
    assert len(contexts) == 1
    assert contexts[0].privacy_score == 0.8
    assert contexts[0].threat_score is None

def test_invalid_csv_records_skipped(tmp_path):
    csv_file = tmp_path / "test.csv"
    # missing suci in second row
    csv_file.write_text("timestamp,ue_id,suci,registration_type,slice_type,dnn\n"
                        "2024-01-15 10:30:00.123,UE-1,suci-1,initial,eMBB,internet\n"
                        "2024-01-15 10:31:00.123,UE-2,,mobility,URLLC,ims\n")
    
    loader = ContextLoader(str(csv_file))
    contexts = loader.load_all()
    assert len(contexts) == 1
    assert contexts[0].ue_id == "UE-1"

def test_get_summary(tmp_path):
    csv_file = tmp_path / "test.csv"
    csv_file.write_text("timestamp,ue_id,suci,registration_type,slice_type,dnn\n"
                        "2024-01-15 10:30:00.123,UE-1,suci-1,initial,eMBB,internet\n"
                        "2024-01-15 10:31:00.123,UE-2,suci-2,mobility,URLLC,ims\n")
    
    loader = ContextLoader(str(csv_file))
    summary = loader.get_summary()
    assert summary["total_records"] == 2
    assert summary["unique_ues"] == 2
    assert summary["registration_types"] == {"initial": 1, "mobility": 1}
    assert summary["slices"] == {"eMBB": 1, "URLLC": 1}
