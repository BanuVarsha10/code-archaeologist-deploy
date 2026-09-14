import pytest
import os
from capss.log_converter.converter import LogConverter

def test_parse_single_log_line():
    converter = LogConverter()
    line = "[2024-01-15 10:30:00.123] [amf] [info] Registration Request from UE [suci:suci-0-001-01-1234] [type:initial] [slice:eMBB] [dnn:internet]"
    parsed = converter.parse_log_entry(line)
    
    assert parsed is not None
    assert parsed["timestamp"] == "2024-01-15 10:30:00.123"
    assert parsed["suci"] == "suci-0-001-01-1234"
    assert parsed["registration_type"] == "initial"
    assert parsed["slice_type"] == "eMBB"
    assert parsed["dnn"] == "internet"
    assert parsed["ue_id"] == "suci-0-001-01-1234" # Fallback to suci

def test_parse_log_line_with_ue_id():
    converter = LogConverter()
    line = "[2024-01-15 10:30:00.123] [amf] [info] Registration Request from UE [suci:suci-123] [type:mobility] [slice:URLLC] [dnn:ims] ue_id:UE-007"
    parsed = converter.parse_log_entry(line)
    
    assert parsed is not None
    assert parsed["ue_id"] == "UE-007"
    assert parsed["suci"] == "suci-123"

def test_convert_log_file(tmp_path):
    converter = LogConverter()
    log_file = tmp_path / "test.log"
    log_file.write_text("[2024-01-15 10:30:00.123] [amf] [info] Registration Request from UE [suci:suci-123] [type:initial] [slice:eMBB] [dnn:internet]\n")
    
    out_file = tmp_path / "out.csv"
    res = converter.convert_log_file(str(log_file), str(out_file))
    
    assert res == str(out_file)
    assert out_file.exists()
    content = out_file.read_text()
    assert "timestamp,ue_id,suci,registration_type,slice_type,dnn" in content
    assert "2024-01-15 10:30:00.123,suci-123,suci-123,initial,eMBB,internet" in content

def test_malformed_log_line():
    converter = LogConverter()
    line = "Some random text without matching pattern"
    parsed = converter.parse_log_entry(line)
    assert parsed is None

def test_empty_log_file(tmp_path):
    converter = LogConverter()
    log_file = tmp_path / "empty.log"
    log_file.write_text("")
    
    out_file = tmp_path / "empty_out.csv"
    res = converter.convert_log_file(str(log_file), str(out_file))
    
    assert res == str(out_file)
    assert not out_file.exists()  # Shouldn't create if records are empty
