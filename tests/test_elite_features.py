"""
Verification tests for elite CTF agent features:
- State-space branching (checkpoints)
- OAST (out-of-band exploitation)
- PCAP analysis
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_checkpoint_save_restore():
    """Test checkpoint save/restore functionality."""
    from ctf_rag.session import Session
    
    s = Session("test_challenge")
    s.update_memory("key1", "value1")
    s.note_failure("method1", "reason1")
    s.add_thought("thinking about stuff")
    
    # Save checkpoint
    result = s.save_checkpoint("test_ckpt")
    assert "[checkpoint] Saved state" in result, f"Failed to save checkpoint: {result}"
    
    # Modify state after checkpoint
    s.update_memory("key2", "value2")
    s.note_failure("method2", "reason2")
    assert "key2" in s.working_memory
    assert len(s.failed_methods) == 2
    
    # Restore checkpoint
    result = s.restore_checkpoint("test_ckpt")
    assert "[checkpoint] Restored state" in result, f"Failed to restore: {result}"
    
    # Verify state was restored
    assert "key1" in s.working_memory, "key1 should exist after restore"
    assert "key2" not in s.working_memory, "key2 should NOT exist after restore"
    assert len(s.failed_methods) == 1, "failed_methods should be restored to 1"
    
    print("✓ Checkpoint save/restore: PASSED")
    return True


def test_pcap_analyze_flows():
    """Test PCAP analysis tool."""
    from ctf_rag.tools import execute_tool
    
    pcap_path = "data/test_sample.pcap"
    if not Path(pcap_path).exists():
        print("✓ PCAP analysis: SKIPPED (test PCAP not found)")
        return True
    
    result = execute_tool("pcap_analyze_flows", {"pcap_path": pcap_path}, session=None)
    
    assert "[PCAP Analysis]" in result, f"PCAP analysis failed: {result}"
    assert "HTTP requests:" in result, "Should extract HTTP requests"
    
    # Check JSON was saved
    json_path = "/tmp/pcap_flows.json"
    assert Path(json_path).exists(), f"JSON output not found: {json_path}"
    
    with open(json_path) as f:
        data = json.load(f)
    
    assert "http_requests" in data, "HTTP requests should be extracted"
    assert len(data["http_requests"]) > 0, "Should find HTTP requests"
    
    print("✓ PCAP analysis: PASSED")
    return True


def test_tools_load():
    """Test all tools load correctly."""
    from ctf_rag import tools
    
    tool_names = [t["name"] for t in tools.TOOL_SCHEMAS]
    
    required_tools = [
        "save_state",
        "revert_state", 
        "allocate_oast_payload",
        "check_oast_logs",
        "pcap_analyze_flows",
    ]
    
    for tool in required_tools:
        assert tool in tool_names, f"Missing tool: {tool}"
    
    print(f"✓ Tools load: PASSED ({len(tools.TOOL_SCHEMAS)} tools)")
    return True


def test_checkpoint_tools_in_schemas():
    """Test checkpoint tools are in schemas."""
    from ctf_rag import tools
    
    tool_names = [t["name"] for t in tools.TOOL_SCHEMAS]
    
    assert "save_state" in tool_names, "save_state not in TOOL_SCHEMAS"
    assert "revert_state" in tool_names, "revert_state not in TOOL_SCHEMAS"
    
    print("✓ Checkpoint tools in schemas: PASSED")
    return True


def test_oast_tools_in_schemas():
    """Test OAST tools are in schemas."""
    from ctf_rag import tools
    
    tool_names = [t["name"] for t in tools.TOOL_SCHEMAS]
    
    assert "allocate_oast_payload" in tool_names, "allocate_oast_payload not in TOOL_SCHEMAS"
    assert "check_oast_logs" in tool_names, "check_oast_logs not in TOOL_SCHEMAS"
    
    print("✓ OAST tools in schemas: PASSED")
    return True


def test_pcap_tool_in_schemas():
    """Test PCAP tool is in schemas."""
    from ctf_rag import tools
    
    tool_names = [t["name"] for t in tools.TOOL_SCHEMAS]
    
    assert "pcap_analyze_flows" in tool_names, "pcap_analyze_flows not in TOOL_SCHEMAS"
    
    print("✓ PCAP tool in schemas: PASSED")
    return True


def main():
    """Run all verification tests."""
    print("=" * 60)
    print("Elite Features Verification Tests")
    print("=" * 60)
    
    tests = [
        ("Tools load", test_tools_load),
        ("Checkpoint tools in schemas", test_checkpoint_tools_in_schemas),
        ("OAST tools in schemas", test_oast_tools_in_schemas),
        ("PCAP tool in schemas", test_pcap_tool_in_schemas),
        ("Checkpoint save/restore", test_checkpoint_save_restore),
        ("PCAP analysis", test_pcap_analyze_flows),
    ]
    
    passed = 0
    failed = 0
    
    for name, test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"✗ {name}: FAILED")
        except Exception as e:
            failed += 1
            print(f"✗ {name}: ERROR - {e}")
    
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)