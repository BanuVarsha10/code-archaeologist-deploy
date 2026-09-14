"""Pytest configuration and global test safeguards for CAPSS Agent test suite."""

import os
import pytest

# Repository root directory
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROD_EXP_FILE = os.path.join(REPO_ROOT, "experience_store.json")


@pytest.fixture(autouse=True)
def guard_experience_store_pollution():
    """Autouse fixture that fails loudly if any test creates or modifies repo root experience_store.json."""
    mtime_before = os.path.getmtime(PROD_EXP_FILE) if os.path.exists(PROD_EXP_FILE) else None
    
    yield
    
    if os.path.exists(PROD_EXP_FILE):
        mtime_after = os.path.getmtime(PROD_EXP_FILE)
        if mtime_before is None:
            # File was created by a test run!
            os.remove(PROD_EXP_FILE)
            pytest.fail(
                "TEST REGRESSION SAFEGUARD: A test created 'experience_store.json' in the repo root! "
                "All tests must instantiate CAPSSAgent/ExperienceMemory with an isolated tmp_path."
            )
        elif mtime_after != mtime_before:
            # File was modified by a test run!
            pytest.fail(
                "TEST REGRESSION SAFEGUARD: A test modified 'experience_store.json' in the repo root! "
                "All tests must instantiate CAPSSAgent/ExperienceMemory with an isolated tmp_path."
            )
