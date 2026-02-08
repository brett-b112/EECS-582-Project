"""
pytest configuration for LKSM tests
"""

import pytest
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

@pytest.fixture
def sample_event():
    """Sample event for testing"""
    return {
        'type': 'process',
        'timestamp': 1234567890,
        'pid': 1234,
        'uid': 1000,
        'process_name': 'bash',
        'parent_pid': 1000,
    }

@pytest.fixture
def config_path(tmp_path):
    """Temporary config file path"""
    config = tmp_path / "test_config.yml"
    config.write_text("# Test config\n")
    return config
