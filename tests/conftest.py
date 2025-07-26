"""Pytest configuration and shared fixtures."""

import pytest
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture(autouse=True)
def reset_singleton_instances():
    """Reset singleton instances between tests."""
    # This ensures clean state between tests
    yield
    
    # Add any singleton reset logic here if needed


@pytest.fixture
def mock_env(monkeypatch):
    """Mock environment variables for testing."""
    monkeypatch.setenv("LINKNODE_DEBUG", "false")
    monkeypatch.setenv("LINKNODE_API_KEY", "test-key-123")
    yield monkeypatch