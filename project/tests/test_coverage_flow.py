"""
Test CALDERA coverage checker integration with the full flow.
This tests the coverage checker independently and as part of the technique planner.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from caldera.coverage_checker import CoverageChecker
from caldera.api_client import CalderaClient


class TestCoverageChecker:
    """Test CoverageChecker functionality."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock CalderaClient."""
        return Mock(spec=CalderaClient)

    @pytest.fixture
    def checker(self, mock_client):
        """Create a CoverageChecker with mock client."""
        return CoverageChecker(mock_client)

    def test_checker_initialization(self, mock_client):
        """Test CoverageChecker initializes correctly."""
        checker = CoverageChecker(mock_client)
        assert checker.client == mock_client
        assert checker._ability_cache is None
        assert checker._technique_to_abilities == {}

    def test_load_abilities_empty(self, checker, mock_client):
        """Test loading abilities when none are returned."""
        mock_client.get_abilities.return_value = {"abilities": []}
        
        abilities = checker._load_abilities()
        
        assert abilities == []
        assert checker._ability_cache == []

    def test_load_abilities_with_data(self, checker, mock_client):
        """Test loading abilities with actual data."""
        mock_abilities = {
            "abilities": [
                {
                    "ability_id": "abc123",
                    "name": "Network Discovery",
                    "technique_id": "T1046",
                    "platforms": {"windows": {}, "linux": {}},
                    "tactic": "reconnaissance",
                },
                {
                    "ability_id": "def456",
                    "name": "Brute Force",
                    "technique_id": "T1110",
                    "platforms": {"windows": {}},
                    "tactic": "credential-access",
                },
            ]
        }
        mock_client.get_abilities.return_value = mock_abilities
        
        abilities = checker._load_abilities()
        
        assert len(abilities) == 2
        assert abilities[0]["ability_id"] == "abc123"
        assert abilities[1]["ability_id"] == "def456"

    def test_build_technique_map(self, checker, mock_client):
        """Test building technique-to-ability mapping."""
        mock_abilities = {
            "abilities": [
                {
                    "ability_id": "abc123",
                    "name": "Network Discovery",
                    "technique_id": "T1046",
                    "platforms": {"windows": {}},
                    "tactic": "reconnaissance",
                },
                {
                    "ability_id": "def456",
                    "name": "Brute Force",
                    "technique_id": "T1110",
                    "platforms": {"windows": {}},
                    "tactic": "credential-access",
                },
            ]
        }
        mock_client.get_abilities.return_value = mock_abilities
        
        technique_map = checker._build_technique_map()
        
        assert "T1046" in technique_map
        assert "T1110" in technique_map
        assert len(technique_map["T1046"]) == 1
        assert technique_map["T1046"][0]["ability_id"] == "abc123"

    def test_check_technique_coverage_supported(self, checker, mock_client):
        """Test checking coverage for supported techniques."""
        mock_abilities = {
            "abilities": [
                {
                    "ability_id": "abc123",
                    "name": "Network Discovery",
                    "technique_id": "T1046",
                    "platforms": {"windows": {}},
                    "tactic": "reconnaissance",
                },
            ]
        }
        mock_client.get_abilities.return_value = mock_abilities
        
        coverage = checker.check_technique_coverage(["T1046"])
        
        assert coverage["total"] == 1
        assert coverage["supported"] == 1
        assert coverage["unsupported"] == 0
        assert coverage["techniques"]["T1046"]["supported"] is True
        assert coverage["techniques"]["T1046"]["ability_count"] == 1

    def test_check_technique_coverage_unsupported(self, checker, mock_client):
        """Test checking coverage for unsupported techniques."""
        mock_client.get_abilities.return_value = {"abilities": []}
        
        coverage = checker.check_technique_coverage(["T9999"])
        
        assert coverage["total"] == 1
        assert coverage["supported"] == 0
        assert coverage["unsupported"] == 1
        assert coverage["techniques"]["T9999"]["supported"] is False
        assert coverage["techniques"]["T9999"]["ability_count"] == 0

    def test_check_technique_coverage_mixed(self, checker, mock_client):
        """Test checking coverage for mix of supported and unsupported."""
        mock_abilities = {
            "abilities": [
                {
                    "ability_id": "abc123",
                    "name": "Network Discovery",
                    "technique_id": "T1046",
                    "platforms": {"windows": {}},
                    "tactic": "reconnaissance",
                },
            ]
        }
        mock_client.get_abilities.return_value = mock_abilities
        
        coverage = checker.check_technique_coverage(["T1046", "T9999"])
        
        assert coverage["total"] == 2
        assert coverage["supported"] == 1
        assert coverage["unsupported"] == 1
        assert coverage["techniques"]["T1046"]["supported"] is True
        assert coverage["techniques"]["T9999"]["supported"] is False

    def test_get_supported_techniques(self, checker, mock_client):
        """Test filtering to only supported techniques."""
        mock_abilities = {
            "abilities": [
                {
                    "ability_id": "abc123",
                    "name": "Network Discovery",
                    "technique_id": "T1046",
                    "platforms": {"windows": {}},
                    "tactic": "reconnaissance",
                },
            ]
        }
        mock_client.get_abilities.return_value = mock_abilities
        
        supported = checker.get_supported_techniques(["T1046", "T9999"])
        
        assert len(supported) == 1
        assert "T1046" in supported
        assert "T9999" not in supported

    def test_clear_cache(self, checker):
        """Test clearing the ability cache."""
        checker._ability_cache = ["something"]
        checker._technique_to_abilities = {"T1046": []}
        
        checker.clear_cache()
        
        assert checker._ability_cache is None
        assert checker._technique_to_abilities == {}

    def test_cache_is_used(self, checker, mock_client):
        """Test that cache is used on subsequent calls."""
        mock_abilities = {
            "abilities": [
                {
                    "ability_id": "abc123",
                    "name": "Network Discovery",
                    "technique_id": "T1046",
                    "platforms": {"windows": {}},
                    "tactic": "reconnaissance",
                },
            ]
        }
        mock_client.get_abilities.return_value = mock_abilities
        
        # First call - loads from API
        checker.check_technique_coverage(["T1046"])
        assert mock_client.get_abilities.call_count == 1
        
        # Second call - uses cache
        checker.check_technique_coverage(["T1046"])
        assert mock_client.get_abilities.call_count == 1  # Should not increase


class TestCoverageCheckerEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def mock_client(self):
        return Mock(spec=CalderaClient)

    @pytest.fixture
    def checker(self, mock_client):
        return CoverageChecker(mock_client)

    def test_empty_technique_list(self, checker):
        """Test with empty technique list."""
        coverage = checker.check_technique_coverage([])
        
        assert coverage["total"] == 0
        assert coverage["supported"] == 0
        assert coverage["unsupported"] == 0
        assert coverage["techniques"] == {}

    def test_technique_case_insensitivity(self, checker, mock_client):
        """Test that technique IDs are normalized to uppercase."""
        mock_abilities = {
            "abilities": [
                {
                    "ability_id": "abc123",
                    "name": "Network Discovery",
                    "technique_id": "T1046",
                    "platforms": {"windows": {}},
                    "tactic": "reconnaissance",
                },
            ]
        }
        mock_client.get_abilities.return_value = mock_abilities
        
        coverage = checker.check_technique_coverage(["t1046"])
        
        assert coverage["techniques"]["T1046"]["supported"] is True

    def test_ability_with_nested_technique_dict(self, checker, mock_client):
        """Test handling ability with nested technique dict."""
        mock_abilities = {
            "abilities": [
                {
                    "ability_id": "abc123",
                    "name": "Network Discovery",
                    "technique": {"attack_id": "T1046"},
                    "platforms": {"windows": {}},
                    "tactic": "reconnaissance",
                },
            ]
        }
        mock_client.get_abilities.return_value = mock_abilities
        
        coverage = checker.check_technique_coverage(["T1046"])
        
        assert coverage["techniques"]["T1046"]["supported"] is True
        assert coverage["techniques"]["T1046"]["ability_count"] == 1

    def test_api_error_handling(self, checker, mock_client):
        """Test handling of API errors."""
        from caldera.api_client import CalderaAPIError
        mock_client.get_abilities.side_effect = CalderaAPIError("Connection failed")
        
        coverage = checker.check_technique_coverage(["T1046"])
        
        # Should handle gracefully and return unsupported
        assert coverage["total"] == 1
        assert coverage["unsupported"] == 1
