import pytest
from unittest import mock
from ReversingLabs.SDK.advanced import AdvancedActions

SHA1 = "5377d0ed664246a604363f90a2764aa10fa63ad0"
HOST = "https://example.com"
USERNAME = "username"
PASSWORD = "password"


@pytest.fixture
def dynamic_analysis_mock():
	with mock.patch("ReversingLabs.SDK.ticloud.DynamicAnalysis.get_dynamic_analysis_results", autospec=True) as dynamic_mock:
		yield dynamic_mock


@pytest.fixture
def file_analysis_mock():
	with mock.patch("ReversingLabs.SDK.ticloud.FileAnalysis.get_analysis_results", autospec=True) as rldata_mock:
		yield rldata_mock


class TestAdvancedActions:
	@classmethod
	def setup_class(cls):
		cls.adv_actions = AdvancedActions(HOST, USERNAME, PASSWORD)

	def test_no_da_report(self, dynamic_analysis_mock, file_analysis_mock):
		dynamic_analysis_mock.return_value.json.return_value = {}

		file_analysis_mock.return_value.json.return_value = {
			"rl": {
				"sample": {
					"sha1": SHA1
				}
			}
		}

		result = self.adv_actions.enriched_file_analysis(sample_hash=SHA1)
		expected_result = {}

		assert result == expected_result

	def test_existing_da_field(self, dynamic_analysis_mock, file_analysis_mock):
		dynamic_analysis_mock.return_value.json.return_value = {
			"rl": {
				"report": {
					"da_key": "da_value"
				}
			}
		}

		file_analysis_mock.return_value.json.return_value = {
			"rl": {
				"sample": {
					"sha1": SHA1,
					"dynamic_analysis": {
						"entries": [
							{"existing_field": "existing_value"}
						]
					}
				}
			}
		}

		result = self.adv_actions.enriched_file_analysis(sample_hash=SHA1)
		assert "entries" in result.get("rl").get("sample").get("dynamic_analysis")
		assert "report" in result.get("rl").get("sample").get("dynamic_analysis")