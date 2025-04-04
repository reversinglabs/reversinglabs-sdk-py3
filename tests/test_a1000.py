import inspect
import pytest
from unittest import mock
from ReversingLabs.SDK import __version__
from ReversingLabs.SDK.a1000 import CLASSIFICATIONS, AVAILABLE_PLATFORMS, A1000
from ReversingLabs.SDK.helper import WrongInputError, DEFAULT_USER_AGENT


MD5 = "512fca9e83c47fd9c36aa7d50a856396"
SHA1 = "5377d0ed664246a604363f90a2764aa10fa63ad0"
SHA256 = "00f8cd09187d311707b52a1c52018e7cfb5f2f78e47bf9200f16281098741422"
EXPECTED_PLATFORMS = ("windows7", "windows10", "macos_11", "windows11", "linux")


def test_classifications():
	assert "macos11" not in AVAILABLE_PLATFORMS, "Did we start using macos11 in these classifications?"

	assert "KNOWN" not in CLASSIFICATIONS, "Are you sure that KNOWN should be in allowed classifications?"
	assert "GOODWARE" in CLASSIFICATIONS, "Are you sure that GOODWARE should be removed from allowed classifications?"


def test_available_platforms():
	for platform in AVAILABLE_PLATFORMS:
		assert platform in EXPECTED_PLATFORMS


def test_a1000_object():
	invalid_host = "my.host"
	valid_host = f"https://{invalid_host}"
	token = "my_mock_token"

	a1000 = A1000(
		host=valid_host,
		token=token,
		verify=True
	)

	assert a1000._url == valid_host + "{endpoint}"

	with pytest.raises(WrongInputError, match=r"host parameter must contain a protocol definition at the beginning."):
		A1000(host=invalid_host, token=token)

	with pytest.raises(WrongInputError, match=r"If token is not provided username and password are required."):
		A1000(host=valid_host)

	authorization = a1000._headers.get("Authorization")
	assert authorization == f"Token {token}"


@pytest.fixture
def requests_mock():
	with mock.patch('ReversingLabs.SDK.a1000.requests', autospec=True) as requests_mock:
		yield requests_mock


class TestA1000:
	host = "https://my.host"
	token = "token"
	fields = ("id", "sha1", "sha256", "sha512", "md5", "category", "file_type", "file_subtype",
	   "identification_name", "identification_version", "file_size", "extracted_file_count",
	   "local_first_seen", "local_last_seen", "classification_origin", "classification_reason",
	   "classification_source", "classification", "riskscore", "classification_result", "ticore", "tags",
	   "summary", "ticloud", "aliases", "networkthreatintelligence", "domainthreatintelligence"
	   )

	ticore_fields = "sha1, sha256, sha512, md5, imphash, info, application, protection, security, behaviour," \
					" certificate, document, mobile, media, web, email, strings, interesting_strings," \
					" classification, indicators, tags, attack, story"

	headers = {"User-Agent": DEFAULT_USER_AGENT, "Authorization": f"Token {token}"}

	@classmethod
	def setup_class(cls):
		cls.a1000 = A1000(cls.host, token=cls.token)

	def test_submit_url(self, requests_mock):
		self.a1000.submit_url_for_analysis(url_string="https://some.url")

		expected_url = f"{self.host}/api/uploads/"
		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} submit_url_for_analysis"

		requests_mock.post.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None,
			json=None,
			data={"url": "https://some.url", "analysis": "cloud"},
			files=None
		)

	def test_sample_from_file(self):
		with pytest.raises(WrongInputError, match=r"file_source parameter must be a file open in 'rb' mode."):
			self.a1000.upload_sample_from_file(file_source="/path/to/file")

	def test_file_status(self, requests_mock):
		self.a1000.file_analysis_status(sample_hashes=[SHA1, SHA1], sample_status="MALICIOUS")

		expected_url = f"{self.host}/api/samples/status/"
		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} file_analysis_status"

		requests_mock.post.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params={"status": "MALICIOUS"},
			json=None,
			data={"hash_values": [SHA1, SHA1]},
			files=None
		)

	def test_url_status(self, requests_mock):
		self.a1000.check_submitted_url_status(task_id="aaa")

		expected_url = f"{self.host}/api/uploads/v2/url-samples/aaa"
		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} check_submitted_url_status"

		requests_mock.get.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None
		)

	def test_url_report(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"task_id parameter must be a string."):
			self.a1000.get_submitted_url_report(task_id=123, retry=False)

	def test_detailed_report(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"fields parameter must be a list of strings."):
			self.a1000.get_detailed_report_v2(sample_hashes=SHA1, fields="field1,field2")

	def test_download_sample(self, requests_mock):
		self.a1000.download_sample(sample_hash=SHA1)

		expected_url = f"{self.host}/api/samples/{SHA1}/download/"
		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} download_sample"

		requests_mock.get.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None
		)

	def test_wrong_id(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"task_id parameter must be a string."):
			self.a1000.get_submitted_url_report(task_id=123, retry=False)

		assert not requests_mock.get.called

	def test_classification(self, requests_mock):
		self.a1000.get_classification_v3(sample_hash=SHA1, local_only=True)

		expected_url = f"{self.host}/api/samples/v3/{SHA1}/classification/?localonly=1&av_scanners=0"
		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} get_classification_v3"

		requests_mock.get.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None
		)

	def test_reanalyze(self, requests_mock):
		self.a1000.reanalyze_samples_v2(
			hash_input=SHA1,
			titanium_cloud=True
		)

		data = {
			"hash_value": [SHA1],
			"analysis": "cloud",
			"rl_cloud_sandbox_platform": None
		}

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} reanalyze_samples_v2"

		requests_mock.post.assert_called_with(
			url=f"{self.host}/api/samples/v2/analyze_bulk/",
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None,
			json=None,
			data=data,
			files=None
		)

	def test_extracted_files(self, requests_mock):
		self.a1000.list_extracted_files_v2(SHA1)

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} list_extracted_files_v2"

		requests_mock.get.assert_called_with(
			url=f"{self.host}/api/samples/v2/{SHA1}/extracted-files/",
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None
		)

	def test_download_extracted(self, requests_mock):
		self.a1000.download_extracted_files(SHA1)

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} download_extracted_files"

		requests_mock.get.assert_called_with(
			url=f"{self.host}/api/samples/{SHA1}/unpacked/",
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None
		)

	def test_delete_file(self, requests_mock):
		self.a1000.delete_samples([SHA1, SHA1])

		data = {"hash_values": [SHA1, SHA1]}

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} delete_samples"

		requests_mock.post.assert_called_with(
			url=f"{self.host}/api/samples/v2/delete_bulk/",
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None,
			json=None,
			data=data,
			files=None
		)

	def test_pdf_report(self, requests_mock):
		self.a1000.create_pdf_report(SHA1)

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} __utilize_pdf_endpoint"

		requests_mock.get.assert_called_with(
			url=f"{self.host}/api/pdf/{SHA1}/create",
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None
		)

	def test_ticore_report(self, requests_mock):
		self.a1000.get_titanium_core_report_v2(SHA1)

		expected_url = f"{self.host}/api/v2/samples/{SHA1}/ticore/?fields={self.ticore_fields}"

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} get_titanium_core_report_v2"

		requests_mock.get.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None
		)

	def test_dynamic_report(self, requests_mock):
		self.a1000.create_dynamic_analysis_report(SHA1, "pdf")

		expected_url = f"{self.host}/api/rl_dynamic_analysis/export/summary/{SHA1}/pdf/create/"

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} __utilize_dynamic_analysis_endpoint"

		requests_mock.get.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None
		)

	def test_wrong_dynamic_params(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"report_format parameter must be either 'html' or 'pdf'."):
			self.a1000.download_dynamic_analysis_report(SHA1, "xml")

		assert not requests_mock.get.called

	def test_set_classification(self, requests_mock):
		self.a1000.set_classification(SHA1, classification="malicious", system="local")

		data = {
			"classification": "malicious",
			"analysis": "cloud"
		}

		expected_url = f"{self.host}/api/samples/{SHA1}/setclassification/local/"

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} set_classification"

		requests_mock.post.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None,
			json=None,
			data=data,
			files=None
		)

	def test_user_tags(self, requests_mock):
		self.a1000.post_user_tags(SHA1, ["tag1", "tag2"])

		post_json = {"tags": ["tag1", "tag2"]}

		expected_url = f"{self.host}/api/tag/{SHA1}/"

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} post_user_tags"

		requests_mock.post.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None,
			json=post_json,
			data=None,
			files=None
		)

	def test_yara(self, requests_mock):
		self.a1000.get_yara_rulesets_on_the_appliance_v2(source="all")

		expected_url = f"{self.host}/api/yara/v2/rulesets/?source=all"

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} get_yara_rulesets_on_the_appliance_v2"

		requests_mock.get.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None
		)

	def test_enable_yara(self, requests_mock):
		self.a1000.enable_or_disable_yara_ruleset(
			enabled=True,
			name="the_ruleset",
			publish=True
		)

		data = {
			"name": "the_ruleset",
			"publish": True,
			"analysis": "cloud"
		}

		expected_url = f"{self.host}/api/yara/ruleset/enable/"

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} enable_or_disable_yara_ruleset"

		requests_mock.post.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None,
			json=None,
			data=data,
			files=None
		)

	def test_start_yara_retro(self, requests_mock):
		self.a1000.start_or_stop_yara_local_retro_scan("START")

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} start_or_stop_yara_local_retro_scan"

		requests_mock.post.assert_called_with(
			url=f"{self.host}/api/uploads/local-retro-hunt/",
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None,
			json=None,
			data={"operation": "START"},
			files=None
		)

	def test_yara_retro_status(self, requests_mock):
		pass

	def test_wrong_operation(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"operation parameter must be either 'START' or 'STOP'"):
			self.a1000.start_or_stop_yara_local_retro_scan("BEGIN")

		assert not requests_mock.post.called

	def test_advanced_search(self, requests_mock):
		self.a1000.advanced_search_v3(query_string="av-count:5 available:TRUE", sorting_criteria="sha1", sorting_order="desc", page_number=2, records_per_page=5)

		post_json = {"query": "av-count:5 available:TRUE", "ticloud": False, "page": 2,
					 "records_per_page": 5, "sort": "sha1 desc"}

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} advanced_search_v3"

		requests_mock.post.assert_called_with(
			url=f"{self.host}/api/samples/v3/search/",
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None,
			json=post_json,
			data=None,
			files=None
		)

	def test_list_containers(self, requests_mock):
		self.a1000.list_containers_for_hashes([SHA1, SHA1])

		data = {"hash_values": [SHA1, SHA1]}

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} list_containers_for_hashes"

		requests_mock.post.assert_called_with(
			url=f"{self.host}/api/samples/containers/",
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None,
			json=None,
			data=data,
			files=None
		)

	def test_domain_report(self, requests_mock):
		domain = "some.test.domain"

		self.a1000.network_domain_report(domain)

		expected_url = f"{self.host}/api/network-threat-intel/domain/{domain}/"

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} network_domain_report"

		requests_mock.get.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params=None
		)

	def test_ip_to_domain(self, requests_mock):
		self.a1000.network_ip_to_domain("1.2.3.4")

		params = {
			"page": None,
			"page_size": 500
		}

		expected_url = f"{self.host}/api/network-threat-intel/ip/1.2.3.4/resolutions/"

		self.headers["User-Agent"] = f"{DEFAULT_USER_AGENT}; {self.a1000.__class__.__name__} __ip_addr_endpoints"

		requests_mock.get.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers=self.headers,
			params=params
		)

	def test_files_from_ip(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"is allowed as the classification input"):
			self.a1000.network_files_from_ip(ip_addr="1.2.3.4", classification="KNOWN")
