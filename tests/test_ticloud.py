import pytest
import requests
from unittest import mock
from ReversingLabs.SDK.ticloud import TiCloudAPI, FileReputation, AVScanners, FileAnalysis, FileAnalysisNonMalicious, \
	AdvancedSearch, ExpressionSearch, RHA1FunctionalSimilarity, RHA1Analytics, URIStatistics, URIIndex, FileDownload, \
	URLThreatIntelligence, AnalyzeURL, DomainThreatIntelligence, IPThreatIntelligence, FileUpload, DeleteFile, \
	ReanalyzeFile, DataChangeSubscription, DynamicAnalysis, CertificateIndex, RansomwareIndicators, NewMalwareFilesFeed, \
	NewMalwareURIFeed, ImpHashSimilarity, YARAHunting, YARARetroHunting, TAXIIRansomwareFeed, CustomerUsage, NetworkReputation, \
	CLASSIFICATIONS, AVAILABLE_PLATFORMS, RHA1_TYPE_MAP, \
	resolve_hash_type, calculate_hash, NotFoundError
from ReversingLabs.SDK.helper import WrongInputError, BadGatewayError, DEFAULT_USER_AGENT

MD5 = "512fca9e83c47fd9c36aa7d50a856396"
SHA1 = "5377d0ed664246a604363f90a2764aa10fa63ad0"
SHA256 = "00f8cd09187d311707b52a1c52018e7cfb5f2f78e47bf9200f16281098741422"
HOST = "https://example.com"
USERNAME = "username"
PASSWORD = "password"

EXPECTED_PLATFORMS = ("windows7", "windows10", "macos11", "windows11", "linux")
EXPECTED_RHA1_TYPES = {
	"PE": "pe01",
	"PE+": "pe01",
	"PE16": "pe01",
	"PE32": "pe01",
	"PE32+": "pe01",
	"MachO32 Big": "macho01",
	"MachO32 Little": "macho01",
	"MachO64 Big": "macho01",
	"MachO64 Little": "macho01",
	"ELF32 Big": "elf01",
	"ELF32 Little": "elf01",
	"ELF64 Big": "elf01",
	"ELF64 Little": "elf01"
}


def test_calculate_hash():
	test_url = "https://some.url.com/document.xml"

	assert calculate_hash(test_url, "sha1") == "6f87faff4a44a3a97827ce42233c58104e9411e0"


def test_classifications():
	assert "KNOWN" in CLASSIFICATIONS, "Are you sure that KNOWN should be removed from allowed classifications?"
	assert "GOODWARE" not in CLASSIFICATIONS, "Are you sure that GOODWARE should be in allowed classifications?"


def test_platforms():
	assert "macos_11" not in AVAILABLE_PLATFORMS, "Did we start using macos_11 in cloud classifications?"

	for platform in EXPECTED_PLATFORMS:
		assert platform in AVAILABLE_PLATFORMS, "Are you sure some of the existing platforms needs to be removed?"


def test_rha1_types():
	for rha1_type in EXPECTED_RHA1_TYPES:
		assert rha1_type in RHA1_TYPE_MAP, "Are you sure some of the existing RHA1 types need to be changed or removed?"


def test_ticloud_object():
	valid_host = "some.host"
	invalid_host = "http://some.host"
	username = "u/username"
	password = "password"

	cloud_obj = TiCloudAPI(
		host=valid_host,
		username=username,
		password=password
	)

	assert cloud_obj._host == f"https://{valid_host}"

	with pytest.raises(WrongInputError, match=r"Unsupported protocol definition"):
		TiCloudAPI(host=invalid_host, username=username, password=password)

	resp = requests.Response()
	resp.status_code = 502

	with pytest.raises(BadGatewayError) as e:
		cloud_obj._raise_on_error(response=resp)
		assert e.value.response_object, "The _raise_on_error method did not assign the response object."


def test_hash_resolving():
	same_hash_types = [
		"5377d0ed664246a604363f90a2764aa10fa63ad0",
		"21841b32c6165b27dddbd4d6eb3a672defe54271",
		"efabc8b39de9d1f136abc48dc6e47f30a2ce9245"
	]
	various_hash_types = [
		"5377d0ed664246a604363f90a2764aa10fa63ad0",
		"00f8cd09187d311707b52a1c52018e7cfb5f2f78e47bf9200f16281098741422",
		"512fca9e83c47fd9c36aa7d50a856396"
	]

	assert resolve_hash_type(sample_hashes=same_hash_types) == "sha1"

	with pytest.raises(WrongInputError, match=r"Hash on position 1 is a/an sha256"):
		resolve_hash_type(sample_hashes=various_hash_types)


@pytest.fixture
def requests_mock():
	with mock.patch('ReversingLabs.SDK.ticloud.requests', autospec=True) as requests_mock:
		yield requests_mock


@pytest.fixture
def file_type_mock():
	with mock.patch("ReversingLabs.SDK.ticloud.get_rha1_type", autospec=True) as file_type_mock:
		yield file_type_mock


class TestFileReputation:
	password = "password"

	@classmethod
	def setup_class(cls):
		cls.file_reputation = FileReputation(HOST, USERNAME, PASSWORD)

	def test_wrong_input_hash(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"Only hash string or list of hash strings are allowed"):
			self.file_reputation.get_file_reputation(123)

		with pytest.raises(WrongInputError, match=r"The given hash input string is not a valid hexadecimal value."):
			self.file_reputation.get_file_reputation([123, 456])

		assert not requests_mock.get.called

	def test_request_single_hash(self, requests_mock):
		requests_mock.get.return_value.status_code = 200
		self.file_reputation.get_file_reputation(SHA1)

		expected_url = (f"{HOST}/api/databrowser/malware_presence/query/sha1/{SHA1}?extended=true&"
						f"show_hashes=true&format=json")

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)

	def test_request_multiple_hashes(self, requests_mock):
		requests_mock.post.return_value.status_code = 200
		hashes = [SHA1] * 3

		self.file_reputation.get_file_reputation(hashes)

		expected_url = f"{HOST}/api/databrowser/malware_presence/bulk_query/json?extended=true&show_hashes=true"

		expected_payload = {"rl": {"query": {"hash_type": "sha1", "hashes": hashes}}}

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			json=expected_payload,
			data=None,
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)

	def test_error_status_code(self, requests_mock):
		requests_mock.get.return_value.status_code = 404

		with pytest.raises(NotFoundError):
			self.file_reputation.get_file_reputation(SHA1)


class TestAVScanners:
	@classmethod
	def setup_class(cls):
		cls.av_scanners = AVScanners(HOST, USERNAME, PASSWORD)

	def test_wrong_input_hash(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"Only hash string or list of hash strings are allowed"):
			self.av_scanners.get_scan_results(123)

		with pytest.raises(WrongInputError, match=r"The given hash input string is not a valid hexadecimal value."):
			self.av_scanners.get_scan_results(f"{SHA1},{SHA1}")

		assert not requests_mock.get.called

	def test_single_hash(self, requests_mock):
		requests_mock.get.return_value.status_code = 200

		self.av_scanners.get_scan_results(SHA1, historical_results=True)

		expected_url = f"{HOST}/api/xref/v2/query/sha1/{SHA1}?format=json&history=true"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestFileAnalysis:
	@classmethod
	def setup_class(cls):
		cls.rldata = FileAnalysis(HOST, USERNAME, PASSWORD)

	def test_wrong_input_hash(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"Only hash string or list of hash strings are allowed"):
			self.rldata.get_analysis_results(123)

		assert not requests_mock.get.called

	def test_bulk_query(self, requests_mock):
		requests_mock.post.return_value.status_code = 200

		self.rldata.get_analysis_results([SHA256, SHA256])

		expected_url = f"{HOST}/api/databrowser/rldata/bulk_query/json"

		post_json = {"rl": {"query": {"hash_type": "sha256", "hashes": [SHA256, SHA256]}}}

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None,
			json=post_json,
			data=None
		)


class TestFileAnalysisNonMalicious:
	@classmethod
	def setup_class(cls):
		cls.rldata_nonmal = FileAnalysisNonMalicious(HOST, USERNAME, PASSWORD)

	def test_wrong_input_hash(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"The given hash input string is not a valid hexadecimal value."):
			self.rldata_nonmal.get_analysis_results(123)

		assert not requests_mock.get.called

	def test_single_query(self, requests_mock):
		requests_mock.get.return_value.status_code = 200

		self.rldata_nonmal.get_analysis_results(SHA1)

		expected_url = f"{HOST}/api/databrowser/rldata/goodware/query/sha1/{SHA1}"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params={"format": "json"}
		)


class TestRHA1FunctionalSimilarity:
	hash = "21841b32c6165b27dddbd4d6eb3a672defe54271"

	@classmethod
	def setup_class(cls):
		cls.rha1 = RHA1FunctionalSimilarity(HOST, USERNAME, PASSWORD)

	def test_wrong_input_hash(self, requests_mock):
		with pytest.raises(WrongInputError,
						   match=r"Only hash strings of the following types are allowed as input values:"):
			self.rha1.get_similar_hashes(SHA256)

		assert not requests_mock.get.called

	def test_single_query(self, requests_mock, file_type_mock):
		requests_mock.get.return_value.status_code = 200
		file_type_mock.return_value = "pe01"

		self.rha1.get_similar_hashes(self.hash, extended_results=True)

		expected_url = f"{HOST}/api/group_by_rha1/v1/query/pe01/{self.hash}?format=json&limit=1000&extended=true"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestRHA1Analytics:
	hash = "21841b32c6165b27dddbd4d6eb3a672defe54271"

	@classmethod
	def setup_class(cls):
		cls.rha1 = RHA1Analytics(HOST, USERNAME, PASSWORD)

	def test_wrong_input_hash(self, requests_mock):
		with pytest.raises(WrongInputError,
						   match=r"Only hash strings of the following types are allowed as input values:"):
			self.rha1.get_rha1_analytics(SHA256)

		assert not requests_mock.get.called

	def test_single_query(self, requests_mock, file_type_mock):
		requests_mock.get.return_value.status_code = 200
		file_type_mock.return_value = "pe01"

		self.rha1.get_rha1_analytics(self.hash, extended_results=True)

		expected_url = f"{HOST}/api/rha1/analytics/v1/query/pe01/{self.hash}?format=json&extended=true"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestURIStatistics:
	test_url = "https://www.softpedia.com/get/Office-tools/Text-editors/Sublime-Text.shtml"

	@classmethod
	def setup_class(cls):
		cls.uristats = URIStatistics(HOST, USERNAME, PASSWORD)

	def test_query(self, requests_mock):
		requests_mock.get.return_value.status_code = 200

		self.uristats.get_uri_statistics(self.test_url)

		expected_url = f"{HOST}/api/uri/statistics/uri_state/sha1/0164af1f2e83a7411a3c8cfd02b1424156a21b6b?format=json"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestURIIndex:
	test_url = "https://www.softpedia.com/get/Office-tools/Text-editors/Sublime-Text.shtml"

	@classmethod
	def setup_class(cls):
		cls.uri_index = URIIndex(HOST, USERNAME, PASSWORD)

	def test_wrong_input(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"Only a single email address, URL, DNS name or IPv4 string is "
												  r"allowed as the uri_input parameter."):
			self.uri_index.get_uri_index(123)

	def test_single_query(self, requests_mock):
		requests_mock.get.return_value.status_code = 200

		self.uri_index.get_uri_index(self.test_url, classification="MALICIOUS",
									 page_sha1="21841b32c6165b27dddbd4d6eb3a672defe54271")

		expected_url = (f"{HOST}/api/uri_index/v1/query/0164af1f2e83a7411a3c8cfd02b1424156a21b6b/21841b32c6165b27dddbd4d6eb3a672defe54271?"
						f"format=json&classification=MALICIOUS")

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestAdvancedSearch:
	@classmethod
	def setup_class(cls):
		cls.adv_search = AdvancedSearch(HOST, USERNAME, PASSWORD)

	def test_wrong_input(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"records_per_page parameter must be integer with value between 1 and 10000"):
			self.adv_search.search("search_query", records_per_page=12000)

		with pytest.raises(WrongInputError, match=r"Sorting criteria must be one of the following options"):
			self.adv_search.search("search_query", sorting_criteria="wrong", sorting_order="also_wrong")

		assert not requests_mock.post.called

	def test_single_query(self, requests_mock):
		requests_mock.post.return_value.status_code = 200

		self.adv_search.search(query_string="av-count:5 available:TRUE", sorting_criteria="sha1", sorting_order="desc", page_number=2, records_per_page=5)

		expected_url = f"{HOST}/api/search/v1/query"

		post_json = {"query": "av-count:5 available:TRUE", "page": 2, "records_per_page": 5, "format": "json", "sort": "sha1 desc"}

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None,
			json=post_json,
			data=None
		)


class TestExpressionSearch:
	@classmethod
	def setup_class(cls):
		cls.exp_search = ExpressionSearch(HOST, USERNAME, PASSWORD)

	def test_wrong_input(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"query parameter must be a list of strings."):
			self.exp_search.search(query="av-count:5 available:TRUE")

		with pytest.raises(WrongInputError, match=r"query list must have at least 2 expressions."):
			self.exp_search.search(query=["status=MALICIOUS"])

		with pytest.raises(WrongInputError, match=r"All expressions in the query list must be strings."):
			self.exp_search.search(query=["status=MALICIOUS", 123])

		assert not requests_mock.get.called

	def test_single_query(self, requests_mock):
		requests_mock.get.return_value.status_code = 200

		self.exp_search.search(query=["one=1", "two=2"], date="2024-07-03", page_number=2)

		expected_url = f"{HOST}/api/sample/search/download/v1/query/date/2024-07-03?format=json&page=2&one=1&two=2"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestFileDownload:
	@classmethod
	def setup_class(cls):
		cls.download = FileDownload(HOST, USERNAME, PASSWORD)

	def test_status(self, requests_mock):
		requests_mock.post.return_value.status_code = 200

		self.download.get_download_status(SHA1)

		expected_url = f"{HOST}/api/spex/download/v2/status/bulk_query/json?format=json"

		post_json = {"rl": {"query": {"hash_type": "sha1", "hashes": [SHA1]}}}

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None,
			json=post_json,
			data=None
		)

	def test_download(self, requests_mock):
		requests_mock.get.return_value.status_code = 200

		self.download.download_sample(SHA1)

		expected_url = f"{HOST}/api/spex/download/v2/query/sha1/{SHA1}"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestURLThreatIntelligence:
	test_url = "https://www.softpedia.com/get/Office-tools/Text-editors/Sublime-Text.shtml"

	@classmethod
	def setup_class(cls):
		cls.url_ti = URLThreatIntelligence(HOST, USERNAME, PASSWORD)

	def test_query(self, requests_mock):
		self.url_ti.get_url_report(self.test_url)

		expected_url = f"{HOST}/api/networking/url/v1/report/query/json"

		post_json = {"rl": {"query": {"url": "https://www.softpedia.com/get/Office-tools/Text-editors/Sublime-Text.shtml", "response_format": "json"}}}

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None,
			json=post_json,
			data=None
		)


class TestAnalyzeURL:
	test_url = "https://www.softpedia.com/get/Office-tools/Text-editors/Sublime-Text.shtml"

	@classmethod
	def setup_class(cls):
		cls.analyze_url = AnalyzeURL(HOST, USERNAME, PASSWORD)

	def test_query(self, requests_mock):
		self.analyze_url.submit_url(url_input=self.test_url)

		expected_url = f"{HOST}/api/networking/url/v1/analyze/query/json"

		post_json = {"rl": {"query": {"url": "https://www.softpedia.com/get/Office-tools/Text-editors/Sublime-Text.shtml", "response_format": "json"}}}

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None,
			json=post_json,
			data=None
		)


class TestDomainThreatIntelligence:
	domain = "some.test.domain"

	@classmethod
	def setup_class(cls):
		cls.domain_ti = DomainThreatIntelligence(HOST, USERNAME, PASSWORD)

	def test_query(self, requests_mock):
		self.domain_ti.get_domain_report(self.domain)

		expected_url = f"{HOST}/api/networking/domain/report/v1/query/json"

		post_json = {"rl": {"query": {"domain": "some.test.domain", "response_format": "json"}}}

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None,
			json=post_json,
			data=None
		)


class TestIPThreatIntelligence:
	ip = "1.1.1.1"

	@classmethod
	def setup_class(cls):
		cls.ip_ti = IPThreatIntelligence(HOST, USERNAME, PASSWORD)

	def test_wrong_input(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"p_address parameter must be string."):
			self.ip_ti.get_ip_report(ip_address=1.1)

		assert not requests_mock.post.called

	def test_query(self, requests_mock):
		self.ip_ti.get_ip_report(ip_address=self.ip)

		expected_url = f"{HOST}/api/networking/ip/report/v1/query/json"

		post_json = {"rl": {"query": {"ip": "1.1.1.1", "response_format": "json"}}}

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None,
			json=post_json,
			data=None
		)


class TestFileUpload:
	@classmethod
	def setup_class(cls):
		cls.upload = FileUpload(HOST, USERNAME, PASSWORD)

	def test_upload_meta(self, requests_mock):
		self.upload._FileUpload__upload_meta(
			url="https://mock.url",
			sample_name="test_name",
			sample_domain="test_domain",
			subscribe="data_change",
			archive_type=None,
			archive_password=None
		)

		expected_url = "https://mock.url/meta"
		params = {"subscribe": "data_change"}
		meta_xml = ("<rl><properties><property><name>file_name</name><value>test_name</value></property></properties>"
					"<domain>test_domain</domain></rl>")

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=params,
			json=None,
			data=meta_xml
		)


class TestDeleteFile:
	@classmethod
	def setup_class(cls):
		cls.delete_file = DeleteFile(HOST, USERNAME, PASSWORD)

	def test_query(self, requests_mock):
		self.delete_file.delete_samples(SHA1, delete_on=1234567)

		expected_url = f"{HOST}/api/delete/sample/v1/query/sha1/{SHA1}?delete_on=1234567"

		requests_mock.delete.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			json=None
		)


class TestReanalyzeFile:
	@classmethod
	def setup_class(cls):
		cls.reanalyze = ReanalyzeFile(HOST, USERNAME, PASSWORD)

	def test_query(self, requests_mock):
		self.reanalyze.reanalyze_samples(SHA1)

		expected_url = f"{HOST}/api/rescan/v1/query/sha1/{SHA1}"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestDataChangeSubscription:
	@classmethod
	def setup_class(cls):
		cls.data_change = DataChangeSubscription(HOST, USERNAME, PASSWORD)

	def test_query(self, requests_mock):
		self.data_change.subscribe([SHA1, SHA1])

		expected_url = f"{HOST}/api/subscription/data_change/v1/bulk_query/subscribe/json"

		post_json = {"rl": {"query": {"hash_type": "sha1", "hashes": [SHA1, SHA1]}}}

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None,
			json=post_json,
			data=None
		)


class TestDynamicAnalysis:
	@classmethod
	def setup_class(cls):
		cls.da = DynamicAnalysis(HOST, USERNAME, PASSWORD)

	def test_detonate_file(self, requests_mock):
		self.da.detonate_sample(
			sample_hash=SHA1,
			platform="windows10",
			internet_simulation=True,
			sample_name="sample_name"
		)

		expected_url = f"{HOST}/api/dynamic/analysis/analyze/v1/query/json"

		post_json = {"rl": {"platform": "windows10", "response_format": "json", "sha1": SHA1, "optional_parameters": "sample_name=sample_name, internet_simulation=true"}}

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None,
			json=post_json,
			data=None
		)


class TestCertificateIndex:
	@classmethod
	def setup_class(cls):
		cls.ci = CertificateIndex(HOST, USERNAME, PASSWORD)

	def test_query(self, requests_mock):
		self.ci.get_certificate_information(SHA1, classification="MALICIOUS", next_page_hash=SHA1)

		expected_url = (f"{HOST}/api/certificate/index/v1/query/thumbprint/{SHA1}/page/{SHA1}"
						f"?format=json&extended=true&limit=100&classification=MALICIOUS")

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestRansomwareIndicators:
	@classmethod
	def setup_class(cls):
		cls.rf = RansomwareIndicators(HOST, USERNAME, PASSWORD)

	def test_query(self, requests_mock):
		self.rf.get_indicators(
			hours_back=3,
			indicator_types=['ipv4', 'hash', 'domain', 'uri']
		)

		expected_url = f"{HOST}/api/public/v1/ransomware/indicators?withHealth=0&tagFormat=dict&" \
						  "hours=3&indicatorTypes=ipv4,hash,domain,uri&onlyFreemium=0"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestNewMalwareFilesFeed:
	@classmethod
	def setup_class(cls):
		cls.feed = NewMalwareFilesFeed(HOST, USERNAME, PASSWORD)

	def test_pull(self, requests_mock):
		self.feed.pull_with_timestamp(
			time_format="timestamp",
			time_value="1234567"
		)

		expected_url = f"{HOST}/api/feed/malware/detection/v1/query/timestamp/1234567?format=json&sample_available=false&limit=1000"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestNewMalwareURIFeed:
	@classmethod
	def setup_class(cls):
		cls.feed = NewMalwareURIFeed(HOST, USERNAME, PASSWORD)

	def test_pull(self, requests_mock):
		self.feed.pull_latest()

		expected_url = f"{HOST}/api/feed/malware_uri/v1/query/latest?format=json"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestImpHashSimilarity:
	@classmethod
	def setup_class(cls):
		cls.imphash = ImpHashSimilarity(HOST, USERNAME, PASSWORD)

	def test_imphash(self, requests_mock):
		imphash = "abcdefg"

		self.imphash.get_imphash_index(imphash, next_page_sha1=SHA1)

		expected_url = f"{HOST}/api/imphash_index/v1/query/{imphash}/start_sha1/{SHA1}?format=json"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None
		)


class TestYARAHunting:
	@classmethod
	def setup_class(cls):
		cls.yara = YARAHunting(HOST, USERNAME, PASSWORD)

	def test_yara(self, requests_mock):
		self.yara.create_ruleset(
			ruleset_name="name",
			ruleset_text="ruleset_text"
		)

		post_json = {
			"ruleset_name": "name",
			"text": "ruleset_text"
		}

		expected_url = f"{HOST}/api/yara/admin/v1/ruleset"

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None,
			json=post_json,
			data=None
		)

	def test_wrong_ruleset_text(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"ruleset_text parameter must be unicode string."):
			self.yara.create_ruleset(ruleset_name="name", ruleset_text=123)

		assert not requests_mock.post.called


class TestYARARetroHunting:
	@classmethod
	def setup_class(cls):
		cls.yara = YARARetroHunting(HOST, USERNAME, PASSWORD)

	def test_enable_retro(self, requests_mock):
		ruleset_name = "name"

		self.yara.enable_retro_hunt(ruleset_name=ruleset_name)

		expected_url = f"{HOST}/api/yara/admin/v1/ruleset/enable-retro-hunt"

		post_json = {"ruleset_name": ruleset_name}

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None,
			json=post_json,
			data=None
		)


class TestTAXIIRansomwareFeed:
	@classmethod
	def setup_class(cls):
		cls.taxii = TAXIIRansomwareFeed(HOST, USERNAME, PASSWORD)

	def test_get_objects(self, requests_mock):
		self.taxii.get_objects(
			api_root="lite-root",
			collection_id="123456"
		)

		query_params = {
			"limit": 500,
			"added_after": None,
			"match[id]": None,
			"next": None
		}

		expected_url = f"{HOST}/api/taxii/lite-root/collections/123456/objects/"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT, 'Accept': 'application/taxii+json;version=2.1'},
			params=query_params
		)


class TestCustomerUsage:
	@classmethod
	def setup_class(cls):
		cls.usage = CustomerUsage(HOST, USERNAME, PASSWORD)

	def test_usage(self, requests_mock):
		self.usage.daily_usage(single_date="2024-07-03")

		expected_url = f"{HOST}/api/customer_usage/v1/usage/daily"

		requests_mock.get.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params={"date": "2024-07-03", "format": "json", "from": None, "to": None}
		)


class TestNetworkReputation:
	@classmethod
	def setup_class(cls):
		cls.net_rep = NetworkReputation(HOST, USERNAME, PASSWORD)

	def test_query(self, requests_mock):
		locations = ["some.domain", "another.domain"]

		self.net_rep.get_network_reputation(
			network_locations=locations
		)

		expected_url = f"{HOST}/api/networking/reputation/v1/query/json"

		post_json = {"rl": {"query": {"network_locations": [{"network_location": "some.domain"}, {"network_location": "another.domain"}], "response_format": "json"}}}

		requests_mock.post.assert_called_with(
			url=expected_url,
			auth=(USERNAME, PASSWORD),
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT},
			params=None,
			json=post_json,
			data=None
		)
