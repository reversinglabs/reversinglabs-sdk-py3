import pytest
from unittest import mock
from ReversingLabs.SDK import __version__
from ReversingLabs.SDK.fie import FileInspectionEngine
from ReversingLabs.SDK.helper import WrongInputError, DEFAULT_USER_AGENT


def test_fie_object():
	invalid_host = "my.host"
	valid_host = f"https://{invalid_host}"

	fie = FileInspectionEngine(
		host=valid_host,
		verify=True
	)

	assert fie._url == valid_host + "{endpoint}"

	with pytest.raises(WrongInputError, match=r"host parameter must contain a protocol definition at the beginning."):
		FileInspectionEngine(host=invalid_host)

	user_agent = fie._headers.get("User-Agent")
	assert __version__ in user_agent


@pytest.fixture
def requests_mock():
	with mock.patch('ReversingLabs.SDK.fie.requests', autospec=True) as requests_mock:
		yield requests_mock


class TestFIE:
	host = "http://my.host"

	@classmethod
	def setup_class(cls):
		cls.fie = FileInspectionEngine(cls.host)

	def test_scan_using_path(self):
		with pytest.raises(WrongInputError, match=r"file_path must be a string."):
			self.fie.scan_using_file_path(file_path=123)

	def test_scan_using_file(self):
		with pytest.raises(WrongInputError, match=r"file_source parameter must be a file open in 'rb' mode."):
			self.fie.scan_using_open_file(file_source="/path/to/file")

	def test_report_using_path(self):
		with pytest.raises(WrongInputError, match=r"file_path must be a string."):
			self.fie.report_using_file_path(file_path=123)

	def test_report_using_file(self):
		with pytest.raises(WrongInputError, match=r"file_source parameter must be a file open in 'rb' mode."):
			self.fie.report_using_open_file(file_source="/path/to/file")
