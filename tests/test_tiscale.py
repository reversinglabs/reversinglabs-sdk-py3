import pytest
from unittest import mock
from ReversingLabs.SDK import __version__
from ReversingLabs.SDK.tiscale import TitaniumScale
from ReversingLabs.SDK.helper import WrongInputError, DEFAULT_USER_AGENT


def test_tiscale_object():
	invalid_host = "my.host"
	valid_host = f"https://{invalid_host}"
	token = "my_mock_token"

	tiscale = TitaniumScale(
		host=valid_host,
		token=token,
		verify=True
	)

	assert tiscale._url == valid_host + "{endpoint}"

	with pytest.raises(WrongInputError, match=r"host parameter must contain a protocol definition at the beginning."):
		TitaniumScale(host=invalid_host, token=token)

	user_agent = tiscale._headers.get("User-Agent")
	assert __version__ in user_agent


@pytest.fixture
def requests_mock():
	with mock.patch('ReversingLabs.SDK.tiscale.requests', autospec=True) as requests_mock:
		yield requests_mock


class TestTitaniumScale:
	host = "https://my.host"
	token = "token"

	@classmethod
	def setup_class(cls):
		cls.tiscale = TitaniumScale(cls.host, token=cls.token)

	def test_list_tasks(self, requests_mock):
		self.tiscale.list_processing_tasks(age=10, custom_token="custom")

		query_params = {
			"age": 10,
			"token": "Token custom"
		}

		expected_url = f"{self.host}/api/tiscale/v1/task"

		requests_mock.get.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT, "Authorization": f"Token {self.token}"},
			params=query_params
		)

	def test_task_info(self, requests_mock):
		self.tiscale.get_processing_task_info(
			task_id=1,
			full=True
		)

		query_params = {
			"full": "true",
			"v13": "false"
		}

		expected_url = f"{self.host}/api/tiscale/v1/task/1"

		requests_mock.get.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT, "Authorization": f"Token {self.token}"},
			params=query_params
		)

	def test_delete_task(self, requests_mock):
		self.tiscale.delete_processing_task(
			task_id=1
		)

		expected_url = f"{self.host}/api/tiscale/v1/task/1"

		requests_mock.delete.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT, "Authorization": f"Token {self.token}"}
		)

	def test_wrong_task_id(self, requests_mock):
		with pytest.raises(WrongInputError, match=r"task_id parameter must be integer."):
			self.tiscale.delete_processing_task(task_id="123")

		assert not requests_mock.delete.called

	def test_delete_multiple(self, requests_mock):
		self.tiscale.delete_multiple_tasks(age=10)

		query_params = {"age": 10}

		expected_url = f"{self.host}/api/tiscale/v1/task"

		requests_mock.delete.assert_called_with(
			url=expected_url,
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT, "Authorization": f"Token {self.token}"},
			params=query_params
		)

	def test_yara_id(self, requests_mock):
		self.tiscale.get_yara_id()

		requests_mock.get.assert_called_with(
			url=f"{self.host}/api/tiscale/v1/yara",
			verify=True,
			proxies=None,
			headers={"User-Agent": DEFAULT_USER_AGENT, "Authorization": f"Token {self.token}"}
		)

