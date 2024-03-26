import pytest
from ReversingLabs.SDK import __version__
from ReversingLabs.SDK.a1000 import CLASSIFICATIONS, AVAILABLE_PLATFORMS, A1000
from ReversingLabs.SDK.helper import WrongInputError


EXPECTED_PLATFORMS = ("windows7", "windows10", "macos_11", "windows11", "linux")


def test_classifications():
	assert "KNOWN" not in CLASSIFICATIONS
	assert "GOODWARE" in CLASSIFICATIONS


def test_available_platforms():
	for platform in AVAILABLE_PLATFORMS:
		assert platform in EXPECTED_PLATFORMS


def test_a1000_object():
	invalid_host = "my.host"
	valid_host = f"https://{invalid_host}"

	a1000 = A1000(
		host=valid_host,
		token="my_mock_token",
		verify=True
	)

	assert a1000._url == valid_host + "{endpoint}"

	with pytest.raises(WrongInputError, match=r"host parameter must contain a protocol definition at the beginning."):
		A1000(host=invalid_host, token="my_mock_token")

	with pytest.raises(WrongInputError, match=r"If token is not provided username and password are required."):
		A1000(host=valid_host)

	user_agent = a1000._headers.get("User-Agent")
	assert __version__ in user_agent


