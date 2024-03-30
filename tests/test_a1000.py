import pytest
from ReversingLabs.SDK import __version__
from ReversingLabs.SDK.a1000 import CLASSIFICATIONS, AVAILABLE_PLATFORMS, A1000
from ReversingLabs.SDK.helper import WrongInputError


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

	user_agent = a1000._headers.get("User-Agent")
	assert __version__ in user_agent

	authorization = a1000._headers.get("Authorization")
	assert authorization == f"Token {token}"

