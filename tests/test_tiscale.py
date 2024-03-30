import pytest
from ReversingLabs.SDK import __version__
from ReversingLabs.SDK.tiscale import TitaniumScale
from ReversingLabs.SDK.helper import WrongInputError


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
