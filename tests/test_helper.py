from ReversingLabs.SDK.helper import *
from ReversingLabs.SDK import __version__


STATUS_ERRORS = (
	NotFoundError, NoFileTypeError, UnauthorizedError, WrongInputError, ForbiddenError, BadRequestError,
	RequestTimeoutError, ConflictError, RequestTooLargeError, InternalServerError, BadGatewayError,
	ServiceUnavailableError, NotAllowedError, TooManyRequestsError, NotAcceptableError
)
OTHER_ERRORS = (
	WrongInputError,
)
ALL_ERRORS = STATUS_ERRORS + OTHER_ERRORS


def test_vars():
	assert HASH_LENGTH_MAP.get(32) == MD5
	assert HASH_LENGTH_MAP.get(40) == SHA1
	assert HASH_LENGTH_MAP.get(64) == SHA256
	assert HASH_LENGTH_MAP.get(128) == SHA512

	assert MD5 == "md5"
	assert SHA1 == "sha1"
	assert SHA256 == "sha256"
	assert SHA512 == "sha512"

	assert __version__ in DEFAULT_USER_AGENT


def test_errors():
	for err_cls in ALL_ERRORS:
		if err_cls in OTHER_ERRORS:
			continue

		err_cls(response_object=True)
		del err_cls


def test_validate_hashes():
	validate_hashes(
		hash_input=[
			"00f8cd09187d311707b52a1c52018e7cfb5f2f78e47bf9200f16281098741422",
			"5377d0ed664246a604363f90a2764aa10fa63ad0",
			"512fca9e83c47fd9c36aa7d50a856396",
		],
		allowed_hash_types=(SHA256, SHA1, MD5)
	)
