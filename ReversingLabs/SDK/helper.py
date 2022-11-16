"""
author: Mislav Sever

Helper
A Python module containing common helper functions and variables for ReversingLabsSDK.
"""

import codecs
import binascii
from http import HTTPStatus


MD5 = "md5"
SHA1 = "sha1"
SHA256 = "sha256"
SHA512 = "sha512"

HASH_LENGTH_MAP = {
    32: MD5,
    40: SHA1,
    64: SHA256,
    128: SHA512
}

AVAILABLE_PLATFORMS = ("windows7", "windows10")

DEFAULT_USER_AGENT = "ReversingLabs integrations default user agent"
ADVANCED_SEARCH_SORTING_CRITERIA = ("sha1", "firstseen", "threatname", "sampletype", "filecount", "size")


class NotFoundError(Exception):
    def __init__(self, message="Not found. No reference was found for this input"):
        super(NotFoundError, self).__init__(message)


class NoFileTypeError(Exception):
    def __init__(self, message="There is no determinable file type"):
        super(NoFileTypeError, self).__init__(message)


class WrongInputError(Exception):
    def __init__(self, message="This input type is not allowed"):
        super(WrongInputError, self).__init__(message)


class UnauthorizedError(Exception):
    def __init__(self, message="The provided credentials are invalid"):
        super(UnauthorizedError, self).__init__(message)


class ForbiddenError(Exception):
    def __init__(self, message="The provided credentials do not have the required rights to access this resource"):
        super(ForbiddenError, self).__init__(message)


class BadRequestError(Exception):
    def __init__(self, message="Bad request created"):
        super(BadRequestError, self).__init__(message)


class RequestTimeoutError(Exception):
    def __init__(self, message="Request timed out"):
        super(RequestTimeoutError, self).__init__(message)


class ConflictError(Exception):
    def __init__(self, message="Can't complete the request due to a conflict"):
        super(ConflictError, self).__init__(message)


class RequestTooLargeError(Exception):
    def __init__(self, message="The request is too large"):
        super(RequestTooLargeError, self).__init__(message)


class InternalServerError(Exception):
    def __init__(self, message="Internal server error"):
        super(InternalServerError, self).__init__(message)


class BadGatewayError(Exception):
    def __init__(self, message="The server received an invalid response from another server"):
        super(BadGatewayError, self).__init__(message)


class ServiceUnavailableError(Exception):
    def __init__(self, message="Service unavailable"):
        super(ServiceUnavailableError, self).__init__(message)


class NotAllowedError(Exception):
    def __init__(self, message="This method is not allowed"):
        super(NotAllowedError, self).__init__(message)


class TooManyRequestsError(Exception):
    def __init__(self, message="Too many requests. Your quota limit might be reached"):
        super(TooManyRequestsError, self).__init__(message)


class NotAcceptableError(Exception):
    def __init__(self, message="This content is not acceptable"):
        super(NotAcceptableError, self).__init__(message)


RESPONSE_CODE_ERROR_MAP = {
    HTTPStatus.UNAUTHORIZED: UnauthorizedError,
    HTTPStatus.FORBIDDEN: ForbiddenError,
    HTTPStatus.NOT_FOUND: NotFoundError,
    HTTPStatus.METHOD_NOT_ALLOWED: NotAllowedError,
    HTTPStatus.NOT_ACCEPTABLE: NotAcceptableError,
    HTTPStatus.TOO_MANY_REQUESTS: TooManyRequestsError,
    HTTPStatus.BAD_REQUEST: BadRequestError,
    HTTPStatus.REQUEST_TIMEOUT: RequestTimeoutError,
    HTTPStatus.CONFLICT: ConflictError,
    HTTPStatus.REQUEST_ENTITY_TOO_LARGE: RequestTooLargeError,
    HTTPStatus.INTERNAL_SERVER_ERROR: InternalServerError,
    HTTPStatus.BAD_GATEWAY: BadGatewayError,
    HTTPStatus.SERVICE_UNAVAILABLE: ServiceUnavailableError
}


def validate_hashes(hash_input, allowed_hash_types):
    """Checks if the hash input is of the allowed hash types.
        :param hash_input: a list of hashes
        :type hash_input:list[str]
        :param allowed_hash_types: allowed hash types
        :type allowed_hash_types: tuple
    """
    if not hash_input:
        raise WrongInputError("At least one hash needs to be supplied as input.")

    for hash_string in hash_input:
        try:
            codecs.decode(hash_string, "hex")
        except (TypeError, binascii.Error):
            raise WrongInputError("The given hash input string is not a valid hexadecimal value.")

        hashing_algorithm = HASH_LENGTH_MAP.get(len(hash_string), None)
        if hashing_algorithm not in allowed_hash_types:
            raise WrongInputError(
                "Only hash strings of the following types are allowed as input values: {allowed}".format(
                    allowed=allowed_hash_types
                ))
