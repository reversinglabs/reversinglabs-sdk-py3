"""
author: Mislav Sever

File Inspection Engine (FIE)
A Python module for the ReversingLabs File Inspection Engine REST API.
"""

import requests
from io import BytesIO

from ReversingLabs.SDK.helper import DEFAULT_USER_AGENT, RESPONSE_CODE_ERROR_MAP, WrongInputError


class FileInspectionEngine(object):

	__SCAN_ENDPOINT = "/scan"
	__REPORT_ENDPOINT = "/report"

	def __init__(self, host, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT):
		self._host = self.__validate_host(host)
		self._url = "{host}{{endpoint}}".format(host=self._host)
		self._verify = verify

		self._headers = {"User-Agent": user_agent}

		if proxies:
			if not isinstance(proxies, dict):
				raise WrongInputError("proxies parameter must be a dictionary.")
			if len(proxies) == 0:
				raise WrongInputError("proxies parameter can not be an empty dictionary.")
		self._proxies = proxies

	@staticmethod
	def __validate_host(host):
		"""Returns a formatted host URL including the protocol prefix.
			:param host: URL string
			:type host: str
			:returns: formatted URL string
			:rtype: str
		"""
		if not isinstance(host, str):
			raise WrongInputError("host parameter must be string.")

		if not host.startswith(("http://", "https://")):
			raise WrongInputError("host parameter must contain a protocol definition at the beginning.")

		host = host.rstrip("/")

		return host

	def test_connection(self):
		"""Creates a lightweight request towards the FIE scan API to test the connection.
		"""
		fake_file = BytesIO(b'this is a sample text')

		response = self.scan_using_open_file(
			file_source=fake_file
		)

		self.__raise_on_error(response)

		return

	def scan_using_file_path(self, file_path):
		"""Sends a file to the FIE for inspection and returns a simple verdict in the submit response.
		Uses a file path string as input.
			:param file_path: local path to the file
			:type file_path: str
			:return: response
			:rtype: requests.Response
		"""
		if not isinstance(file_path, str):
			raise WrongInputError("file_path must be a string.")

		try:
			file_handle = open(file_path, "rb")
		except IOError as error:
			raise WrongInputError("Error while opening file in 'rb' mode - {error}".format(error=str(error)))

		response = self.__upload_file(
			file_source=file_handle,
			endpoint=self.__SCAN_ENDPOINT
		)

		return response

	def scan_using_open_file(self, file_source):
		"""Sends a file to the FIE for inspection and returns a simple verdict in the submit response.
		Uses an open file handle as input.
			:param file_source: open file in rb mode
			:type file_source: file or BinaryIO
			:return: response
			:rtype: requests.Response
		"""
		response = self.__upload_file(
			file_source=file_source,
			endpoint=self.__SCAN_ENDPOINT
		)

		return response

	def report_using_file_path(self, file_path):
		"""Sends a file to the FIE for inspection and returns a more complex analysis report in the submit response.
		Uses a file path string as input.
			:param file_path: local path to the file
			:type file_path: str
			:return: response
			:rtype: requests.Response
		"""
		if not isinstance(file_path, str):
			raise WrongInputError("file_path must be a string.")

		try:
			file_handle = open(file_path, "rb")
		except IOError as error:
			raise WrongInputError("Error while opening file in 'rb' mode - {error}".format(error=str(error)))

		response = self.__upload_file(
			file_source=file_handle,
			endpoint=self.__REPORT_ENDPOINT
		)

		return response

	def report_using_open_file(self, file_source):
		"""Sends a file to the FIE for inspection and returns a more complex analysis report in the submit response.
		Uses an open file handle as input.
			:param file_source: open file in rb mode
			:type file_source: file or BinaryIO
			:return: response
			:rtype: requests.Response
		"""
		response = self.__upload_file(
			file_source=file_source,
			endpoint=self.__REPORT_ENDPOINT
		)

		return response

	def __upload_file(self, file_source, endpoint):
		"""Internal method for utilizing the FIE endpoints.
			:param file_source: open file in rb mode
			:type file_source: file or BinaryIO
			:param endpoint: endpoint string
			:type endpoint: str
			:return: response
			:rtype: requests.Response
		"""
		if not hasattr(file_source, "read"):
			raise WrongInputError("file_source parameter must be a file open in 'rb' mode.")

		url = self._url.format(endpoint=endpoint)

		response = requests.post(
			url=url,
			data=file_source,
			verify=self._verify,
			proxies=self._proxies,
			headers=self._headers
		)

		self.__raise_on_error(response)

		return response

	@staticmethod
	def __raise_on_error(response):
		"""Accepts a response object for validation and raises an exception if an error status code is received.
			:return: response
			:rtype: requests.Response
		"""
		exception = RESPONSE_CODE_ERROR_MAP.get(response.status_code, None)
		if not exception:
			return
		raise exception(response_object=response)
