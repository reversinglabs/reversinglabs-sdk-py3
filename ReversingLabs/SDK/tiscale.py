"""
author: Mislav Sever

TitaniumScale
A Python module for the ReversingLabs TitaniumScale appliance REST API.
"""

import requests
import time

from ReversingLabs.SDK.helper import DEFAULT_USER_AGENT, RESPONSE_CODE_ERROR_MAP, \
    RequestTimeoutError, WrongInputError


class TitaniumScale(object):

    __UPLOAD_ENDPOINT = "/api/tiscale/v1/upload"

    def __init__(self, host, token, wait_time_seconds=2, retries=10, verify=True, proxies=None,
                 user_agent=DEFAULT_USER_AGENT):

        self._host = self.__validate_host(host)
        self._url = "{host}{{endpoint}}".format(host=self._host)

        self._headers = {
            "User-Agent": user_agent,
            "Authorization": "Token {token}".format(token=token)
        }
        self._verify = verify

        if not isinstance(wait_time_seconds, int):
            raise WrongInputError("wait_time_seconds must be an integer.")
        self._wait_time_seconds = wait_time_seconds

        if not isinstance(retries, int):
            raise WrongInputError("retries must be an integer.")
        self._retries = retries

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
        """Creates a request towards the TitaniumScale task API to test the connection
        with TitaniumScale.
        """
        test_url = self._url.format(endpoint="/api/tiscale/v1/task")

        response = self.__get_results(
            task_url=test_url
        )

        self.__raise_on_error(response)

        return

    def upload_sample_from_path(self, file_path):
        """Accepts a file path string for file upload and returns a response.
            :param file_path: path to file
            :type file_path: str
            :returns: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        if not isinstance(file_path, str):
            raise WrongInputError("file_path must be a string.")

        try:
            file_handle = open(file_path, "rb")
        except IOError as error:
            raise WrongInputError("Error while opening file in 'rb' mode - {error}".format(error=str(error)))

        response = self.__upload_files(file_handle=file_handle)

        self.__raise_on_error(response)

        return response

    def upload_sample_from_file(self, file_source):
        """Accepts an open file in 'rb' mode for file upload and returns a response.
            :param file_source: open file
            :type file_source: file or BinaryIO
            :returns: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        if not hasattr(file_source, "read"):
            raise WrongInputError("file_source parameter must be a file open in 'rb' mode.")

        response = self.__upload_files(file_handle=file_source)

        self.__raise_on_error(response)

        return response

    def get_results(self, task_url, full_report=False):
        """Accepts an analysis task URL string and returns an analysis report response.
        This method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready.
            :param task_url: task URL string
            :type task_url: str
            :param full_report: return the full version of the report
            :type full_report: bool
            :returns: :class:`Response <Response>` object or None
            :rtype: requests.Response or None
        """
        if not isinstance(task_url, str):
            raise WrongInputError("task_url must be string.")

        if full_report not in (True, False):
            raise WrongInputError("full_report parameter must be boolean.")

        for _ in range(self._retries + 1):
            response = self.__get_results(task_url=task_url, full_report=full_report)

            self.__raise_on_error(response)

            if response.json().get("processed"):
                return response

            time.sleep(self._wait_time_seconds)

        return None

    def upload_sample_and_get_results(self, file_path=None, file_source=None, full_report=False):
        """Accepts either a file path string or an open file in 'rb' mode for file upload
         and returns an analysis report response.
        This method combines uploading a sample and obtaining the analysis results.
        The result obtaining action of this method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready.
            :param file_path: file path
            :type file_path: str
            :param file_source: open file
            :type file_source: file or BinaryIO
            :param full_report: return the full version of the report
            :type full_report: bool
            :returns: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        if (file_path and file_source) or (not file_path and not file_source):
            raise WrongInputError("Either file_path or file_source parameter must be provided. "
                                  "Using both or none of the parameters in sot allowed.")

        if file_path:
            upload_response = self.upload_sample_from_path(file_path)
        else:
            upload_response = self.upload_sample_from_file(file_source)

        task_url = upload_response.json().get("task_url")
        response = self.get_results(task_url, full_report)

        if not response:
            raise RequestTimeoutError("No report could be obtained or maximum number of retries was exceeded.")

        return response

    def __get_results(self, task_url, full_report=False):
        """A generic GET request method for all TitaniumScale methods.
            :param task_url: task URL string
            :type task_url: str
            :param full_report: return the full version of the report
            :type full_report: bool
            :return: response
            :rtype: requests.Response
        """
        full_report = str(full_report).lower()

        url = "{task_url}?full={full_report}".format(
            task_url=task_url,
            full_report=full_report
        )

        response = requests.get(
            url=url,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers
        )

        return response

    def __upload_files(self, file_handle):
        """A generic POST request method for all TitaniumScale methods.
            :param file_handle: files to send
            :return: response
            :rtype: requests.Response
        """
        url = self._url.format(endpoint=self.__UPLOAD_ENDPOINT)

        files = {"file": file_handle}

        response = requests.post(
            url=url,
            files=files,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers
        )

        return response

    @staticmethod
    def __raise_on_error(response):
        """Accepts a response object for validation and raises an exception if an error status code is received.
            :param response: response object
            :type response: requests.Response
        """
        exception = RESPONSE_CODE_ERROR_MAP.get(response.status_code, None)
        if not exception:
            return
        raise exception
