"""
author: Mislav Sever

TitaniumScale
A Python module for the ReversingLabs TitaniumScale appliance REST API.
"""

import json
import requests
import time

from ReversingLabs.SDK.helper import DEFAULT_USER_AGENT, RESPONSE_CODE_ERROR_MAP, \
    RequestTimeoutError, WrongInputError


class TitaniumScale(object):

    __UPLOAD_ENDPOINT = "/api/tiscale/v1/upload"
    __SINGLE_TASK_ENDPOINT = "/api/tiscale/v1/task/{task_id}"
    __MULTIPLE_TASKS_ENDPOINT = "/api/tiscale/v1/task"
    __YARA_ID_ENDPOINT = "/api/tiscale/v1/yara"

    def __init__(self, host, token=None, wait_time_seconds=2, retries=10, verify=True, proxies=None,
                 user_agent=DEFAULT_USER_AGENT):

        self._host = self.__validate_host(host)
        self._url = "{host}{{endpoint}}".format(host=self._host)

        self._headers = {"User-Agent": user_agent}
        if token:
            self._headers["Authorization"] = "Token {token}".format(token=token)

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

    def upload_sample_from_path(self, file_path, custom_token=None, user_data=None, custom_data=None):
        """Accepts a file path string for file upload and returns a response.
            :param file_path: path to file
            :type file_path: str
            :param custom_token: custom token for filtering processing tasks
            :type custom_token: str
            :param user_data: user-defined data in the form of a JSON string; this data is
            NOT included in file analysis reports
            :type user_data: str
            :param custom_data: user-defined data in the form of a JSON string; this data is
            included in file analysis reports
            :type custom_data: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(file_path, str):
            raise WrongInputError("file_path must be a string.")

        try:
            file_handle = open(file_path, "rb")
        except IOError as error:
            raise WrongInputError("Error while opening file in 'rb' mode - {error}".format(error=str(error)))

        response = self.__upload_files(
            file_handle=file_handle,
            custom_token=custom_token,
            user_data=user_data,
            custom_data=custom_data
        )

        self.__raise_on_error(response)

        return response

    def upload_sample_from_file(self, file_source, custom_token=None, user_data=None, custom_data=None):
        """Accepts an open file in 'rb' mode for file upload and returns a response.
            :param file_source: open file
            :type file_source: file or BinaryIO
            :param custom_token: custom token for filtering processing tasks
            :type custom_token: str
            :param user_data: user-defined data in the form of a JSON string; this data is
            NOT included in file analysis reports
            :type user_data: str
            :param custom_data: user-defined data in the form of a JSON string; this data is
            included in file analysis reports
            :type custom_data: str
            :return: response
            :rtype: requests.Response
        """
        if not hasattr(file_source, "read"):
            raise WrongInputError("file_source parameter must be a file open in 'rb' mode.")

        response = self.__upload_files(
            file_handle=file_source,
            custom_token=custom_token,
            user_data=user_data,
            custom_data=custom_data
        )

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

    def upload_sample_and_get_results(self, file_path=None, file_source=None, full_report=False, custom_token=None,
                                      user_data=None, custom_data=None):
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
            :param custom_token: custom token for filtering processing tasks
            :type custom_token: str
            :param user_data: user-defined data in the form of a JSON string; this data is
            NOT included in file analysis reports
            :type user_data: str
            :param custom_data: user-defined data in the form of a JSON string; this data is
            included in file analysis reports
            :type custom_data: str
            :return: response
            :rtype: requests.Response
        """
        if (file_path and file_source) or (not file_path and not file_source):
            raise WrongInputError("Either file_path or file_source parameter must be provided. "
                                  "Using both or none of the parameters in sot allowed.")

        if file_path:
            upload_response = self.upload_sample_from_path(
                file_path=file_path,
                custom_token=custom_token,
                user_data=user_data,
                custom_data=custom_data
            )
        else:
            upload_response = self.upload_sample_from_file(
                file_source=file_source,
                custom_token=custom_token,
                user_data=user_data,
                custom_data=custom_data
            )

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

    def __upload_files(self, file_handle, custom_token, user_data, custom_data):
        """A generic POST request method for all TitaniumScale methods.
            :param file_handle: files to send
            :type file_handle: file or BinaryIO
            :param custom_token: set custom token string for filtering processing tasks (X-TiScale-Token)
            :type custom_token: str
            :param user_data: user-defined data in the form of a JSON string; this data is
            NOT included in file analysis reports
            :type user_data: str
            :param custom_data: user-defined data in the form of a JSON string; this data is
            included in file analysis reports
            :type custom_data: str
            :return: response
            :rtype: requests.Response
        """
        if custom_token is not None:
            if not isinstance(custom_token, str):
                raise WrongInputError("custom_token parameter must be string.")

            self._headers["X-TiScale-Token"] = "Token {custom_token}".format(custom_token=custom_token)

        form_data = {}

        if user_data is not None:
            try:
                json.loads(user_data)
                form_data["user_data"] = user_data

            except (TypeError, json.decoder.JSONDecodeError):
                raise WrongInputError("user_data parameter must be a valid JSON string.")

        if custom_data is not None:
            try:
                json.loads(custom_data)
                form_data["custom_data"] = custom_data

            except (TypeError, json.decoder.JSONDecodeError):
                raise WrongInputError("custom_data parameter must be a valid JSON string.")

        files = {"file": file_handle}

        url = self._url.format(endpoint=self.__UPLOAD_ENDPOINT)

        response = requests.post(
            url=url,
            files=files,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers,
            data=form_data
        )

        return response

    def list_processing_tasks(self, age=None, custom_token=None):
        """Lists processing tasks generated by file submission requests.
            :param age: number of seconds for filtering processing tasks by age
            :type age: int
            :param custom_token: get only tasks with this custom token string (X-TiScale-Token)
            :type custom_token: str
            :return: response
            :rtype: requests.Response
        """
        query_params = {}

        if age is not None:
            if not isinstance(age, int):
                raise WrongInputError("age parameter must be integer.")

            query_params["age"] = age

        if custom_token is not None:
            if not isinstance(custom_token, str):
                raise WrongInputError("custom_token parameter must be string.")

            query_params["token"] = "Token {custom_token}".format(custom_token=custom_token)

        url = self._url.format(endpoint=self.__MULTIPLE_TASKS_ENDPOINT)

        response = requests.get(
            url=url,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers,
            params=query_params
        )

        self.__raise_on_error(response)

        return response

    def get_processing_task_info(self, task_id, full=True, v13=False, view=None):
        """Retrieves information about a completed file processing task.
            :param task_id: numerical ID of the file processing task
            :type task_id: int
            :param full: retrieve the full info
            :type full: bool
            :param v13: retrieve the info in TitaniumScale Worker v1.3 mode
            :type v13: bool
            :param view: state a custom view for returner info
            :type view: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(task_id, int):
            raise WrongInputError("task_id parameter must be integer.")

        if not isinstance(full, bool):
            raise WrongInputError("full parameter must be boolean.")

        if not isinstance(v13, bool):
            raise WrongInputError("v13 parameter must be boolean.")

        query_params = {
            "full": str(full).lower(),
            "v13": str(v13).lower()
        }

        if view is not None:
            if not isinstance(view, str):
                raise WrongInputError("view parameter must be string.")

            query_params["view"] = view

        endpoint = self.__SINGLE_TASK_ENDPOINT.format(task_id=task_id)
        url = self._url.format(endpoint=endpoint)

        response = requests.get(
            url=url,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers,
            params=query_params
        )

        self.__raise_on_error(response)

        return response

    def delete_processing_task(self, task_id):
        """Deletes a processing task record from the system.
            :param task_id: numerical ID of the file processing task
            :type task_id: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(task_id, int):
            raise WrongInputError("task_id parameter must be integer.")

        endpoint = self.__SINGLE_TASK_ENDPOINT.format(task_id=task_id)
        url = self._url.format(endpoint=endpoint)

        response = requests.delete(
            url=url,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers
        )

        self.__raise_on_error(response)

        return response

    def delete_multiple_tasks(self, age):
        """Deletes multiple task records from the system based on the time when they were submitted.
            :param age: age of tasks you want to delete in seconds
            :type age: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(age, int):
            raise WrongInputError("age parameter must be integer.")

        query_params = {"age": age}

        url = self._url.format(endpoint=self.__MULTIPLE_TASKS_ENDPOINT)

        response = requests.delete(
            url=url,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers,
            params=query_params
        )

        self.__raise_on_error(response)

        return response

    def get_yara_id(self):
        """Retrieves the identifier of the current set of YARA rules on the TitaniumScale Worker instance."""
        url = self._url.format(endpoint=self.__YARA_ID_ENDPOINT)

        response = requests.get(
            url=url,
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
