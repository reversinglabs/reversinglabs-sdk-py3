"""
author: Savo Kovacevic

CloudDeepScan
A Python module for the ReversingLabs Cloud Deep Scan REST API.
"""

import os
import time
import requests
import concurrent
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import HTTPError
from urllib3.connectionpool import connection_from_url
from ReversingLabs.SDK.helper import CloudDeepScanException


class CloudDeepScan(object):

    def __init__(self, token_endpoint, rest_hostname, client_id, client_secret):
        """Handles communication with Cloud Deep Scan API endpoints.
        Admins can find token endpoint, rest hostname, client id and secret on Cloud Deep Scan web UI.
        Go to settings -> REST API Authorization tab.

        :param token_endpoint: token endpoint that is used to fetch authorization token
        :type token_endpoint: str
        :param rest_hostname: REST API hostname which represents a base URL of all Cloud Deep Scan API endpoints
        :type rest_hostname: str
        :param client_id: ID of OAuth2.0 client used for authorization
        :type client_id: str
        :param client_secret: secret of OAuth2.0 client used for authorization
        :type client_secret: str
        """
        self.token_endpoint = token_endpoint
        self.rest_hostname = rest_hostname
        self.client_id = client_id
        self.client_secret = client_secret

        self.__in_memory_chunk_size = 2 * 1000 * 1000  # read chunks of 2MB in memory during the upload
        self.__submissions_endpoint = "/v1/submissions"
        self.__uploads_endpoint = "/v1/uploads"

        self.__token = None
        self.__token_expires_at = None

    def upload_sample(self, sample_path, max_concurrent_requests=10):
        """Uploads sample to Cloud Deep Scan REST API

        :param sample_path: path to the sample that should be scanned
        :type sample_path: str
        :param max_concurrent_requests: amount of part uploads that will be done in parallel,
            used only if there are more parts than max_concurrent_requests value, defaults to 10,
            minimum is 1, maximum is 1000. Keep in mind that raising this number will impact RAM usage of the upload.
        :type max_concurrent_requests: int
        :raises CloudDeepScanException: if sample upload fails in any way
        :return: submission ID that can be used to fetch submission status
        :rtype: str
        """
        if max_concurrent_requests > 1000:
            raise RuntimeError("maximum number of concurrent requests is 1000")
        if max_concurrent_requests < 1:
            raise RuntimeError("minimum number of concurrent requests is 1")

        file_name, file_size = self.__get_file_info(path=sample_path)
        upload = self.__create_upload(file_name=file_name, file_size=file_size)
        etags = self.__upload_parts(
            sample_path=sample_path,
            parts=upload["parts"],
            max_concurrent_requests=max_concurrent_requests
        )
        if "id" in upload:
            self.__complete_upload(upload_id=upload["id"], etags=etags, object_key=upload["object_key"])
        return upload["submission_id"]

    def fetch_submission(self, submission_id):
        """Fetches submission status by submission ID.
        Submission ID is returned when sample is uploaded.
        Returned status object has three fields:
        - id: submission ID
        - created_at: datetime with timezone info (UTC)
        - status: can be one of scanned, scanning and error
        - report: can be either None if status is not "scanned" or URL pointing to report location

        :param submission_id: submission ID that status is requested for
        :type submission_id: str
        :raises CloudDeepScanException: if anything goes wrong during the communication with the API
        :return: status object describing submission status
        :rtype: CloudDeepScanSubmissionStatus
        """
        response = self.__api_request(method="GET", endpoint=f"{self.__submissions_endpoint}/{submission_id}")
        try:
            response_data = response.json()["data"]
            status = CloudDeepScanSubmissionStatus(
                id_=response_data["id"],
                created_at=self.__parse_iso8601_time(timestamp=response_data["created_at"]),
                status=response_data["status"],
                report=response_data["report"],
            )
            return status
        except (KeyError, ValueError, requests.exceptions.JSONDecodeError):
            raise CloudDeepScanException("Failed to get submission status: malformed REST API response")

    def fetch_submission_history(self, sample_hash=None, sample_name=None):
        """Fetches submission history filtered by hash or sample name.
        Either sample_name or sample_hash must be provided.
        Returns list of status objects with three fields:
        - id: submission ID
        - created_at: datetime with timezone info (UTC)
        - status: can be one of scanned, scanning and error
        - report: can be either None if status is not "scanned" or URL pointing to report location
        If none samples are found by hash or name, returns empty list.

        :param sample_hash: SHA1 hash of the sample, defaults to None
        :type sample_hash: str, optional
        :param sample_name: name of the sample, defaults to None
        :type sample_name: str, optional
        :rtype: list[CloudDeepScanSubmissionStatus]
        """
        if sample_hash is None and sample_name is None:
            raise RuntimeError("Either sample_hash or sample_name parameter must be specified")
        if sample_hash is not None and sample_name is not None:
            raise RuntimeError("Only one parameter either sample_hash or sample_name parameter can be specified")

        response = self.__api_request(
            method="GET",
            endpoint=self.__submissions_endpoint,
            params={"hash": sample_hash, "name": sample_name}
        )
        try:
            response_data = response.json()["data"]
            submission_statuses = []
            for submission in response_data:
                status = CloudDeepScanSubmissionStatus(
                    id_=submission["id"],
                    created_at=self.__parse_iso8601_time(timestamp=submission["created_at"]),
                    status=submission["status"],
                    report=submission["report"],
                )
                submission_statuses.append(status)
            return submission_statuses
        except (KeyError, ValueError, requests.exceptions.JSONDecodeError):
            raise CloudDeepScanException("Failed to get submission status: malformed REST API response")

    def download_report(self, sample_hash, report_output_path):
        """Downloads latest JSON report for the given hash and saves it to the provided path.

        :param sample_hash: sha1 hash of sample content
        :type sample_hash: str
        :param report_output_path: relative or absolute path where output will be saved with file name included
            e.g. "reports/report1.json"
        :type report_output_path: str
        :raises CloudDeepScanException: if report download fails in any way
        """
        response = self.__api_request(
            method="GET",
            endpoint=f"{self.__submissions_endpoint}/report/{sample_hash}",
            allow_redirects=True
        )
        try:
            abs_report_path = os.path.abspath(report_output_path)
            report_parent_dir = os.path.dirname(abs_report_path)
            if not os.path.isdir(report_parent_dir):
                raise CloudDeepScanException(
                    f"Failed to download report: directory '{report_parent_dir}' does not exist, report cannot be saved"
                )

            with open(report_output_path, "wb") as f:
                f.write(response.content)

        except IOError:
            raise CloudDeepScanException("Failed to download report: failed to save report to disk")

    def __create_upload(self, file_name, file_size):
        """Calls Cloud Deep Scan REST API /api/v1/uploads endpoint to create upload

        :param file_name: name of the uploaded sample
        :type file_name: str
        :param file_size: size of the uploaded sample in bytes
        :type file_size: int
        :raises CloudDeepScanException: if API fails to create upload
        :return: created upload details
        :rtype: dict[any]
        """
        response = self.__api_request(
            method="POST",
            endpoint=self.__uploads_endpoint,
            json={"name": file_name, "size": file_size}
        )
        try:
            response_data = response.json()["data"]
        except requests.exceptions.JSONDecodeError:
            raise CloudDeepScanException("Failed to create upload: malformed API response")
        return response_data

    def __complete_upload(self, upload_id, etags, object_key):
        """Calls Cloud Deep Scan REST API to complete upload

        :param upload_id: upload ID, returned by API when created
        :type upload_id: str
        :param etags: list of etags from uploaded parts, all etags must be present in order to have successful upload
        :type etags: list[str]
        :param object_key: S3 key of the object, returned by the API
        :type object_key: str
        :raises CloudDeepScanException: if complete API call goes wrong
        """
        response = self.__api_request(
            method="PATCH",
            endpoint=f"{self.__uploads_endpoint}/{upload_id}",
            json={"object_key": object_key, "etags": etags}
        )
        if response.status_code != 204:
            raise CloudDeepScanException("Failed to create upload")

    def __api_request(self, method, endpoint, **kwargs):
        """Calls Cloud Deep Scan REST API endpoint while handling authentication

        :param method: request HTTP method ("GET", "POST" etc.)
        :type method: str
        :param endpoint: endpoint that should be called e.g. "/v1/api/uploads"
        :type endpoint: str
        :param kwargs: proxied to requests.reqeust method
        :type kwargs: dict, optional
        :raises CloudDeepScanException: if API call fails
        :return: response from the server
        :rtype: requests.Response
        """
        token = self.__get_authorization_token()
        url = f"{self.rest_hostname}{endpoint}"
        base_headers = {
            "Authorization": f"Bearer {token}"
        }
        headers = base_headers
        headers.update(kwargs.get("headers", {}))
        # Make sure there is a default timeout so requests don't get stuck
        timeout = kwargs.get("timeout", 10)
        try:
            response = requests.request(method, url, headers=headers, timeout=timeout, **kwargs)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            msg = None
            try:
                payload = e.response.json()
                msg = payload["error"]
            except (requests.exceptions.JSONDecodeError, KeyError):
                pass
            if e.response.status_code == 404:
                raise CloudDeepScanException(f"API request failed: {msg or 'resource not found'}")
            elif e.response.status_code == 400:
                raise CloudDeepScanException(f"API request failed: {msg or 'malformed request'}")
            elif e.response.status_code == 401:
                raise CloudDeepScanException(f"API request failed: {msg or 'unauthorized'}")
            elif e.response.status_code >= 500:
                raise CloudDeepScanException(f"API request failed: {msg or 'internal server error'}")
            raise CloudDeepScanException(f"API request failed: {msg or 'something went wrong'}")
        except requests.exceptions.RequestException as e:
            raise CloudDeepScanException(f"Failed to complete request: {str(e)}")
        return response

    def __get_authorization_token(self):
        """Checks if current token saved in the instance is valid, if not, 
        acquires access token via OAuth2.0 client credential flow:
        https://www.rfc-editor.org/rfc/rfc6749#section-4.4

        :raises CloudDeepScanException: if it fails acquiring token
        :return: token
        :rtype: str
        """
        if not self.__is_token_valid():
            token_leeway = 20  # leeway is added to eliminate window where token may be expired on the server but not for SDK due to timings
            try:
                token_response = requests.post(
                    self.token_endpoint,
                    data={"grant_type": "client_credentials"},
                    auth=(self.client_id, self.client_secret),
                    timeout=10
                )
                token_response.raise_for_status()
                token_data = token_response.json()
            except requests.exceptions.RequestException as e:
                raise CloudDeepScanException(f"Failed to fetch access token: {str(e)}")

            try:
                self.__token = token_data["access_token"]
                self.__token_expires_at = time.time() + token_data["expires_in"] - token_leeway
            except KeyError:
                raise CloudDeepScanException("Failed to fetch access token: malformed response from identity provider")
        return self.__token

    def __is_token_valid(self):
        """Validates token set on the instance

        :return: token validity
        :rtype: bool
        """
        if self.__token_expires_at is None or self.__token is None:
            return False
        return time.time() < self.__token_expires_at

    def __upload_parts(self, sample_path, parts, max_concurrent_requests):
        """Uploads sample as parts to dedicated S3 bucket.

        :param sample_path: path to the sample that needs to be uploaded
        :type sample_path: str
        :param parts: list of part info dicitionaries returned from the API
        :type parts: list of dicts
        :param max_concurrent_requests: amount of uploads that will be done in parallel, used only if there are more parts than max_concurrent_requests value
        :type max_concurrent_requests: int
        :raises CloudDeepScanException: if sample cannot be read from disk or response from API is malformed
        :return: list of etags that are required to complete download
        :rtype: list[str]
        """
        etags = ["" for part in parts]
        start_byte = 0
        worker_count = len(parts) if len(parts) < max_concurrent_requests else max_concurrent_requests
        pool = ThreadPoolExecutor(max_workers=worker_count)
        futures = []
        for part_number, part in enumerate(parts):
            future = pool.submit(self.__upload_part_to_s3, part["url"], sample_path, start_byte, part["content_length"], part_number)
            futures.append(future)
            start_byte += part["content_length"]

        for completed_future in concurrent.futures.as_completed(futures):
            etag, part_number = completed_future.result()
            etags[part_number] = etag
        return etags

    def __upload_part_to_s3(self, url, path, start_byte, content_length, part_number):
        """Uploads data to the given presigned s3 url

        :param url: presigned S3 upload URL
        :type url: str
        :param path: path to the file that needs to be uploaded
        :type path: str
        :param start_byte: byte from which to start upload
        :type start_byte: int
        :param content_length: amount of bytes that should be uploaded
        :type content_length: int
        :param part_number: part number that is later used to order etags before completing upload
        :type part_number: int
        :raises CloudDeepScanException: if upload fails
        :return: etag of the successful upload and part number
        :rtype: tuple(str, int)
        """
        uploaded_bytes = 0
        try:
            conn_pool = connection_from_url(url=url)
            connection = conn_pool._get_conn()
            connection.putrequest(
                "PUT",
                url,
                skip_accept_encoding=True,
                skip_host=True,
            )
            connection.putheader("Content-Length", str(content_length))
            connection.endheaders()

            with open(path, "rb") as f:
                f.seek(start_byte)
                while uploaded_bytes != content_length:
                    if (uploaded_bytes + self.__in_memory_chunk_size) <= content_length:
                        chunk_size = self.__in_memory_chunk_size
                    else:
                        # Calculate remainder if it is less than the configured chunk size
                        chunk_size = content_length - uploaded_bytes

                    chunk = f.read(chunk_size)
                    connection.send(chunk)
                    uploaded_bytes += chunk_size

            response = connection.getresponse()
            etag = response.headers["ETag"]
        except HTTPError:
            connection.close()
            raise CloudDeepScanException("Failed to upload sample part: upload failed")
        except PermissionError:
            raise CloudDeepScanException("Failed to read sample: permission denied")
        except FileNotFoundError:
            raise CloudDeepScanException("Failed to read sample: file does not exist")
        except OSError:
            raise CloudDeepScanException("Failed to upload sample part")
        except KeyError:
            raise CloudDeepScanException("Failed to upload sample part: malformed upload response")
        return etag, part_number

    @staticmethod
    def __parse_iso8601_time(timestamp):
        return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")

    @staticmethod
    def __get_file_info(path):
        """Stats file to determine size

        :param path: path to the file
        :type path: str
        :raises CloudDeepScanException: if file cannot be found or os.stat fails in any way, or path is not a file
        :return: file name and file size
        :rtype: tuple(str, int)
        """
        try:
            if not os.path.isfile(path):
                raise CloudDeepScanException("Sample is not a file")
            stat_result = os.stat(path)
        except FileNotFoundError:
            raise CloudDeepScanException("Sample does not exist")
        except OSError:
            raise CloudDeepScanException("Failed to get file info")
        file_size = stat_result.st_size
        file_name = os.path.basename(path)
        return file_name, file_size


class CloudDeepScanSubmissionStatus(object):

    def __init__(self, id_, created_at, status, report):
        """Submission status representation

        :param id_: submission id
        :type id_: str
        :param created_at: time when submission was created
        :type created_at: datetime
        :param status: submission status, can be one of: scanned, scanning, error
        :type status: str
        :param report: URI where report can be found
        :type report: str, optional
        """
        self.id = id_
        self.created_at = created_at
        self.status = status
        self.report = report

    def __eq__(self, other):
        return self.id == other.id and self.created_at == other.created_at and self.status == other.status and self.report == other.report

    def __repr__(self):
        return f"CloudDeepScanSubmissionStatus('{self.id}')"
