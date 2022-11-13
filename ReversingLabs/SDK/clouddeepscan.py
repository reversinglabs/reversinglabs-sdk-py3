import os
import time
import base64
import hashlib
import requests
from datetime import datetime
from ReversingLabs.SDK.helper import CloudDeepScanException


class CloudDeepScan(object):

    def __init__(self, token_endpoint, rest_hostname, client_id, client_secret):
        """Handles communication with Cloud Deep Scan API endpoints.
        Admins can find token endpoint, rest hostname, client id and secret on Cloud Deep Scan web UI.
        Go to settings -> REST API Authorization tab.

        :param token_endpoint: token endpoint that will be used to fetch authorization token
        :type token_endpoint: str
        :param rest_hostname: REST API hostname that will be used as base URL to generate endpoints
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

        self.__token = None
        self.__token_expires_at = None

    def upload_sample(self, sample_path):
        """Uploads sample to Cloud Deep Scan REST API

        :param sample_path: Path to the sample that should be scanned
        :type sample_path: str
        :raises CloudDeepScanException: if sample upload fails in any way
        :return: submission ID that can be used to fetch submission status
        :rtype: str
        """
        file_name, file_size = self.__get_file_info(path=sample_path)
        upload = self.__create_upload(file_name=file_name, file_size=file_size)
        etags = self.__upload_parts(sample_path=sample_path, parts=upload["parts"])
        self.__complete_upload(upload_id=upload["upload_id"], etags=etags, object_key=upload["object_key"])
        return upload["submission_id"]

    def fetch_submission_status(self, submission_id):
        response = self.__do_api_request("GET", f"/api/v1/submissions/{sample_id}")
        try:
            status = CloudDeepScanSubmissionStatus(
                id_=response["id"],
                created_at=self.__parse_iso8601_time(timestamp=response["created_at"]),
                status=response["status"]
            )
            return status
        except (KeyError, ValueError):
            raise CloudDeepScanException("Failed to get submission status: malformed REST API response")

    def fetch_latest_report(self, sample_hash):
        pass

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
        response = self.__do_api_request("POST", "/api/v1/uploads", body={"file_name": file_name, "file_size": file_size})
        try:
            response_data = response.json()
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
        response = self.__do_api_request("PATCH", f"/api/v1/uploads/{upload_id}", body={"object_key": object_key, "etags": etags})
        if response.status_code != 204:
            raise CloudDeepScanException("Failed to create upload")

    def __do_api_request(self, method, endpoint, body=None, params=None):
        """Calls Cloud Deep Scan REST API endpoint while handling authentication

        :param method: request HTTP method ("GET", "POST" etc.)
        :type method: str
        :param endpoint: endpoint that should be called e.g. "/v1/api/uploads"
        :type endpoint: str
        :param body: body that should be sent to the endpoint, defaults to None
        :type body: dict, bytes or string, optional
        :param params: URL parameters that should be sent, defaults to None
        :type params: dict, optional
        :raises CloudDeepScanException: if API call fails
        :return: response from the server
        :rtype: requests.Response
        """
        token = self.__get_authorization_token()
        url = f"{self.rest_hostname}{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        try:
            response = requests.request(method, url, data=body, headers=headers, timeout=10)
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
        return time.time() > self.__token_expires_at

    def __upload_parts(self, sample_path, parts):
        """Uploads sample as parts to dedicated S3 bucket.

        :param sample_path: path to the sample that needs to be uploaded
        :type sample_path: str
        :param parts: list of part info dicitionaries returned from the API
        :type parts: list of dicts
        :raises CloudDeepScanException: if sample cannot be read from disk or response from API is malformed
        :return: list of etags that are required to complete download
        :rtype: list[str]
        """
        etags = []
        try:
            with open(sample_path, "rb") as f:
                for part in parts:    
                    try:
                        data = f.read(part["content_length"])
                        etag = self.__upload_part_to_s3(url=part["url"], data=data)
                    except KeyError:
                        raise CloudDeepScanException("Failed to upload sample part: malformed response from REST API")
                    etags.append(etag)
        except PermissionError:
            raise CloudDeepScanException("Failed to read sample: permission denied")
        except FileNotFoundError:
            raise CloudDeepScanException("Failed to read sample: file does not exist")
        except OSError:
            raise CloudDeepScanException("Failed to read sample")
        return etags

    def __upload_part_to_s3(self, url, data):
        """Uploads data to the given presigned s3 url

        :param url: presigned S3 upload URL
        :type url: str
        :param data: bytes of data that should be uploaded
        :type data: bytes
        :raises CloudDeepScanException: if upload fails
        :return: etag of the successful upload
        :rtype: str
        """
        content_hash = hashlib.md5(data).digest()
        encoded_hash = base64.b64encode(content_hash)
        headers = {
            # This is not required but useful, S3 validates payload based on provided payload's md5 hash
            # More info here:
            # https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html#API_UploadPart_RequestSyntax
            "Content-MD5": encoded_hash.decode(),
            "Content-Length": len(data)
        }
        try:
            response = requests.put(url, data=data)
            response.raise_for_status()
            etag = response.headers["ETag"]
        except requests.exceptions.RequestException as e:
            raise CloudDeepScanException("Failed to upload sample part: upload request failed")
        except KeyError:
            raise CloudDeepScanException("Failed to upload sample part: malformed upload response")
        return etag

    @staticmethod
    def __parse_iso8601_time(timestamp):
        return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")

    def __get_file_info(self, path):
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
            raise CloudDeepScanException("Failed to read sample")
        file_size = stat_result.st_size
        file_name = os.path.basename(path)
        return file_name, file_size


class CloudDeepScanSubmissionStatus(object):

    def __init__(self, id_, created_at, status):
        """Submission status representation.

        :param id_: submission id
        :type id_: str
        :param created_at: time when submission was created
        :type created_at: datetime
        :param status: submission status, can be one of: scanned, scanning, error
        :type status: str
        """
        self.id = id_
        self.created_at = created_at
        self.status = status

    def __eq__(self, other):
        return self.id == other.id and self.created_at == other.created_at and self.status == other.status

    def __repr__(self):
        return f"CloudDeepScanSubmissionStatus('{self.id}')"
