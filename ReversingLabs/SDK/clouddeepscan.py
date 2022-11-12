import os
import time
import base64
import hashlib
import requests


class CloudDeepScanException(Exception):
    pass


class CloudDeepScan(object):

    def __init__(self, token_endpoint, rest_hostname, client_id, client_secret):
        self.token_endpoint = token_endpoint
        self.rest_hostname = rest_hostname
        self.client_id = client_id
        self.client_secret = client_secret

        self.__token = None
        self.__token_expires_at = None

    def upload_sample(self, sample_path):
        file_name, file_size = self.__get_file_info(path=sample_path)
        upload = self.__create_upload(file_name=file_name, file_size=file_size)
        etags = self.__upload_parts(sample_path=sample_path, parts=upload["parts"])
        self.__complete_upload(upload_id=upload["upload_id"], etags=etags, object_key=upload["object_key"])
        submission_id = upload["submission_id"]
        return submission_id

    def download_report(self, content_hash, output_path):
        pass

    def __do_rest_api_request(self, method, endpoint, body=None, params=None):
        token = self.__get_authorization_token()
        url = f"{self.rest_hostname}{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        try:
            response = requests.request(method, url, data=body, headers=headers, timeout=10)
        except requests.exceptions.RequestException as e:
            raise CloudDeepScanException(f"Failed to complete REST API request: {str(e)}")
        return response

    def __get_authorization_token(self):
        """Acquires access token via OAuth2.0 client credential flow:
        https://www.rfc-editor.org/rfc/rfc6749#section-4.4
        """
        if not self.__is_token_valid():
            token_leeway = 20  # Add leeway to eliminate window where token may be expired on the server but not for us due to timings
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
        if self.__token_expires_at is None or self.__token is None:
            return False
        return time.time() > self.__token_expires_at

    def __upload_parts(self, sample_path, parts):
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
        content_hash = hashlib.md5(data).digest()
        encoded_hash = base64.b64encode(content_hash)
        headers = {
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

    def __get_file_info(self, path):
        try:
            stat_result = os.stat(path)
        except FileNotFoundError:
            raise CloudDeepScanException("Sample does not exist")
        except OSError:
            raise CloudDeepScanException("Failed to read sample")
        file_size = stat_result.st_size
        file_name = os.path.basename(path)
        return file_name, file_size

    def __create_upload(self, file_name, file_size):
        response = self.__do_rest_api_request("POST", "/api/v1/uploads", body={"file_name": file_name, "file_size": file_size})
        try:
            response.raise_for_status()
            response_data = response.json()
        except requests.exceptions.RequestException:
            raise CloudDeepScanException("Failed to create upload")
        return response_data

    def __complete_upload(self, upload_id, etags, object_key):
        response = self.__do_rest_api_request("PATCH", f"/api/v1/uploads/{upload_id}", body={"object_key": object_key, "etags": etags})
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            raise CloudDeepScanException("Failed to complete upload")
