import os
import time
import base64
import hashlib
import requests


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
        return upload["submission_id"]

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
        except:
            pass
        return response

    def __get_authorization_token(self):
        """Acquires access token via OAuth2.0 client credential flow:
        https://www.rfc-editor.org/rfc/rfc6749#section-4.4
        """
        if not self.__is_token_valid():
            token_leeway = 20  # Add leeway to eliminate window where token may be expired on the server but not for us due to timings
            try:
                token_response = requests.post(self.token_endpoint, data={"grant_type": "client_credentials"}, auth=(self.client_id, self.client_secret), timeout=10)
                token_response.raise_for_status()
                token_data = token_response.json()
            except:
                # TODO error handling
                raise

            try:
                self.__token = token_data["access_token"]
                self.__token_expires_at = time.time() + token_data["expires_in"] - token_leeway
            except KeyError:
                # TODO error handling
                raise

        return self.__token
    
    def __is_token_valid(self):
        if self.__token_expires_at is None or self.__token is None:
            return False
        return time.time() > self.__token_expires_at

    def __upload_parts(self, sample_path, parts):
        etags = []
        with open(sample_path, "rb") as f:
            for part in parts:
                data = f.read(part["content_length"])
                etag = self.__upload_part_to_s3(url=part["url"], data=data)
                etags.append(etag)
        return etags

    def __upload_part_to_s3(self, url, data):
        content_hash = hashlib.md5(data).digest()
        encoded_hash = base64.b64encode(content_hash)
        headers = {
            "Content-MD5": encoded_hash.decode(),
            "Content-Length": len(body)
        }
        response = requests.put(url, data=data, timeout=10)
        response.raise_for_status()
        return response.headers["ETag"]

    def __get_file_info(self, path):
        stat_result = os.stat(path)
        file_size = stat_result.st_size
        file_name = os.path.basename(path)
        return file_name, file_size

    def __create_upload(self, file_name, file_size):
        response = self.__do_rest_api_request("POST", "/api/v1/uploads", body={"file_name": file_name, "file_size": file_size})
        response.raise_for_status()
        return response.json()

    def __complete_upload(self, upload_id, etags, object_key):
        response = self.__do_rest_api_request("PATCH", f"/api/v1/uploads/{upload_id}", body={"object_key": object_key, "etags": etags})
        response.raise_for_status()
    