"""
author: Mislav Sever

A1000
A Python module for the ReversingLabs A1000 appliance REST API.
"""

import datetime
import requests
import time
from urllib import parse
from warnings import warn

from ReversingLabs.SDK.helper import ADVANCED_SEARCH_SORTING_CRITERIA, DEFAULT_USER_AGENT, RESPONSE_CODE_ERROR_MAP, \
    MD5, SHA1, SHA256, SHA512, \
    RequestTimeoutError, WrongInputError, \
    validate_hashes


CLASSIFICATIONS = ("MALICIOUS", "SUSPICIOUS", "GOODWARE", "UNKNOWN")
AVAILABLE_PLATFORMS = ("windows7", "windows10", "macos_11", "windows11", "linux")


class A1000(object):

    __TOKEN_ENDPOINT = "/api-token-auth/"
    __UPLOAD_ENDPOINT = "/api/uploads/"
    __FILE_ANALYSIS_STATUS_ENDPOINT = "/api/samples/status/"
    __URL_ANALYSIS_STATUS_ENDPOINT = "/api/uploads/v2/url-samples/{task_id}"
    __RESULTS_ENDPOINT = "/api/samples/list/"
    __SUMMARY_REPORT_ENDPOINT_V2 = "/api/samples/v2/list/"
    __DETAILED_REPORT_ENDPOINT_V2 = "/api/samples/v2/list/details/"
    __CLASSIFY_ENDPOINT_V2 = "/api/v2/samples/{hash_value}/classification/?localonly={localonly}"
    __CLASSIFY_ENDPOINT_V3 = "/api/samples/v3/{hash_value}/classification/"
    __REANALYZE_ENDPOINT = "/api/samples/{hash_value}/analyze/"
    __REANALYZE_BULK_ENDPOINT = "/api/samples/analyze_bulk/"
    __REANALYZE_BULK_ENDPOINT_V2 = "/api/samples/v2/analyze_bulk/"
    __LIST_EXTRACTED_FILES_ENDPOINT = "/api/samples/{hash_value}/extracted-files/"
    __LIST_EXTRACTED_FILES_ENDPOINT_V2 = "/api/samples/v2/{hash_value}/extracted-files/"
    __DOWNLOAD_EXTRACTED_FILES_ENDPOINT = "/api/samples/{hash_value}/unpacked/"
    __DOWNLOAD_SAMPLE_ENDPOINT = "/api/samples/{hash_value}/download/"
    __DELETE_SAMPLE_ENDPOINT = "/api/samples/{hash_value}/"
    __DELETE_SAMPLES_BULK_ENDPOINT_V2 = "/api/samples/v2/delete_bulk/"
    __CHECK_SAMPLE_REMOVAL_STATUS_ENDPOINT_V2 = "/api/samples/v2/delete_bulk/status/?id={task_id}"
    __PDF_REPORT_CREATE_ENDPOINT = "/api/pdf/{hash_value}/create"
    __PDF_REPORT_STATUS_ENDPOINT = "/api/pdf/{hash_value}/status"
    __PDF_REPORT_DOWNLOAD_ENDPOINT = "/api/pdf/{hash_value}/download"
    __TITANIUM_CORE_REPORT_ENDPOINT_V2 = "/api/v2/samples/{hash_value}/ticore/?fields={fields}"
    __DYNAMIC_ANALYSIS_REPORT_CREATE_ENDPOINT = "/api/rl_dynamic_analysis/export/summary/{hash_value}/{format}/create/"
    __DYNAMIC_ANALYSIS_REPORT_STATUS_ENDPOINT = "/api/rl_dynamic_analysis/export/summary/{hash_value}/{format}/status/"
    __DYNAMIC_ANALYSIS_REPORT_DOWNLOAD_ENDPOINT = "/api/rl_dynamic_analysis/export/summary/{hash_value}/{format}" \
                                                  "/download/"
    __SET_OR_DELETE_CLASSIFICATION_ENDPOINT = "/api/samples/{hash_value}/setclassification/{system}/"
    __TAGS_ENDPOINT = "/api/tag/{hash_value}/"
    __RETRIEVE_YARA_RULESETS_ENDPOINT_V2 = "/api/yara/v2/rulesets/"
    __RETRIEVE_YARA_RULESET_CONTENTS_ENDPOINT = "/api/yara/ruleset/content/?name={ruleset_name}"
    __RETRIEVE_MATCHES_FOR_A_YARA_RULESET_ENDPOINT_V2 = "/api/yara/v2/ruleset/matches/"
    __YARA_RULESET_ENDPOINT = "/api/yara/ruleset/"
    __ENABLE_OR_DISABLE_YARA_RULESET_ENDPOINT = "/api/yara/ruleset/{operation}/"
    __GET_OR_SET_YARA_RULESET_SYNCHRONIZATION_TIME_ENDPOINT = "/api/yara/ticloud/time/"
    __YARA_LOCAL_RETROSCAN_ENDPOINT = "/api/uploads/local-retro-hunt/"
    __YARA_CLOUD_RETROSCANS_ENDPOINT = "/api/yara/ruleset/{ruleset_name}/cloud-retro-hunt/"
    __ADVANCED_SEARCH_ENDPOINT_V2 = "/api/samples/v2/search/"
    __ADVANCED_SEARCH_ENDPOINT_V3 = "/api/samples/v3/search/"
    __LIST_CONTAINERS_ENDPOINT = "/api/samples/containers/"
    __URL_REPORT_ENDPOINT = "/api/network-threat-intel/url/"
    __DOMAIN_REPORT_ENDPOINT = "/api/network-threat-intel/domain/{domain}/"
    __IP_REPORT_ENDPOINT = "/api/network-threat-intel/ip/{ip}/report/"
    __IP_TO_DOMAIN_ENDPOINT = "/api/network-threat-intel/ip/{ip}/resolutions/"
    __URLS_FROM_IP_ENDPOINT = "/api/network-threat-intel/ip/{ip}/urls/"
    __FILES_FROM_IP_ENDPOINT = "/api/network-threat-intel/ip/{ip}/downloaded_files/"

    __FIELDS_V2 = ("id", "sha1", "sha256", "sha512", "md5", "category", "file_type", "file_subtype",
                   "identification_name", "identification_version", "file_size", "extracted_file_count",
                   "local_first_seen", "local_last_seen", "classification_origin", "classification_reason",
                   "classification_source", "classification", "riskscore", "classification_result", "ticore", "tags",
                   "summary", "ticloud", "aliases", "networkthreatintelligence", "domainthreatintelligence"
                   )

    __TITANIUM_CORE_FIELDS = "sha1, sha256, sha512, md5, imphash, info, application, protection, security, behaviour," \
                             " certificate, document, mobile, media, web, email, strings, interesting_strings," \
                             " classification, indicators, tags, attack, story"

    def __init__(self, host, username=None, password=None, token=None, fields_v2=__FIELDS_V2,
                 ticore_fields=__TITANIUM_CORE_FIELDS, wait_time_seconds=2, retries=10, verify=True, proxies=None,
                 user_agent=DEFAULT_USER_AGENT):

        self._host = self.__validate_host(host)
        self._url = "{host}{{endpoint}}".format(host=self._host)
        self._verify = verify
        self._user_agent = user_agent

        if proxies:
            if not isinstance(proxies, dict):
                raise WrongInputError("proxies parameter must be a dictionary.")
            if len(proxies) == 0:
                raise WrongInputError("proxies parameter can not be an empty dictionary.")
        self._proxies = proxies

        if not token:
            if not username or not password:
                raise WrongInputError("If token is not provided username and password are required.")
            token = self.__get_token(username, password)

        self._headers = {
            "User-Agent": self._user_agent,
            "Authorization": "Token {token}".format(token=token)
        }
        self._fields_v2 = fields_v2
        self._ticore_fields = ticore_fields

        if not isinstance(wait_time_seconds, int):
            raise WrongInputError("wait_time_seconds must be an integer.")
        self._wait_time_seconds = wait_time_seconds

        if not isinstance(retries, int):
            raise WrongInputError("retries must be an integer.")
        self._retries = retries

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

    def configuration_dump(self):
        """Returns the configuration of the instantiated A1000 object.
            :return: configuration string
            :rtype: str
        """
        configuration = """
            Host: {host}
            Report summary fields: {fields}
            Wait time in seconds: {wait_time_seconds}
            Number of retries: {retries}
            User agent: {user_agent}
            SSL verify: {verify}
        """.format(
            host=self._host,
            fields=self._fields_v2,
            wait_time_seconds=self._wait_time_seconds,
            retries=self._retries,
            user_agent=self._user_agent,
            verify=self._verify
        )

        return configuration

    def test_connection(self):
        """Creates a request towards the A1000 Check Status API to test the connection
        with A1000.
        """
        self.file_analysis_status(
            sample_hashes=["0000000000000000000000000000000000000000"],
            sample_status="processed"
        )

        return

    def upload_sample_from_path(self, file_path, custom_filename=None, archive_password=None,
                                rl_cloud_sandbox_platform=None, tags=None, comment=None, cloud_analysis=True):
        """Accepts a file path string for file upload and returns a response.
        Additional parameters can be provided.
            :param file_path: path to file
            :type file_path: str
            :param custom_filename: custom file name for upload
            :type custom_filename: str
            :param archive_password: password, if file is a password-protected archive
            :type archive_password: str
            :param rl_cloud_sandbox_platform: Cloud Sandbox platform (windows7, windows10 or macos_11)
            :type rl_cloud_sandbox_platform: str
            :param tags: a string of comma separated tags
            :type tags: str
            :param comment: comment string
            :type comment: str
            :param cloud_analysis: use cloud analysis
            :type cloud_analysis: bool
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        if not isinstance(file_path, str):
            raise WrongInputError("file_path must be a string.")

        data = self.__create_post_payload(
            custom_filename=custom_filename,
            archive_password=archive_password,
            rl_cloud_sandbox_platform=rl_cloud_sandbox_platform,
            tags=tags,
            comment=comment,
            cloud_analysis=cloud_analysis
        )

        url = self._url.format(endpoint=self.__UPLOAD_ENDPOINT)

        try:
            file_handle = open(file_path, "rb")
        except IOError as error:
            raise WrongInputError("Error while opening file in 'rb' mode - {error}".format(error=str(error)))

        response = self.__post_request(
            url=url,
            files={"file": file_handle},
            data=data
        )

        self.__raise_on_error(response)

        return response

    def upload_sample_from_file(self, file_source, custom_filename=None, archive_password=None,
                                rl_cloud_sandbox_platform=None, tags=None, comment=None, cloud_analysis=True):
        """Accepts an open file in 'rb' mode for file upload and returns a response.
        Additional parameters can be provided.
            :param file_source: open file
            :type file_source: file or BinaryIO
            :param custom_filename: custom file name for upload
            :type custom_filename: str
            :param archive_password: password, if file is a password-protected archive
            :type archive_password: str
            :param rl_cloud_sandbox_platform: Cloud Sandbox platform (windows7, windows10 or macos_11)
            :type rl_cloud_sandbox_platform: str
            :param tags: a string of comma separated tags
            :type tags: str
            :param comment: comment string
            :type comment: str
            :param cloud_analysis: use cloud analysis
            :type cloud_analysis: bool
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        if not hasattr(file_source, "read"):
            raise WrongInputError("file_source parameter must be a file open in 'rb' mode.")

        data = self.__create_post_payload(
            custom_filename=custom_filename,
            archive_password=archive_password,
            rl_cloud_sandbox_platform=rl_cloud_sandbox_platform,
            tags=tags,
            comment=comment,
            cloud_analysis=cloud_analysis
        )

        url = self._url.format(endpoint=self.__UPLOAD_ENDPOINT)

        response = self.__post_request(
            url=url,
            files={"file": file_source},
            data=data
        )

        self.__raise_on_error(response)

        return response

    def upload_sample_from_url(self, file_url, crawler=None, archive_password=None, rl_cloud_sandbox_platform=None):
        """Accepts a file url and returns a response.
        Additional parameters can be provided.
            :param file_url: URL from which the appliance should download the data
            :type file_url: str
            :param crawler: crawler method (local or cloud)
            :type crawler: str
            :param archive_password: password, if file is a password-protected archive
            :type archive_password: str
            :param rl_cloud_sandbox_platform: Cloud Sandbox platform (windows7, windows10 or macos_11)
            :type rl_cloud_sandbox_platform: str
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """

        data = self.__create_post_payload(
            crawler=crawler,
            archive_password=archive_password,
            rl_cloud_sandbox_platform=rl_cloud_sandbox_platform,
            file_url=file_url
        )

        url = self._url.format(endpoint=self.__UPLOAD_ENDPOINT)

        response = self.__post_request(
            url=url,
            data=data,
        )

        self.__raise_on_error(response)

        return response

    def file_analysis_status(self, sample_hashes, sample_status=None):
        """Accepts a list of file hashes and returns their analysis completion information.
            :param sample_hashes: list of hash strings
            :type sample_hashes: list[str]
            :param sample_status: return only samples with this classification;
            supported values are 'processed' and 'not_found'
            :type sample_status: str
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        data = {"hash_values": sample_hashes}

        params = {}

        if sample_status:
            params["status"] = sample_status

        url = self._url.format(endpoint=self.__FILE_ANALYSIS_STATUS_ENDPOINT)

        response = self.__post_request(
            url=url,
            data=data,
            params=params
        )

        self.__raise_on_error(response)

        return response

    def check_submitted_url_status(self, task_id):
        """Accepts a task ID returned by the upload sample from url
            :param task_id: ID of the submitted sample
            :type task_id: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(task_id, str):
            raise WrongInputError("task_id parameter must be a string.")

        endpoint = self.__URL_ANALYSIS_STATUS_ENDPOINT.format(task_id=task_id)

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def get_submitted_url_report(self, task_id, retry):
        """Accepts a task ID returned by the upload sample from url and returns a report response.
        This method combines uploading a sample from url and obtaining the analysis report.
        Additional fields can be provided.
        The result fetching action of this method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready.
            :param task_id: ID of the submitted sample
            :type task_id: str
            :param retry: if set to False there will only be one try at obtaining the analysis report
            :type retry: bool
            :return: response
            :rtype: requests.Response
        """

        if retry not in (True, False):
            raise WrongInputError("retry parameter must be boolean.")

        retries = self._retries if retry else 0

        for iteration in range(retries + 1):
            if iteration:
                time.sleep(self._wait_time_seconds)

            response = self.check_submitted_url_status(task_id=task_id)
            status = response.json().get("processing_status")

            if status == "error":
                raise Exception(response.json().get("message"))

            if status == "complete":
                return response

        raise RequestTimeoutError("Report fetching attempts finished - The analysis report is still not ready "
                                  "or the sample does not exist on the appliance.")

    def upload_sample_from_url_and_get_report(self, file_url, retry=True, crawler="local", archive_password=None,
                                              rl_cloud_sandbox_platform=None):
        """Accepts a file url for file upload and returns a report response.
        This method combines uploading a sample from url and obtaining the summary analysis report.
        Additional fields can be provided.
        The result fetching action of this method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready.
            :param file_url: URL from which the appliance should download the data
            :type file_url: str
            :param retry: if set to False there will only be one try at obtaining the analysis report
            :type retry: bool
            :param crawler: crawler method (local or cloud)
            :type crawler: string
            :param archive_password: password, if file is a password-protected archive
            :type archive_password: str
            :param rl_cloud_sandbox_platform: Cloud Sandbox platform (windows7, windows10 or macos_11)
            :type rl_cloud_sandbox_platform: str
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """

        upload_response = self.upload_sample_from_url(file_url=file_url, crawler=crawler,
                                                      archive_password=archive_password,
                                                      rl_cloud_sandbox_platform=rl_cloud_sandbox_platform)

        response_detail = upload_response.json().get("detail")
        task_id = response_detail.get("id")
        task_id = str(task_id)

        response = self.get_submitted_url_report(task_id=task_id, retry=retry)

        return response

    def get_summary_report_v2(self, sample_hashes, retry=True, fields=None, include_networkthreatintelligence=True,
                              skip_reanalysis=False):
        """Accepts a single hash or a list of hashes and returns JSON containing a summary report for each of them.
        This method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready.
            :param sample_hashes: hash string or list of hash strings
            :type sample_hashes: str or list[str]
            :param retry: if set to False there will only be one try at obtaining the analysis report
            :type retry: bool
            :param fields: list of A1000 report 'fields' to query
            :type fields: list[str]
            :param include_networkthreatintelligence: include network threat intelligence in the summary report
            :type include_networkthreatintelligence: bool
            :param skip_reanalysis: skip sample reanalysis when fetching the summary report
            :type skip_reanalysis: bool
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        if fields and not isinstance(fields, list):
            raise WrongInputError("fields parameter must be a list of strings.")

        if not fields:
            fields = self._fields_v2

        if retry not in (True, False):
            raise WrongInputError("retry parameter must be boolean.")

        if isinstance(sample_hashes, str):
            sample_hashes = [sample_hashes]

        validate_hashes(
            hash_input=sample_hashes,
            allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
        )

        retries = self._retries if retry else 0

        analysis_is_finished = False

        for iteration in range(retries + 1):
            if iteration:
                time.sleep(self._wait_time_seconds)

            analysis_status = self.file_analysis_status(sample_hashes=sample_hashes, sample_status="processed")

            if len(analysis_status.json().get("results")) == len(sample_hashes):
                analysis_is_finished = True

                break

        if not analysis_is_finished:
            raise RequestTimeoutError("Report fetching attempts finished - The analysis report is still not ready "
                                      "or the sample does not exist on the appliance.")

        url = self._url.format(endpoint=self.__SUMMARY_REPORT_ENDPOINT_V2)

        if include_networkthreatintelligence not in (True, False):
            raise WrongInputError("include_networkthreatintelligence parameter must be boolean.")

        if include_networkthreatintelligence and \
                ("networkthreatintelligence" not in fields or "domainthreatintelligence" not in fields):
            raise WrongInputError("If include_networkthreatintelligence is set to True, the fields list must include "
                                  "both 'networkthreatintelligence' and 'domainthreatintelligence'.")

        if skip_reanalysis not in (True, False):
            raise WrongInputError("skip_reanalysis parameter must be boolean.")

        data = {
            "hash_values": sample_hashes,
            "fields": fields,
            "include_networkthreatintelligence": str(include_networkthreatintelligence).lower(),
            "skip_reanalysis": str(skip_reanalysis).lower()
        }

        response = self.__post_request(url=url, data=data)

        self.__raise_on_error(response)

        return response

    def upload_sample_and_get_summary_report_v2(self, file_path=None, file_source=None, retry=True, fields=None,
                                                include_networkthreatintelligence=True, skip_reanalysis=False,
                                                custom_filename=None, tags=None, comment=None, cloud_analysis=True,
                                                archive_password=None, rl_cloud_sandbox_platform=None):
        """Accepts either a file path string or an open file in 'rb' mode for file upload and returns a summary analysis
        report response. This method combines uploading a sample and obtaining the summary analysis report.
        Additional fields can be provided.
        The result fetching action of this method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready.
            :param file_path: file path
            :type file_path: str
            :param file_source: open file
            :type file_source: file or BinaryIO
            :param retry: if set to False there will only be one try at obtaining the analysis report
            :type retry: bool
            :param fields: list of A1000 report 'fields' to query
            :type fields: list[str]
            :param include_networkthreatintelligence: include network threat intelligence in the summary report
            :type include_networkthreatintelligence: bool
            :param skip_reanalysis: skip sample reanalysis when fetching the summary report
            :type skip_reanalysis: bool
            :param custom_filename: custom file name for upload
            :type custom_filename: str
            :param tags: a string of comma separated tags
            :type tags: str
            :param comment: comment string
            :type comment: str
            :param cloud_analysis: use cloud analysis
            :type cloud_analysis: bool
            :param archive_password: password, if file is a password-protected archive
            :type archive_password: str
            :param rl_cloud_sandbox_platform: Cloud Sandbox platform (windows7, windows10 or macos_11)
            :type rl_cloud_sandbox_platform: str
            :return: response
            :rtype: requests.Response
        """
        if (file_path and file_source) or (not file_path and not file_source):
            raise WrongInputError("Either file_path or file_source parameter must be provided. "
                                  "Using both or none of the parameters in sot allowed.")

        if file_path:
            upload_response = self.upload_sample_from_path(file_path, custom_filename, archive_password,
                                                           rl_cloud_sandbox_platform, tags, comment, cloud_analysis)
        else:
            upload_response = self.upload_sample_from_file(file_source, custom_filename, tags, archive_password,
                                                           rl_cloud_sandbox_platform, comment, cloud_analysis)

        response_detail = upload_response.json().get("detail")
        sha1 = response_detail.get("sha1")
        sha1 = str(sha1)

        response = self.get_summary_report_v2(
            sample_hashes=[sha1],
            retry=retry,
            fields=fields,
            include_networkthreatintelligence=include_networkthreatintelligence,
            skip_reanalysis=skip_reanalysis
        )

        return response

    def get_detailed_report_v2(self, sample_hashes, retry=False, fields=None, skip_reanalysis=False):
        """Accepts a single hash or a list of hashes and returns a detailed analysis report for the selected samples.
        This method utilizes the set number of retries and wait time in seconds and times out if the
        analysis results are not ready.
            :param sample_hashes: hash string or list of hash strings
            :type sample_hashes: str or list[str]
            :param retry: if set to False there will only be one try at obtaining the analysis report
            :type retry: bool
            :param fields: list of A1000 report 'fields' to query
            :type fields: list[str]
            :param skip_reanalysis: skip sample reanalysis when fetching the summary report
            :type skip_reanalysis: bool
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        if fields and not isinstance(fields, list):
            raise WrongInputError("fields parameter must be a list of strings.")

        if retry not in (True, False):
            raise WrongInputError("retry parameter must be boolean.")

        if skip_reanalysis not in (True, False):
            raise WrongInputError("skip_reanalysis parameter must be boolean.")

        if not fields:
            fields = self._fields_v2

        if isinstance(sample_hashes, str):
            sample_hashes = [sample_hashes]

        validate_hashes(
            hash_input=sample_hashes,
            allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
        )

        retries = self._retries if retry else 0

        analysis_is_finished = False

        for iteration in range(retries + 1):
            if iteration:
                time.sleep(self._wait_time_seconds)

            analysis_status = self.file_analysis_status(sample_hashes=sample_hashes, sample_status="processed")

            if len(analysis_status.json().get("results")) == len(sample_hashes):
                analysis_is_finished = True

                break

        if not analysis_is_finished:
            raise RequestTimeoutError("Report fetching attempts finished - The analysis report is still not ready "
                                      "or the sample does not exist on the appliance.")

        url = self._url.format(endpoint=self.__DETAILED_REPORT_ENDPOINT_V2)

        data = {
            "hash_values": sample_hashes,
            "fields": fields,
            "skip_reanalysis": str(skip_reanalysis).lower()
        }

        response = self.__post_request(url=url, data=data)

        self.__raise_on_error(response)

        return response

    def upload_sample_and_get_detailed_report_v2(self, file_path=None, file_source=None, retry=True, fields=None,
                                                 custom_filename=None, tags=None, comment=None, cloud_analysis=True,
                                                 archive_password=None, rl_cloud_sandbox_platform=None,
                                                 skip_reanalysis=False):
        """Accepts either a file path string or an open file in 'rb' mode for file upload and returns a detailed
        analysis report response. This method combines uploading a sample and obtaining the detailed analysis report.
        Additional fields can be provided.
        The result fetching action of this method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready.
            :param file_path: file path
            :type file_path: str
            :param file_source: open file
            :type file_source: file or BinaryIO
            :param retry: if set to False there will only be one try at obtaining the analysis report
            :type retry: bool
            :param fields: list of A1000 report 'fields' to query
            :type fields: list[str]
            :param skip_reanalysis: skip sample reanalysis when fetching the detailed report
            :type skip_reanalysis: bool
            :param custom_filename: custom file name for upload
            :type custom_filename: str
            :param tags: a string of comma separated tags
            :type tags: str
            :param comment: comment string
            :type comment: str
            :param cloud_analysis: use cloud analysis
            :type cloud_analysis: bool
            :param archive_password: password, if file is a password-protected archive
            :type archive_password: str
            :param rl_cloud_sandbox_platform: Cloud Sandbox platform (windows7, windows10 or macos_11)
            :type rl_cloud_sandbox_platform: str
            :return: response
            :rtype: requests.Response
        """
        if (file_path and file_source) or (not file_path and not file_source):
            raise WrongInputError("Either file_path or file_source parameter must be provided. "
                                  "Using both or none of the parameters in sot allowed.")

        if file_path:
            upload_response = self.upload_sample_from_path(file_path, custom_filename, archive_password,
                                                           rl_cloud_sandbox_platform, tags, comment, cloud_analysis)
        else:
            upload_response = self.upload_sample_from_file(file_source, custom_filename, tags, archive_password,
                                                           rl_cloud_sandbox_platform, comment, cloud_analysis)

        response_detail = upload_response.json().get("detail")
        sha1 = response_detail.get("sha1")
        sha1 = str(sha1)

        response = self.get_detailed_report_v2(
            sample_hashes=sha1,
            retry=retry,
            fields=fields,
            skip_reanalysis=skip_reanalysis
        )

        return response

    def get_classification_v3(self, sample_hash, local_only=False, av_scanners=False):
        """Get classification for one sample.
        The default value of local_only is False, which, if not changed, will send a request to TitaniumCloud to
        get the sample. The av_scanners parameter decides if the AV scanner results will be included in the
        classification report.
            :param sample_hash: hash string
            :type sample_hash: str
            :param local_only: return only local samples without querying TitaniumCloud
            :type local_only: bool
            :param av_scanners: return AV scanner results
            :type av_scanners: bool
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
        )

        if local_only not in (True, False):
            raise WrongInputError("local_only parameter must be boolean.")

        if av_scanners not in (True, False):
            raise WrongInputError("av_scanners parameter must be boolean.")

        if local_only and av_scanners:
            raise WrongInputError("local_only must be False if av_scanners are used.")

        params = "localonly={local_only}&av_scanners={av_scanners}".format(
            local_only=str(int(local_only)),
            av_scanners=str(int(av_scanners))
        )

        endpoint = "{endpoint}?{params}".format(
            endpoint=self.__CLASSIFY_ENDPOINT_V3.format(hash_value=sample_hash),
            params=params
        )

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def reanalyze_samples_v2(self, hash_input, titanium_cloud=False, titanium_core=False, rl_cloud_sandbox=False,
                             cuckoo_sandbox=False, fireeye=False, joe_sandbox=False, cape=False,
                             rl_cloud_sandbox_platform=None):
        """Accepts a single hash or a list of hashes of various types and reanalyzes the corresponding sample(s).
        This method can be used for reanalyzing a single sample or a batch of samples, depending on the data type
        passed.
        AT least one analysis type must be used (set to True).
        If rl_cloud_sandbox is used as an analysis type, rl_cloud_sandbox_platform must be defined.
            :param hash_input: single hash or a list of hashes
            :type hash_input: str or list[str]
            :param titanium_cloud: use TitaniumCloud
            :type titanium_cloud: bool
            :param titanium_core: use TitaniumCore
            :type titanium_core: bool
            :param rl_cloud_sandbox: use RL cloud sandbox
            :type rl_cloud_sandbox: bool
            :param cuckoo_sandbox: use Cuckoo sandbox
            :type cuckoo_sandbox: bool
            :param fireeye: use FireEye
            :type fireeye: bool
            :param joe_sandbox: use Joe sandbox
            :type joe_sandbox: bool
            :param cape: use Cape
            :type cape: bool
            :param rl_cloud_sandbox_platform: desired platform on which the sample will be detonated;
                                            see ReversingLabs.SDK.helper.AVAILABLE PLATFORMS for options
            :type rl_cloud_sandbox_platform: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(hash_input, list):
            hash_input = [hash_input]

        validate_hashes(
            hash_input=hash_input,
            allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
        )

        analysis_type_dict = {"cloud": titanium_cloud, "core": titanium_core, "rl_cloud_sandbox": rl_cloud_sandbox,
                              "cuckoo": cuckoo_sandbox, "fireeye": fireeye, "joe": joe_sandbox, "cape": cape}

        if not all(isinstance(analysis_type, bool) for analysis_type in analysis_type_dict.values()):
            raise WrongInputError("All analysis type parameters must be boolean.")

        if rl_cloud_sandbox and rl_cloud_sandbox_platform not in AVAILABLE_PLATFORMS:
            raise WrongInputError("if rl_cloud_sandbox is used, rl_cloud_sandbox_platform parameter must be one "
                                  "of the following values: {platforms}".format(platforms=AVAILABLE_PLATFORMS))

        analysis_list = [key for key, value in analysis_type_dict.items() if value]

        if not analysis_list:
            raise WrongInputError("At least one analysis type parameter needs to be defined.")

        analysis_types = ",".join(analysis_list)

        url = self._url.format(endpoint=self.__REANALYZE_BULK_ENDPOINT_V2)

        data = {
            "hash_value": hash_input,
            "analysis": analysis_types,
            "rl_cloud_sandbox_platform": rl_cloud_sandbox_platform
        }

        response = self.__post_request(url=url, data=data)

        self.__raise_on_error(response)

        return response

    def list_extracted_files_v2(self, sample_hash, page_size=None, page=None):
        """Get a list of all files TitaniumCore engine extracted from the requested sample during static analysis.
        If the page parameter is used, it needs to be combined with the page_size parameter while keeping track of
        remaining pages of results.
        e.g. - if result count is 5 and page_size is 2, there is only 3 pages worth of results.
        The page_size parameter can be used without the page parameter.
        If page_size and page are not used, all results are returned in one response.
            :param sample_hash: hash string
            :type sample_hash: str
            :param page_size: defines the number of results on the returned page
            :type page_size: int
            :param page: defines which page of results should be fetched
            :type page: int
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
        )

        if page and not page_size:
            raise WrongInputError("If the page parameter is used, page_size must be defined.")

        endpoint = self.__LIST_EXTRACTED_FILES_ENDPOINT_V2.format(
            hash_value=sample_hash
        )

        url = self._url.format(endpoint=endpoint)

        params_dict = {"page": page, "page_size": page_size}

        params_list = []

        for key, value in params_dict.items():
            if value:
                if not isinstance(value, int):
                    raise WrongInputError("{param} parameter must be integer.".format(param=key))

                params_list.append("{key}={value}".format(key=key, value=value))

        if params_list:
            params = "?{params}".format(params="&".join(params_list))

            url = "{url}{params}".format(url=url, params=params)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def list_extracted_files_v2_aggregated(self, sample_hash, max_results=None):
        """Get a list of all files TitaniumCore engine extracted from the requested sample during static analysis.
        Paging is done automatically and results from individual responses aggregated into one list and returned.
        The max_results parameter defines the maximum number of results to be returned to the list.
            :param sample_hash: hash string
            :type sample_hash: str
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        result_list = []
        next_page = 1

        while next_page:
            response = self.list_extracted_files_v2(
                sample_hash=sample_hash,
                page=next_page,
                page_size=100
            )

            response_json = response.json()

            results = response_json.get("results", [])
            result_list.extend(results)

            next_page_url = response_json.get("next", None)
            next_page = int(next_page_url.split("?")[1].split("&")[0].split("=")[1]) if next_page_url else None

            if not max_results:
                if not next_page:
                    return result_list

            else:
                if not next_page or len(result_list) >= max_results:
                    return result_list[:max_results]

    def download_extracted_files(self, sample_hash):
        """Accepts a single hash string and returns a downloadable archive file
        containing files extracted from the desired sample.
            :param sample_hash: hash string
            :type sample_hash: str
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
        )

        endpoint = self.__DOWNLOAD_EXTRACTED_FILES_ENDPOINT.format(hash_value=sample_hash)

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def download_sample(self, sample_hash):
        """Accepts a single hash string and returns a downloadable sample.
            :param sample_hash: hash string
            :type sample_hash: str
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
        )

        endpoint = self.__DOWNLOAD_SAMPLE_ENDPOINT.format(hash_value=sample_hash)

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def delete_samples(self, hash_input):
        """Accepts a single hash string or a list of hashes and deletes the corresponding samples.
        This method combines the use of two endpoints for the following two actions.
        - Delete a single sample: 'Delete sample' endpoint
        - Delete a batch of samples: 'Delete multiple samples v2' endpoint
            :param hash_input: single hash string or a list of hashes
            :type hash_input: str or list[str]
            :return: response
            :rtype: requests.Response
        """
        if isinstance(hash_input, str):
            validate_hashes(
                hash_input=[hash_input],
                allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
            )

            endpoint = self.__DELETE_SAMPLE_ENDPOINT.format(hash_value=hash_input)

            url = self._url.format(endpoint=endpoint)

            response = self.__delete_request(url=url)

        elif isinstance(hash_input, list):
            validate_hashes(
                hash_input=hash_input,
                allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
            )

            url = self._url.format(endpoint=self.__DELETE_SAMPLES_BULK_ENDPOINT_V2)

            data = {"hash_values": hash_input}

            response = self.__post_request(url=url, data=data)

        else:
            raise WrongInputError("hash_input parameter must be a single hash string or "
                                  "a list of hash strings of the same type.")

        self.__raise_on_error(response)

        return response

    def check_sample_removal_status_v2(self, task_id):
        """Accepts the task ID returned by the bulk sample removal endpoint and returns a response that
        indicates if the removal request was finished successfully and if all samples have been deleted.
            :param task_id: ID of the bulk sample removal task
            :type task_id: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(task_id, str):
            raise WrongInputError("task_id parameter must be string.")

        endpoint = self.__CHECK_SAMPLE_REMOVAL_STATUS_ENDPOINT_V2.format(task_id=task_id)

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def __utilize_pdf_endpoint(self, sample_hash, endpoint):
        """Accepts a single hash string and utilizes pdf report endpoint for initiation, status checking and downloading
        of a PDF analysis report for the requested sample.
            :param sample_hash: hash string
            :type sample_hash: str
            :param endpoint: endpoint string
            :type endpoint: str
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(MD5, SHA1, SHA256)
        )

        endpoint = endpoint.format(
            hash_value=sample_hash,
        )

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def create_pdf_report(self, sample_hash):
        """Accepts a single hash string and initiates the creation of a PDF analysis report for the requested sample.
        The response includes links to the pdf creation status endpoint and pdf download ednpoint for the requested
        sample.
            :param sample_hash: hash string
            :type sample_hash: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__utilize_pdf_endpoint(sample_hash, self.__PDF_REPORT_CREATE_ENDPOINT)
        return response

    def check_pdf_report_creation(self, sample_hash):
        """Accepts a single hash string that should correspond to the hash used in the request with
        create_pdf_report method. The response includes an informative message about the status of the PDF
        report previously requested.
            :param sample_hash: hash string
            :type sample_hash: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__utilize_pdf_endpoint(sample_hash, self.__PDF_REPORT_STATUS_ENDPOINT)
        return response

    def download_pdf_report(self, sample_hash):
        """Accepts a single hash string that should correspond to the hash used in the request with
        create_pdf_report method.
            :param sample_hash: hash string
            :type sample_hash: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__utilize_pdf_endpoint(sample_hash, self.__PDF_REPORT_DOWNLOAD_ENDPOINT)
        return response

    def get_titanium_core_report_v2(self, sample_hash, fields=None):
        """Accepts a single hash string and gets the full TitaniumCore static analysis report for the requested sample.
        The requested sample must be present on the appliance. If the optional fields parameter is not provided in the
        request, all available parts of the static analysis report are returned in the response.
            :param sample_hash: hash string
            :type sample_hash: str
            :param fields: a string of comma separated TitaniumCore 'fields' to query
            :type fields: str
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
        )

        if fields and not isinstance(fields, str):
            raise WrongInputError("fields parameter must be a string.")

        if fields is None:
            fields = self._ticore_fields

        endpoint = self.__TITANIUM_CORE_REPORT_ENDPOINT_V2.format(
            hash_value=sample_hash,
            fields=fields
        )

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def __utilize_dynamic_analysis_endpoint(self, sample_hash, report_format, endpoint):
        """Accepts endpoint, a single hash string and a report format and utilizes dynamic analysis endpoint for
        initiation, status checking and downloading of PDF or HTML reports
        for samples that have gone through dynamic analysis in the ReversingLabs Cloud Sandbox.
            :param sample_hash: hash string
            :type sample_hash: str
            :param report_format: report format ('html' or 'pdf')
            :rtype report_format: str
            :param endpoint: endpoint string
            :type endpoint: str
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(SHA1,)
        )

        if report_format not in ("html", "pdf"):
            raise WrongInputError("report_format parameter must be either 'html' or 'pdf'.")

        endpoint = endpoint.format(
            hash_value=sample_hash,
            format=report_format,
        )

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def create_dynamic_analysis_report(self, sample_hash, report_format):
        """Accepts a single hash string and a report format and initiates the creation of PDF or HTML reports for
        samples that have gone through dynamic analysis in the ReversingLabs Cloud Sandbox.
        The response includes links to the report creation status endpoint and report download endpoint for the
        requested sample.
            :param sample_hash: hash string
            :type sample_hash: str
            :param report_format: report format ('html' or 'pdf')
            :rtype report_format: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__utilize_dynamic_analysis_endpoint(sample_hash,
                                                            report_format,
                                                            self.__DYNAMIC_ANALYSIS_REPORT_CREATE_ENDPOINT)
        return response

    def check_dynamic_analysis_report_status(self, sample_hash, report_format):
        """Accepts a single hash string and report format parameters that should correspond to the parameters used in
        the request with create_dynamic_analysis_report method. The response includes an informative
        message about the status of the report previously requested.
            :param sample_hash: hash string
            :type sample_hash: str
            :param report_format: report format ('html' or 'pdf')
            :rtype report_format: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__utilize_dynamic_analysis_endpoint(sample_hash,
                                                            report_format,
                                                            self.__DYNAMIC_ANALYSIS_REPORT_STATUS_ENDPOINT)
        return response

    def download_dynamic_analysis_report(self, sample_hash, report_format):
        """Accepts a single hash string and report format parameters that should correspond to the parameters used in
        the request with create_dynamic_analysis_report method.
            :param sample_hash: hash string
            :type sample_hash: str
            :param report_format: report format ('html' or 'pdf')
            :rtype report_format: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__utilize_dynamic_analysis_endpoint(sample_hash,
                                                            report_format,
                                                            self.__DYNAMIC_ANALYSIS_REPORT_DOWNLOAD_ENDPOINT)
        return response

    def set_classification(self, sample_hash, classification, system, risk_score=None, threat_platform=None,
                           threat_type=None, threat_name=None):
        """Accepts a single hash string, allows the user to set the classification of a sample, either in TitaniumCloud
        or locally on the A1000. Returns a response containing a new classification.
            :param sample_hash: hash string
            :type sample_hash: str
            :param system: 'local' or 'ticloud'
            :type system: str
            :param classification: 'goodware', 'suspicious' or 'malicious'
            :type classification: str
            :param risk_score: If specified, it must be within range for the specified classification. If not specified,
            a default value is used: Goodware: 0, Suspicious: 6, Malicious: 10
            :type risk_score: int
            :param threat_platform: if specified, it must be on the supported list (platforms and subplatforms - see
            official API docs). If not specified, the default value is 'Win32'.
            :type threat_platform: str
            :param threat_type: If specified, it must be on the supported list (malware types - see official API docs).
            If not specified, the default value is 'Malware'.
            :type threat_type: str
            :param threat_name: If specified, must be an alphanumeric string not longer than 32 characters. If not
            specified, the default value is 'Generic'.
            :type threat_name: str
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
        )

        if system not in ("local", "ticloud"):
            raise WrongInputError("system parameter must be either 'local' or 'ticloud'.")

        endpoint = self.__SET_OR_DELETE_CLASSIFICATION_ENDPOINT.format(
            hash_value=sample_hash,
            system=system
        )

        data = self.__create_post_payload(
            classification=classification,
            risk_score=risk_score,
            threat_platform=threat_platform,
            threat_type=threat_type,
            threat_name=threat_name
        )

        url = self._url.format(endpoint=endpoint)

        response = self.__post_request(url=url, data=data)

        self.__raise_on_error(response)

        return response

    def delete_classification(self, sample_hash, system="local"):
        """Accepts a single hash string, allows the user to delete the classification of a sample, either in
        TitaniumCloud or locally on the A1000.
            :param sample_hash: hash string
            :type sample_hash: str
            :param system: 'local' or 'ticloud'
            :type system: str
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
        )

        if system and system not in ("local", "ticloud"):
            raise WrongInputError("system parameter must be either 'local' or 'ticloud'.")

        endpoint = self.__SET_OR_DELETE_CLASSIFICATION_ENDPOINT.format(
            hash_value=sample_hash,
            system=system
        )

        url = self._url.format(endpoint=endpoint)

        response = self.__delete_request(url=url)

        self.__raise_on_error(response)

        return response

    def get_user_tags(self, sample_hash):
        """Accepts a single hash string and returns lists of existing user tags for the requested sample.
           :param sample_hash: hash string
           :type sample_hash: str
           :return: response
           :rtype: requests.Response
           """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(MD5, SHA1, SHA256)
        )

        endpoint = self.__TAGS_ENDPOINT.format(
            hash_value=sample_hash
        )

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def post_user_tags(self, sample_hash, tags):
        """Accepts a single hash string and adds one or more user tags to the requested sample.
           :param sample_hash: hash string
           :type sample_hash: str
           :param tags: list of hash strings
           :type tags: list[str]
           :return: response
           :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(MD5, SHA1, SHA256)
        )

        if not isinstance(tags, list):
            raise WrongInputError("tags parameter must be a list of strings.")

        endpoint = self.__TAGS_ENDPOINT.format(
            hash_value=sample_hash
        )

        post_json = {"tags": tags}

        url = self._url.format(endpoint=endpoint)

        response = self.__post_request(url=url, post_json=post_json)

        self.__raise_on_error(response)

        return response

    def delete_user_tags(self, sample_hash, tags):
        """Accepts a single hash string and removes one or more user tags from the requested sample.
           :param sample_hash: hash string
           :type sample_hash: str
           :param tags: list of hash strings
           :type tags: list[str]
           :return: response
           :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(MD5, SHA1, SHA256)
        )

        if not isinstance(tags, list):
            raise WrongInputError("tags parameter must be a list of strings.")

        endpoint = self.__TAGS_ENDPOINT.format(
            hash_value=sample_hash
        )

        post_json = {"tags": tags}

        url = self._url.format(endpoint=endpoint)

        response = self.__delete_request(url=url, post_json=post_json)

        self.__raise_on_error(response)

        return response

    def get_yara_rulesets_on_the_appliance_v2(self, owner_type=None, status=None, source=None, page=None, page_size=None):
        """Retrieves a list of YARA rulesets that are on the A1000 appliance. The list can be filtered by several
        criteria (ruleset status, source, and owner) using optional parameters.
            :param owner_type: supported values: my (default - currently authenticated user), user, system, all
            :type owner_type: str
            :param status: supported values: all (default), error, active, disabled, pending, invalid, capped
            :type status: str
            :param source: supported values: all (default), local, cloud
            :type source: str
            :param page: when this parameter is omitted from the request, all available results are returned at once
            :type page: str
            :param page_size: parameter that controls how many results to return per page in the response
            :type page_size: str
            :return: response
            :rtype: requests.Response
        """
        params = {"type": owner_type, "status": status, "source": source, "page": page, "page_size": page_size}
        params_string_array = []

        if bool(params["page"]) != bool(params["page_size"]):
            raise WrongInputError("page and page_size parametes must be used together")

        for key, val in params.items():
            if val:
                if not isinstance(val, str):
                    raise WrongInputError("{key} parameter must be a string".format(key=key))
                params_string_array.append("{key}={val}".format(key=key, val=val))

        if len(params_string_array) > 0:
            query_string = "&".join(params_string_array)
            endpoint = "{endpoint}?{query_string}".format(endpoint=self.__RETRIEVE_YARA_RULESETS_ENDPOINT_V2,
                                                          query_string=query_string)
        else:
            endpoint = self.__RETRIEVE_YARA_RULESETS_ENDPOINT_V2

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def get_yara_ruleset_contents(self, ruleset_name):
        """
        Retrieves the full contents of the requested ruleset in raw text/plain format. All rulesets can be retrieved,
        regardless of their current status on the appliance (enabled, disabled…)
            :param ruleset_name: name of the YARA ruleset to retrieve. Ruleset names are case-sensitive
            :type ruleset_name: str
            :return: response
            :rtype: requests.Response:
        """
        if not isinstance(ruleset_name, str):
            raise WrongInputError("ruleset_name parameter must be a string")

        endpoint = self.__RETRIEVE_YARA_RULESET_CONTENTS_ENDPOINT.format(ruleset_name=ruleset_name)

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def get_yara_ruleset_matches_v2(self, ruleset_name, page=None, page_size=None):
        """Retrieves the list of YARA matches (both local and cloud) for requested rulesets. If multiple rulesets are
        provided in the request, only the samples that match all requested rulesets are listed in the response.
            :param ruleset_name: name of a single ruleset (string) or multiple rulesets (list of strings)
            :type ruleset_name: str or list[str]
            :param page: when this parameter is omitted from the request, all available results are returned at once
            :type page: str
            :param page_size: parameter that controls how many results to return per page in the response
            :type page_size: str
            :return: response
            :rtype: requests.Response:
        """
        param_list = []

        if isinstance(ruleset_name, list):
            for i, name in enumerate(ruleset_name):
                ruleset_name[i] = f"name={name}"

            param_list.extend(ruleset_name)

        else:
            param_list.append(f"name={ruleset_name}")

        if page:
            param_list.append(f"page={page}")

            if page_size:
                param_list.append(f"page_size={page_size}")

            else:
                raise WrongInputError("page and page_size parameters must be used together")

        query_string = "&".join(param_list)
        endpoint = "{endpoint}?{query_string}".format(endpoint=self.__RETRIEVE_MATCHES_FOR_A_YARA_RULESET_ENDPOINT_V2,
                                                      query_string=query_string)

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def create_or_update_yara_ruleset(self, name, content, publish=None, ticloud=None):
        """Creates a new YARA ruleset if it doesn’t exist. If a ruleset with the specified name already exists, a new
        revision (update) of the ruleset is created.
            :param name: name of the ruleset to create or update
            :type name: str
            :param content: content of the YARA ruleset to create or update
            :type content: str
            :param publish: determines whether the ruleset should be synchronized to other appliances in the same
            C1000 cluster
            :type publish: bool
            :param ticloud: determines whether the ruleset should be synchronized with TitaniumCloud or not
            :type ticloud: bool
            :return: response
            :rtype: requests.Response:
        """
        data = self.__create_post_payload(
            name=name,
            content=content,
            publish=publish,
            ticloud=ticloud
        )

        endpoint = self.__YARA_RULESET_ENDPOINT

        url = self._url.format(endpoint=endpoint)

        response = self.__post_request(url=url, data=data)

        self.__raise_on_error(response)

        return response

    def delete_yara_ruleset(self, name, publish=None):
        """Deletes the specified YARA ruleset and its matches from the appliance.
            :param name: name of the ruleset to create or update
            :type name: str
            :param publish: determines whether the ruleset should be synchronized to other appliances in the same
            C1000 cluster
            :type publish: bool
            :return: response
            :rtype: requests.Response:
        """
        post_json = self.__create_post_payload(
            name=name,
            publish=publish,

        )
        endpoint = self.__YARA_RULESET_ENDPOINT

        url = self._url.format(endpoint=endpoint)

        response = self.__delete_request(url=url, post_json=post_json)

        self.__raise_on_error(response)

        return response

    def enable_or_disable_yara_ruleset(self, enabled, name, publish=None):
        """Enables/disables ruleset on the appliance. Administrators can manage any ruleset while regular A1000 users
        can only manage their own rulesets.
            :param enabled: whether to enable (enabled=True) or disable (enabled=False) the specified ruleset
            :type enabled: bool
            :param name: name of the ruleset to enable/disable
            :type name: str
            :param publish: determines whether the ruleset should be synchronized to other appliances in the same
            C1000 cluster
            :type publish: bool
            :return: response
            :rtype: requests.Response:
        """
        data = self.__create_post_payload(
            name=name,
            publish=publish,
        )

        if enabled and enabled not in (True, False):
            raise WrongInputError("enabled parameter must be boolean.")

        endpoint = self.__ENABLE_OR_DISABLE_YARA_RULESET_ENDPOINT.format(operation="enable" if enabled else "disable")

        url = self._url.format(endpoint=endpoint)

        response = self.__post_request(url=url, data=data)

        self.__raise_on_error(response)

        return response

    def get_yara_ruleset_synchronization_time(self):
        """Gets information about the current synchronization status for TitaniumCloud-enabled rulesets.
            :return: response
            :rtype: requests.Response:
        """
        endpoint = self.__GET_OR_SET_YARA_RULESET_SYNCHRONIZATION_TIME_ENDPOINT

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def update_yara_ruleset_synchronization_time(self, sync_time):
        """Updates the TitaniumCloud synchronization time for TitaniumCloud-enabled YARA rulesets.
            :param sync_time: format should be UTC (YYYY-MM-DD hh:mm)
            :type sync_time: str
            :return: response
            :rtype: requests.Response:
        """
        try:
            datetime.datetime.strptime(sync_time, '%Y-%m-%d %H:%M')
        except ValueError:
            raise WrongInputError("Incorrect sync_time format, should be YYYY-MM-DD hh:mm")

        endpoint = self.__GET_OR_SET_YARA_RULESET_SYNCHRONIZATION_TIME_ENDPOINT

        url = self._url.format(endpoint=endpoint)

        response = self.__post_request(url=url, data={"time": sync_time})

        self.__raise_on_error(response)

        return response

    def start_or_stop_yara_local_retro_scan(self, operation):
        """Allows users to initiate the Local Retro scan on the A1000 appliance, and stop the Local Retro scan that is
        in progress on the appliance.
            :param operation: accepted values: START, STOP (case-sensitive)
            :type operation: str
            :return: response
            :rtype: requests.Response:
        """
        if operation not in ("START", "STOP"):
            raise WrongInputError("operation parameter must be either 'START' or 'STOP'")

        endpoint = self.__YARA_LOCAL_RETROSCAN_ENDPOINT

        url = self._url.format(endpoint=endpoint)

        response = self.__post_request(url=url, data={"operation": operation})

        self.__raise_on_error(response)

        return response

    def get_yara_local_retro_scan_status(self):
        """Allows users to check the status of Local Retro on the A1000 appliance. The response indicates the current
        state of Local Retro, time and date when the latest Local Retro scan was started and/or stopped, and a list of
        previous Local Retro scans with the same details.
            :return: response
            :rtype: requests.Response:
        """
        endpoint = self.__YARA_LOCAL_RETROSCAN_ENDPOINT

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def start_or_stop_yara_cloud_retro_scan(self, operation, ruleset_name):
        """Allows users to start and stop a Cloud Retro scan for a specified ruleset on the A1000 appliance, as well as
        to clear all Cloud Retro results for the ruleset.
            :param operation: accepted values: START, STOP, CLEAR (case-sensitive)
            :type operation: str
            :param ruleset_name: name of the YARA ruleset that the Cloud Retro scan should be run on
            :type ruleset_name: str
            :return: response
            :rtype: requests.Response
        """
        if operation not in ("START", "STOP", "CLEAR"):
            raise WrongInputError("operation parameter must be either 'START', 'STOP' or 'CLEAR'")

        if not isinstance(ruleset_name, str):
            raise WrongInputError("ruleset_name parameter must be a string")

        endpoint = self.__YARA_CLOUD_RETROSCANS_ENDPOINT.format(ruleset_name=ruleset_name)

        url = self._url.format(endpoint=endpoint)

        response = self.__post_request(url=url, data={"operation": operation})

        self.__raise_on_error(response)

        return response

    def get_yara_cloud_retro_scan_status(self, ruleset_name):
        """Allows users to check the status of Cloud Retro for the specified YARA ruleset. The response indicates the
        current state of Cloud Retro, time and date when the latest Cloud Retro scan was started and/or stopped, and a
        list of previous Cloud Retro scans with the same details.
            :param ruleset_name: name of the YARA ruleset for which to check for the Cloud Retro scan status
            :type ruleset_name: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(ruleset_name, str):
            raise WrongInputError("ruleset_name parameter must be a string")

        endpoint = self.__YARA_CLOUD_RETROSCANS_ENDPOINT.format(ruleset_name=ruleset_name)

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def advanced_search_v2(self, query_string, ticloud=False, page_number=1, records_per_page=20, sorting_criteria=None,
                           sorting_order="desc"):
        """THIS METHOD IS DEPRECATED. Use advanced_search_v3 instead.

        Sends a query string to the A1000 Advanced Search API v2.
        The query string must be composed of key-value pairs separated by space.
        A key is separated from its value by a colon symbol and no spaces.
        For directions on how to write advanced search queries, consult the A1000 documentation.
        If a page number is not provided, the first page of results will be returned.
            Query string example:
            'av-count:5 available:TRUE'

            :param query_string: query string
            :type query_string: str
            :param ticloud: show only cloud results
            :type ticloud: bool
            :param page_number: page number
            :type page_number: int
            :param records_per_page: number of records returned per page; maximum value is 100
            :type records_per_page: int
            :param sorting_criteria: define the criteria used in sorting; possible values are 'sha1', 'firstseen',
            'threatname', 'sampletype', 'filecount', 'size'
            :type sorting_criteria: str
            :param sorting_order: sorting order; possible values are 'desc', 'asc'
            :type sorting_order: str
            :return: response
            :rtype: requests.Response
        """
        warn("This method is deprecated. Use advanced_search_v3 instead.", DeprecationWarning)

        if not isinstance(query_string, str):
            raise WrongInputError("The search query must be a string.")

        if not isinstance(ticloud, bool):
            raise WrongInputError("ticloud parameter must be boolean.")

        if not isinstance(records_per_page, int) or not 1 <= records_per_page <= 100:
            raise WrongInputError("records_per_page parameter must be an integer with a value "
                                  "between 1 and 100 (included).")

        url = self._url.format(endpoint=self.__ADVANCED_SEARCH_ENDPOINT_V2)

        post_json = {"query": query_string, "ticloud": ticloud, "page": page_number,
                     "records_per_page": records_per_page}

        if sorting_criteria:
            if sorting_criteria not in ADVANCED_SEARCH_SORTING_CRITERIA or sorting_order not in ("desc", "asc"):
                raise WrongInputError("Sorting criteria must be one of the following options: {criteria}. "
                                      "Sorting order needs to be 'desc' or 'asc'.".format(
                    criteria=ADVANCED_SEARCH_SORTING_CRITERIA
                ))
            sorting_expression = "{criteria} {order}".format(
                criteria=sorting_criteria,
                order=sorting_order
            )

            post_json["sort"] = sorting_expression

        response = self.__post_request(url=url, post_json=post_json)

        self.__raise_on_error(response)

        return response

    def advanced_search_v2_aggregated(self, query_string, ticloud=False, max_results=None, sorting_criteria=None,
                                      sorting_order="desc"):
        """THIS METHOD IS DEPRECATED. Use advanced_search_v3_aggregated instead.

        Sends a query string to the A1000 Advanced Search API v2.
        The query string must be composed of key-value pairs separated by space.
        A key is separated from its value by a colon symbol and no spaces.
        For directions on how to write advanced search queries, consult the A1000 documentation.
        Paging is done automatically and results from individual
        responses aggregated into one list and returned`.
        The 'max_results' parameter defines the maximum desired number of results to be returned.
            Query string example:
            'av-count:5 available:TRUE'

            :param query_string: search query - see API documentation for details on writing search queries
            :type query_string: str
            :param ticloud: show only cloud results
            :type ticloud: bool
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :param sorting_criteria: define the criteria used in sorting; possible values are 'sha1', 'firstseen',
            'threatname', 'sampletype', 'filecount', 'size'
            :type sorting_criteria: str
            :param sorting_order: sorting order; possible values are 'desc', 'asc'
            :type sorting_order: str
            :return: list of results
            :rtype: list
        """
        warn("This method is deprecated. Use advanced_search_v3_aggregated instead.", DeprecationWarning)

        results = []
        next_page = 1
        more_pages = True

        while more_pages:
            response = self.advanced_search_v2(
                query_string=query_string,
                ticloud=ticloud,
                page_number=next_page,
                records_per_page=100,
                sorting_criteria=sorting_criteria,
                sorting_order=sorting_order
            )

            response_json = response.json()

            entries = response_json.get("rl").get("web_search_api").get("entries", [])
            results.extend(entries)

            next_page = response_json.get("rl").get("web_search_api").get("next_page", None)
            more_pages = response_json.get("rl").get("web_search_api").get("more_pages", False)

            if not max_results:
                if not more_pages:
                    return results

            else:
                if not more_pages or len(results) >= max_results:
                    return results[:max_results]

    def advanced_search_v3(self, query_string, ticloud=False, start_search_date=None, end_search_date=None,
                           page_number=1, records_per_page=20, sorting_criteria=None, sorting_order="desc"):
        """Sends a query string to the A1000 Advanced Search API v3.
        The query string must be composed of key-value pairs separated by space.
        A key is separated from its value by a colon symbol and no spaces.
        For directions on how to write advanced search queries, consult the A1000 documentation.
        If a page number is not provided, the first page of results will be returned.
            Query string example:
            'av-count:5 available:TRUE'

            :param query_string: query string
            :type query_string: str
            :param ticloud: show only cloud results
            :type ticloud: bool
            :param start_search_date: the starting date for the search; this parameter represents the later
            date, as searches are performed backwards in time; required if the ticloud parameter is set to True
            :type start_search_date: str
            :param end_search_date: the ending date for the search; this parameter represents the earlier
            date, as searches are performed backwards in time; required if the ticloud parameter is set to True
            :type end_search_date: str
            :param page_number: page number
            :type page_number: int
            :param records_per_page: number of records returned per page; maximum value is 100
            :type records_per_page: int
            :param sorting_criteria: define the criteria used in sorting; possible values are 'sha1', 'firstseen',
            'threatname', 'sampletype', 'filecount', 'size'
            :type sorting_criteria: str
            :param sorting_order: sorting order; possible values are 'desc', 'asc'
            :type sorting_order: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(query_string, str):
            raise WrongInputError("The search query must be a string.")

        if not isinstance(ticloud, bool):
            raise WrongInputError("ticloud parameter must be boolean.")

        if not isinstance(records_per_page, int) or not 1 <= records_per_page <= 100:
            raise WrongInputError("records_per_page parameter must be an integer with a value "
                                  "between 1 and 100 (included).")

        url = self._url.format(endpoint=self.__ADVANCED_SEARCH_ENDPOINT_V3)

        post_json = {"query": query_string, "ticloud": ticloud, "page": page_number,
                     "records_per_page": records_per_page}

        if ticloud:
            if not all((start_search_date, end_search_date)):
                raise WrongInputError("if ticloud parameter is set to True, both start_search_date and "
                                      "end_search_date must be defined.")

            post_json["start_search_date"] = start_search_date
            post_json["end_search_date"] = end_search_date

        if sorting_criteria:
            if sorting_criteria not in ADVANCED_SEARCH_SORTING_CRITERIA or sorting_order not in ("desc", "asc"):
                raise WrongInputError("Sorting criteria must be one of the following options: {criteria}. "
                                      "Sorting order needs to be 'desc' or 'asc'.".format(
                                        criteria=ADVANCED_SEARCH_SORTING_CRITERIA
                                      ))
            sorting_expression = "{criteria} {order}".format(
                criteria=sorting_criteria,
                order=sorting_order
            )

            post_json["sort"] = sorting_expression

        response = self.__post_request(url=url, post_json=post_json)

        self.__raise_on_error(response)

        return response

    def advanced_search_v3_aggregated(self, query_string, ticloud=False, start_search_date=None, end_search_date=None,
                                      records_per_page=20, max_results=None, sorting_criteria=None,
                                      sorting_order="desc"):
        """This method handles the paging automatically.
        Sends a query string to the A1000 Advanced Search API v3.
        The query string must be composed of key-value pairs separated by space.
        A key is separated from its value by a colon symbol and no spaces.
        For directions on how to write advanced search queries, consult the A1000 documentation.
        If a page number is not provided, the first page of results will be returned.
            Query string example:
            'av-count:5 available:TRUE'

            :param query_string: query string
            :type query_string: str
            :param ticloud: show only cloud results
            :type ticloud: bool
            :param start_search_date: the starting date for the search; this parameter represents the later
            date, as searches are performed backwards in time; required if the ticloud parameter is set to True
            :type start_search_date: str
            :param end_search_date: the ending date for the search; this parameter represents the earlier
            date, as searches are performed backwards in time; required if the ticloud parameter is set to True
            :type end_search_date: str
            :param records_per_page: number of records returned per page; maximum value is 100
            :type records_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :param sorting_criteria: define the criteria used in sorting; possible values are 'sha1', 'firstseen',
            'threatname', 'sampletype', 'filecount', 'size'
            :type sorting_criteria: str
            :param sorting_order: sorting order; possible values are 'desc', 'asc'
            :type sorting_order: str
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = 1
        more_pages = True

        while more_pages:
            response = self.advanced_search_v3(
                query_string=query_string,
                ticloud=ticloud,
                page_number=next_page,
                records_per_page=records_per_page,
                sorting_criteria=sorting_criteria,
                sorting_order=sorting_order,
                start_search_date=start_search_date,
                end_search_date=end_search_date
            )

            response_json = response.json()

            entries = response_json.get("rl").get("web_search_api").get("entries", [])
            results.extend(entries)

            next_page = response_json.get("rl").get("web_search_api").get("next_page", None)
            more_pages = response_json.get("rl").get("web_search_api").get("more_pages")

            if not max_results:
                if not more_pages:
                    return results

            else:
                if not more_pages or len(results) >= max_results:
                    return results[:max_results]

    def list_containers_for_hashes(self, sample_hashes):
        """Gets a list of all top-level containers from which the requested sample has been extracted during analysis.
        This is a bulk API, meaning that a single request can be used to simultaneously query containers for multiple
        file hashes. If a requested hash doesn’t have a container, it will not be included in the response.
            :param sample_hashes: a list of one or more hash values, but must all be of the same type(SHA1, SHA256,
            or MD5)
            :type sample_hashes list[str]
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(sample_hashes, list):
            raise WrongInputError("sample_hashes parameter must be a list of strings.")

        validate_hashes(
            hash_input=sample_hashes,
            allowed_hash_types=(MD5, SHA1, SHA256)
        )

        endpoint = self.__LIST_CONTAINERS_ENDPOINT

        url = self._url.format(endpoint=endpoint)

        response = self.__post_request(url=url, data={"hash_values": sample_hashes})

        self.__raise_on_error(response)

        return response

    def network_url_report(self, requested_url):
        """Accepts a URL string and returns a report about the requested URL.
            :param requested_url: URL for analysis
            :type requested_url: str
            :return: response
            :rtype: requests.Response
        """

        if not isinstance(requested_url, str):
            raise WrongInputError("url parameter must be string.")

        encoded_url = parse.quote_plus(requested_url)

        endpoint = "{endpoint}?url={url}".format(
            endpoint=self.__URL_REPORT_ENDPOINT,
            url=encoded_url
        )

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def network_domain_report(self, domain):
        """Accepts a domain string and returns a report about the requested domain.
            :param domain: domain for analysis
            :type domain: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(domain, str):
            raise WrongInputError("domain parameter must be string.")

        endpoint = self.__DOMAIN_REPORT_ENDPOINT.format(domain=domain)

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def network_ip_addr_report(self, ip_addr):
        """Accepts an IP address string and returns a report about the requested IP address.
            :param ip_addr: IP address for analysis
            :type ip_addr: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__ip_addr_endpoints(
            ip_addr=ip_addr,
            specific_endpoint=self.__IP_REPORT_ENDPOINT
        )

        return response

    def network_ip_to_domain(self, ip_addr, page=None, page_size=500):
        """Accepts an IP address string and returns a list of IP-to-domain mappings.
            :param ip_addr: requested IP address
            :type ip_addr: str
            :param page: page string
            :type page: str or None
            :param page_size: number of results per page
            :type page_size: int
            :return: response
            :rtype: requests.Response
        """
        if page and not isinstance(page, str):
            raise WrongInputError("page parameter must be string.")

        if page_size and not isinstance(page_size, int):
            raise WrongInputError("page_size parameter must be integer.")

        params = {
            "page": page,
            "page_size": page_size
        }

        response = self.__ip_addr_endpoints(
            ip_addr=ip_addr,
            specific_endpoint=self.__IP_TO_DOMAIN_ENDPOINT,
            params=params
        )

        return response

    def network_ip_to_domain_aggregated(self, ip_addr, page_size=500, max_results=None):
        """Accepts an IP address string and returns a list of IP-to-domain mappings.
        This method performs the paging automatically and returns a specified maximum number of records.
            :param ip_addr: requested IP address
            :type ip_addr: str
            :param page_size: number of records per page
            :type page_size: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = None

        while True:
            response = self.network_ip_to_domain(
                ip_addr=ip_addr,
                page=next_page,
                page_size=page_size
            )

            response_json = response.json()

            resolutions = response_json.get("resolutions", [])
            results.extend(resolutions)

            next_page = response_json.get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def network_urls_from_ip(self, ip_addr, page=None, page_size=500):
        """Accepts an IP address string and returns a list of URLs hosted on the requested IP address.
            :param ip_addr: requested IP address
            :type ip_addr: str
            :param page: page string
            :type page: str or None
            :param page_size: number of records per page
            :type page_size: int
            :return: response
            :rtype: requests.Response
        """
        if page and not isinstance(page, str):
            raise WrongInputError("page parameter must be string.")

        if page_size and not isinstance(page_size, int):
            raise WrongInputError("page_size parameter must be integer.")

        params = {
            "page": page,
            "page_size": page_size
        }

        response = self.__ip_addr_endpoints(
            ip_addr=ip_addr,
            specific_endpoint=self.__URLS_FROM_IP_ENDPOINT,
            params=params
        )

        return response

    def network_urls_from_ip_aggregated(self, ip_addr, page_size=500, max_results=None):
        """Accepts an IP address string and returns a list of URLs hosted on the requested IP address.
        This method performs the paging automatically and returns a specified maximum number of records.
            :param ip_addr: requested IP address
            :type ip_addr: str
            :param page_size: number of records per page
            :type page_size: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = None

        while True:
            response = self.network_urls_from_ip(
                ip_addr=ip_addr,
                page=next_page,
                page_size=page_size
            )

            response_json = response.json()

            urls = response_json.get("urls", [])
            results.extend(urls)

            next_page = response_json.get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def network_files_from_ip(self, ip_addr, extended_results=True, classification=None, page=None, page_size=500):
        """Accepts an IP address string and returns a list of hashes and
        classifications for files found on the requested IP address.
            :param ip_addr: requested IP address
            :type ip_addr: str
            :param extended_results: return extended results
            :type extended_results: bool
            :param classification: return only records with this classification
            :type classification: str
            :param page: page string
            :type page: str or None
            :param page_size: number of records per page
            :type page_size: int
            :return: response
            :rtype: requests.Response
        """
        if page and not isinstance(page, str):
            raise WrongInputError("page parameter must be string.")

        if page_size and not isinstance(page_size, int):
            raise WrongInputError("page_size parameter must be integer.")

        if not isinstance(extended_results, bool):
            raise WrongInputError("extended_results parameter must be boolean.")

        if classification and classification not in CLASSIFICATIONS:
            raise WrongInputError("Only {classifications} is allowed "
                                  "as the classification input.".format(classifications=CLASSIFICATIONS))

        params = {
            "extended": extended_results,
            "classification": classification,
            "page": page,
            "page_size": page_size
        }

        response = self.__ip_addr_endpoints(
            ip_addr=ip_addr,
            specific_endpoint=self.__FILES_FROM_IP_ENDPOINT,
            params=params
        )

        return response

    def network_files_from_ip_aggregated(self, ip_addr, extended_results=True, classification=None, page_size=500,
                                         max_results=None):
        """Accepts an IP address string and returns a list of hashes and
        classifications for files found on the requested IP address.
        This method performs the paging automatically and returns a specified maximum number of records.
            :param ip_addr: requested IP address
            :type ip_addr: str
            :param extended_results: return extended results
            :type extended_results: bool
            :param classification: return only records with this classification
            :type classification: str
            :param page_size: number of records per page
            :type page_size: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = None

        while True:
            response = self.network_files_from_ip(
                ip_addr=ip_addr,
                extended_results=extended_results,
                classification=classification,
                page=next_page,
                page_size=page_size
            )

            response_json = response.json()

            downloaded_files = response_json.get("downloaded_files", [])
            results.extend(downloaded_files)

            next_page = response_json.get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def __ip_addr_endpoints(self, ip_addr, specific_endpoint, params=None):
        """Private method for all IP related endpoints from the Network Threat Intelligence API.
            :param ip_addr: requested IP address
            :type ip_addr: str
            :param specific_endpoint: requested endpoint string
            :type specific_endpoint: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(ip_addr, str):
            raise WrongInputError("ip_addr parameter must be string.")

        endpoint = specific_endpoint.format(ip=ip_addr)

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url, params=params)

        self.__raise_on_error(response)

        return response

    def __get_token(self, username, password):
        """Returns an obtained token using the provided username and password.
            :return: token string
            :rtype: str
        """
        credentials = {"username": username, "password": password}

        response = requests.post(
            url=self._host + self.__TOKEN_ENDPOINT,
            data=credentials,
            verify=self._verify,
            proxies=self._proxies
        )

        self.__raise_on_error(response)

        token = response.json().get("token")

        return token

    @staticmethod
    def __create_post_payload(custom_filename=None, file_url=None,  crawler=None, archive_password=None,
                              rl_cloud_sandbox_platform=None, tags=None, comment=None, cloud_analysis=True,
                              classification=None, risk_score=None, threat_platform=None, threat_type=None,
                              threat_name=None, name=None, content=None, publish=None, ticloud=None):
        """Accepts optional fields and returns a formed dictionary of those fields.
            :param custom_filename: custom file name for upload
            :type custom_filename: str
            :param file_url: URL from which the appliance should download the data
            :type file_url: str
            :param crawler: crawler method (local or cloud)
            :type crawler: str
            :param archive_password: password, if file is a password-protected archive
            :type archive_password: str
            :param rl_cloud_sandbox_platform: Cloud Sandbox platform (windows7, windows10 or macos_11)
            :type rl_cloud_sandbox_platform: str
            :param tags: a string of comma separated tags
            :type tags: str
            :param comment: comment string
            :type comment: str
            :param cloud_analysis: use cloud analysis
            :type cloud_analysis: bool
            :param classification: 'goodware', 'suspicious' or 'malicious'
            :type classification: str
            :param risk_score: If specified, it must be within range for the specified classification. If not specified,
            a default value is used: Goodware: 0, Suspicious: 6, Malicious: 10
            :type risk_score: int
            :param threat_platform: if specified, it must be on the supported list (platforms and subplatforms - see
            official API docs). If not specified, the default value is 'Win32'.
            :type threat_platform: str
            :param threat_type: If specified, it must be on the supported list (malware types - see pfficial API docs).
            If not specified, the default value is 'Malware'.
            :type threat_type: str
            :param threat_name: If specified, must be an alphanumeric string not longer than 32 characters. If not
            specified, the default value is 'Generic'.
            :type threat_name: str
            :param name: name of the ruleset to create or update
            :type name: str
            :param content: content of the YARA ruleset to create or update
            :type content: str
            :param publish: determines whether the ruleset should be synchronized to other appliances in the same
            C1000 cluster
            :type publish: bool
            :param ticloud: determines whether the ruleset should be synchronized with TitaniumCloud or not
            :type ticloud: bool
            :return: dictionary of defined optional fields or None
            :rtype: dict or None
        """
        if custom_filename and not isinstance(custom_filename, str):
            raise WrongInputError("custom_filename parameter must be string.")

        if tags and not isinstance(tags, str):
            raise WrongInputError("tags parameter must be string.")

        if file_url:
            if not isinstance(file_url, str):
                raise WrongInputError("file_url parameter must be string.")
            if not file_url.startswith(("http://", "https://")):
                raise WrongInputError("Supported file_url protocols are HTTP and HTTPS.")

        if crawler and crawler not in ("cloud", "local"):
            raise WrongInputError("crawler parameter must be either 'cloud' or 'local'.")

        if archive_password and not isinstance(archive_password, str):
            raise WrongInputError("archive_password parameter must be string.")

        if rl_cloud_sandbox_platform and rl_cloud_sandbox_platform not in AVAILABLE_PLATFORMS:
            raise WrongInputError("rl_cloud_sandbox_platform parameter must be one od the following: "
                                  "{platforms}".format(platforms=AVAILABLE_PLATFORMS))

        if comment and not isinstance(comment, str):
            raise WrongInputError("comment parameter must be string.")

        if cloud_analysis not in (True, False):
            raise WrongInputError("cloud_analysis parameter must be boolean.")

        allowed_classifications_and_risk_scores = {'goodware': [0, 1, 2, 3, 4, 5],
                                                   'suspicious': [6, 7, 8, 9, 10],
                                                   'malicious': [6, 7, 8, 9, 10]}

        if classification and classification not in allowed_classifications_and_risk_scores.keys():
            raise WrongInputError("classification parameter must be some of the following values:" +
                                  " ".join(str(key) for key in allowed_classifications_and_risk_scores.keys()))
        else:
            if risk_score and risk_score not in allowed_classifications_and_risk_scores[classification]:
                raise WrongInputError(f"risk_score {risk_score} is not allowed for classification '{classification}'.")

        if threat_platform and not isinstance(threat_platform, str):
            raise WrongInputError("threat_platform parameter must be string.")

        if threat_type and not isinstance(threat_type, str):
            raise WrongInputError("threat_type parameter must be string.")

        if threat_name and not isinstance(threat_name, str):
            raise WrongInputError("threat_type parameter must be string.")

        if name and not isinstance(name, str):
            raise WrongInputError("name parameter must be string.")

        if content and not isinstance(content, str):
            raise WrongInputError("content parameter must be string.")

        if publish and publish not in (True, False):
            raise WrongInputError("publish parameter must be boolean.")

        if ticloud and ticloud not in (True, False):
            raise WrongInputError("ticloud parameter must be boolean.")

        data = {}

        if custom_filename:
            data["filename"] = custom_filename

        if crawler:
            data["crawler"] = crawler

        if archive_password:
            data["archive_password"] = archive_password

        if rl_cloud_sandbox_platform:
            data["rl_cloud_sandbox_platform"] = rl_cloud_sandbox_platform

        if tags:
            data["tags"] = tags

        if comment:
            data["comment"] = comment

        if cloud_analysis:
            data["analysis"] = "cloud"

        if file_url:
            data["url"] = file_url

        if classification:
            data['classification'] = classification

        if risk_score:
            data['risk_score'] = risk_score

        if threat_platform:
            data['threat_platform'] = threat_platform

        if threat_type:
            data['threat_type'] = threat_type

        if threat_name:
            data['threat_name'] = threat_name

        if name:
            data['name'] = name

        if content:
            data['content'] = content

        if publish:
            data['publish'] = publish

        if ticloud:
            data['ticloud'] = ticloud

        if not data:
            return None

        return data

    def __get_request(self, url, params=None):
        """A generic GET request method for all A1000 methods.
            :param url: request URL
            :type url: str
            :return: response
            :rtype: requests.Response
        """
        response = requests.get(
            url=url,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers,
            params=params
        )

        return response

    def __post_request(self, url, post_json=None, files=None, data=None, params=None):
        """A generic POST request method for all A1000 methods.
            :param url: request URL
            :type url: str
            :param post_json: JSON body
            :type post_json: dict
            :param files: files to send
            :param data: data to send
            :param params: additional params to send
            :return: response
            :rtype: requests.Response
        """
        response = requests.post(
            url=url,
            json=post_json,
            files=files,
            data=data,
            params=params,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers
        )

        return response

    def __delete_request(self, url, post_json=None):
        """A generic DELETE request method for all A1000 methods.
        :param url: request URL
        :type url: str
        :return: response
        :rtype: requests.Response
        """
        response = requests.delete(
            url=url,
            json=post_json,
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
        raise exception(response_object=response)
