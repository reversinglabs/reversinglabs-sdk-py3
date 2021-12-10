"""
author: Mislav Sever

A1000
A Python module for the ReversingLabs A1000 appliance REST API.
"""

import requests
import time

from ReversingLabs.SDK.helper import ADVANCED_SEARCH_SORTING_CRITERIA, DEFAULT_USER_AGENT, RESPONSE_CODE_ERROR_MAP, \
    MD5, SHA1, SHA256, SHA512, \
    RequestTimeoutError, WrongInputError, \
    validate_hashes


class A1000(object):

    __TOKEN_ENDPOINT = "/api-token-auth/"
    __UPLOAD_ENDPOINT = "/api/uploads/"
    __CHECK_STATUS_ENDPOINT = "/api/samples/status/"
    __RESULTS_ENDPOINT = "/api/samples/list/"
    __CLASSIFY_ENDPOINT = "/api/v2/samples/{hash_value}/classification/?localonly={localonly}"
    __REANALYZE_ENDPOINT = "/api/samples/{hash_value}/analyze/"
    __REANALYZE_BULK_ENDPOINT = "/api/samples/analyze_bulk/"
    __LIST_EXTRACTED_FILES_ENDPOINT = "/api/samples/{hash_value}/extracted-files/"
    __DOWNLOAD_EXTRACTED_FILES_ENDPOINT = "/api/samples/{hash_value}/unpacked/"
    __DELETE_SAMPLE_ENDPOINT = "/api/samples/{hash_value}/"
    __DOWNLOAD_SAMPLE_ENDPOINT = "/api/samples/{hash_value}/download/"
    __DELETE_SAMPLES_BULK_ENDPOINT = "/api/samples/v2/delete_bulk/"
    __ADVANCED_SEARCH_ENDPOINT = "/api/samples/search/"

    __FIELDS = (
        "id",
        "sha1",
        "sha256",
        "sha512",
        "md5",
        "category",
        "file_type",
        "file_subtype",
        "identification_name",
        "identification_version",
        "file_size",
        "extracted_file_count",
        "local_first_seen",
        "local_last_seen",
        "classification_origin",
        "classification_reason",
        "threat_status",
        "trust_factor",
        "threat_level",
        "threat_name",
        "ticore",
        "summary",
        "ticloud",
        "aliases"
    )

    def __init__(self, host, username=None, password=None, token=None, fields=__FIELDS, wait_time_seconds=2, retries=10,
                 verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT):

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
        self._fields = fields

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
            fields=self._fields,
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
        _ = self.__analysis_is_finished(
            sample_hashes=["0000000000000000000000000000000000000000"]
        )

        return

    def upload_sample_from_path(self, file_path, custom_filename=None, tags=None, comment=None,
                                cloud_analysis=True):
        """Accepts a file path string for file upload and returns a response.
        Additional parameters can be provided.
            :param file_path: path to file
            :type file_path: str
            :param custom_filename: custom file name for upload
            :type custom_filename: str
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

    def upload_sample_from_file(self, file_source, custom_filename=None, tags=None, comment=None, cloud_analysis=True):
        """Accepts an open file in 'rb' mode for file upload and returns a response.
        Additional parameters can be provided.
            :param file_source: open file
            :type file_source: file or BinaryIO
            :param custom_filename: custom file name for upload
            :type custom_filename: str
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

    def get_results(self, sample_hashes, retry=True, fields=None):
        """Accepts a list of hashes and returns JSON containing a summary report for each of them.
        This method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready.
            :param sample_hashes: hash string or list of hash strings
            :type sample_hashes: str or list[str]
            :param retry: if set to False there will only be one try at obtaining the analysis report
            :type retry: bool
            :param fields: list of A1000 report 'fields' to query
            :type fields: list[str]
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        if fields and not isinstance(fields, list):
            raise WrongInputError("fields parameter must be a list of strings.")

        if not fields:
            fields = self._fields

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

            analysis_is_finished = self.__analysis_is_finished(sample_hashes)
            if analysis_is_finished:
                break

        if not analysis_is_finished:
            raise RequestTimeoutError("Report fetching attempts finished - The analysis report is still not ready "
                                      "or the sample does not exist on the appliance.")

        url = self._url.format(endpoint=self.__RESULTS_ENDPOINT)

        data = {
            "hash_values": sample_hashes,
            "fields": fields
        }

        response = self.__post_request(url=url, data=data)

        self.__raise_on_error(response)

        return response

    def upload_sample_and_get_results(self, file_path=None, file_source=None, retry=True, custom_filename=None,
                                      tags=None, comment=None, cloud_analysis=True):
        """Accepts either a file path string or an open file in 'rb' mode for file upload and returns
        an analysis report response. This method combines uploading a sample and obtaining the analysis results.
        Additional fields can be provided.
        The result obtaining action of this method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready.
            :param file_path: file path
            :type file_path: str
            :param file_source: open file
            :type file_source: file or BinaryIO
            :param retry: if set to False there will only be one try at obtaining the analysis report
            :type retry: bool
            :param custom_filename: custom file name for upload
            :type custom_filename: str
            :param tags: a string of comma separated tags
            :type tags: str
            :param comment: comment string
            :type comment: str
            :param cloud_analysis: use cloud analysis
            :type cloud_analysis: bool
            :return: response
            :rtype: requests.Response
        """
        if (file_path and file_source) or (not file_path and not file_source):
            raise WrongInputError("Either file_path or file_source parameter must be provided. "
                                  "Using both or none of the parameters in sot allowed.")

        if file_path:
            upload_response = self.upload_sample_from_path(file_path, custom_filename, tags, comment,
                                                           cloud_analysis)
        else:
            upload_response = self.upload_sample_from_file(file_source, custom_filename, tags,
                                                           comment, cloud_analysis)

        response_detail = upload_response.json().get("detail")
        sha1 = response_detail.get("sha1")
        sha1 = str(sha1)

        response = self.get_results(
            sample_hashes=[sha1],
            retry=retry
        )

        return response

    def get_classification(self, sample_hash, local_only=True):
        """Get classification for one sample hash.
            :param sample_hash: hash string
            :type sample_hash: str
            :param local_only: return only local samples
            :type local_only: bool
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
        )

        if local_only not in (True, False):
            raise WrongInputError("local_only parameter must be boolean.")

        endpoint = self.__CLASSIFY_ENDPOINT.format(
            hash_value=sample_hash,
            localonly=int(local_only)
        )

        url = self._url.format(endpoint=endpoint)

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

    def reanalyze_samples(self, hash_input, titanium_cloud=True, titanium_core=True):
        """Accepts a single hash or a list of hashes of the same type and reanalyzes the
        corresponding samples.
            :param hash_input: single hash or a list of hashes
            :type hash_input: str or list[str]
            :param titanium_cloud: use TitaniumCloud
            :type titanium_cloud: bool
            :param titanium_core: use TitaniumCore
            :type titanium_core: bool
            :return: response
            :rtype: requests.Response
        """
        if titanium_cloud not in (True, False):
            raise WrongInputError("titanium_cloud parameter must be boolean.")

        if titanium_core not in (True, False):
            raise WrongInputError("titanium_core parameter must be boolean.")

        parameter_dict = {'core': titanium_core, 'cloud': titanium_cloud}
        analysis_list = [key for key, value in parameter_dict.items() if value]

        if len(analysis_list) == 0:
            raise WrongInputError("At least one of the following parameters needs to be enabled: "
                                  "titanium_cloud, titanium_core.")

        analysis_type = ",".join(analysis_list)

        if isinstance(hash_input, str):
            validate_hashes(
                hash_input=[hash_input],
                allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
            )

            endpoint = self.__REANALYZE_ENDPOINT.format(hash_value=hash_input)

            url = self._url.format(endpoint=endpoint)

            response = self.__post_request(url=url, data={"analysis": analysis_type})

        elif isinstance(hash_input, list):
            validate_hashes(
                hash_input=hash_input,
                allowed_hash_types=(MD5, SHA1, SHA256, SHA512)
            )

            url = self._url.format(endpoint=self.__REANALYZE_BULK_ENDPOINT)

            data = {"hash_value": hash_input, "analysis": analysis_type}

            response = self.__post_request(url=url, data=data)

        else:
            raise WrongInputError("hash_input parameter can only be a single hash string or "
                                  "a list of hash strings of the same type.")

        self.__raise_on_error(response)

        return response

    def get_extracted_files(self, sample_hash, page_size=None, page=None):
        """Get a list of all files TitaniumCore engine extracted from the requested sample during static analysis.
        If used, page_size and page need to be combined while keeping track of remaining pages of results.
        e.g. - if result count is 5 and page_size is 2, there is only 3 pages worth of results.
        The page parameter can not be used without page_size. page and page_size need to be used together.
        If page_size and page are not used, all results are returned in one response.
            :param sample_hash: hash string
            :type sample_hash: str
            :param page_size: if defined, results are returned in pages of this size
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

        endpoint = self.__LIST_EXTRACTED_FILES_ENDPOINT.format(
            hash_value=sample_hash
        )

        url = self._url.format(endpoint=endpoint)

        if (page_size and not page) or (not page_size and page):
            raise WrongInputError("Parameters page_size and page must be used together.")

        if page:
            if not isinstance(page_size, int) or not isinstance(page, int):
                raise WrongInputError("page_size and page parameters need to be integer.")

            url = "{url}?page_size={page_size}&page={page}".format(
                url=url,
                page_size=page_size,
                page=page
            )

        response = self.__get_request(url=url)

        self.__raise_on_error(response)

        return response

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

    def delete_samples(self, hash_input):
        """Accepts a single hash string or a list of hashes and deletes the corresponding samples.
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

            url = self._url.format(endpoint=self.__DELETE_SAMPLES_BULK_ENDPOINT)

            data = {"hash_values": hash_input}

            response = self.__post_request(url=url, data=data)

        else:
            raise WrongInputError("hash_input parameter must be a single hash string or "
                                  "a list of hash strings of the same type.")

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

    def advanced_search(self, query_string, page_number=1, records_per_page=20, sorting_criteria=None,
                        sorting_order="desc"):
        """Sends the query string to the A1000 Advanced Search API.
        The query string must be composed of key-value pairs separated by space.
        A key is separated from its value by a colon symbol and no spaces.
        If a page number is not provided, the first page of results will be returned.
            Query string example:
            'av-count:5 available:TRUE'

            :param query_string: query string
            :type query_string: str
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

        if not isinstance(records_per_page, int) or not 1 <= records_per_page <= 100:
            raise WrongInputError("records_per_page parameter must be an integer with a value "
                                  "between 1 and 100 (included).")

        url = self._url.format(endpoint=self.__ADVANCED_SEARCH_ENDPOINT)

        post_json = {"query": query_string, "page": page_number, "records_per_page": records_per_page}

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

    def advanced_search_aggregated(self, query_string, max_results=5000, sorting_criteria=None, sorting_order="desc"):
        """Sends the query string to the A1000 Advanced Search API.
        The query string must be composed of key-value pairs separated by space.
        A key is separated from its value by a colon symbol and no spaces.
        Pagination is done automatically and results from individual
        responses aggregated into one list and returned.
        The 'max_results' parameter defines the maximum desired number of results to be returned.
            Query string example:
            'av-count:5 available:TRUE'

            :param query_string: search query - see API documentation for details on writing search queries
            :type query_string: str
            :param max_results: maximum results to be returned in a list; default value is 5000
            :type max_results: int
            :param sorting_criteria: define the criteria used in sorting; possible values are 'sha1', 'firstseen',
            'threatname', 'sampletype', 'filecount', 'size'
            :type sorting_criteria: str
            :param sorting_order: sorting order; possible values are 'desc', 'asc'
            :type sorting_order: str
            :return: list of results
            :rtype: list
        """
        if not isinstance(max_results, int):
            raise WrongInputError("max_results parameter must be integer.")

        results = []
        next_page = 1
        more_pages = True

        while more_pages:
            response = self.advanced_search(
                query_string=query_string,
                page_number=next_page,
                records_per_page=100,
                sorting_criteria=sorting_criteria,
                sorting_order=sorting_order
            )

            response_json = response.json()

            entries = response_json.get("rl").get("web_search_api").get("entries", [])
            results.extend(entries)

            if len(results) > max_results:
                results = results[:max_results]
                return results

            next_page = response_json.get("rl").get("web_search_api").get("next_page", None)
            more_pages = response_json.get("rl").get("web_search_api").get("more_pages", False)

        return results

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
    def __create_post_payload(custom_filename=None, tags=None, comment=None, cloud_analysis=True):
        """Accepts optional fields and returns a formed dictionary of those fields.
            :param custom_filename: custom file name for upload
            :type custom_filename: str
            :param tags: a string of comma separated tags
            :type tags: str
            :param comment: comment string
            :type comment: str
            :param cloud_analysis: use cloud analysis
            :type cloud_analysis: bool
            :return: dictionary of defined optional fields or None
            :rtype: dict or None
        """
        if custom_filename and not isinstance(custom_filename, str):
            raise WrongInputError("custom_filename parameter must be string.")

        if tags and not isinstance(tags, str):
            raise WrongInputError("tags parameter must be string.")

        if comment and not isinstance(comment, str):
            raise WrongInputError("comment parameter must be string.")

        if cloud_analysis not in (True, False):
            raise WrongInputError("cloud_analysis parameter must be boolean.")

        data = {}

        if custom_filename:
            data["filename"] = custom_filename

        if tags:
            data["tags"] = tags

        if comment:
            data["comment"] = comment

        if cloud_analysis:
            data["analysis"] = "cloud"

        if len(data) == 0:
            data = None

        return data

    def __analysis_is_finished(self, sample_hashes):
        """Accepts a list of hashes and returns boolean for the get_results method.
            :param sample_hashes: list of hash strings
            :type sample_hashes: list[str]
            :return: boolean for processing status.
            :rtype: bool
        """
        data = {"hash_values": sample_hashes}
        params = {"status": "processed"}

        url = self._url.format(endpoint=self.__CHECK_STATUS_ENDPOINT)

        response = self.__post_request(
            url=url,
            data=data,
            params=params
        )

        self.__raise_on_error(response)

        if len(response.json().get("results")) == len(sample_hashes):
            return True

        return False

    def __get_request(self, url):
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
            headers=self._headers
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

    def __delete_request(self, url):
        """A generic DELETE request method for all A1000 methods.
        :param url: request URL
        :type url: str
        :return: response
        :rtype: requests.Response
        """
        response = requests.delete(
            url=url,
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
