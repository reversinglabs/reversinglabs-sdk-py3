"""
author: Mislav Sever

TitaniumCloud
A Python module for the ReversingLabs TitaniumCloud REST API-s.
"""

import base64
import datetime
import hashlib
import json
import os
import requests
from warnings import warn

from ReversingLabs.SDK.helper import ADVANCED_SEARCH_SORTING_CRITERIA, DEFAULT_USER_AGENT, HASH_LENGTH_MAP, \
    RESPONSE_CODE_ERROR_MAP, MD5, SHA1, SHA256, SHA512, NoFileTypeError, NotFoundError, \
    WrongInputError, validate_hashes


XML = "xml"
JSON = "json"

CLASSIFICATIONS = ("MALICIOUS", "SUSPICIOUS", "KNOWN", "UNKNOWN")
AVAILABLE_PLATFORMS = ("windows7", "windows10", "windows11", "macos11", "linux")
VERTICAL_FEEDS_CATEGORIES = ("financial", "retail", "ransomware", "apt", "exploit", "configuration")

RHA1_TYPE_MAP = {
    "PE": "pe01",
    "PE+": "pe01",
    "PE16": "pe01",
    "PE32": "pe01",
    "PE32+": "pe01",
    "MachO32 Big": "macho01",
    "MachO32 Little": "macho01",
    "MachO64 Big": "macho01",
    "MachO64 Little": "macho01",
    "ELF32 Big": "elf01",
    "ELF32 Little": "elf01",
    "ELF64 Big": "elf01",
    "ELF64 Little": "elf01"
}


class TiCloudAPI(object):
    """Parent class for ReversingLabs TitaniumCloud API classes."""

    def __init__(self, host, username, password, verify=True, proxies=None,
                 user_agent=DEFAULT_USER_AGENT, allow_none_return=False):

        self._host = self.__validate_host(host)
        self._username = username
        self._password = password
        self._credentials = (self._username, self._password)
        self._verify = verify

        if proxies:
            if not isinstance(proxies, dict):
                raise WrongInputError("proxies parameter must be a dictionary.")
            if len(proxies) == 0:
                raise WrongInputError("proxies parameter can not be an empty dictionary.")
        self._proxies = proxies

        self._headers = {
            "User-Agent": user_agent
        }
        self._allow_none_return = allow_none_return

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

        if host.startswith("http://"):
            raise WrongInputError("Unsupported protocol definition: "
                                  "TitaniumCloud services can only be used over HTTPS.")

        if not host.startswith("https://"):
            host = "https://{host}".format(host=host)

        host = host.rstrip("/")

        return host

    def _get_request(self, url, params=None):
        """A generic GET request method for all ticloud module classes.
            :param url: request URL
            :type url: str
            :param params: query parameters
            :type params: dict
            :return: response
            :rtype: requests.Response
        """
        response = requests.get(
            url=url,
            auth=self._credentials,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers,
            params=params
        )

        return response

    def _post_request(self, url, post_json=None, data=None, params=None):
        """A generic POST request method for all ticloud module classes.
            :param url: request URL
            :type url: str
            :param post_json: JSON body
            :type post_json: dict
            :param data: data to send
            :param params: query parameters
            :type params: dict
            :return: response
            :rtype: requests.Response
        """
        response = requests.post(
            url=url,
            auth=self._credentials,
            json=post_json,
            data=data,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers,
            params=params
        )

        return response

    def _delete_request(self, url, payload_json=None):
        """A generic DELETE request method for all ticloud module classes.
            :param url: request URL
            :type url: str
            :param payload_json: JSON body
            :type payload_json: dict
            :return: response
            :rtype: requests.Response
        """
        response = requests.delete(
            url=url,
            auth=self._credentials,
            json=payload_json,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers
        )

        return response

    def _put_request(self, url):
        """A generic PUT request method for all ticloud module classes.
            :param url: request URL
            :type url: str
            :return: response
            :rtype: requests.Response
        """
        response = requests.put(
            url=url,
            auth=self._credentials,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers
        )

        return response

    def _raise_on_error(self, response):
        """Accepts a response object for validation and raises an exception if an error status code is received.
            :param response: response object
            :type response: requests.Response
        """
        exception = RESPONSE_CODE_ERROR_MAP.get(response.status_code, None)
        if not exception:
            return
        if exception == NotFoundError and self._allow_none_return:
            return None
        raise exception(response_object=response)


class FileReputation(TiCloudAPI):
    """TCA-0101 - File Reputation (Malware Presence)"""

    __SINGLE_QUERY_ENDPOINT = "/api/databrowser/malware_presence/query/{hash_type}/{hash_value}?" \
                              "extended={extended_results}&show_hashes={show_hashes_in_results}&format=json"
    __BULK_QUERY_ENDPOINT = "/api/databrowser/malware_presence/bulk_query/json?" \
                            "extended={extended_results}&show_hashes={show_hashes_in_results}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(FileReputation, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                             allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_file_reputation(self, hash_input, extended_results=True, show_hashes_in_results=True):
        """Accepts a hash string or a list of hash strings and returns a response.
        Hash strings in a passed list must all be of the same hashing algorithm.
            :param hash_input: string or list of strings
            :type hash_input: str or list[str]
            :param extended_results: show extended results
            :type extended_results: bool
            :param show_hashes_in_results: show all sample hashes in results
            :type show_hashes_in_results: bool
            :return: response
            :rtype: requests.Response
        """
        extended_results = str(extended_results).lower()
        if extended_results not in ("true", "false"):
            raise WrongInputError("extended_results must be boolean type.")

        show_hashes_in_results = str(show_hashes_in_results).lower()
        if show_hashes_in_results not in ("true", "false"):
            raise WrongInputError("show_hashes_in_results must be boolean type.")

        if isinstance(hash_input, str):
            validate_hashes(
                hash_input=[hash_input],
                allowed_hash_types=(MD5, SHA1, SHA256)
            )

            hashing_algorithm = HASH_LENGTH_MAP.get(len(hash_input))
            endpoint = self.__SINGLE_QUERY_ENDPOINT.format(
                hash_type=hashing_algorithm,
                hash_value=hash_input,
                extended_results=extended_results,
                show_hashes_in_results=show_hashes_in_results
            )

            url = self._url.format(endpoint=endpoint)

            response = self._get_request(url=url)

        elif isinstance(hash_input, list) and len(hash_input) > 0:
            validate_hashes(
                hash_input=hash_input,
                allowed_hash_types=(MD5, SHA1, SHA256)
            )

            hashing_algorithm = HASH_LENGTH_MAP.get(len(hash_input[0]))
            endpoint = self.__BULK_QUERY_ENDPOINT.format(
                extended_results=extended_results,
                show_hashes_in_results=show_hashes_in_results
            )

            url = self._url.format(endpoint=endpoint)

            post_json = {"rl": {"query": {"hash_type": hashing_algorithm, "hashes": hash_input}}}
            response = self._post_request(url=url, post_json=post_json)

        else:
            raise WrongInputError("Only hash string or list of hash strings are allowed as the hash_input parameter.")

        self._raise_on_error(response)

        return response


class FileReputationUserOverride(TiCloudAPI):
    """TCA-0102 - File Reputation User Override"""

    __OVERRIDE_REQUEST_ENDPOINT = "/api/databrowser/malware_presence/user_override/{post_format}"
    __LIST_OVERRIDES_ENDPOINT = "/api/databrowser/malware_presence/user_override/list_hashes/{hash_type}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(FileReputationUserOverride, self).__init__(host, username, password, verify, proxies,
                                                         user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def override_classification(self, override_samples=None, remove_override=None):
        """Accepts two parameters:
            1. A list of samples whose classification needs to be overriden
            2. A list of samples whose classification override needs to me removed
        Both parameters are lists of Python dictionaries and
        both need to contain all three of the following hashes of a sample: sha1, sha256, md5
        For specific examples and a more detailed explanation, read the API documentation.
            :param override_samples: samples whose classification needs to be overriden;
            :type override_samples: list[dict]
            :param remove_override: samples whose classification override needs to me removed
            :type remove_override: list[dict]
            :return: response
            :rtype: requests.Response
        """
        if override_samples is None:
            override_samples = []

        if remove_override is None:
            remove_override = []

        endpoint = self.__OVERRIDE_REQUEST_ENDPOINT.format(post_format="json")

        url = self._url.format(endpoint=endpoint)

        post_json = {"rl": {"query": {"override_samples": override_samples, "remove_override": remove_override}}}

        response = self._post_request(
            url=url,
            post_json=post_json
        )

        self._raise_on_error(response)

        return response

    def list_active_overrides(self, hash_type, start_hash=None):
        """Accepts a hash type designation and returns the hashes of all currently active
        classification overrides for the current organization.
        If used, the start_hash parameter marks the start of a certain page of results
            :param hash_type: type of hashes that will be returned
            :type hash_type: str
            :param start_hash: hash string that marks the start of a certain page of results
            :type start_hash: str
            :return: response
            :rtype: requests.Response
        """
        if hash_type not in (MD5, SHA1, SHA256):
            raise WrongInputError("hash_type needs to be one of the following: {hash_types}".format(
                hash_types=(MD5, SHA1, SHA256)))

        base = self.__LIST_OVERRIDES_ENDPOINT.format(hash_type=hash_type)
        endpoint = "{base}?format=json".format(base=base)

        if start_hash is not None:
            validate_hashes(
                hash_input=[start_hash],
                allowed_hash_types=(hash_type,)
            )

            endpoint = "{endpoint}&start_hash={start_hash}".format(
                endpoint=endpoint,
                start_hash=start_hash
            )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def list_active_overrides_aggregated(self, hash_type, max_results=None):
        """Accepts a hash type designation and returns the hashes of all currently active
        classification overrides for the current organization.
        This method does the paging action automatically and a maximum number of results returned
        in the list can be defined with the max_results parameter.
            :param hash_type: type of hashes that will be returned
            :type hash_type: str
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_hash = None

        while True:
            response = self.list_active_overrides(
                hash_type=hash_type,
                start_hash=next_hash
            )

            response_json = response.json()

            hash_list = response_json.get("rl").get("user_override").get("hash_values", [])
            results.extend(hash_list)

            next_hash = response_json.get("rl").get("user_override").get("next_hash", None)

            if not max_results:
                if not next_hash:
                    return results

            else:
                if not next_hash or len(results) >= max_results:
                    return results[:max_results]


class AVScanners(TiCloudAPI):
    """TCA-0103 - Historic Multi-AV Scan Records (XREF)"""

    __SINGLE_QUERY_ENDPOINT = "/api/xref/v2/query/{hash_type}/{hash_value}?format=json&history={history}"
    __BULK_QUERY_ENDPOINT = "/api/xref/v2/bulk_query/json?history={history}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(AVScanners, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                         allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_scan_results(self, hash_input, historical_results=False):
        """Accepts a hash string or a list of hash strings and returns a response.
        Hash strings in a passed list must all be of the same hashing algorithm.
            :param hash_input: string or list of strings
            :type hash_input: str or list[str]
            :param historical_results: return historical results
            :type historical_results: bool
            :return: response
            :rtype: requests.Response
        """
        historical_results = str(historical_results).lower()
        if historical_results not in ("true", "false"):
            raise WrongInputError("historical_results parameter must be boolean.")

        if isinstance(hash_input, str):
            validate_hashes(
                hash_input=[hash_input],
                allowed_hash_types=(MD5, SHA1, SHA256)
            )

            hashing_algorithm = HASH_LENGTH_MAP.get(len(hash_input))
            endpoint = self.__SINGLE_QUERY_ENDPOINT.format(
                hash_type=hashing_algorithm,
                hash_value=hash_input,
                history=historical_results
            )

            url = self._url.format(endpoint=endpoint)

            response = self._get_request(url=url)

        elif isinstance(hash_input, list) and len(hash_input) > 0:
            validate_hashes(
                hash_input=hash_input,
                allowed_hash_types=(MD5, SHA1, SHA256)
            )

            hashing_algorithm = HASH_LENGTH_MAP.get(len(hash_input[0]))
            endpoint = self.__BULK_QUERY_ENDPOINT.format(
                history=historical_results
            )

            url = self._url.format(endpoint=endpoint)

            post_json = {"rl": {"query": {"hash_type": hashing_algorithm, "hashes": hash_input}}}
            response = self._post_request(url=url, post_json=post_json)

        else:
            raise WrongInputError("Only hash string or list of hash strings are allowed as the hash_input parameter.")

        self._raise_on_error(response)

        return response


class FileAnalysis(TiCloudAPI):
    """TCA-0104 - File Analysis - Hash (RLDATA)"""

    __SINGLE_QUERY_ENDPOINT = "/api/databrowser/rldata/query/{hash_type}/{hash_value}?format=json"
    __BULK_QUERY_ENDPOINT = "/api/databrowser/rldata/bulk_query/json"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(FileAnalysis, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                           allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_analysis_results(self, hash_input):
        """Accepts a hash string or a list of hash strings and returns a response.
        Hash strings in a passed list must all be of the same hashing algorithm.
            :param hash_input: string or list of strings
            :type hash_input: str or list[str]
            :return: response
            :rtype: requests.Response
        """
        if isinstance(hash_input, str):
            validate_hashes(
                hash_input=[hash_input],
                allowed_hash_types=(MD5, SHA1, SHA256)
            )

            hashing_algorithm = HASH_LENGTH_MAP.get(len(hash_input))

            endpoint = self.__SINGLE_QUERY_ENDPOINT.format(
                hash_type=hashing_algorithm,
                hash_value=hash_input
            )

            url = self._url.format(endpoint=endpoint)

            response = self._get_request(url=url)

        elif isinstance(hash_input, list) and len(hash_input) > 0:
            validate_hashes(
                hash_input=hash_input,
                allowed_hash_types=(MD5, SHA1, SHA256)
            )

            hashing_algorithm = HASH_LENGTH_MAP.get(len(hash_input[0]))

            url = self._url.format(endpoint=self.__BULK_QUERY_ENDPOINT)

            post_json = {"rl": {"query": {"hash_type": hashing_algorithm, "hashes": hash_input}}}
            response = self._post_request(url=url, post_json=post_json)

        else:
            raise WrongInputError("Only hash string or list of hash strings are allowed as the hash_input parameter.")

        self._raise_on_error(response)

        return response

    @staticmethod
    def extract_uri_list_from_report(report_dict):
        """Return a list of all the URIs from a file analysis report dictionary.
            :param report_dict: file analysis report dictionary
            :type report_dict: dict
            :return: list of uris
            :rtype: list
        """
        if not isinstance(report_dict, dict):
            raise WrongInputError("reports_dict parameter must be a dictionary.")

        sha1_key = SHA1
        from_key = "from"
        category_key = "category"
        port_key = "port"
        type_key = "type"
        ip_key = "ip"
        uri_key = "uri"

        def network_uris(network_report, report_from, sha1):
            net_uris = []

            for uri in network_report.get("udp_destinations", []):
                net_uris.append({
                    sha1_key: sha1,
                    from_key: report_from,
                    category_key: "udp_destinations",
                    port_key: uri["port"],
                    uri_key: uri["address"]
                })

            for uri in network_report.get("dns_requests", []):
                net_uris.append({
                    sha1_key: sha1,
                    from_key: report_from,
                    category_key: "dns_requests",
                    type_key: uri["type"],
                    uri_key: uri["query"]
                })

            for uri in network_report.get("domains", []):
                net_uris.append({
                    sha1_key: sha1,
                    from_key: report_from,
                    category_key: "domains",
                    ip_key: uri["ip"],
                    uri_key: uri["name"]
                })

            for uri in network_report.get("tcp_destinations", []):
                net_uris.append({
                    sha1_key: sha1,
                    from_key: report_from,
                    category_key: "tcp_destinations",
                    port_key: uri["port"],
                    uri_key: uri["address"]
                })

            for uri in network_report.get("http_requests", []):
                net_uris.append({
                    sha1_key: sha1,
                    from_key: report_from,
                    category_key: "http_requests",
                    uri_key: uri["uri"]
                })

            return net_uris

        uris = []

        sample = report_dict.get("rl", {}).get("sample", {})
        for entry in sample.get("analysis", {}).get("entries", []):
            for interesting_string in entry.get("tc_report", {}).get("interesting_strings", []):
                for value in interesting_string['values']:
                    uris.append({
                        sha1_key: sample[SHA1],
                        from_key: "interesting_strings",
                        category_key: interesting_string["category"],
                        uri_key: value
                    })

            for property in entry.get("tc_report", {}).get("info", {}).get("package", {}).get("properties", []):
                if property.get("name", "").startswith("botServer"):
                    uris.append({
                        sha1_key: sample[SHA1],
                        from_key: "package",
                        category_key: "uri",
                        uri_key: property["value"]
                    })

        for entry in sample.get("sources", {}).get("entries", []):
            if "domain" in entry:
                uris.append({
                    sha1_key: sample[SHA1],
                    from_key: "sources",
                    category_key: "domain",
                    uri_key: entry["domain"].get("name")
                })
            for property in entry.get("properties", []):
                if property["name"] == "url" and property["value"] != '':
                    uris.append({
                        sha1_key: sample[SHA1],
                        from_key: "sources",
                        category_key: "url",
                        uri_key: property["value"]
                    })

        for entry in sample.get("dynamic_analysis", {}).get("entries", []):
            if "dynamic_analysis_report_joe_sandbox" in entry:
                report_dict = entry["dynamic_analysis_report_joe_sandbox"]
                if "network" in report_dict:
                    uris.extend(network_uris(report_dict["network"],
                                             "dynamic_analysis_report_joe_sandbox",
                                             sample[SHA1]))

            if "dynamic_analysis_report" in entry:
                report_dict = entry["dynamic_analysis_report"]
                if "network" in report_dict:
                    uris.extend(network_uris(report_dict["network"],
                                             "dynamic_analysis_report",
                                             sample[SHA1]))

        transitional_dict = {}
        for item in uris:
            item_str = json.dumps(item)
            transitional_dict[item_str] = item_str

        deduplicated_uris = []
        for key, _ in transitional_dict.items():
            item = json.loads(key)
            deduplicated_uris.append(item)

        return deduplicated_uris

    def get_file_type(self, sample_hash):
        """Returns a TitaniumCore classified file type.
            :param sample_hash: hash string
            :type sample_hash: str
            :returns: file type string
            :rtype: str
        """
        rldata_response = self.get_analysis_results(hash_input=sample_hash)
        rldata_json = rldata_response.json()

        try:
            file_type = rldata_json["rl"]["sample"]["analysis"]["entries"][0]["tc_report"]["info"]["file"]["file_type"]
        except KeyError:
            raise KeyError("There is no file type definition in the File Analysis API response for the provided sample."
                           " Can not return file type.")

        return file_type


class FileAnalysisNonMalicious(TiCloudAPI):
    """TCA-0105 - File Analysis - Non-Malicious"""

    __SINGLE_QUERY_ENDPOINT = "/api/databrowser/rldata/goodware/query/{hash_type}/{hash_value}"
    __BULK_QUERY_ENDPOINT = "/api/databrowser/rldata/goodware/bulk_query/{post_format}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(FileAnalysisNonMalicious, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                       allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_analysis_results(self, hash_input):
        """Accepts a hash string or a list of hash strings and returns knowledge
        about the given samples if they are classified as goodware.
            :param hash_input: hash string or list of hash strings
            :type hash_input: str or list[str]
            :return: response
            :rtype: requests.Response
        """
        is_bulk = isinstance(hash_input, list)

        validate_hashes(
            hash_input=hash_input if is_bulk else [hash_input],
            allowed_hash_types=(MD5, SHA1, SHA256)
        )

        hash_type = resolve_hash_type(sample_hashes=hash_input if is_bulk else [hash_input])

        if is_bulk:
            post_json = {"rl": {"query": {"hash_type": hash_type, "hashes": hash_input}}}

            endpoint = self.__BULK_QUERY_ENDPOINT.format(post_format="json")
            url = self._url.format(endpoint=endpoint)

            response = self._post_request(url=url, post_json=post_json)

        else:
            query_params = {"format": "json"}

            endpoint = self.__SINGLE_QUERY_ENDPOINT.format(hash_type=hash_type, hash_value=hash_input)
            url = self._url.format(endpoint=endpoint)

            response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response


class RHA1FunctionalSimilarity(TiCloudAPI):
    """TCA-0301 - RHA Functional Similarity (Group by RHA1)"""

    __SINGLE_QUERY_ENDPOINT = "/api/group_by_rha1/v1/query/{rha1_type}/{hash_value}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(RHA1FunctionalSimilarity, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                       allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_similar_hashes(self, hash_input, extended_results=True, classification=None, page_sha1=None,
                           results_per_page=1000):
        """Accepts a hash string and returns a response.
        This method returns only one page of results per call and accepts defining
        the specific page that will be returned by stating its first SHA-1 hash in the result list.
        If no specific page is defined, only the first page will be returned.
            :param hash_input: sha1 hash string
            :type hash_input: str
            :param extended_results: show extended response
            :type extended_results: bool
            :param classification: show only results of certain classification
            :type classification: str
            :param page_sha1: first SHA-1 hash of the desired page
            :type page_sha1: hash
            :param results_per_page: limit the number of result entries; default and maximum is 1000
            :type results_per_page: int
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[hash_input],
            allowed_hash_types=(SHA1,)
        )

        if not isinstance(results_per_page, int) or not 1 <= results_per_page <= 1000:
            raise WrongInputError("results_per_page parameter must be integer with value "
                                  "between 1 and 1000 (included).")

        extended_results = str(extended_results).lower()
        if extended_results not in ("true", "false"):
            raise WrongInputError("extended_results parameter must be boolean.")

        rha1_type = get_rha1_type(
            host=self._host,
            username=self._username,
            password=self._password,
            verify=self._verify,
            hash_input=hash_input,
            allow_none_return=self._allow_none_return
        )

        endpoint_base = self.__SINGLE_QUERY_ENDPOINT.format(
            rha1_type=rha1_type,
            hash_value=hash_input,
        )

        optional_parameters = "?format=json&limit={limit}&extended={extended}".format(
            limit=results_per_page,
            extended=extended_results
        )

        if page_sha1:
            validate_hashes(
                hash_input=[page_sha1],
                allowed_hash_types=(SHA1,)
            )

            optional_parameters = "/{page_sha1}{params}".format(
                page_sha1=page_sha1,
                params=optional_parameters
            )

        if classification:
            classification = str(classification).upper()
            if classification not in CLASSIFICATIONS:
                raise WrongInputError("Only the following options are allowed as the classification parameter: "
                                      "{classifications} ".format(classifications=CLASSIFICATIONS))

            optional_parameters = "{params}&classification={classification}".format(
                params=optional_parameters,
                classification=classification
            )

        endpoint = "{base}{params}".format(
            base=endpoint_base,
            params=optional_parameters
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)
        self._raise_on_error(response)

        return response

    def get_similar_hashes_aggregated(self, hash_input, extended_results=True, classification=None,
                                      results_per_page=1000, max_results=None):
        """ This method accepts a hash string and returns a list of results aggregated throughout the pages.
        A maximum number of desired results can be defined with the 'max_results' parameter.
            :param hash_input: sha1 hash string
            :type hash_input: str
            :param extended_results: show extended response
            :type extended_results: bool
            :param classification: show only results of certain classification
            :type classification: str
            :param results_per_page: number of results returned per page
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page_sha1 = None

        while True:
            response = self.get_similar_hashes(
                hash_input=hash_input,
                extended_results=extended_results,
                classification=classification,
                page_sha1=next_page_sha1,
                results_per_page=results_per_page
            )

            response_json = response.json()

            sha1_list = response_json.get("rl").get("group_by_rha1").get("sha1_list", [])
            results.extend(sha1_list)

            next_page_sha1 = response_json.get("rl").get("group_by_rha1").get("next_page_sha1", None)

            if not max_results:
                if not next_page_sha1:
                    return results

            else:
                if not next_page_sha1 or len(results) >= max_results:
                    return results[:max_results]


class RHA1Analytics(TiCloudAPI):
    """TCA-0321 - RHA1 Analytics"""

    __SINGLE_QUERY_ENDPOINT = "/api/rha1/analytics/v1/query/{rha1_type}/{sha1}" \
                              "?format=json&extended={extended_results}"
    __BULK_QUERY_ENDPOINT = "/api/rha1/analytics/v1/query/json"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(RHA1Analytics, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                            allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_rha1_analytics(self, hash_input, extended_results=True):
        """Accepts a SHA-1 hash string and returns a response.
            :param hash_input: sha1 hash string or list of sha1 strings
            :type hash_input: str or list[str]
            :param extended_results: show extended response
            :type extended_results: bool
            :return: response
            :rtype: requests.Response
        """
        extended_results = str(extended_results).lower()
        if extended_results not in ("true", "false"):
            raise WrongInputError("extended_results parameter must be boolean.")

        if isinstance(hash_input, str):
            validate_hashes(
                hash_input=[hash_input],
                allowed_hash_types=(SHA1,)
            )

            rha1_type = get_rha1_type(
                host=self._host,
                username=self._username,
                password=self._password,
                verify=self._verify,
                hash_input=hash_input,
                allow_none_return=self._allow_none_return
            )

            endpoint = self.__SINGLE_QUERY_ENDPOINT.format(
                rha1_type=rha1_type,
                sha1=hash_input,
                extended_results=extended_results
            )

            url = self._url.format(endpoint=endpoint)

            response = self._get_request(url=url)

        elif isinstance(hash_input, list) and len(hash_input) > 0:
            validate_hashes(
                hash_input=hash_input,
                allowed_hash_types=(SHA1,)
            )

            rha1_type = get_rha1_type(
                host=self._host,
                username=self._username,
                password=self._password,
                verify=self._verify,
                hash_input=hash_input[0],
                allow_none_return=self._allow_none_return
            )

            url = "{host}{endpoint}".format(
                host=self._host,
                endpoint=self.__BULK_QUERY_ENDPOINT
            )

            post_json = {"rl": {"query": {"rha1_type": rha1_type, "response_format": "json",
                                          "extended": extended_results, "hashes": hash_input}}}

            response = self._post_request(url=url, post_json=post_json)

        else:
            raise WrongInputError("Only hash string or list of hash strings are allowed as the hash_input parameter.")

        self._raise_on_error(response)

        return response


class URIStatistics(TiCloudAPI):
    """TCA-0402 - URI Statistics"""

    __SINGLE_QUERY_ENDPOINT = "/api/uri/statistics/uri_state/sha1/{sha1}?format=json"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(URIStatistics, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                            allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_uri_statistics(self, uri_input):
        """Accepts an email address, URL, DNS name or IPv4 string and returns a response.
            :param uri_input: email address, URL, DNS name or IPv4 string
            :type uri_input: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(uri_input, str):
            raise WrongInputError("Only a single email address, URL, DNS name or IPv4 string is allowed "
                                  "as the uri_input parameter.")

        hash_string = calculate_hash(
            data_input=uri_input,
            hashing_algorithm=SHA1
        )

        endpoint = self.__SINGLE_QUERY_ENDPOINT.format(sha1=hash_string)

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)
        self._raise_on_error(response)

        return response


class URIIndex(TiCloudAPI):
    """TCA-0401 - URI to Hash Search (URI Index)"""

    __SINGLE_QUERY_ENDPOINT = "/api/uri_index/v1/query/{sha1}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(URIIndex, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                       allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_uri_index(self, uri_input, classification=None, page_sha1=None):
        """Accepts an email address, URL, DNS name or IPv4 string and returns a response.
        This method returns only one page of results per call and accepts defining
        the specific page that will be returned by stating its first SHA-1 hash in the result list.
        If no specific page is defined, only the first page will be returned.
            :param uri_input: email address, URL, DNS name or IPv4 string
            :type uri_input: str
            :param classification: only samples of this classification will be returned
            :type classification: str
            :param page_sha1: first SHA-1 hash of the desired page
            :type page_sha1: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(uri_input, str):
            raise WrongInputError("Only a single email address, URL, DNS name or IPv4 string is allowed "
                                  "as the uri_input parameter.")

        uri_hash = calculate_hash(
            data_input=uri_input,
            hashing_algorithm=SHA1
        )

        endpoint_base = self.__SINGLE_QUERY_ENDPOINT.format(
            sha1=uri_hash
        )

        optional_parameters = "?format=json"

        if page_sha1:
            validate_hashes(
                hash_input=[page_sha1],
                allowed_hash_types=(SHA1,)
            )

            optional_parameters = "/{page_sha1}{params}".format(
                page_sha1=page_sha1,
                params=optional_parameters
            )

        if classification:
            classification = str(classification).upper()
            if classification not in CLASSIFICATIONS:
                raise WrongInputError("Only {classifications} is allowed "
                                      "as the classification input.".format(classifications=CLASSIFICATIONS))

            optional_parameters = "{params}&classification={classification}".format(
                params=optional_parameters,
                classification=classification
            )

        endpoint = "{base}{parameters}".format(
            base=endpoint_base,
            parameters=optional_parameters
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)
        self._raise_on_error(response)

        return response

    def get_uri_index_aggregated(self, uri_input, classification=None, max_results=None):
        """Accepts an email address, URL, DNS name or IPv4 string and returns a response.
        This method returns a list of results aggregated throughout the pages.
        A maximum number of desired results can be defined.
            :param uri_input: email address, URL, DNS name or IPv4 string
            :type uri_input: str
            :param classification: only samples of this classification will be returned
            :type classification: str
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page_sha1 = ""

        while True:
            response = self.get_uri_index(
                uri_input=uri_input,
                classification=classification,
                page_sha1=next_page_sha1
            )

            response_json = response.json()

            sha1_list = response_json.get("rl").get("uri_index").get("sha1_list", [])
            results.extend(sha1_list)

            next_page_sha1 = response_json.get("rl").get("uri_index").get("next_page_sha1", None)

            if not max_results:
                if not next_page_sha1:
                    return results

            else:
                if not next_page_sha1 or len(results) >= max_results:
                    return results[:max_results]


class AdvancedSearch(TiCloudAPI):
    """TCA-0320 - Advanced Search"""

    __SINGLE_QUERY_ENDPOINT = "/api/search/v1/query"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(AdvancedSearch, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                             allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def search(self, query_string, sorting_criteria=None, sorting_order="desc", page_number=1, records_per_page=10000):
        """Sends the query string to the Advanced Search API.
        The query string must be composed of key-value pairs separated by space.
        A key is separated from its value by a colon symbol and no spaces.
        If a page number is not provided, the first page of results will be returned.
            Query string example:

            'av-count:5 available:TRUE'

            :param query_string: query string
            :type query_string: str
            :param sorting_criteria: define the criteria used in sorting; possible values are 'sha1', 'firstseen',
            'threatname', 'sampletype', 'filecount', 'size'
            :type sorting_criteria: str
            :param sorting_order: sorting order; possible values are 'desc', 'asc'
            :type sorting_order: str
            :param page_number: page number
            :type page_number: int
            :param records_per_page: number of records returned per page
            :type records_per_page: int
            :returns: response
            :rtype: requests.Response
        """
        if not isinstance(query_string, str):
            raise WrongInputError("The search query must be a string.")

        if not isinstance(records_per_page, int) or not 1 <= records_per_page <= 10000:
            raise WrongInputError("records_per_page parameter must be integer "
                                  "with value between 1 and 10000 (included).")

        url = self._url.format(endpoint=self.__SINGLE_QUERY_ENDPOINT)

        post_json = {"query": query_string, "page": page_number, "records_per_page": records_per_page, "format": "json"}

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

        response = self._post_request(url=url, post_json=post_json)

        self._raise_on_error(response)

        return response

    def search_aggregated(self, query_string, sorting_criteria=None, sorting_order="desc", max_results=None,
                          records_per_page=10000):
        """Sends the query string to the Advanced Search API.
        The query string must be composed of key-value pairs separated by space.
        A key is separated from its value by a colon symbol and no spaces.
        Results from individual responses are aggregated into one list and returned.
        The 'max_results' parameter defines the maximum desired number of results to be returned.
            Query string example:
            'av-count:5 available:TRUE'

            :param query_string: search query - see API documentation for details on writing search queries
            :type query_string: str
            :param sorting_criteria: define the criteria used in sorting; possible values are 'sha1', 'firstseen',
            'threatname', 'sampletype', 'filecount', 'size'
            :type sorting_criteria: str
            :param sorting_order: sorting order; possible values are 'desc', 'asc'
            :type sorting_order: str
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :param records_per_page: number of records returned per page
            :type records_per_page: int
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = 1
        more_pages = True

        while more_pages:
            response = self.search(
                query_string=query_string,
                sorting_criteria=sorting_criteria,
                sorting_order=sorting_order,
                page_number=next_page,
                records_per_page=records_per_page
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


class ExpressionSearch(TiCloudAPI):
    """TCA-0306 - Expression Search with Statistics (Sample Search)"""

    __EXPRESSION_QUERY_ENDPOINT = "/api/sample/search/download/v1/query/date/{str_date}"
    __LATEST_EXPRESSION_ENDPOINT = "/api/sample/search/download/v1/query/latest"
    __STATISTICS_QUERY_ENDPOINT = "/api/sample/search/download/v1/statistics/{time_format}/{time_value}"
    __LATEST_STATISTICS_QUERY_ENDPOINT = "/api/sample/search/download/v1/statistics/latest"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(ExpressionSearch, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                               allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def search(self, query, date=None, page_number=1):
        """Sends the query to the Expression Search API.
        The query must be a list of at least 2 strings. Each string is in the form of a key and a value with
        an equals sign between them and no spaces.
        The value can have multiple options separated with a pipe symbol.
        This method returns only one page with a maximum of 1000 results.
        If a page number is not provided, the first page of results will be returned.
            Query examples:

            ['status=MALICIOUS',
            'sample_type=MicrosoftWord|MicrosoftExcel|MicrosoftPowerPoint']

            or

            ['threat_level>=3',
            'status=malicious',
            'malware_family=CVE-2017-11882']

            :param query: search query
            :type query: list
            :param date: return results from this date forward. the accepted date format is YYYY-mm-dd
            :type date: str or any
            :param page_number: page number
            :type page_number: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(query, list):
            raise WrongInputError("query parameter must be a list of strings.")

        if len(query) < 2:
            raise WrongInputError("query list must have at least 2 expressions.")

        try:
            query_expression = "&".join(query)
        except TypeError:
            raise WrongInputError("All expressions in the query list must be strings.")

        if not isinstance(page_number, int):
            raise WrongInputError("page_number parameter must be integer.")

        if not date:
            date = datetime.date.today() - datetime.timedelta(days=1)
        if isinstance(date, str):
            date = datetime.datetime.fromisoformat(date)

        str_date = date.strftime("%Y-%m-%d")

        endpoint_base = self.__EXPRESSION_QUERY_ENDPOINT.format(
            str_date=str_date
        )

        parameters = "?format=json&page={page}&{query_expression}".format(
            page=page_number,
            query_expression=query_expression
        )

        endpoint = "{base}{params}".format(
            base=endpoint_base,
            params=parameters
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)
        self._raise_on_error(response)

        return response

    def search_aggregated(self, query, date=None, max_results=None):
        """Sends the query to the Expression Search API.
        The query must be a list of at least 2 strings. Each string is in the form of a key and a value with
        an equals sign between them and no spaces.
        The value can have multiple options separated with a pipe symbol.
        This method returns a list of aggregated results with a maximum length defined in the 'max_results' parameter.
            Query examples:

            ['status=MALICIOUS',
            'sample_type=MicrosoftWord|MicrosoftExcel|MicrosoftPowerPoint']

            or

            ['threat_level>=3',
            'status=malicious',
            'malware_family=CVE-2017-11882']

            :param query: search query
            :type query: list
            :param date: return results from this date forward
            :type date: str or any
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = 1

        while next_page:
            response = self.search(
                query=query,
                date=date,
                page_number=next_page
            )

            response_json = response.json()

            entries = response_json.get("rl").get("web_sample_search_download").get("entries", [])
            results.extend(entries)

            next_page = response_json.get("rl").get("web_sample_search_download").get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def get_latest_expression(self, query):
        """Service returns only new samples from the last 24 hours.
        The query must be a list of at least 2 strings. Each string is in the form of a key and a value with 
        an equals sign between then and no spaces.
        The value can have multiple options separated with a pipe symbol.
            Query examples:

            ['status=MALICIOUS',
            'sample_type=MicrosoftWord|MicrosoftExcel|MicrosoftPowerPoint']

            or

            ['threat_level>=3',
            'status=malicious',
            'malware_family=CVE-2017-11882']

            :param query: search query
            :type query: list
            :return: list of results
            :rtype: list
        """
        if not isinstance(query, list):
            raise WrongInputError("query parameter must be a list of strings.")

        if len(query) < 2:
            raise WrongInputError("query list must have at least 2 expressions.")

        try:
            query_expression = "&".join(query)
        except TypeError:
            raise WrongInputError("All expressions in the query list must be strings.")

        base = self.__LATEST_EXPRESSION_ENDPOINT

        endpoint = "{base}?{query_expression}".format(
            base=base,
            query_expression=query_expression
        )

        query_params = {
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def statistics_search(self, query, time_format, time_value, page_number=1):
        """Returns statistics about new samples in the TitaniumCloud system
        that match the requested criteria. Service returns samples on the requested
        date. At least 2 search criteria must be provided in each request. Every 
        request returns a maximum of 1000 results. If more than 1000 samples match
        the requested criteria, the response includes a next_page field to indicate this.
            Query examples:

            ['status=MALICIOUS',
            'sample_type=MicrosoftWord|MicrosoftExcel|MicrosoftPowerPoint']

            or

            ['threat_level>=3',
            'status=malicious',
            'malware_family=CVE-2017-11882']

            :param query: search query
            :type query: list
            :param time_format: possible values 'timestamp', 'utc' or 'date'
            :type time_format: str
            :param time_value: results will be retrieved from the specified date
            :type time_value: str
            :param page_number: page number
            :type page_number: int
            :return: response
            :rtype: requests.Response
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("if timestamp is used, time_value needs to be a unix timestamp")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("if utc is used, time_value needs to be in format 'YYYY-MM-DDThh:mm:ss'")

        elif time_format == "date":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%d")

            except ValueError:
                raise WrongInputError("if the date format is used, time_value must be provided as 'YYYY-MM-DD'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'timestamp', 'utc', 'date'")

        if not isinstance(query, list):
            raise WrongInputError("query parameter must be a list of strings.")

        if len(query) < 2:
            raise WrongInputError("query list must have at least 2 expressions.")

        try:
            query_expression = "&".join(query)
        except TypeError:
            raise WrongInputError("All expressions in the query list must be strings.")

        if not isinstance(page_number, int):
            raise WrongInputError("page_number parameter must be integer.")

        base = self.__STATISTICS_QUERY_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        endpoint = "{base}?{query_expression}".format(
            base=base,
            query_expression=query_expression
        )

        query_params = {
            "page": page_number,
            "format": "json"
        } 

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def get_latest_statistics(self, query):
        """Returns statistics about new samples in the TitaniumCloud system
        that match the requested criteria. Service returns samples on the requested
        date. At least 2 search criteria must be provided in each request. Every 
        request returns a maximum of 1000 results. If more than 1000 samples match
        the requested criteria, the response includes a next_page field to indicate this.
            Query examples:

            ['status=MALICIOUS',
            'sample_type=MicrosoftWord|MicrosoftExcel|MicrosoftPowerPoint']

            or

            ['threat_level>=3',
            'status=malicious',
            'malware_family=CVE-2017-11882']

            :param query: search query
            :type query: list
            :return: list of results
            :rtype: list
        """
        if not isinstance(query, list):
            raise WrongInputError("query parameter must be a list of strings.")

        if len(query) < 2:
            raise WrongInputError("query list must have at least 2 expressions.")

        try:
            query_expression = "&".join(query)
        except TypeError:
            raise WrongInputError("All expressions in the query list must be strings.")

        base = self.__LATEST_STATISTICS_QUERY_ENDPOINT

        endpoint = "{base}?{query_expression}".format(
            base=base,
            query_expression=query_expression
        )

        query_params = {
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response


class FileDownload(TiCloudAPI):
    """TCA-0201 - File Download (SPEX Download)"""

    __STATUS_ENDPOINT = "/api/spex/download/v2/status/bulk_query/json?format=json"
    __DOWNLOAD_ENDPOINT = "/api/spex/download/v2/query/{hash_type}/{hash_value}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(FileDownload, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                           allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_download_status(self, hash_input):
        """Accepts a hash string or a list of hash strings and returns a response.
         Hash strings in a passed list must all be of the same hashing algorithm.
             :param hash_input: string or list of strings
             :type hash_input: str or list[str]
             :return: response
             :rtype: requests.Response
         """
        if not isinstance(hash_input, list):
            hash_input = [hash_input]

        validate_hashes(
            hash_input=hash_input,
            allowed_hash_types=(MD5, SHA1, SHA256)
        )
        hashing_algorithm = HASH_LENGTH_MAP.get(len(hash_input[0]))

        post_json = {"rl": {"query": {"hash_type": hashing_algorithm, "hashes": hash_input}}}

        url = self._url.format(endpoint=self.__STATUS_ENDPOINT)

        response = self._post_request(url=url, post_json=post_json)
        self._raise_on_error(response)

        return response

    def download_sample(self, hash_input):
        """Downloads the requested sample.
        Accepts a hash string and returns a response.
            :param hash_input: hash string
            :type hash_input: str
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[hash_input],
            allowed_hash_types=(MD5, SHA1, SHA256)
        )
        hashing_algorithm = HASH_LENGTH_MAP.get(len(hash_input))

        endpoint = self.__DOWNLOAD_ENDPOINT.format(
            hash_type=hashing_algorithm,
            hash_value=hash_input
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)
        self._raise_on_error(response)

        return response


class URLThreatIntelligence(TiCloudAPI):
    """TCA-0403 - URL Threat Intelligence"""

    __URL_REPORT_ENDPOINT = "/api/networking/url/v1/report/query/json"
    __DOWNLOADED_FILES_ENDPOINT = "/api/networking/url/v1/downloaded_files/query/json"
    __URL_ANALYSIS_FEED_LATEST = "/api/networking/url/v1/notifications/query/latest"
    __URL_ANALYSIS_FEED_FROM_DATE = "/api/networking/url/v1/notifications/query/from"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(URLThreatIntelligence, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                    allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_url_report(self, url_input):
        """Accepts a URL string and returns a URL analysis report.
            :param url_input: URL string
            :type url_input: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(url_input, str):
            raise WrongInputError("The input can only be a URL string.")

        url = self._url.format(endpoint=self.__URL_REPORT_ENDPOINT)

        post_json = {"rl": {"query": {"url": url_input, "response_format": "json"}}}

        response = self._post_request(url=url, post_json=post_json)
        self._raise_on_error(response)

        return response

    def get_downloaded_files(self, url_input, extended=True, classification=None, last_analysis=False, analysis_id=None,
                             page_string=None, results_per_page=1000):
        """Accepts a URL string and returns a report wih a list of files downloaded from the submitted URL.
        A string designating a desired page of results can be provided as an optional parameter.
        Other optional parameters include file number limit,requesting an extended report, requesting only files of specific
        classification, requesting only files from the last analysis and requesting only files from a specific analysis.
            :param url_input: URL string
            :type url_input: str
            :param extended: return extended report
            :type extended: bool
            :param classification: return only files of this classification
            :type classification: str
            :param last_analysis: return only files from the last analysis
            :type last_analysis: bool
            :param analysis_id: return only files from this analysis
            :type analysis_id: str
            :param page_string: page designation string returned in the 'next_page' element
            :type page_string: str
            :param results_per_page: number of results to be returned in one page; maximum value is 1000
            :type results_per_page: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(url_input, str):
            raise WrongInputError("The input can only be a URL string.")

        if not isinstance(results_per_page, int) or not 1 <= results_per_page <= 1000:
            raise WrongInputError("results_per_page parameter must be integer with value "
                                  "between 1 and 1000 (included).")

        if extended not in (True, False):
            raise WrongInputError("extended parameter must be boolean.")

        if last_analysis not in (True, False):
            raise WrongInputError("last_analysis parameter must be boolean.")

        url = self._url.format(endpoint=self.__DOWNLOADED_FILES_ENDPOINT)

        post_json = {"rl": {"query": {"url": url_input, "response_format": "json", "limit": results_per_page,
                                      "extended": extended, "last_analysis": last_analysis}}}

        if page_string:
            if not isinstance(page_string, str):
                raise WrongInputError("page_string parameter must be string.")
            post_json["rl"]["query"]["page"] = page_string

        if classification:
            classification = classification.upper()
            if classification not in CLASSIFICATIONS:
                raise WrongInputError("Only {classifications} is allowed "
                                      "as the classification input.".format(classifications=CLASSIFICATIONS))

            post_json["rl"]["query"]["classification"] = classification

        if analysis_id:
            if last_analysis:
                raise WrongInputError("Can not use analysis_id because last_analysis is being used.")
            if not isinstance(analysis_id, str):
                raise WrongInputError("analysis_id parameter must be string.")

            post_json["rl"]["query"]["analysis_id"] = analysis_id

        response = self._post_request(url=url, post_json=post_json)

        self._raise_on_error(response)

        return response

    def get_downloaded_files_aggregated(self, url_input, extended=True, classification=None, last_analysis=False,
                                        analysis_id=None, results_per_page=1000, max_results=None):
        """Accepts a URL string and returns a list of downloaded files aggregated through multiple pages of results.
        A maximum number of desired results in the list can be defined with the 'max_results' parameter.
        Optional parameters include file number limit,requesting an extended report, requesting only files of specific
        classification, requesting only files from the last analysis and requesting only files from a specific analysis.
            :param url_input: URL string
            :type url_input: str
            :param extended: return extended report
            :type extended: bool
            :param classification: return only files of this classification
            :type classification: str
            :param last_analysis: return only files from the last analysis
            :type last_analysis: bool
            :param analysis_id: return only files from this analysis
            :type analysis_id: str
            :param results_per_page: number of results to be returned in one page; maximum value is 1000
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = None

        while True:
            response = self.get_downloaded_files(
                url_input=url_input,
                extended=extended,
                classification=classification,
                last_analysis=last_analysis,
                analysis_id=analysis_id,
                page_string=next_page,
                results_per_page=results_per_page
            )

            response_json = response.json()

            files = response_json.get("rl").get("files", [])
            results.extend(files)

            next_page = response_json.get("rl").get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def get_latest_url_analysis_feed(self, page_string=None, results_per_page=1000):
        """Returns the latest URL analyses reports.
        A string designating a desired page of results can be provided as an optional parameter.
            :param page_string: page designation string returned in the 'next_page' element
            :type page_string: str
            :param results_per_page: number of results per response; maximum value is 1000
            :type results_per_page: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(results_per_page, int) or not 1 <= results_per_page <= 1000:
            raise WrongInputError("results_per_page parameter must be integer with value "
                                  "between 1 and 1000 (included).")

        endpoint_base = self.__URL_ANALYSIS_FEED_LATEST

        if page_string:
            if not isinstance(page_string, str):
                raise WrongInputError("page_string parameter must be string.")

            endpoint_base = "{base}/page/{page_string}".format(
                base=endpoint_base,
                page_string=page_string
            )

        optional_parameters = "?format=json&limit={results_per_page}".format(
            results_per_page=results_per_page
        )

        endpoint = "{base}{params}".format(
            base=endpoint_base,
            params=optional_parameters
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def get_latest_url_analysis_feed_aggregated(self, results_per_page=1000, max_results=None):
        """Returns the latest URL analyses reports aggregated as list.
        Maximum desired number of results in the list can be defined with the 'max_results' parameter.
            :param results_per_page: number of results per response; maximum value is 1000
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = ""

        while True:
            response = self.get_latest_url_analysis_feed(
                page_string=next_page,
                results_per_page=results_per_page
            )

            response_json = response.json()

            urls = response_json.get("rl").get("urls", [])
            results.extend(urls)

            next_page = response_json.get("rl").get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def get_url_analysis_feed_from_date(self, time_format, start_time, page_string=None, results_per_page=1000):
        """Accepts time format and a start time and returns URL analyses reports from that defined time onward.
        It is possible to list analyses up to 90 days into the past.
        A string designating a desired page of results can be provided as an optional parameter.
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param start_time: time from which to retrieve results onwards; up to 90 days into the past
            :type start_time: str
            :param page_string: page designation string returned in the 'next_page' element
            :type page_string: str
            :param results_per_page: number of results per response
            :type results_per_page: int
            :return: response
            :rtype: requests.Response
        """
        if time_format not in ("utc", "timestamp"):
            raise WrongInputError("time_format parameter must be one of the following values: 'utc', 'timestamp'")

        if not isinstance(start_time, str):
            raise WrongInputError("start_time parameter must be string.")

        if not isinstance(results_per_page, int) or not 1 <= results_per_page <= 1000:
            raise WrongInputError("results_per_page parameter must be integer with value "
                                  "between 1 and 1000 (included).")

        time_definition = "/{time_format}/{start_time}".format(
            time_format=time_format,
            start_time=start_time
        )

        endpoint_base = "{base}{time_definition}".format(
            base=self.__URL_ANALYSIS_FEED_FROM_DATE,
            time_definition=time_definition
        )

        if page_string:
            if not isinstance(page_string, str):
                raise WrongInputError("page_string parameter must be string.")

            endpoint_base = "{base}/page/{page_string}".format(
                base=endpoint_base,
                page_string=page_string
            )

        optional_parameters = "?format=json&limit={results_per_page}".format(
            results_per_page=results_per_page
        )

        endpoint = "{base}{params}".format(
            base=endpoint_base,
            params=optional_parameters
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def get_url_analysis_feed_from_date_aggregated(self, time_format, start_time, results_per_page=1000,
                                                   max_results=None):
        """Accepts time format and a start time and returns URL analyses reports
        from that defined time onward aggregated as a list.
        It is possible to list analyses up to 90 days into the past.
        Maximum desired number of results in the list can be defined with the 'max_results' parameter.
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param start_time: time from which to retrieve results onwards; up to 90 days into the past
            :type start_time: str
            :param results_per_page: number of results per response
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = ""

        while True:
            response = self.get_url_analysis_feed_from_date(
                time_format=time_format,
                start_time=start_time,
                page_string=next_page,
                results_per_page=results_per_page
            )

            response_json = response.json()

            urls = response_json.get("rl").get("urls", [])
            results.extend(urls)

            next_page = response_json.get("rl").get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]


class AnalyzeURL(TiCloudAPI):
    """TCA-0404 - Analyze URL"""

    __SUBMIT_URL_ENDPOINT = "/api/networking/url/v1/analyze/query/json"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(AnalyzeURL, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                         allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def submit_url(self, url_input):
        """Accepts a URL string for analysis and returns an analysis ID in a response.
        The analysis ID can be used as parameter in TCA-0403 URL Threat Intelligence.
            :param url_input: URL string
            :type url_input: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(url_input, str):
            raise WrongInputError("The input can only be a URL string.")

        url = self._url.format(endpoint=self.__SUBMIT_URL_ENDPOINT)

        post_json = {"rl": {"query": {"url": url_input, "response_format": "json"}}}

        response = self._post_request(url=url, post_json=post_json)
        self._raise_on_error(response)

        return response


class DomainThreatIntelligence(TiCloudAPI):
    """TCA-0405 - Domain Threat Intelligence"""

    __DOMAIN_REPORT_ENDPOINT = "/api/networking/domain/report/v1/query/{format}"
    __DOWNLOADED_FILES_ENDPOINT = "/api/networking/domain/downloaded_files/v1/query/{format}"
    __URLS_DOMAIN_ENDPOINT = "/api/networking/domain/urls/v1/query/{format}"
    __RESOLUTIONS_ENDPOINT = "/api/networking/domain/resolutions/v1/query/{format}"
    __RELATED_DOMAINS_ENDPOINT = "/api/networking/domain/related_domains/v1/query/{format}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(DomainThreatIntelligence, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                       allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_domain_report(self, domain):
        """Accepts a domain string and returns threat intelligence data for the submitted domain.
            :param domain: domain string
            :type domain: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(domain, str):
            raise WrongInputError("domain parameter must be string.")

        endpoint = self.__DOMAIN_REPORT_ENDPOINT.format(format="json")
        url = self._url.format(endpoint=endpoint)

        post_json = {"rl": {"query": {"domain": domain, "response_format": "json"}}}

        response = self._post_request(url=url, post_json=post_json)
        self._raise_on_error(response)

        return response

    def get_downloaded_files(self, domain, extended=True, classification=None, page_string=None, results_per_page=1000):
        """Accepts a domain string and retrieves a list of files downloaded from the submitted domain.
            :param domain: domain string
            :type domain: str
            :param extended: return extended results
            :type extended: bool
            :param classification: return only results with this classification
            :type classification: str
            :param page_string: string representing a page of results
            :type page_string: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(domain, str):
            raise WrongInputError("domain parameter must be string.")

        if not isinstance(results_per_page, int):
            raise WrongInputError("results_per_page parameter must be integer.")

        if extended not in (True, False):
            raise WrongInputError("extended parameter must be boolean.")

        post_json = {"rl": {"query": {"domain": domain, "response_format": "json", "limit": results_per_page,
                                      "extended": extended}}}

        if classification:
            classification = classification.upper()

            if classification not in CLASSIFICATIONS:
                raise WrongInputError("Only {classifications} is allowed "
                                      "as the classification input.".format(classifications=CLASSIFICATIONS))

            post_json["rl"]["query"]["classification"] = classification

        if page_string:
            if not isinstance(page_string, str):
                raise WrongInputError("page_string parameter must be string.")
            post_json["rl"]["query"]["page"] = page_string

        endpoint = self.__DOWNLOADED_FILES_ENDPOINT.format(format="json")
        url = self._url.format(endpoint=endpoint)

        response = self._post_request(url=url, post_json=post_json)
        self._raise_on_error(response)

        return response

    def get_downloaded_files_aggregated(self, domain, extended=True, classification=None, results_per_page=1000,
                                        max_results=None):
        """Accepts a domain string and retrieves a list of files downloaded from the submitted domain.
        This method performs the paging automatically and returns a list of results. The maximum number of results
        to be returned can be set.
            :param domain: domain string
            :type domain: str
            :param extended: return extended results
            :type extended: bool
            :param classification: return only results with this classification
            :type classification: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = None

        while True:
            response = self.get_downloaded_files(
                domain=domain,
                extended=extended,
                classification=classification,
                page_string=next_page,
                results_per_page=results_per_page
            )

            response_json = response.json()

            downloaded_files = response_json.get("rl").get("downloaded_files", [])
            results.extend(downloaded_files)

            next_page = response_json.get("rl").get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def urls_from_domain(self, domain, page_string=None, results_per_page=1000):
        """Accepts a domain string and returns a list of URLs associated with the requested domain.
            :param domain: domain string
            :type domain: str
            :param page_string: string representing a page of results
            :type page_string: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :return: response
            :rtype: requests.Response
        """
        response = self.__domain_endpoints(
            domain=domain,
            results_per_page=results_per_page,
            page_string=page_string,
            specific_endpoint=self.__URLS_DOMAIN_ENDPOINT
        )

        return response

    def urls_from_domain_aggregated(self, domain, results_per_page=1000, max_results=None):
        """Accepts a domain string and returns a list of URLs associated with the requested domain.
        This method performs the paging automatically and returns a list of results. The maximum number of results
        to be returned can be set.
            :param domain: domain string
            :type domain: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = ""

        while True:
            response = self.urls_from_domain(
                domain=domain,
                page_string=next_page,
                results_per_page=results_per_page
            )

            response_json = response.json()

            urls = response_json.get("rl").get("urls", [])
            results.extend(urls)

            next_page = response_json.get("rl").get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def domain_to_ip_resolutions(self, domain, page_string=None, results_per_page=1000):
        """Accepts a domain string and returns a list of domain-to-IP mappings for the requested domain.
            :param domain: domain string
            :type domain: str
            :param page_string: string representing a page of results
            :type page_string: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :return: response
            :rtype: requests.Response
        """
        response = self.__domain_endpoints(
            domain=domain,
            results_per_page=results_per_page,
            page_string=page_string,
            specific_endpoint=self.__RESOLUTIONS_ENDPOINT
        )

        return response

    def domain_to_ip_resolutions_aggregated(self, domain, results_per_page=1000, max_results=None):
        """Accepts a domain string and returns a list of domain-to-IP mappings for the requested domain.
        This method performs the paging automatically and returns a list of results. The maximum number of results
        to be returned can be set.
            :param domain: domain string
            :type domain: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = ""

        while True:
            response = self.domain_to_ip_resolutions(
                domain=domain,
                page_string=next_page,
                results_per_page=results_per_page
            )

            response_json = response.json()

            resolutions = response_json.get("rl").get("resolutions", [])
            results.extend(resolutions)

            next_page = response_json.get("rl").get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def related_domains(self, domain, page_string=None, results_per_page=1000):
        """Accepts a domain string and returns a list of domains that have
        the same top parent domain as the requested domain.
            :param domain: domain string
            :type domain: str
            :param page_string: string representing a page of results
            :type page_string: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :return: response
            :rtype: requests.Response
        """
        response = self.__domain_endpoints(
            domain=domain,
            results_per_page=results_per_page,
            page_string=page_string,
            specific_endpoint=self.__RELATED_DOMAINS_ENDPOINT
        )

        return response

    def related_domains_aggregated(self, domain, results_per_page=1000, max_results=None):
        """Accepts a domain string and returns a list of domains that have
        the same top parent domain as the requested domain.
        This method performs the paging automatically and returns a list of results. The maximum number of results
        to be returned can be set.
            :param domain: domain string
            :type domain: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = ""

        while True:
            response = self.related_domains(
                domain=domain,
                page_string=next_page,
                results_per_page=results_per_page
            )

            response_json = response.json()

            related_domains = response_json.get("rl").get("related_domains", [])
            results.extend(related_domains)

            next_page = response_json.get("rl").get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def __domain_endpoints(self, domain, results_per_page, page_string, specific_endpoint):
        """Private method for domain-related endpoints.
            :param domain: domain string
            :type domain: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :param specific_endpoint: requested endpoint string
            :type specific_endpoint: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(domain, str):
            raise WrongInputError("domain parameter must be string.")

        if not isinstance(results_per_page, int):
            raise WrongInputError("results_per_page parameter must be integer.")

        post_json = {"rl": {"query": {"domain": domain, "response_format": "json", "limit": results_per_page}}}

        if page_string:
            if not isinstance(page_string, str):
                raise WrongInputError("page_string parameter must be string.")
            post_json["rl"]["query"]["page"] = page_string

        endpoint = specific_endpoint.format(format="json")
        url = self._url.format(endpoint=endpoint)

        response = self._post_request(url=url, post_json=post_json)
        self._raise_on_error(response)

        return response


class IPThreatIntelligence(TiCloudAPI):
    """TCA-0406 - IP Threat Intelligence"""

    __IP_REPORT_ENDPOINT = "/api/networking/ip/report/v1/query/{format}"
    __DOWNLOADED_FILES_ENDPOINT = "/api/networking/ip/downloaded_files/v1/query/{format}"
    __URLS_IP_ENDPOINT = "/api/networking/ip/urls/v1/query/{format}"
    __RESOLUTIONS_ENDPOINT = "/api/networking/ip/resolutions/v1/query/{format}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(IPThreatIntelligence, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                   allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_ip_report(self, ip_address):
        """Accepts an IP address as a string and returns threat intelligence
        data for the submitted IP address.
            :param ip_address: IP address
            :type ip_address: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(ip_address, str):
            raise WrongInputError("ip_address parameter must be string.")

        endpoint = self.__IP_REPORT_ENDPOINT.format(format="json")
        url = self._url.format(endpoint=endpoint)

        post_json = {"rl": {"query": {"ip": ip_address, "response_format": "json"}}}

        response = self._post_request(url=url, post_json=post_json)
        self._raise_on_error(response)

        return response

    def get_downloaded_files(self, ip_address, extended=True, classification=None, page_string=None,
                             results_per_page=1000):
        """Accepts an IP address as a string and returns a list of files
        downloaded from the submitted IP address.
            :param ip_address: IP address
            :type ip_address: str
            :param extended: return extended results
            :type extended: bool
            :param classification: return only results with this classification
            :type classification: str
            :param page_string: string representing a page of results
            :type page_string: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(ip_address, str):
            raise WrongInputError("ip_address parameter must be string.")

        if not isinstance(results_per_page, int):
            raise WrongInputError("results_per_page parameter must be integer.")

        if extended not in (True, False):
            raise WrongInputError("extended parameter must be boolean.")

        post_json = {"rl": {"query": {"ip": ip_address, "response_format": "json", "limit": results_per_page,
                                      "extended": extended}}}

        if classification:
            classification = classification.upper()

            if classification not in CLASSIFICATIONS:
                raise WrongInputError("Only {classifications} is allowed "
                                      "as the classification input.".format(classifications=CLASSIFICATIONS))

            post_json["rl"]["query"]["classification"] = classification

        if page_string:
            if not isinstance(page_string, str):
                raise WrongInputError("page_string parameter must be string.")
            post_json["rl"]["query"]["page"] = page_string

        endpoint = self.__DOWNLOADED_FILES_ENDPOINT.format(format="json")
        url = self._url.format(endpoint=endpoint)

        response = self._post_request(url=url, post_json=post_json)
        self._raise_on_error(response)

        return response

    def get_downloaded_files_aggregated(self, ip_address, extended=True, classification=None, results_per_page=1000,
                                        max_results=None):
        """Accepts an IP address as a string and returns a list of files
        downloaded from the submitted IP address.
        This method performs the paging automatically and returns a list of results. The maximum number of results
        to be returned can be set.
            :param ip_address: IP address
            :type ip_address: str
            :param extended: return extended results
            :type extended: bool
            :param classification: return only results with this classification
            :type classification: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = ""

        while True:
            response = self.get_downloaded_files(
                ip_address=ip_address,
                extended=extended,
                classification=classification,
                page_string=next_page,
                results_per_page=results_per_page
            )

            response_json = response.json()

            downloaded_files = response_json.get("rl").get("downloaded_files", [])
            results.extend(downloaded_files)

            next_page = response_json.get("rl").get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def urls_from_ip(self, ip_address, page_string=None, results_per_page=1000):
        """Accepts an IP address as a string and returns a list of URLs associated with the requested IP.
            :param ip_address: IP address
            :type ip_address: str
            :param page_string: string representing a page of results
            :type page_string: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :return: response
            :rtype: requests.Response
        """
        response = self.__ip_endpoints(
            ip_address=ip_address,
            results_per_page=results_per_page,
            page_string=page_string,
            specific_endpoint=self.__URLS_IP_ENDPOINT
        )

        return response

    def urls_from_ip_aggregated(self, ip_address, results_per_page=1000, max_results=None):
        """Accepts an IP address as a string and returns a list of URLs associated with the requested IP.
        This method performs the paging automatically and returns a list of results. The maximum number of results
        to be returned can be set.
            :param ip_address: IP address
            :type ip_address: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = ""

        while True:
            response = self.urls_from_ip(
                ip_address=ip_address,
                page_string=next_page,
                results_per_page=results_per_page
            )

            response_json = response.json()

            urls = response_json.get("rl").get("urls", [])
            results.extend(urls)

            next_page = response_json.get("rl").get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def ip_to_domain_resolutions(self, ip_address, page_string=None, results_per_page=1000):
        """Accepts an IP address as a string and returns a list of IP-to-domain
        mappings for the specified IP address.
            :param ip_address: IP address
            :type ip_address: str
            :param page_string: string representing a page of results
            :type page_string: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :return: response
            :rtype: requests.Response
        """
        response = self.__ip_endpoints(
            ip_address=ip_address,
            results_per_page=results_per_page,
            page_string=page_string,
            specific_endpoint=self.__RESOLUTIONS_ENDPOINT
        )

        return response

    def ip_to_domain_resolutions_aggregated(self, ip_address, results_per_page=1000, max_results=None):
        """Accepts an IP address as a string and returns a list of IP-to-domain
        mappings for the specified IP address.
        This method performs the paging automatically and returns a list of results. The maximum number of results
        to be returned can be set.
            :param ip_address: IP address
            :type ip_address: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = ""

        while True:
            response = self.ip_to_domain_resolutions(
                ip_address=ip_address,
                page_string=next_page,
                results_per_page=results_per_page
            )

            response_json = response.json()

            resolutions = response_json.get("rl").get("resolutions", [])
            results.extend(resolutions)

            next_page = response_json.get("rl").get("next_page", None)

            if not max_results:
                if not next_page:
                    return results

            else:
                if not next_page or len(results) >= max_results:
                    return results[:max_results]

    def __ip_endpoints(self, ip_address, results_per_page, page_string, specific_endpoint):
        """Private method for IP-related endpoints.
            :param ip_address: IP address
            :type ip_address: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :param specific_endpoint: requested endpoint string
            :type specific_endpoint: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(ip_address, str):
            raise WrongInputError("ip_address parameter must be string.")

        if not isinstance(results_per_page, int):
            raise WrongInputError("results_per_page parameter must be integer.")

        post_json = {"rl": {"query": {"ip": ip_address, "response_format": "json", "limit": results_per_page}}}

        if page_string:
            if not isinstance(page_string, str):
                raise WrongInputError("page_string parameter must be string.")
            post_json["rl"]["query"]["page"] = page_string

        endpoint = specific_endpoint.format(format="json")
        url = self._url.format(endpoint=endpoint)

        response = self._post_request(url=url, post_json=post_json)
        self._raise_on_error(response)

        return response


class FileUpload(TiCloudAPI):
    """TCA-0202 and TCA-0203"""

    __UPLOAD_ENDPOINT = "/api/spex/upload"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(FileUpload, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                         allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def upload_sample_from_path(self, file_path, sample_name=None, sample_domain=None, subscribe=None,
                                archive_type=None, archive_password=None):
        """Accepts a file path string and uploads the desired file to the File Upload API.
            :param file_path: file path string
            :type file_path: str
            :param sample_name: optional name of the sample to be displayed in the cloud
            :type sample_name: str
            :param sample_domain: optional domain string of the sample to be displayed in the cloud
            :type sample_domain: str
            :param subscribe: if the value is 'data_change' this parameter adds the sample to the user's
            data change feed subscription list
            :type subscribe: str
            :param archive_type: used to define the compression algorithm if sending an archive file;
            supported values: 'zip'
            :type archive_type: str
            :param archive_password: the password for extracting the content of the archive
            :type archive_password: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(file_path, str):
            raise WrongInputError("file_path parameter must be string.")

        if sample_name:
            if not isinstance(sample_name, str):
                raise WrongInputError("sample_name parameter must be string.")
        else:
            sample_name = self.__get_sample_name(file_path=file_path)

        try:
            file_handle = open(file_path, "rb")
        except IOError as error:
            raise WrongInputError("Error while opening file in 'rb' mode - {error}".format(error=str(error)))

        response = self.upload_sample_from_file(
            file_handle=file_handle,
            sample_name=sample_name,
            sample_domain=sample_domain,
            subscribe=subscribe,
            archive_type=archive_type,
            archive_password=archive_password
        )

        return response

    def upload_sample_from_file(self, file_handle, sample_name=None, sample_domain=None, subscribe=None,
                                archive_type=None, archive_password=None):
        """Accepts an open file handle and uploads the desired file to the File Upload API.
            :param file_handle: open file
            :type file_handle: file or BinaryIO
            :param sample_name: optional name of the sample to be displayed in the cloud
            :type sample_name: str
            :param sample_domain: optional domain string of the sample to be displayed in the cloud
            :type sample_domain: str
            :param subscribe: if the value is 'data_change' this parameter adds the sample to the user's
            data change feed subscription list
            :type subscribe: str
            :param archive_type: used to define the compression algorithm if sending an archive file;
            supported values: 'zip'
            :type archive_type: str
            :param archive_password: the password for extracting the content of the archive
            :type archive_password: str
            :return: response
            :rtype: requests.Response
        """
        if not hasattr(file_handle, "read"):
            raise WrongInputError("file_handle parameter must be a file open in 'rb' mode.")

        if sample_name:
            if not isinstance(sample_name, str):
                raise WrongInputError("sample_name parameter must be string.")
        else:
            sample_name = "sample"

        if sample_domain:
            if not isinstance(sample_domain, str):
                raise WrongInputError("sample_domain parameter must be string.")
        else:
            sample_domain = ""

        file_sha1 = calculate_hash(
            data_input=file_handle,
            hashing_algorithm=SHA1
        )

        file_handle.seek(0)

        endpoint = "{endpoint_base}/{sha1}".format(
            endpoint_base=self.__UPLOAD_ENDPOINT,
            sha1=file_sha1
        )

        url = self._url.format(endpoint=endpoint)

        self._headers["Content-Type"] = "application/octet-stream"

        response = self._post_request(url=url, data=file_handle)

        self._raise_on_error(response)

        response = self.__upload_meta(
            url=url,
            sample_name=sample_name,
            sample_domain=sample_domain,
            subscribe=subscribe,
            archive_type=archive_type,
            archive_password=archive_password
        )

        return response

    def __upload_meta(self, url, sample_name, sample_domain, subscribe, archive_type, archive_password):
        """Private method for setting up and uploading metadata of a sample uploaded to the File Upload API.
            :param url: URL used for sample upload
            :type url: str
            :param sample_name: optional name of the sample to be displayed in the cloud
            :type sample_name: str
            :param sample_domain: web domain where the sample was found and downloaded from
            :type sample_domain: str
            :param subscribe: if the value is 'data_change' this parameter adds the sample to the user's
            data change feed subscription list
            :type subscribe: str
            :param archive_type: used to define the compression algorithm if sending an archive file;
            supported values: 'zip'
            :type archive_type: str
            :param archive_password: the password for extracting the content of the archive
            :type archive_password: str
            :return: response
            :rtype: requests.Response
        """
        base_xml = "<properties><property><name>file_name</name><value>{sample_name}</value></property>" \
                   "</properties><domain>{domain}</domain>".format(domain=sample_domain, sample_name=sample_name)

        if archive_type:
            if not isinstance(archive_type, str):
                raise WrongInputError("archive_type parameter must be string.")

            base_xml = "{base}<archive><archive_type>{archive_type}</archive_type>".format(
                base=base_xml,
                archive_type=archive_type
            )

            if archive_password:
                if not isinstance(archive_password, str):
                    raise WrongInputError("archive_password parameter must be string.")

                base_xml = "{base}<archive_password>{archive_password}</archive_password>".format(
                    base=base_xml,
                    archive_password=archive_password
                )

            base_xml = "{base}</archive>".format(base=base_xml)

        elif archive_password and not archive_type:
            raise WrongInputError("archive_password can not be used without archive_type.")

        meta_xml = "<rl>{base}</rl>".format(base=base_xml)

        meta_url = "{url}/meta".format(url=url)

        query_params = None

        if subscribe:
            if not isinstance(subscribe, str):
                raise WrongInputError("subscribe parameter must be string.")

            query_params = {"subscribe": subscribe}

        response = self._post_request(
            url=meta_url,
            data=meta_xml,
            params=query_params
        )

        self._raise_on_error(response)

        return response

    @staticmethod
    def __get_sample_name(file_path):
        """Private method for parsing the name of the sample if one is not provided.
            :param file_path: file path string
            :type file_path: str
            :return: parsed sample name
            :rtype: str
        """
        if "nt" in os.name:
            split_path = file_path.split("\\")
        else:
            split_path = file_path.split("/")

        sample_name = split_path[-1]

        if len(sample_name) == 0:
            sample_name = "sample"

        return sample_name


class DeleteFile(TiCloudAPI):
    """TCA-0204"""

    __SINGLE_QUERY_ENDPOINT = "/api/delete/sample/v1/query/{hash_type}/{hash_value}"
    __BULK_QUERY_ENDPOINT = "/api/delete/sample/v1/bulk_query/json"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(DeleteFile, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                         allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def delete_samples(self, sample_hashes, delete_on=None):
        """Accepts a single hash string or a list of hash strings
        belonging to samples you want to delete from the cloud.
        You can only delete samples that were uploaded by the same cloud account.
        In case a list with multiple sample hashes is being used, all hashes must be of the same type.
        An optional parameter for setting a future deletion time can be used in the form of a Unix timestamp.
            :param sample_hashes: hash string or a list of hash strings
            :type sample_hashes: str or list[str]
            :param delete_on: future deletion time
            :type delete_on: int
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=sample_hashes if isinstance(sample_hashes, list) else [sample_hashes],
            allowed_hash_types=(MD5, SHA1, SHA256)
        )

        hash_type = resolve_hash_type(sample_hashes if isinstance(sample_hashes, list) else [sample_hashes])

        if delete_on and not isinstance(delete_on, int):
            raise WrongInputError("delete_on parameter must be an integer unix timestamp.")

        if isinstance(sample_hashes, str):
            endpoint = self.__SINGLE_QUERY_ENDPOINT.format(
                hash_type=hash_type,
                hash_value=sample_hashes
            )

            if delete_on:
                endpoint = "{endpoint}?delete_on={delete_on}".format(
                    endpoint=endpoint,
                    delete_on=delete_on
                )

            url = self._url.format(endpoint=endpoint)

            response = self._delete_request(url=url)

        elif isinstance(sample_hashes, list):
            payload_json = {"rl": {"query": {"hash_type": hash_type, "hashes": sample_hashes}}}

            if delete_on:
                payload_json["rl"]["query"]["delete_on"] = str(delete_on)

            url = self._url.format(endpoint=self.__BULK_QUERY_ENDPOINT)

            response = self._delete_request(url=url, payload_json=payload_json)

        else:
            raise WrongInputError("Only hash string or list of hash strings are allowed as the "
                                  "sample_hashes parameter.")

        self._raise_on_error(response)

        return response


class ReanalyzeFile(TiCloudAPI):
    """TCA-0205"""

    __SINGLE_QUERY_ENDPOINT = "/api/rescan/v1/query/{hash_type}/{hash_value}"
    __BULK_QUERY_ENDPOINT = "/api/rescan/v1/bulk_query/json"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(ReanalyzeFile, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                            allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def reanalyze_samples(self, sample_hashes):
        """Accepts a single hash string or a list of hash strings
        belonging to samples in the cloud you want to reanalyze.
        The samples need to be already present in the cloud in order to be reanalyzed.
        In case a list with multiple sample hashes is being used, all hashes must be of the same type.
            :param sample_hashes: hash string or a list of hash strings
            :type sample_hashes: str or list[str]
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=sample_hashes if isinstance(sample_hashes, list) else [sample_hashes],
            allowed_hash_types=(MD5, SHA1, SHA256)
        )

        hash_type = resolve_hash_type(sample_hashes if isinstance(sample_hashes, list) else [sample_hashes])

        if isinstance(sample_hashes, str):
            endpoint = self.__SINGLE_QUERY_ENDPOINT.format(
                hash_type=hash_type,
                hash_value=sample_hashes
            )

            url = self._url.format(endpoint=endpoint)

            response = self._get_request(url=url)

        elif isinstance(sample_hashes, list):
            payload_json = {"rl": {"query": {"hash_type": hash_type, "hashes": sample_hashes}}}

            url = self._url.format(endpoint=self.__BULK_QUERY_ENDPOINT)

            response = self._post_request(url=url, post_json=payload_json)

        else:
            raise WrongInputError("Only hash string or list of hash strings are allowed as the "
                                  "sample_hashes parameter.")

        self._raise_on_error(response)

        return response


class DataChangeSubscription(TiCloudAPI):
    """TCA-0206 - Alert on Reputation and Metadata Changes"""

    __SUBSCRIBE_ENDPOINT = "/api/subscription/data_change/v1/bulk_query/subscribe/{post_format}"
    __UNSUBSCRIBE_ENDPOINT = "/api/subscription/data_change/v1/bulk_query/unsubscribe/{post_format}"
    __PULL_ENDPOINT = "/api/feed/data_change/v3/pull"
    __START_ENDPOINT = "/api/feed/data_change/v3/start/{time_format}/{time_value}"
    __CONTINUOUS_FEED_ENDPOINT = "/api/feed/data_change/v3/query/{time_format}/{time_value}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(DataChangeSubscription, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                     allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def subscribe(self, hashes):
        """Subscribes to a list of samples (hashes) for which the changed data (if there are any)
        will be delivered in the Data Change Feed.
            :param hashes: list of hash strings
            :type hashes: list[str]
            :return: response
            :rtype: requests.Response
        """
        response = self.__subscription_action(hashes=hashes, specific_endpoint=self.__SUBSCRIBE_ENDPOINT)

        return response

    def unsubscribe(self, hashes):
        """Unsubscribes from a list of samples that the user was previously subscribed to.
            :param hashes: list of hash strings
            :type hashes: list[str]
            :return: response
            :rtype: requests.Response
        """
        response = self.__subscription_action(hashes=hashes, specific_endpoint=self.__UNSUBSCRIBE_ENDPOINT)

        return response

    def __subscription_action(self, hashes, specific_endpoint):
        """Internal method for subscribing and unsubscribing from data changes in samples.
            :param hashes: list of hash strings
            :type hashes: list[str]
            :param specific_endpoint: requested endpoint string
            :type specific_endpoint: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(hashes, list):
            raise WrongInputError("hashes parameter must be a list of strings.")

        validate_hashes(
            hash_input=hashes,
            allowed_hash_types=(MD5, SHA1, SHA256)
        )

        hash_type = resolve_hash_type(sample_hashes=hashes)

        post_json = {"rl": {"query": {"hash_type": hash_type, "hashes": hashes}}}

        endpoint = specific_endpoint.format(post_format="json")
        url = self._url.format(endpoint=endpoint)

        response = self._post_request(url=url, post_json=post_json)

        self._raise_on_error(response)

        return response

    def set_start_time(self, time_format, time_value):
        """Sets the starting point for the DataChangeSubscription.pull_from_feed method.
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :return: response
            :rtype: requests.Response
        """
        self.__validate_time(time_format=time_format, time_value=time_value)

        endpoint = self.__START_ENDPOINT.format(time_format=time_format, time_value=time_value)
        url = self._url.format(endpoint=endpoint)

        response = self._put_request(url=url)

        self._raise_on_error(response)

        return response

    def pull_from_feed(self, events=None, limit=None):
        """Returns a recordset with samples to which the user is subscribed.
        The starting point for this action is set using the DataChangeSubscription.set_start_time method.
        If the starting point is not set, this method will return records starting with the current timestamp.
        Every subsequent request will continue from the timestamp where the previous request ended.
            :param events: list of sections that will be included in the response; leaving it as None
            will return all available sections
            :type events: list[str]
            :param limit: number of records to return in response
            :type limit: int
            :return: response
            :rtype: requests.Response
        """
        query_params = {"format": "json"}

        if events:
            if not isinstance(events, list):
                raise WrongInputError("events parameter must be a list of strings.")

            events = ",".join(events)
            query_params["events"] = events

        if limit:
            if not isinstance(limit, int):
                raise WrongInputError("limit parameter must be an integer.")

            query_params["limit"] = limit

        url = self._url.format(endpoint=self.__PULL_ENDPOINT)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def continuous_data_change_feed(self, time_format, time_value, events=None):
        """Returns a recordset with samples to which the user is subscribed from
        the timestamp stated in the request onwards.
        To fetch the next recordset, use the last_timestamp value from the response
        and submit it in a new request as the time_value parameter.
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param events: list of sections that will be included in the response; leaving it as None
            will return all available sections
            :type events: list[str]
            :return: response
            :rtype: requests.Response
        """
        self.__validate_time(time_format=time_format, time_value=time_value)

        query_params = {"format": "json"}

        if events:
            if not isinstance(events, list):
                raise WrongInputError("events parameter must be a list of strings.")

            events = ",".join(events)
            query_params["events"] = events

        endpoint = self.__CONTINUOUS_FEED_ENDPOINT.format(time_format=time_format, time_value=time_value)
        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    @staticmethod
    def __validate_time(time_format, time_value):
        """Internal method for validating the time format and time values
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("If the timestamp time_format is used, time_value parameter must be a Unix "
                                      "timestamp string.")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("If the utc time_format is used, time_value parameter must be written in the "
                                      "YYYY-MM-DDThh:mm:ss format.")

        else:
            raise WrongInputError("time_format parameter mus be one of the following values: 'timestamp', 'utc'.")


class DynamicAnalysis(TiCloudAPI):
    """TCA-0207 and TCA-0106"""

    __DETONATE_ENDPOINT = "/api/dynamic/analysis/analyze/v1/query/json"
    __DETONATE_ARCHIVE_ENDPOINT = "/api/dynamic/analysis/analyze/v1/archive/query/json"
    __GET_FILE_RESULTS = "/api/dynamic/analysis/report/v1/query/{hash_type}"
    __GET_ARCHIVE_RESULTS_ENDPOINT = "/api/dynamic/analysis/report/v1/archive/query/{hash_type}"
    __GET_URL_RESULTS_BASE64 = "/api/dynamic/analysis/report/v1/query/url/base64"
    __GET_URL_RESULTS_SHA1 = "/api/dynamic/analysis/report/v1/query/url/sha1"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(DynamicAnalysis, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                              allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def detonate_url(self, url_string, platform):
        """Submits a URL for dynamic analysis and returns processing info.
            :param url_string: URL string
            :type url_string: str
            :param platform: desired platform on which the sample or archive will be detonated; see available platforms
            :type platform: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(url_string, str):
            raise WrongInputError("url_string parameter must be a string")

        response = self.__detonate(
            url_string=url_string,
            platform=platform,
        )
        
        return response

    def detonate_sample(self, sample_hash=None, platform=None, is_archive=False, internet_simulation=False,
                        sample_name=None, sample_sha1=None):
        """Submits a sample or a file archive available in the cloud for dynamic analysis and returns processing info.
            :param sample_hash: SHA1, MD5 or SHA256 hash of the sample or archive
            :type sample_hash: str
            :param platform: desired platform on which the sample or archive will be detonated; see available platforms
            :type platform: str
            :param is_archive: needs to be set to True if a file archive is being detonated;
            currently supported archive types: .zip
            :type is_archive: bool
            :param internet_simulation: perform the dynamic analysis without connecting to the internet
            :type internet_simulation: bool
            :param sample_name: custom name for the sample
            :type sample_name: str
            :param sample_sha1: SHA1 hash of the sample or archive (DEPRECATED)
            :type sample_sha1: str
            :return: response
            :rtype: requests.Response
        """
        if sample_hash:
            validate_hashes(
                hash_input=[sample_hash],
                allowed_hash_types=(SHA1, SHA256, MD5)
            )

        elif sample_sha1:
            warn("DEPRECATION WARNING - Parameter sample_sha1 will soon be removed. Use sample_hash instead", Warning)

            validate_hashes(
                hash_input=[sample_sha1],
                allowed_hash_types=(SHA1,)
            )

            sample_hash = sample_sha1

        else:
            raise WrongInputError("A hash parameter needs provided: sample_hash or sample_sha1 (deprecated)")

        if not platform:
            raise WrongInputError("The platform parameter needs to be provided.")

        response = self.__detonate(
            sample_hash=sample_hash,
            platform=platform,
            is_archive=is_archive,
            internet_simulation=internet_simulation,
            sample_name=sample_name
        )

        return response

    def __detonate(self, platform, sample_hash=None, url_string=None, is_archive=False, internet_simulation=False,
                   sample_name=None):
        """Submits a sample, a file archive available in the cloud or a URL for 
        dynamic analysis and returns processing info.
        This is a private method for all dynamic analysis submission methods.
            :param sample_hash: SHA1, MD5 or SHA256 hash of the sample or archive
            :type sample_hash: str
            :param url_string: URL string
            :type url_string: str
            :param platform: desired platform on which the sample or archive will be detonated; see available platforms
            :type platform: str
            :param is_archive: needs to be set to True if a file archive is being detonated;
            currently supported archive types: .zip
            :type is_archive: bool
            :param internet_simulation: perform the dynamic analysis without connecting to the internet
            :type internet_simulation: bool
            :param sample_name: custom name for the sample
            :type sample_name: str
            :return: response
            :rtype: requests.Response
        """
        if platform not in AVAILABLE_PLATFORMS:
            raise WrongInputError("platform parameter must be one "
                                  "of the following values: {platforms}".format(platforms=AVAILABLE_PLATFORMS))

        post_json = {"rl": {"platform": platform, "response_format": "json"}}

        if not isinstance(internet_simulation, bool):
            raise WrongInputError("internet_simulation parameter must be boolean.")

        if sample_hash:
            hash_type = HASH_LENGTH_MAP.get(len(sample_hash))
            post_json["rl"][hash_type] = sample_hash

            optional_parameters = []

            if sample_name:
                optional_parameters.append(f"sample_name={sample_name}")

            if internet_simulation:
                optional_parameters.append("internet_simulation=true")

            post_json["rl"]["optional_parameters"] = ", ".join(optional_parameters)

        elif url_string:
            post_json["rl"]["url"] = url_string

        if not is_archive:
            url = self._url.format(endpoint=self.__DETONATE_ENDPOINT)

        else:
            url = self._url.format(endpoint=self.__DETONATE_ARCHIVE_ENDPOINT)

        response = self._post_request(
            url=url,
            post_json=post_json
        )

        self._raise_on_error(response)

        return response

    def get_dynamic_analysis_results(self, sample_hash=None, url=None, url_sha1=None, is_archive=False, latest=False,
                                     analysis_id=None):
        """Returns dynamic analysis results for a desired file, URL or a file archive.
        The analysis of the selected artifact must be finished for the results to be available.
            :param sample_hash: SHA1, MD5 or SHA256 hash of a desired sample or archive. mutually exclusive with url
            :type sample_hash: str
            :param url: URL string; mutually exclusive with sample_hash
            :type url: str
            :param url_sha1: the sha1 of the submitter URL; it can be found in the response of the
            DynamicAnalysis.detonate_url method; mutually exclusive with sample_hash and url
            :type url_sha1: str
            :param is_archive: needs to be set to True if results for a file archive are being fetched;
            currently supported archive types: .zip; used only with sample_hash
            :type is_archive: bool
            :param latest: return only the latest analysis results
            :type latest: bool
            :param analysis_id: return only the results of this analysis
            :type analysis_id: str
            :return: response
            :rtype: requests.Response
        """
        if sample_hash:
            validate_hashes(
                hash_input=[sample_hash],
                allowed_hash_types=(SHA1, MD5, SHA256)
            )
            indicator = sample_hash

            if not is_archive:
                endpoint_base = self.__GET_FILE_RESULTS

            else:
                endpoint_base = self.__GET_ARCHIVE_RESULTS_ENDPOINT

            hashing_algorithm = HASH_LENGTH_MAP.get(len(sample_hash))
            endpoint_base = endpoint_base.format(hash_type=hashing_algorithm)

        elif url:
            if not isinstance(url, str):
                raise WrongInputError("url parameter must be a string")

            indicator = base64.urlsafe_b64encode(url.encode("utf-8")).strip(b"=").decode()
            endpoint_base = self.__GET_URL_RESULTS_BASE64

        elif url_sha1:
            validate_hashes(
                hash_input=[url_sha1],
                allowed_hash_types=(SHA1,)
            )
            indicator = url_sha1
            endpoint_base = self.__GET_URL_RESULTS_SHA1

        else:
            raise WrongInputError("Either sample_hash or url need to be defined as parameters")

        endpoint = "{endpoint_base}/{indicator}".format(
            endpoint_base=endpoint_base,
            indicator=indicator
        )

        if latest:
            if analysis_id:
                raise WrongInputError("Can not use analysis_id because latest is being used.")

            if str(latest).lower() != "true":
                raise WrongInputError("latest parameter must be boolean.")

            endpoint = "{endpoint}/latest".format(endpoint=endpoint)

        if not is_archive:
            if analysis_id:
                if not isinstance(analysis_id, str):
                    raise WrongInputError("analysis_id parameter bust be string.")

                endpoint = "{endpoint}/{analysis_id}".format(
                    endpoint=endpoint,
                    analysis_id=analysis_id
                )

        endpoint = "{endpoint}?format=json".format(endpoint=endpoint)

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response


class CertificateIndex(TiCloudAPI):
    """TCA-0501"""

    __CERTIFICATE_INDEX_ENDPOINT = "/api/certificate/index/v1/query/thumbprint/{thumbprint}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(CertificateIndex, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                               allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_certificate_information(self, certificate_thumbprint, extended_results=True,
                                    results_per_page=100, classification=None, next_page_hash=None):
        """Accepts a hash (thumbprint) and returns a list of SHA1 hashes for samples signed with the certificate
         matching the requested thumbprint.
         Extended information for each returned hash can be requested.
            :param certificate_thumbprint: hash string
            :type certificate_thumbprint: str
            :param extended_results: return extended results
            :type extended_results: bool
            :param results_per_page: number of returned results per page; default and maximum is 100
            :type results_per_page: int
            :param classification: return only results with a specific classification; allowed values are 'MALICIOUS',
            'SUSPICIOUS', 'KNOWN' and 'UNKNOWN'
            :type classification: str or None
            :param next_page_hash: hash string of the next page of results
            :type next_page_hash: str or None
            :return: response
            :rtype: requests.Response
         """
        validate_hashes(
            hash_input=[certificate_thumbprint],
            allowed_hash_types=(MD5, SHA1, SHA256)
        )

        extended_results = str(extended_results).lower()
        if extended_results not in ("true", "false"):
            raise WrongInputError("extended_results parameter must be boolean.")

        if not isinstance(results_per_page, int):
            raise WrongInputError("results_per_page parameter must be integer.")

        optional_params = "?format=json&extended={extended_results}&limit={results_per_page}".format(
            extended_results=extended_results,
            results_per_page=results_per_page
        )

        if next_page_hash:
            optional_params = "/page/{page_hash}{optional_params}".format(
                page_hash=next_page_hash,
                optional_params=optional_params
            )

        if classification:
            classification = str(classification).upper()
            if classification not in CLASSIFICATIONS:
                raise WrongInputError("Only the following options are allowed as the classification parameter: "
                                      "{classifications} ".format(classifications=CLASSIFICATIONS))

            optional_params = "{optional_params}&classification={classification}".format(
                optional_params=optional_params,
                classification=classification
            )

        endpoint = "{endpoint}{params}".format(
            endpoint=self.__CERTIFICATE_INDEX_ENDPOINT.format(thumbprint=certificate_thumbprint),
            params=optional_params
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def get_certificate_information_aggregated(self, certificate_thumbprint, extended_results=True, classification=None,
                                               results_per_page=100, max_results=None):
        """Accepts a hash (thumbprint) and returns a list of SHA1 hashes for samples signed with the certificate
         matching the requested thumbprint.
         This method automatically handles paging and returns a list of results instead of a Response object.
         Extended information for each returned hash can be requested.
            :param certificate_thumbprint: hash string
            :type certificate_thumbprint: str
            :param extended_results: return extended results
            :type extended_results: bool
            :param classification: return only results with a specific classification; allowed values are 'MALICIOUS',
            'SUSPICIOUS', 'KNOWN' and 'UNKNOWN'
            :type classification: str or None
            :param results_per_page: number of returned results per page; default and maximum is 100
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page_hash = None

        while True:
            response = self.get_certificate_information(
                certificate_thumbprint=certificate_thumbprint,
                extended_results=extended_results,
                results_per_page=results_per_page,
                classification=classification,
                next_page_hash=next_page_hash
            )

            response_json = response.json()

            samples = response_json.get("rl").get("samples", [])
            results.extend(samples)

            next_page_hash = response_json.get("rl").get("next_page", None)

            if not max_results:
                if not next_page_hash:
                    return results

            else:
                if not next_page_hash or len(results) >= max_results:
                    return results[:max_results]


class CertificateAnalytics(TiCloudAPI):
    """TCA-0502"""

    __SINGLE_QUERY_ENDPOINT = "/api/certificate/analytics/v1/query/thumbprint"
    __BULK_QUERY_ENDPOINT = "/api/certificate/analytics/v1/query/thumbprint/json"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(CertificateAnalytics, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                   allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_certificate_analytics(self, certificate_thumbprints):
        """Accepts a certificate hash thumbprint and returns certificate analytics results.
            :param certificate_thumbprints: hash string or list of hash strings
            :type certificate_thumbprints: str or list[str]
            :return: response
            :rtype: requests.Response
        """
        if isinstance(certificate_thumbprints, str):
            validate_hashes(
                hash_input=[certificate_thumbprints],
                allowed_hash_types=(MD5, SHA1, SHA256)
            )

            endpoint = "{endpoint_base}/{thumbprint}?format=json".format(
                endpoint_base=self.__SINGLE_QUERY_ENDPOINT,
                thumbprint=certificate_thumbprints
            )

            url = self._url.format(endpoint=endpoint)

            response = self._get_request(url=url)

        elif isinstance(certificate_thumbprints, list) and len(certificate_thumbprints) > 0:
            validate_hashes(
                hash_input=certificate_thumbprints,
                allowed_hash_types=(MD5, SHA1, SHA256)
            )

            url = self._url.format(endpoint=self.__BULK_QUERY_ENDPOINT)

            post_json = {"rl": {"query": {"thumbprints": certificate_thumbprints, "format": "json"}}}

            response = self._post_request(url=url, post_json=post_json)

        else:
            raise WrongInputError("Only hash string or list of hash strings are allowed as the thumbprint parameter.")

        self._raise_on_error(response)

        return response


class CertificateThumbprintSearch(TiCloudAPI):
    """TCA-0503"""

    __CERTIFICATE_SEARCH_ENDPOINT = "/api/certificate/search/v1/query/subject/json"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(CertificateThumbprintSearch, self).__init__(host, username, password, verify, proxies,
                                                          user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def search_common_names(self, common_name, next_page_common_name=None, next_page_thumbprint=None,
                            results_per_page=100):
        """Accepts a certificate common name and returns common names matching the request, along with the list of
        thumbprints of all the certificates sharing that common name.
        The common name can contain an asterisk wildcard ('*') substituting any number of any characters.
        To use paging, both next_page_common_name and next_page_thumbprint parameters must be provided.
            :param common_name: certificate common name
            :type common_name: str
            :param next_page_common_name: common name on the next page of results
            :type next_page_common_name: str or None
            :param next_page_thumbprint: hash thumbprint on the next page of result
            :type next_page_thumbprint: str or None
            :param results_per_page: number of results per page
            :type results_per_page: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(common_name, str):
            raise WrongInputError("common_name parameter must be string.")

        if not isinstance(results_per_page, int):
            raise WrongInputError("limit parameter must be integer.")

        post_json = {"rl": {"query": {"common_name": common_name, "limit": results_per_page,
                                      "response_format": "json"}}}

        if all((next_page_common_name, next_page_thumbprint)):
            if not isinstance(next_page_common_name, str) or not isinstance(next_page_thumbprint, str):
                raise WrongInputError("Both next_page_common_name and next_page_thumbprint parameters need to be "
                                      "strings.")

            post_json["rl"]["query"]["next_page_common_name"] = next_page_common_name
            post_json["rl"]["query"]["next_page_thumbprint"] = next_page_thumbprint

        elif any((next_page_common_name, next_page_thumbprint)):
            raise WrongInputError("Both next_page_common_name and next_page_thumbprint parameters need to be used "
                                  "together for paging.")

        url = self._url.format(endpoint=self.__CERTIFICATE_SEARCH_ENDPOINT)

        response = self._post_request(url=url, post_json=post_json)

        self._raise_on_error(response)

        return response

    def search_common_names_aggregated(self, common_name, results_per_page=100, max_results=None):
        """Accepts a certificate common name and returns common names matching the request, along with the list of
        thumbprints of all the certificates sharing that common name.
        The common name can contain an asterisk wildcard ('*') substituting any number of any characters.
        This method automatically handles paging and returns a list of results instead of a Response object.
            :param common_name: certificate common name
            :type common_name: str
            :param results_per_page: number of results per page
            :type results_per_page: int
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page_common_name, next_page_thumbprint = None, None

        while True:
            response = self.search_common_names(
                common_name=common_name,
                next_page_common_name=next_page_common_name,
                next_page_thumbprint=next_page_thumbprint,
                results_per_page=results_per_page
            )

            response_json = response.json()

            common_names = response_json.get("rl").get("search", [])
            results.extend(common_names)

            next_page_common_name = response_json.get("rl").get("next_page_common_name", None)
            next_page_thumbprint = response_json.get("rl").get("next_page_thumbprint", None)

            if not max_results:
                if not any((next_page_common_name, next_page_thumbprint)):
                    return results

            else:
                if not any((next_page_common_name, next_page_thumbprint)) or len(results) >= max_results:
                    return results[:max_results]


class RansomwareIndicators(TiCloudAPI):
    """Ransomware Indicators Feed"""

    __FEED_ENDPOINT = "/api/public/v1/ransomware/indicators?withHealth={health}&tagFormat={tag_format}&" \
                      "hours={hours_back}&indicatorTypes={indicator_types}&onlyFreemium={only_freemium}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(RansomwareIndicators, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                   allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)
        self._allowed_indicator_types = ("ipv4", "hash", "domain", "uri")

    def get_indicators(self, hours_back, indicator_types, tag_format="dict", health_check=0, only_freemium=0):
        """Accepts a list of indicator type strings and an integer for historical hours.
        Returns indicators of ransomware and related tools.
            :param hours_back: historical hours - from this moment back
            :type hours_back: int
            :param indicator_types: a list of indicator types to fetch; possible values are 'ipv4', 'hash', 'domain', 'uri'
            :type indicator_types: list[str]
            :param tag_format: response format; default is 'dict'
            :type tag_format: str
            :param health_check: defines whether this request is an API health check;
            possible values are 0 and 1; default is 0
            :type health_check: int
            :param only_freemium: return only freemium indicators of all types;
            possible values are 0 and 1: default is 0; if set to 1, parameter indicator_types is ignored
            :type only_freemium: int
            :return: response
            :rtype: requests.Response
        """
        if not (isinstance(hours_back, int) and 1 <= hours_back <= 48):
            raise WrongInputError("hours_back parameter must be integer with a value between 1 and 48.")

        try:
            lowered_indicator_types = [indicator_type.lower() for indicator_type in indicator_types]

        except (AttributeError, TypeError):
            raise WrongInputError("indicator_types parameter must be a list of strings.")

        if not all(element in self._allowed_indicator_types for element in lowered_indicator_types):
            raise WrongInputError("Only the following values are allowed as indicator types: "
                                  "{indicator_types}".format(indicator_types=self._allowed_indicator_types))

        indicator_types = ",".join(lowered_indicator_types)

        if health_check not in (0, 1):
            raise WrongInputError("health_check parameter must be 0 or 1.")

        if only_freemium not in (0, 1):
            raise WrongInputError("only_freemium parameter must be 0 or 1.")

        endpoint = self.__FEED_ENDPOINT.format(
            health=health_check,
            tag_format=tag_format,
            hours_back=hours_back,
            indicator_types=indicator_types,
            only_freemium=only_freemium
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response


class ContinuousFeed(TiCloudAPI):
    """Parent class for continuous feeds"""

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(ContinuousFeed, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                             allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def _pull_with_timestamp(self, timestamp_endpoint, time_format, time_value, sample_available=False, record_limit=1000):
        """Common method for pulling records with a timestamp in continuous feeds."""
        if time_format.lower() not in ("timestamp", "utc"):
            raise WrongInputError("time_format parameter mus be one of the following values: 'timestamp', 'utc'.")

        if time_format.lower() == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("If the timestamp time_format is used, time_value parameter must be a Unix "
                                      "timestamp string.")

        elif time_format.lower() == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("If the utc time_format is used, time_value parameter must be written in the "
                                      "YYYY-MM-DDThh:mm:ss format.")

        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not all((isinstance(record_limit, int), 0 < record_limit <= 1000)):
            raise WrongInputError("record_limit parameter must be an integer with the value 1-1000.")

        params = "&sample_available={available}&limit={record_limit}".format(
            available=str(sample_available).lower(),
            record_limit=record_limit
        )

        timestamp_endpoint = "{base}{params}".format(
            base=timestamp_endpoint.format(time_format=time_format, time_value=time_value),
            params=params
        )

        url = self._url.format(endpoint=timestamp_endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def _pull(self, pull_endpoint, sample_available=False, record_limit=1000):
        """Common method for pulling records without a timestamp in continuous feeds."""
        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not all((isinstance(record_limit, int), 0 < record_limit <= 1000)):
            raise WrongInputError("record_limit parameter must be an integer with the value 1-1000.")

        params = "&sample_available={available}&limit={record_limit}".format(
            available=str(sample_available).lower(),
            record_limit=record_limit
        )

        endpoint = "{base}{params}".format(
            base=pull_endpoint,
            params=params
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def _set_start(self, start_endpoint, time_format, time_value):
        """Common method for setting a starting time in continuous feeds."""
        if time_format.lower() not in ("timestamp", "utc"):
            raise WrongInputError("time_format parameter mus be one of the following values: 'timestamp', 'utc'.")

        if time_format.lower() == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("If the timestamp time_format is used, time_value parameter must be a Unix "
                                      "timestamp string.")

        elif time_format.lower() == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("If the utc time_format is used, time_value parameter must be written in the "
                                      "YYYY-MM-DDThh:mm:ss format.")

        endpoint = start_endpoint.format(time_format=time_format, time_value=time_value)

        url = self._url.format(endpoint=endpoint)

        response = self._put_request(url=url)

        self._raise_on_error(response)

        return response


class NewMalwareFilesFeed(ContinuousFeed):
    """TCF-0101"""

    __TIMESTAMP_PULL_ENDPOINT = "/api/feed/malware/detection/v1/query/{time_format}/{time_value}?format=json"
    __PULL_ENDPOINT = "/api/feed/malware/detection/v1/query/pull?format=json"
    __START_ENDPOINT = "/api/feed/malware/detection/v1/query/start/{time_format}/{time_value}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(NewMalwareFilesFeed, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                  allow_none_return=allow_none_return)

    def pull_with_timestamp(self, time_format, time_value, sample_available=False, record_limit=1000):
        """Accepts a time format definition and a time value. Returns malware detections from the requested time.
        To fetch the next batch of records, use the last_timestamp from the response increased by 1.
        The time value needs to be within the last 365 days.
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param sample_available: get only samples available for download
            :type sample_available: bool
            :param record_limit: max number of records to be returned
            :type record_limit: int
            :return: response
            :rtype: requests.Response
        """
        response = self._pull_with_timestamp(
            timestamp_endpoint=self.__TIMESTAMP_PULL_ENDPOINT,
            time_format=time_format,
            time_value=time_value,
            sample_available=sample_available,
            record_limit=record_limit
        )

        return response

    def pull(self, sample_available=False, record_limit=1000):
        """Returns a list of malware detections since the point in time set by the self.set_start() method.
        If the user has not previously used this method, nor has the self.set_start() method been called,
        it will return records starting with the current timestamp.
        Every subsequent call will continue from the timestamp where the previous call ended.
            :param sample_available: get only samples available for download
            :type sample_available: bool
            :param record_limit: max number of records to be returned
            :type record_limit: int
            :return: response
            :rtype: requests.Response
        """
        response = self._pull(
            pull_endpoint=self.__PULL_ENDPOINT,
            sample_available=sample_available,
            record_limit=record_limit
        )

        return response

    def set_start(self, time_format, time_value):
        """This method sets the starting time for the self.pull() method.
        The starting time must be within the last 365 days.
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
        """
        response = self._set_start(
            start_endpoint=self.__START_ENDPOINT,
            time_format=time_format,
            time_value=time_value
        )

        return response


class NewFilesFirstScan(TiCloudAPI):
    """TCF-0107"""

    __FEED_ENDPOINT = "/api/feed/malware/first_scan/v1/query/{time_format}/{time_value}"
    __START_ENDPOINT = "/api/feed/malware/first_scan/v1/query/start/{time_format}/{time_value}"
    __PULL_ENDPOINT = "/api/feed/malware/first_scan/v1/query/pull"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(NewFilesFirstScan, self).__init__(host, username, password, verify, proxies,
                                                          user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def feed_query(self, time_format, time_value, sample_available=False, limit=1000):
        """Returns a list of hashes for samples collected from various sources and scanned
        for the first time in TitaniumCloud system
            :param time_format: possible values: 'timestamp' or 'utc'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param sample_available: return only samples available for download. Default is 'false'
            :type sample_available: boolean
            :param limit: number of records to return in the response
            :type limit: int
            :return: response
            :rtype: requests.Response
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("if timestamp is used, time_value needs to be a unix timestamp")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("if utc is used, time_value needs to be in format 'YYYY-MM-DDThh:mm:ss'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'timestamp' or 'utc'")

        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not isinstance(limit, int):
            raise WrongInputError("limit parameter must be integer.")

        endpoint = self.__FEED_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        query_params = {
            "sample_available": sample_available,
            "limit": limit,
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def start_query(self, time_format, time_value):
        """Sets the starting timestamp for the pull_query
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :return: response
            :rtype: requests.Response
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("if timestamp is used, time_value needs to be a unix timestamp")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("if utc is used, time_value needs to be in format 'YYYY-MM-DDThh:mm:ss'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'timestamp' or 'utc'")

        endpoint = self.__START_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        url = self._url.format(endpoint=endpoint)

        response = self._put_request(url=url)

        self._raise_on_error(response)

        return response

    def pull_query(self, sample_available=False, limit=1000):
        """Returns the list of hashes for samples scanned for the first time,
        starting with the timestamp defined with the start_query
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :param limit: number of records to return in the response
            :type limit: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean")

        if not isinstance(limit, int):
            raise WrongInputError("limit parameter must be an integer.")

        query_params = {
            "sample_available": str(sample_available).lower(),
            "limit": limit,
            "format": "json"
        }

        url = self._url.format(endpoint=self.__PULL_ENDPOINT)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response


class NewFilesFirstAndRescan(TiCloudAPI):
    """TCF-0108"""

    __FEED_ENDPOINT = "/api/feed/malware/scan/v1/query/{time_format}/{time_value}"
    __START_ENDPOINT = "/api/feed/malware/scan/v1/query/start/{time_format}/{time_value}"
    __PULL_ENDPOINT = "/api/feed/malware/scan/v1/query/pull"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(NewFilesFirstAndRescan, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                     allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def feed_query(self, time_format, time_value, sample_available=False, limit=1000):
        """Returns a continuous list of samples in the TitaniumCloud system which have been
        scanned for the first time or rescanned
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until current moment;
            accepted formats are unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :param limit: number of records to return in the response
            :type limit: int
            :return: response
            :rtype: requests.Response
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("if timestamp is used, time_value needs to be a unix timestamp")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("if utc is used, time_value needs to be in format 'YYYY-MM-DDThh:mm:ss'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'timestamp' or 'utc'")

        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not isinstance(limit, int):
            raise WrongInputError("limit parameter must be integer.")

        endpoint = self.__FEED_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        query_params = {
            "sample_available": str(sample_available).lower(),
            "limit": limit,
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def start_query(self, time_format, time_value):
        """Sets the starting timestamp for the pull_query.
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :return: response
            :rtype: requests.Response
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("if timestamp is used, time_value needs to be a unix timestamp")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("if utc is used, time_value needs to be in format 'YYYY-MM-DDThh:mm:ss'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'timestamp' or 'utc'")

        endpoint = self.__START_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        url = self._url.format(endpoint=endpoint)

        response = self._put_request(url=url)

        self._raise_on_error(response)

        return response

    def pull_query(self, sample_available=False, limit=1000):
        """Returns the list of hashes for scanned samples (first time or rescanned),
        starting with the timestamp defined with the start_query
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :param limit: number of records to return in the response
            :type limit: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not isinstance(limit, int):
            raise WrongInputError("limit parameter must be integer.")

        query_params = {
            "sample_available": str(sample_available).lower(),
            "limit": limit,
            "format": "json"
        }

        url = self._url.format(endpoint=self.__PULL_ENDPOINT)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response


class FilesWithDetectionChanges(TiCloudAPI):
    """TCF-0109"""

    __FEED_ENDPOINT = "/api/feed/malware/scan/change/v1/query/{time_format}/{time_value}"
    __START_ENDPOINT = "/api/feed/malware/scan/change/v1/query/start/{time_format}/{time_value}"
    __PULL_ENDPOINT = "/api/feed/malware/scan/change/v1/query/pull"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(FilesWithDetectionChanges, self).__init__(host, username, password, verify, proxies,
                                                        user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def feed_query(self, time_format, time_value, sample_available=False, limit=1000):
        """Returns a list of hashes for scanned samples (first time scan or detection changes),
        starting with the timestamp provided in argument
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :param limit: number of records to return in the response
            :type limit: int
            :return: response
            :rtype: requests.Response
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("if timestamp is used, time_value needs to be a unix timestamp")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("if utc is used, time_value needs to be in format 'YYYY-MM-DDThh:mm:ss'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'timestamp' or 'utc'")

        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not isinstance(limit, int):
            raise WrongInputError("limit parameter must be integer.")

        endpoint = self.__FEED_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        query_params = {
            "sample_available": str(sample_available).lower(),
            "limit": limit,
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def start_query(self, time_format, time_value):
        """Sets the starting timestamp for the pull_query
            param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :return: response
            :rtype: requests.Response
        """
        if time_format not in ("utc", "timestamp"):
            raise WrongInputError("time_format parameter must be one of the following values: 'utc', 'timestamp'")

        if not isinstance(time_value, str):
            raise WrongInputError("time_value parameter must be string.")

        endpoint = self.__START_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        url = self._url.format(endpoint=endpoint)

        response = self._put_request(url=url)

        self._raise_on_error(response)

        return response

    def pull_query(self, sample_available=False, limit=1000):
        """Returns a list of hashes for scanned samples (first time or detection change),
        starting with the timestamp defined with the start_query
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :param limit: number of records to return in the response
            :type limit: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not isinstance(limit, int):
            raise WrongInputError("limit parameter must be integer.")

        query_params = {
            "sample_available": str(sample_available).lower(),
            "limit": limit,
            "format": "json"
        }

        url = self._url.format(endpoint=self.__PULL_ENDPOINT)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response


class MWPChangeEventsFeed(ContinuousFeed):
    """TCF-0111"""

    __TIMESTAMP_PULL_ENDPOINT = "/api/feed/mwp_change_events/v1/query/{time_format}/{time_value}?format=json"
    __PULL_ENDPOINT = "/api/feed/mwp_change_events/v1/query/pull?format=json"
    __START_ENDPOINT = "/api/feed/mwp_change_events/v1/query/start/{time_format}/{time_value}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(MWPChangeEventsFeed, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                  allow_none_return=allow_none_return)

    def pull_with_timestamp(self, time_format, time_value, sample_available=False, record_limit=1000):
        """Accepts a time format definition and a time value. Returns samples with a newly calculated or changed malware
        presence (MWP) classification and threat name from the requested time.
        To fetch the next batch of records, use the last_timestamp from the response increased by 1.
        The time value needs to be within the last 365 days.
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param sample_available: get only samples available for download
            :type sample_available: bool
            :param record_limit: max number of records to be returned
            :type record_limit: int
            :return: response
            :rtype: requests.Response
        """
        response = self._pull_with_timestamp(
            timestamp_endpoint=self.__TIMESTAMP_PULL_ENDPOINT,
            time_format=time_format,
            time_value=time_value,
            sample_available=sample_available,
            record_limit=record_limit
        )

        return response

    def pull(self, sample_available=False, record_limit=1000):
        """Returns a list of classification and threat name changes since the point in
        time set by the self.set_start() method.
        If the user has not previously used this method, nor has the self.set_start() method been called,
        it will return records starting with the current timestamp.
        Every subsequent call will continue from the timestamp where the previous call ended.
            :param sample_available: get only samples available for download
            :type sample_available: bool
            :param record_limit: max number of records to be returned
            :type record_limit: int
            :return: response
            :rtype: requests.Response
        """
        response = self._pull(
            pull_endpoint=self.__PULL_ENDPOINT,
            sample_available=sample_available,
            record_limit=record_limit
        )

        return response

    def set_start(self, time_format, time_value):
        """This method sets the starting time for the self.pull() method.
        The starting time must be within the last 365 days.
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
        """
        response = self._set_start(
            start_endpoint=self.__START_ENDPOINT,
            time_format=time_format,
            time_value=time_value
        )

        return response


class CvesExploitedInTheWild(TiCloudAPI):
    """TCF-0202"""

    __DAILY_CVE_REPORT_ENDPOINT = "/api/report/cve/daily/v1/query/{time_format}/{time_value}?format=json"
    __LATEST_CVE_REPORT_ENDPOINT = "/api/report/cve/daily/v1/query/latest?format=json"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(CvesExploitedInTheWild, self).__init__(host, username, password, verify, proxies,
                                                          user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def pull_daily_cve_report(self, time_format, time_value):
        """Returns a document containing the list of malware hashes (SHA1, SHA256, MD5), threat
        names, and threat counts associated with the CVE identifiers for the requested day
            :param time_format: specifies the time format; must be 'timestamp' or 'date'
            :type time_format: str
            :param time_value: time value string; accepted formats are unix timestamp string and 'YYYY-MM-DD'
            :type time_value: str
            :return: response
            :rtype: requests.Response
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("if timestamp is used, time_value needs to be a unix timestamp")

        elif time_format == "date":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%d")

            except ValueError:
                raise WrongInputError("If the date format is used, time_value must be provided as 'YYY-MM-DD'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'timestamp' or 'date'")

        endpoint = self.__DAILY_CVE_REPORT_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def pull_latest_cve_report(self):
        """Returns a document containing the list of malware hashes (SHA1, SHA256, MD5), threat names,
        and threat counts associated with CVE identifies for the latest day for which we have data
        """
        url = self._url.format(endpoint=self.__LATEST_CVE_REPORT_ENDPOINT)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response


class NewExploitOrCveSamplesFoundInWildHourly(TiCloudAPI):
    """TCF-0203"""

    __HOURLY_NEW_EXPLOIT_ENDPOINT = "/api/feed/malware/detection/exploit/hourly/v2/query/{time_format}/{time_value}"
    __LATEST_NEW_EXPLOIT_ENDPOINT = "/api/feed/malware/detection/exploit/hourly/v2/query/latest"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(NewExploitOrCveSamplesFoundInWildHourly, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                                allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def hourly_exploit_list_query(self, time_format, time_value, sample_available=False, active_cve=True):
        """Returns a list of new file hashes that contain CVE or Exploit identification and that
        are detected within the requested one-hour period in the TitaniumCloud system
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :param active_cve: when true (default) returns only exploits with active CVE identifiers
            :type active_cve: bool
            :return: response
            :rtype: requests.Response
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("if timestamp is used, time_value needs to be a unix timestamp")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("if utc is used, time_value needs to be in format 'YYYY-MM-DDThh:mm:ss'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'timestamp' or 'utc'")

        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not isinstance(active_cve, bool):
            raise WrongInputError("active_cve parameter must be boolean")
        
        endpoint = self.__HOURLY_NEW_EXPLOIT_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        query_params = {
            "sample_available": str(sample_available).lower(),
            "active_cve": str(active_cve).lower(),
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def latest_hourly_exploit_list_query(self, sample_available=False, active_cve=True):
        """Returns the results from latest hour for which we have data
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :param active_cve: when true (default) returns only exploits with active CVE identifiers
            :type active_cve: bool
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not isinstance(active_cve, bool):
            raise WrongInputError("active_cve parameter must be boolean")

        endpoint = self.__LATEST_NEW_EXPLOIT_ENDPOINT

        query_params = {
            "sample_available": str(sample_available).lower(),
            "active_cve": str(active_cve).lower(),
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response


class NewExploitAndCveSamplesFoundInWildDaily(TiCloudAPI):
    """TCF-0204"""

    __DAILY_NEW_EXPLOIT_ENDPOINT = "/api/feed/malware/exploit/daily/v1/query/{time_format}/{time_value}"
    __LATEST_NEW_EXPLOIT_ENDPOINT = "/api/feed/malware/exploit/daily/v1/query/latest"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(NewExploitAndCveSamplesFoundInWildDaily, self).__init__(host, username, password, verify, proxies,
                                                                      user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def daily_exploit_list_query(self, time_format, time_value, sample_available=False):
        """Returns a list of new file hashes that contain CVE or Exploit identification and that
        are detected per day period in the TitaniumCloud system
            :param time_format: possible values: 'date' or 'utc'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are 'YYYY-MM-DD' and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :return: response
            :rtype: requests.Response
        """
        if time_format == "date":
            try:
                datetime.datetime.strptime(time_value, "%YYYY-MM-DD")

            except ValueError:
                raise WrongInputError("if date is used, time_value needs to be in format 'YYYY-MM-DD'")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("if utc is used, time_value needs to be in format 'YYYY-MM-DDThh:mm:ss'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'date' or 'utc'")

        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        endpoint = self.__DAILY_NEW_EXPLOIT_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        query_params = {
            "sample_available": str(sample_available).lower(),
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def latest_daily_exploit_list_query(self, sample_available=False):
        """Returns the results from latest day for which we have data
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        query_params = {
            "sample_available": str(sample_available).lower(),
            "format": "json"
        }

        url = self._url.format(endpoint=self.__LATEST_NEW_EXPLOIT_ENDPOINT)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response


class NewMalwareURIFeed(TiCloudAPI):
    """TCF-0301"""

    __TIMESTAMP_PULL_ENDPOINT = "/api/feed/malware_uri/v1/query/{time_format}/{time_value}?format=json"
    __PULL_LATEST_ENDPOINT = "/api/feed/malware_uri/v1/query/latest?format=json"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(NewMalwareURIFeed, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def pull_with_timestamp(self, time_format, time_value):
        """Accepts a time format definition and a time value. Returns records with Ps, domains, URLs,
        emails, and sample hashes extracted from malware samples.
        To fetch the next batch of records, use the last_timestamp from the response increased by 1.
        The time value needs to be within the last 365 days.
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :return: response
            :rtype: requests.Response
        """
        if time_format.lower() not in ("timestamp", "utc"):
            raise WrongInputError("time_format parameter mus be one of the following values: 'timestamp', 'utc'.")

        if time_format.lower() == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("If the timestamp time_format is used, time_value parameter must be a Unix "
                                      "timestamp string.")

        elif time_format.lower() == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("If the utc time_format is used, time_value parameter must be written in the "
                                      "YYYY-MM-DDThh:mm:ss format.")

        endpoint = self.__TIMESTAMP_PULL_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def pull_latest(self):
        """Returns a maximum of 1000 latest records with Ps, domains, URLs,
        emails, and sample hashes extracted from malware samples."""
        url = self._url.format(endpoint=self.__PULL_LATEST_ENDPOINT)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response


class NewWhitelistedFiles(TiCloudAPI):
    """TCF-0501"""

    __FEED_ENDPOINT = "/api/feed/whitelisted/v1/query/{time_format}/{time_value}"
    __START_ENDPOINT = "/api/feed/whitelisted/v1/query/start/{time_format}/{time_value}"
    __PULL_ENDPOINT = "/api/feed/whitelisted/v1/query/pull"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(NewWhitelistedFiles, self).__init__(host, username, password, verify, proxies,
                                                  user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def feed_query(self, time_format, time_value, sample_available=False, limit=1000):
        """Returns a list of newly whitelisted samples since the requested time
            :param time_format: possible values: 'timestamp' or 'utc'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are UNIX timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :param limit: the number of records to return in response
            :type limit: int
            :return: response
            :rtype: requests.Response
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("if timestamp is used, time_value needs to be a unix timestamp")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("if utc is used, time_value needs to be in format 'YYYY-MM-DDThh:mm:ss'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'timestamp' or 'utc'")

        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not isinstance(limit, int):
            raise WrongInputError("limit parameter must be int.")

        endpoint = self.__FEED_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        query_params = {
            "sample_available": str(sample_available).lower(),
            "limit": limit,
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def start_query(self, time_format, time_value):
        """Sets the starting timestamp for the pull_query.
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :return: response
            :rtype: requests.Response
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("if timestamp is used, time_value needs to be a unix timestamp")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("if utc is used, time_value needs to be in format 'YYYY-MM-DDThh:mm:ss'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'timestamp' or 'utc'")

        endpoint = self.__START_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        url = self._url.format(endpoint=endpoint)

        response = self._put_request(url=url)

        self._raise_on_error(response)

        return response

    def pull_query(self, sample_available=False, limit=1000):
        """Returns the list of newly whitelisted samples, with the 
        timestamp defined with the start_query
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :param limit: number of records to return in the response
            :type limit: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not isinstance(limit, int):
            raise WrongInputError("limit parameter must be integer.")

        query_params = {
            "sample_available": str(sample_available).lower(),
            "limit": limit,
            "format": "json"
        }

        url = self._url.format(endpoint=self.__PULL_ENDPOINT)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response


class ChangesWhitelistedFiles(TiCloudAPI):
    """TCF-0502"""

    __FEED_ENDPOINT = "/api/feed/whitelisted_change/v1/query/{time_format}/{time_value}"
    __LATEST_ENDPOINT = "/api/feed/whitelisted_change/v1/query/latest"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(ChangesWhitelistedFiles, self).__init__(host, username, password, verify, proxies,
                                                  user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def feed_query(self, time_format, time_value):
        """Returns a list of the samples which changed their whitelist status since requested time
            :param time_format: possible values: 'timestamp' or 'utc'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are UNIX timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :return: response
            :rtype: requests.Response
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("if timestamp is used, time_value needs to be a unix timestamp")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("if utc is used, time_value needs to be in format 'YYYY-MM-DDThh:mm:ss'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'timestamp' or 'utc'")

        endpoint_base = self.__FEED_ENDPOINT.format(
            time_format = time_format,
            time_value = time_value
        )

        endpoint = "{base}?format=json".format(base=endpoint_base)

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def latest_query(self):
        """Returns the 1000 latest samples which changed their whitelist status"""

        endpoint = "{base}?format=json".format(base=self.__LATEST_ENDPOINT)

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response


class ImpHashSimilarity(TiCloudAPI):
    """TCA-0302"""

    __SINGLE_QUERY_ENDPOINT = "/api/imphash_index/v1/query/{hash_value}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(ImpHashSimilarity, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_imphash_index(self, imphash, next_page_sha1=None):
        """Accepts an imphash and returns a list of SHA-1 hashes of files sharing that imphash.
            :param imphash: imphash string
            :type imphash: str
            :param next_page_sha1: SHA-1 string on the next page of results
            :type next_page_sha1: str or None
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(imphash, str):
            raise WrongInputError("imphash parameter must be string.")

        endpoint = self.__SINGLE_QUERY_ENDPOINT.format(hash_value=imphash)

        if next_page_sha1:
            validate_hashes(
                hash_input=[next_page_sha1],
                allowed_hash_types=(SHA1,)
            )

            endpoint = "{base}/start_sha1/{next_page_sha1}".format(
                base=endpoint,
                next_page_sha1=next_page_sha1
            )

        endpoint = "{path}?format=json".format(path=endpoint)

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def get_imphash_index_aggregated(self, imphash, max_results=None):
        """Accepts an imphash and returns a list of SHA-1 hashes of files sharing that imphash.
        This method automatically handles paging and returns a list of results instead of a Response object.
            :param imphash: imphash string
            :type imphash: str
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
       """
        results = []
        next_page_sha1 = None

        while True:
            response = self.get_imphash_index(
                imphash=imphash,
                next_page_sha1=next_page_sha1
            )

            response_json = response.json()

            sha1_list = response_json.get("rl").get("imphash_index").get("sha1_list", [])
            results.extend(sha1_list)

            next_page_sha1 = response_json.get("rl").get("imphash_index").get("next_page_sha1", None)

            if not max_results:
                if not next_page_sha1:
                    return results

            else:
                if not next_page_sha1 or len(results) >= max_results:
                    return results[:max_results]


class YARAHunting(TiCloudAPI):
    """TCA-0303"""

    __RULESET_ENDPOINT = "/api/yara/admin/v1/ruleset"
    __YARA_MATCHES_ENDPOINT = "/api/feed/yara/v1/query/{time_format}/{time_value}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(YARAHunting, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                          allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def create_ruleset(self, ruleset_name, ruleset_text, sample_available=None):
        """Creates a new YARA ruleset.
        The ruleset_text parameter needs to be a stringified YARA ruleset / a Unicode string.
        The sample_available parameter defines which samples will be returned:
            - True: only samples available for download
            - False: only samples not available for download
            - None: all samples
            :param ruleset_name: name of the ruleset
            :type ruleset_name: str
            :param ruleset_text: YARA ruleset text
            :type ruleset_text: str
            :param sample_available: which samples to return
            :type sample_available: bool or None
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(ruleset_name, str):
            raise WrongInputError("ruleset_name parameter must be string.")

        if not isinstance(ruleset_text, str):
            raise WrongInputError("ruleset_text parameter must be unicode string.")

        post_json = {
            "ruleset_name": ruleset_name,
            "text": ruleset_text
        }

        if sample_available is not None:
            if not isinstance(sample_available, bool):
                raise WrongInputError("sample_available parameter must be be either None or boolean.")

            post_json["sample_available"] = sample_available

        url = self._url.format(endpoint=self.__RULESET_ENDPOINT)

        response = self._post_request(url=url, post_json=post_json)

        self._raise_on_error(response)

        return response

    def delete_ruleset(self, ruleset_name):
        """Deletes a YARA ruleset.
            :param ruleset_name: name of the ruleset
            :type ruleset_name: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(ruleset_name, str):
            raise WrongInputError("ruleset_name parameter must be string.")

        endpoint = "{base}/{ruleset_name}".format(
            base=self.__RULESET_ENDPOINT,
            ruleset_name=ruleset_name
        )

        url = self._url.format(endpoint=endpoint)

        response = self._delete_request(url=url)

        self._raise_on_error(response)

        return response

    def get_ruleset_info(self, ruleset_name=None):
        """Get information for a specific YARA ruleset or all YARA rulesets in the collection.
            :param ruleset_name: name of the ruleset; if set to None, all rulesets are returned
            :type ruleset_name: str or None
            :return: response
            :rtype: requests.Response
        """
        endpoint = self.__RULESET_ENDPOINT

        if ruleset_name is not None:
            if not isinstance(ruleset_name, str):
                raise WrongInputError("ruleset_name parameter must be string.")

            endpoint = "{base}/{ruleset_name}".format(
                base=self.__RULESET_ENDPOINT,
                ruleset_name=ruleset_name
            )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def get_ruleset_text(self, ruleset_name):
        """Get the text of a YARA ruleset.
            :param ruleset_name: name of the ruleset
            :type ruleset_name: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(ruleset_name, str):
            raise WrongInputError("ruleset_name parameter must be string.")

        endpoint = "{base}/{ruleset_name}/text".format(
            base=self.__RULESET_ENDPOINT,
            ruleset_name=ruleset_name
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def yara_matches_feed(self, time_format, time_value):
        """Returns a recordset of YARA ruleset matches in the specified time range.
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :return: response
            :rtype: requests.Response
        """
        if time_format not in ("utc", "timestamp"):
            raise WrongInputError("time_format parameter must be one of the following values: 'utc', 'timestamp'")

        if not isinstance(time_value, str):
            raise WrongInputError("time_value parameter must be string.")

        base = self.__YARA_MATCHES_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        endpoint = "{base}?format=json".format(base=base)

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response


class YARARetroHunting(TiCloudAPI):
    """TCA-0319"""

    __RULESET_ENDPOINT = "/api/yara/admin/v1/ruleset"
    __YARA_RETRO_MATCHES_ENDPOINT = "/api/feed/yara/retro/v1/query/{time_format}/{time_value}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(YARARetroHunting, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                               allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def __retro_hunt_action(self, path_suffix, ruleset_name):
        """Private method for retro hunt actions."""
        if not isinstance(ruleset_name, str):
            raise WrongInputError("ruleset_name parameter must be string.")

        if path_suffix in ("enable-retro-hunt", "start-retro-hunt", "cancel-retro-hunt"):
            endpoint = "{base}/{path_suffix}".format(
                base=self.__RULESET_ENDPOINT,
                path_suffix=path_suffix
            )

            post_json = {"ruleset_name": ruleset_name}

            url = self._url.format(endpoint=endpoint)

            response = self._post_request(url=url, post_json=post_json)

        elif path_suffix == "status-retro-hunt":
            endpoint = "{base}/{ruleset_name}/{path_suffix}".format(
                base=self.__RULESET_ENDPOINT,
                ruleset_name=ruleset_name,
                path_suffix=path_suffix
            )

            url = self._url.format(endpoint=endpoint)

            response = self._get_request(url=url)

        else:
            raise WrongInputError("The supplied path_suffix is not valid.")

        self._raise_on_error(response)

        return response

    def enable_retro_hunt(self, ruleset_name):
        """Enables the retro hunt for the specified ruleset that has been submitted to TitaniumCloud
        prior to deployment of YARA retro.
            :param ruleset_name: name of the ruleset
            :type ruleset_name: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__retro_hunt_action(
            path_suffix="enable-retro-hunt",
            ruleset_name=ruleset_name
        )

        return response

    def start_retro_hunt(self, ruleset_name):
        """Starts the retro hunt for the specified ruleset.
            :param ruleset_name: name of the ruleset
            :type ruleset_name: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__retro_hunt_action(
            path_suffix="start-retro-hunt",
            ruleset_name=ruleset_name
        )

        return response

    def check_status(self, ruleset_name):
        """Checks the retro hunt status for the specified ruleset.
            :param ruleset_name: name of the ruleset
            :type ruleset_name: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__retro_hunt_action(
            path_suffix="status-retro-hunt",
            ruleset_name=ruleset_name
        )

        return response

    def cancel_retro_hunt(self, ruleset_name):
        """Cancels the retro hunt for the specified ruleset.
            :param ruleset_name: name of the ruleset
            :type ruleset_name: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__retro_hunt_action(
            path_suffix="cancel-retro-hunt",
            ruleset_name=ruleset_name
        )

        return response

    def yara_retro_matches_feed(self, time_format, time_value):
        """Returns a recordset of YARA ruleset matches in the specified time range.
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :return: response
            :rtype: requests.Response
        """
        if time_format not in ("utc", "timestamp"):
            raise WrongInputError("time_format parameter must be one of the following values: 'utc', 'timestamp'")

        if not isinstance(time_value, str):
            raise WrongInputError("time_value parameter must be string.")

        base = self.__YARA_RETRO_MATCHES_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        endpoint = "{base}?format=json".format(base=base)

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response


class NewMalwarePlatformFiltered(TiCloudAPI):
    """TCF-0102-0106"""

    __FEED_ENDPOINT = "/api/feed/malware/detection/platform/v1/query/{time_format}/{time_value}"
    __START_ENDPOINT = "/api/feed/malware/detection/platform/v1/query/start/{time_format}/{time_value}"
    __PULL_ENDPOINT = "/api/feed/malware/detection/platform/v1/query/pull"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(NewMalwarePlatformFiltered, self).__init__(host, username, password, verify, proxies,
                                                         user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def feed_query(self, time_format, time_value, platforms=None, sample_available=False, limit=1000):
        """Returns a list of malware samples optionally filtered by platform since the requested
        timestamp.
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param platforms: filter the samples by their detected platform value; check the API documentation for
            allowed values; the platforms should be passed as list of strings
            :type platforms: list[str] or None
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :param limit: number of records to return in the response
            :type limit: int
            :return: response
            :rtype: requests.Response
        """
        if time_format not in ("utc", "timestamp"):
            raise WrongInputError("time_format parameter must be one of the following values: 'utc', 'timestamp'")

        if not isinstance(time_value, str):
            raise WrongInputError("time_value parameter must be string.")

        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not isinstance(limit, int):
            raise WrongInputError("limit parameter must be integer.")

        base = self.__FEED_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        query_params = "?sample_available={sample_available}&limit={limit}&format=json".format(
            sample_available=str(sample_available).lower(),
            limit=limit
        )

        if platforms:
            for platform in platforms:
                query_params = query_params + "&platform={platform}".format(platform=platform)

        endpoint = "{base}{query_params}".format(base=base, query_params=query_params)

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def start_query(self, time_format, time_value):
        """Sets the starting timestamp for the pull_query.
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param time_value: results will be retrieved from the specified time up until the current moment;
            accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :return: response
            :rtype: requests.Response
        """
        if time_format not in ("utc", "timestamp"):
            raise WrongInputError("time_format parameter must be one of the following values: 'utc', 'timestamp'")

        if not isinstance(time_value, str):
            raise WrongInputError("time_value parameter must be string.")

        endpoint = self.__START_ENDPOINT.format(
            time_format=time_format,
            time_value=time_value
        )

        url = self._url.format(endpoint=endpoint)

        response = self._put_request(url=url)

        self._raise_on_error(response)

        return response

    def pull_query(self, platforms=None, sample_available=False, limit=1000):
        """Returns the list of malware samples optionally filtered by platform
        since a point in time set by the start_query.
            :param platforms: filter the samples by their detected platform value; check the API documentation for
            allowed values; the platforms should be passed as list of strings
            :type platforms: list[str] or None
            :param sample_available: return only samples available for download
            :type sample_available: bool
            :param limit: number of records to return in the response
            :type limit: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(sample_available, bool):
            raise WrongInputError("sample_available parameter must be boolean.")

        if not isinstance(limit, int):
            raise WrongInputError("limit parameter must be integer.")

        query_params = "?sample_available={sample_available}&limit={limit}&format=json".format(
            sample_available=str(sample_available).lower(),
            limit=limit
        )

        if platforms:
            for platform in platforms:
                query_params = query_params + "&platform={platform}".format(platform=platform)

        endpoint = "{base}{query_params}".format(base=self.__PULL_ENDPOINT, query_params=query_params)

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response


class CustomerUsage(TiCloudAPI):
    """TCA-9999 - Customer Usage"""

    __USAGE = "/api/customer_usage/v1/usage"
    __USAGE_COMPANY = "/api/customer_usage/v1/usage/company"
    __LIMITS = "/api/customer_usage/v1/limits"
    __LIMITS_COMPANY = "/api/customer_usage/v1/limits/company"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(CustomerUsage, self).__init__(host, username, password, verify, proxies,
                                            user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def daily_usage(self, single_date=None, from_date=None, to_date=None,  whole_company=False):
        """Returns information about daily service usage for the TitaniumCloud account that sent the
        request. If the date is not specified in the request, the service returns usage for the current date. The
        users can also specify a from-to time range (in days), to a maximum interval of 365 days.
        If whole_company is set to True, the method will return
        combined daily service usage for all users in the company.
            :param single_date: setting a date string here provides results for only that single date;
            accepted format is 'yyyy-MM-dd'; mutually exclusive with from_date and to_date
            :type single_date: str
            :param from_date: set a start date; accepted format is 'yyyy-MM-dd'; mutually exclusive with single_date
            :type from_date: str
            :param to_date: set an end date; accepted format is 'yyyy-MM-dd'; mutually exclusive with single_date
            :type to_date: str
            :param whole_company: return combined service usage for the whole company
            :type whole_company: bool
            :return: response
            :rtype: requests.Response
        """
        if not whole_company:
            endpoint = self.__USAGE + "/daily"

        else:
            endpoint = self.__USAGE_COMPANY + "/daily"

        if from_date or to_date:
            if single_date:
                raise WrongInputError("single_date can not be used with from_date and to_date.")

            if not (from_date and to_date):
                raise WrongInputError("from_date and to_date need to be used together.")

        query_params = {
            "date": single_date,
            "from": from_date,
            "to": to_date,
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def monthly_usage(self, single_month=None, from_month=None, to_month=None, whole_company=False):
        """Returns information about monthly service usage for the TitaniumCloud account that sent the
        request. If the months are not specified in the request, the service returns usage for the current month.
        The users can also specify a from-to month. If whole_company is set to True,
        the method will return combined monthly service usage for all users in the company.
            :param single_month: setting a month definition string here provides results for that month only;
            accepted format is 'yyyy-MM'; mutually exclusive with from_month and to_month
            :type single_month: str
            :param from_month: set a start month; accepted format is 'yyyy-MM'; mutually exclusive with single_month
            :type from_month: str
            :param to_month: set an end month; accepted format is 'yyyy-MM'; mutually exclusive with single_month
            :type to_month: str
            :param whole_company: return combined service usage for the whole company
            :type whole_company: bool
            :return: response
            :rtype: requests.Response
        """
        if not whole_company:
            endpoint = self.__USAGE + "/monthly"

        else:
            endpoint = self.__USAGE_COMPANY + "/monthly"

        if from_month or to_month:
            if single_month:
                raise WrongInputError("single_month can not be used with from_month and to_month.")

            if not (from_month and to_month):
                raise WrongInputError("from_month and to_month need to be used together.")

        query_params = {
            "month": single_month,
            "from": from_month,
            "to": to_month,
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def date_range_usage(self, whole_company=False):
        """This method returns total usage for all product licenses with a fixed quota over a single date range. Use
        this method for products with quotas that do not reset on a daily or monthly basis. The endpoint
        accepts no additional date specifying parameters, instead always returning total usage for the account
        in question.
            :param whole_company: return combined service usage for the whole company
            :type whole_company: bool
            :return: response
            :rtype: requests.Response
        """
        if not whole_company:
            endpoint = self.__USAGE + "/date_range"

        else:
            endpoint = self.__USAGE_COMPANY + "/date_range"

        query_params = {
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def active_yara_rulesets(self):
        """This method returns information about the number of active YARA rulesets for the TitaniumCloud
        account that sent the request.
            :return: response
            :rtype: requests.Response
        """
        endpoint = self.__USAGE + "/yara"

        query_params = {
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def quota_limits(self, whole_company=False):
        """This method returns current quota limits for API-s accessible to the authenticated user. Products are
        grouped into one object if they share the usage quota and access rights. This means that the same
        users and products can appear multiple times in the response.
            :param whole_company: return combined service usage for the whole company
            :type whole_company: bool
            :return: response
            :rtype: requests.Response
        """
        if not whole_company:
            endpoint = self.__LIMITS

        else:
            endpoint = self.__LIMITS_COMPANY

        query_params = {
            "format": "json"
        }

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response


class NetworkReputation(TiCloudAPI):
    """TCA-0407 - Network Reputation API"""

    __REPUTATION_ENDPOINT = "/api/networking/reputation/v1/query/{post_format}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(NetworkReputation, self).__init__(host, username, password, verify, proxies,
                                                user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_network_reputation(self, network_locations):
        """Returns reputation information about queried URL-, domains and IP addresses.
            :param network_locations: a list of one or more network locations to be queried; possible types of network
            locations are URL-s, IP addresses and domains
            :type network_locations: list[str]
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(network_locations, list):
            raise WrongInputError("network_locations parameter must be a list of strings.")

        locations = []

        for location in network_locations:
            locations.append({"network_location": location})

        post_json = {"rl": {"query": {"network_locations": locations, "response_format": "json"}}}

        endpoint = self.__REPUTATION_ENDPOINT.format(post_format="json")

        url = self._url.format(endpoint=endpoint)

        response = self._post_request(url=url, post_json=post_json)

        self._raise_on_error(response)

        return response


class NetworkReputationUserOverride(TiCloudAPI):
    """TCA-0408 - Network Reputation User Override API"""

    __OVERRIDE_ENDPOINT = "/api/networking/user_override/v1/query/{post_format}"
    __LIST_OVERRIDES_ENDPOINT = "/api/networking/user_override/v1/query/list_overrides"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(NetworkReputationUserOverride, self).__init__(host, username, password, verify, proxies,
                                                            user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def reputation_override(self, override_list=None, remove_overrides_list=None):
        """This method enables two actions in one request:
        1. Send a list of network locations whose classification needs to be overriden
        2. Send a list of network locations whose classification override needs to be removed
            :param override_list: a list of network locations whose classification needs to be overriden;
            format of one object:
            {
                'network_location': 'example_network_location',
                'type': 'network_location_type',
                'classification': 'new_classification',
                'categories': ['list', 'of', 'arbitrary', 'categories']
            }
                'network_location', 'type' and 'classification' are required elements;
                currently the only supported type is 'url'
            :type override_list: list[dict]

            :param remove_overrides_list: a list of network locations whose classification override needs to be removed;
            format of one object:
            {
                'network_location': 'example_network_location',
                'type': 'network_location_type'
            }
                'network_location' and 'type' are  required elements;
                currently the only supported type is 'url'
            :type remove_overrides_list: list[dict]

            :return: response
            :rtype: requests.Response
        """
        if not any((override_list, remove_overrides_list)):
            raise WrongInputError("At least one of the parameters needs to be set.")

        if override_list:
            if not isinstance(override_list, list):
                raise WrongInputError("override_list parameter must be a list of objects")

        else:
            override_list = []

        if remove_overrides_list:
            if not isinstance(remove_overrides_list, list):
                raise WrongInputError("remove_overrides_list parameter must be a list of objects")

        else:
            remove_overrides_list = []

        post_json = {"rl": {"query": {"user_override":
                                          {"override_network_locations": override_list,
                                           "remove_overrides": remove_overrides_list}, "response_format": "json"}}}

        endpoint = self.__OVERRIDE_ENDPOINT.format(post_format="json")

        url = self._url.format(endpoint=endpoint)

        response = self._post_request(url=url, post_json=post_json)

        self._raise_on_error(response)

        return response

    def list_overrides(self, next_page_sha1=None):
        """Returns a list of overrides that the user has made.
            :param next_page_sha1: optional SHA-1 string of the next page of results
            :type next_page_sha1: str
            :return: response
            :rtype: requests.Response
        """
        query_params = {
            "format": "json",
            "next_network_location": next_page_sha1
        }

        url = self._url.format(endpoint=self.__LIST_OVERRIDES_ENDPOINT)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def list_overrides_aggregated(self, max_results=None):
        """Returns a list of overrides that the user has made.
        This method automatically handles paging and returns a list of results instead of a Response object.
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
           :rtype: list
        """
        results = []
        next_page_sha1 = ""

        while True:
            response = self.list_overrides(next_page_sha1=next_page_sha1)

            response_json = response.json()

            overrides_list = response_json.get("rl").get("user_override").get("network_locations", [])
            results.extend(overrides_list)

            next_page_sha1 = response_json.get("rl").get("user_override").get("next_network_location", None)

            if not max_results:
                if not next_page_sha1:
                    return results

            else:
                if not next_page_sha1 or len(results) >= max_results:
                    return results[:max_results]


class MalwareFamilyDetection(TiCloudAPI):
    """TCA-0305 - Malware Family Detection"""

    __SINGLE_QUERY_ENDPOINT = "/api/malware/family/detection/v1/query/{hash_type}/{hash_value}"
    __BULK_QUERY_ENDPOINT = "/api/malware/family/detection/v1/bulk_query/{post_format}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(MalwareFamilyDetection, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                                     allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def get_malware_family(self, hash_type, hash_value):
        """Takes a file hash and returns all malware families to which sample belongs,
        based on the detections from the latest AV scan
            param: hash_type: specifies which hash type will be used in request. Supported values: md5, sha1, sha256
            type: hash_type: str
            param: hash_value: hash of the file for which the user is requesting data
            type: hash_value: str or list[str]
        """
        is_bulk = isinstance(hash_value, list)

        validate_hashes(
            hash_input=hash_value if is_bulk else [hash_value],
            allowed_hash_types=(MD5, SHA1, SHA256)
        )

        if is_bulk:
            post_json = {"rl": {"query": {"hash_type": hash_type.lower(), "hashes": hash_value}}}
               
            endpoint = self.__BULK_QUERY_ENDPOINT.format(post_format="json")

            url = self._url.format(endpoint=endpoint)

            response = self._post_request(url=url, post_json=post_json)

        else:
            endpoint = self.__SINGLE_QUERY_ENDPOINT.format(
                hash_type=hash_type.lower(),
                hash_value=hash_value
            )
            
            url = self._url.format(endpoint=endpoint)

            response = self._get_request(url=url)

        self._raise_on_error(response)

        return response
    

class VerticalFeedsStatistics(TiCloudAPI):
    """
    TCA-0307 - APT Tool and Actor Statistics
    TCA-0308 - Financial Services Malware Statistics
    TCA-0309 - Retail Sector Malware Statistics
    TCA-0310 - Ransomware Statistics 
    TCA-0311 - CVE Statistics
    TCA-0317 - Malware Configuration Statistics
    """

    __API_FEED_ENDPOINT = "/api/feed/malware/detection/family/v2/statistics/category/{category}/{filter}"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(VerticalFeedsStatistics, self).__init__(host, username, password, verify, proxies,
                                                      user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def feed_query(self, category, filter, weeks=0, all_time=False):
        """Provides information about new malware samples detected in TitaniumCloud,
        filtered by category. The service can return a list of malware family names
        newly added to each category, the number of unieque new samples added for each
        malware family in a category, and a list of top 20 malware families per category
            param: category: Corresponds to the verticals feed category the user is requesting to access.
            Only one category can be requested in each query. Note that the response for the 'exploit'
            category contains addional 'scanner_coverage' data not found in other categories.
            Enum: 'financial', 'retail', 'ransomware', 'apt', 'exploit', 'configuration'
            type: category: str
            param: filter: applied to filter data to request. Enum: 'first_seen', 'counts', 'top_list'
            type: filter: str
            param: weeks: specifies the number of weeks for which the data will be returned in response
            type: weeks: int
            param: all_time: Instructs the service to return all available data for the requested category
            type all_time: boolean
        """
        if category not in VERTICAL_FEEDS_CATEGORIES:
            raise WrongInputError("Only the following categories are allowed: {category}".format(
                category=VERTICAL_FEEDS_CATEGORIES))

        if filter.lower() not in ("counts", "top_list", "first_seen"):
            raise WrongInputError("Only the following filters are allowed: 'counts', 'top_list' and 'first_seen'")

        if isinstance(weeks, int):

            if weeks not in range(0, 30):
                raise WrongInputError("The value for weeks can be a number between 0 and 30")

            query_params = {
                "weeks": weeks,
                "format": "json"
            }

            raise WrongInputError("Weeks needs to be provided as integer")

        if all_time:

            query_params = {
                "all_time": "true",
                "format": "json"
            }

        endpoint = self.__API_FEED_ENDPOINT.format(
            category = category,
            filter = filter
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response


class VerticalFeedsSearch(TiCloudAPI):
    """
    TCA-0312 - APT Indicator Search
    TCA-0313 - Financial Services Indicator Search
    TCA-0314 - Retail Sector Indicator Search
    TCA-0315 - Ransomware Search
    TCA-0316 - CVE Search
    TCA-0317 - Malware Configuration Statistics
    TCA-0318 - Malware Configuration Search
    """

    __API_FEED_ENDPOINT = "/api/feed/malware/detection/family/v2/index/family_name/search/{family_name}/from/{time_format}/{time_value}"
    __LATEST_FEED_ENDPOINT = "/api/feed/malware/detection/family/v2/index/family_name/search/{family_name}/latest"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(VerticalFeedsSearch, self).__init__(host, username, password, verify, proxies,
                                                      user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def latest_query(self, family_name, count=100):
        """Provides information about new malware samples from ReversingLabs Targeted
        and Industry-Specific File Indicator Feeds by searching for malware family
        names. Samples are included in the response based on the time when they were
        added to a particular feed.
            param: family_name: Accepts a malware family name or a CVE identifier
            type: family_name: str
            param: count: Optional parameter that specifies the number of hashes to return in the response
            type: count: int
        """
        if not isinstance(family_name, str):
            raise WrongInputError("Provide a malware family name or a CVE identifier. Case-sensitive argument.")

        query_params = {
            "count": count,
            "format": "json"
        }

        endpoint = self.__LATEST_FEED_ENDPOINT.format(
            family_name = family_name
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def feed_query(self, family_name, time_format, time_value, count=100):
        """Provides information about new malware samples from ReversingLabs Targeted
        and Industry-Specific File Indicator Feeds by searching for malware family
        names. Samples are included in the response based on the time when they were
        added to a particular feed.
            param: family_name: Accepts a malware family name or a CVE identifier
            type: family_name: str
            param: time_format: possible values: 'timestamp' or 'utc'
            type: time_format: str
            param: time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            type: time_value: string
            param: count: Optional parameter that specifies the number of hashes to return in the response
            type: count: int
        """
        if time_format == "timestamp":
            try:
                int(time_value)

            except ValueError:
                raise WrongInputError("if timestamp is used, time_value needs to be a unix timestamp")

        elif time_format == "utc":
            try:
                datetime.datetime.strptime(time_value, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                raise WrongInputError("if utc is used, time_value needs to be in format 'YYYY-MM-DDThh:mm:ss'")

        else:
            raise WrongInputError("time_format parameter must be one of the following: 'timestamp' or 'utc'")

        if not isinstance(count, int):
            raise WrongInputError("count parameter must be integer")

        if not isinstance(family_name, str):
            raise WrongInputError("Provide a malware family name or a CVE identifier. Case-sensitive argument.")
        
        query_params = {
            "count": count,
            "format": "json"
        }

        endpoint = self.__API_FEED_ENDPOINT.format(
            family_name=family_name,
            time_format=time_format,
            time_value=time_value
        )

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response 


class TAXIIRansomwareFeed(TiCloudAPI):
    """TCTF-0001"""

    __DISCOVERY_ENDPOINT = "/api/taxii/taxii2/"
    __API_ROOT_ENDPOINT = "/api/taxii/{api_root}/"
    __COLLECTIONS_ENDPOINT = "/api/taxii/{api_root}/collections/"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(TAXIIRansomwareFeed, self).__init__(host, username, password, verify, proxies,
                                                  user_agent=user_agent, allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)
        self._headers["Accept"] = "application/taxii+json;version=2.1"

    def discovery_info(self):
        """Returns the information from the TAXII Server's discovery endpoint.
        The returned info shows the available api roots.
            :return: response
            :rtype: requests.Response
        """
        url = self._url.format(endpoint=self.__DISCOVERY_ENDPOINT)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def __info_endpoints(self, specific_endpoint, api_root):
        """A private method for information TAXII endpoints.
            :param specific_endpoint: specific information endpoint
            :type specific_endpoint: str
            :param api_root: api root name
            :type api_root: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(specific_endpoint, str):
            raise WrongInputError("specific_endpoint parameter must be a string.")

        if not isinstance(api_root, str):
            raise WrongInputError("api_root parameter must be a string.")

        endpoint = specific_endpoint.format(api_root=api_root)

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url)

        self._raise_on_error(response)

        return response

    def api_root_info(self, api_root):
        """Returns information about a specific api root.
            :param api_root: api root name
            :type api_root: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__info_endpoints(
            specific_endpoint=self.__API_ROOT_ENDPOINT,
            api_root=api_root
        )

        return response

    def collections_info(self, api_root):
        """Returns information about available collections in an api root.
            :param api_root: api root name
            :type api_root: str
            :return: response
            :rtype: requests.Response
        """
        response = self.__info_endpoints(
            specific_endpoint=self.__COLLECTIONS_ENDPOINT,
            api_root=api_root
        )

        return response

    def get_objects(self, api_root, collection_id, result_limit=500, added_after=None, match_id=None, page=None):
        """Returns objects from a TAXII collection.
        Results can be filtered using several parameters.
            :param api_root: api root name
            :type api_root: str
            :param collection_id: collection ID
            :type collection_id: str
            :param result_limit: number of returned objects per page
            :type result_limit: int
            :param added_after: timestamp string in the 'YYYY-MM-DDThh:mm:ssZ' format
            :type added_after: str
            :param match_id: return a specific object matching this ID
            :type match_id: str
            :param page: identifier of the requested page
            :type page: str or None
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(result_limit, int):
            raise WrongInputError("result_limit parameter must be an integer.")

        if added_after:
            if not isinstance(added_after, str):
                raise WrongInputError("added_after parameter must be a string.")

        if match_id:
            if not isinstance(match_id, str):
                raise WrongInputError("match_id parameter must be a string.")

        query_params = {
            "limit": result_limit,
            "added_after": added_after,
            "match[id]": match_id,
            "next": page
        }

        endpoint = self.__COLLECTIONS_ENDPOINT.format(api_root=api_root) + collection_id + "/objects/"

        url = self._url.format(endpoint=endpoint)

        response = self._get_request(url=url, params=query_params)

        self._raise_on_error(response)

        return response

    def get_objects_aggregated(self, api_root, collection_id, result_limit=500, added_after=None, max_results=None):
        """Returns objects from a TAXII collection.
        This method does the paging automatically and returns a defined number of objects as a list in the end.
            :param api_root: api root name
            :type api_root: str
            :param collection_id: collection ID
            :type collection_id: str
            :param result_limit: number of returned objects per page; not to be confused with max_results
            :type result_limit: int
            :param added_after: timestamp string in the 'YYYY-MM-DDThh:mm:ssZ' format
            :type added_after: str
            :param max_results: number of results to be returned in the list;
            set as integer to receive a defined number of results or leave as None to receive all available results
            :type max_results: int or None
            :return: list of results
            :rtype: list
        """
        results = []
        next_page = None

        while True:
            response = self.get_objects(
                api_root=api_root,
                collection_id=collection_id,
                result_limit=result_limit,
                added_after=added_after,
                page=next_page
            )

            response_json = response.json()

            objects = response_json.get("objects")
            results.extend(objects)

            next_page = response_json.get("next")
            more_pages = response_json.get("more")

            if not max_results:
                if not more_pages:
                    return results

            else:
                if not more_pages or len(results) >= max_results:
                    return results[:max_results]


def _update_hash_object(input_source, hash_object):
    """Accepts a string or an opened file in 'rb' mode and a created hashlib hash object and
    returns an updated hashlib hash object.
        :param input_source: open file in "rb" mode or string
        :type input_source: str or file or BinaryIO
        :param hash_object: hash object
        :type hash_object: _hashlib._HASH
        :returns: updated hash object
        :rtype: _hashlib.HASH
    """
    if hasattr(input_source, "read"):
        hash_object.update(input_source.read())

    elif isinstance(input_source, str):
        hash_object.update(input_source.encode("utf-8"))

    else:
        raise TypeError("This is not a valid source type: Only string and file opened in 'rb' mode "
                        "are accepted as input source parameters")

    return hash_object


def calculate_hash(data_input, hashing_algorithm):
    """Returns a calculated hash string of a selected hashing algorithm type for a file or string.
        :param data_input: open file in "rb" mode or string
        :type data_input: str or file or BinaryIO
        :param hashing_algorithm: selected hashing algorithm
        :type hashing_algorithm: str
        :returns: hash string
        :rtype: str
    """
    algorithms = {
        MD5: hashlib.md5(),
        SHA1: hashlib.sha1(),
        SHA256: hashlib.sha256(),
        SHA512: hashlib.sha512()
    }

    hash_object = algorithms.get(hashing_algorithm, None)

    if not hash_object:
        allowed = ", ".join(algorithms)
        raise KeyError("Unsupported hashing algorithm specification. "
                       "Only {allowed} can be used.".format(allowed=allowed))

    hash_object = _update_hash_object(data_input, hash_object)
    hash_hex = hash_object.hexdigest()

    return hash_hex


def get_rha1_type(host, username, password, verify, hash_input, allow_none_return):
    """Returns an RHA1 file type string.
        :param host: host string
        :type host: str
        :param username: username
        :type username: str
        :param password: password
        :type password: str
        :param verify: verify SSL certificate
        :type verify: bool
        :param hash_input: sample hash input
        :type hash_input: str
        :param allow_none_return: allow None as return value
        :type allow_none_return: bool
        :returns: RHA1 file type
        :rtype: str
    """
    rldata = FileAnalysis(
        host=host,
        username=username,
        password=password,
        verify=verify
    )

    try:
        file_type = rldata.get_file_type(
            sample_hash=hash_input
        )
    except Exception as error:
        if allow_none_return:
            return None
        else:
            raise NoFileTypeError("There is no determinable file type for this hash. - "
                                  "{error}".format(error=str(error)))

    rha1_type = RHA1_TYPE_MAP.get(file_type, None)
    if not rha1_type:
        raise ValueError("The provided hash belongs to a file type that can not be used in this context: Only the "
                         "following file types can be used: "
                         "{allowed_files}".format(allowed_files=", ".join(RHA1_TYPE_MAP)))

    return rha1_type


def resolve_hash_type(sample_hashes):
    """A method for resolving the hash type from a list of sample hashes.
     The method also checks if all the hashes in the list are of the same type.
     The list can also have only one element.
        :param sample_hashes: hash string or a list of hash strings
        :type sample_hashes: list[str]
        :return: hash type
        :rtype: str
    """
    first_hash_type = HASH_LENGTH_MAP.get(len(sample_hashes[0]))

    for iteration in range(len(sample_hashes) - 1):
        hash_type = HASH_LENGTH_MAP.get(len(sample_hashes[iteration + 1]))

        if hash_type != first_hash_type:
            raise WrongInputError("All hashes in the list must be of the same type. Hash on "
                                  "position {position} is a/an {hash_type} and differs from "
                                  "the first hash, which is a/an {first_hash_type}".format(
                                    position=iteration + 1,
                                    hash_type=hash_type,
                                    first_hash_type=first_hash_type
                                    ))

    return first_hash_type
