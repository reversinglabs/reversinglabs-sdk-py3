"""
author: Mislav Sever

TitaniumCloud
A Python module for the ReversingLabs TitaniumCloud REST API-s.

Copyright (c) ReversingLabs International GmbH. 2016-2021

This unpublished material is proprietary to ReversingLabs International GmbH.. All rights reserved.
Reproduction or distribution, in whole or in part, is forbidden except by express written permission of ReversingLabs International GmbH.
"""

import datetime
import hashlib
import json
import os
import requests

from ReversingLabs.SDK.helper import ADVANCED_SEARCH_SORTING_CRITERIA, DEFAULT_USER_AGENT, HASH_LENGTH_MAP, \
    RESPONSE_CODE_ERROR_MAP, \
    MD5, SHA1, SHA256, SHA512, \
    NoFileTypeError, NotFoundError, WrongInputError, \
    validate_hashes


XML = "xml"
JSON = "json"

CLASSIFICATIONS = ("MALICIOUS", "SUSPICIOUS", "KNOWN", "UNKNOWN")

AVAILABLE_PLATFORMS = ("windows7", "windows10")

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

        if host.startswith("http://"):
            raise WrongInputError("Unsupported protocol definition: "
                                  "TitaniumCloud services can only be used over HTTPS.")
        self._host = self.__format_url(host)

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
    def __format_url(host):
        """Returns a formatted host URL including the protocol prefix.
            :param host: URL string
            :type host: str
            :returns: formatted URL string
            :rtype: str
        """
        if not host.startswith("https://"):
            host = "https://{host}".format(host=host)

        return host

    def _get_request(self, url):
        """A generic GET request method for all ticloud module classes.
            :param url: request URL
            :type url: str
            :return: response
            :rtype: requests.Response
        """
        response = requests.get(
            url=url,
            auth=self._credentials,
            verify=self._verify,
            proxies=self._proxies,
            headers=self._headers
        )

        return response

    def _post_request(self, url, post_json=None, data=None):
        """A generic POST request method for all ticloud module classes.
            :param url: request URL
            :type url: str
            :param post_json: JSON body
            :type post_json: dict
            :param data: data to send
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
        raise exception


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
                raise WrongInputError("Only {classifications} is allowed "
                                      "as the classification input.".format(classifications=CLASSIFICATIONS))

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

    def get_similar_hashes_aggregated(self, hash_input, extended_results=True, classification=None, max_results=5000):
        """ This method accepts a hash string and returns a list of results aggregated throughout the pages.
        A maximum number of desired results can be defined with the 'max_results' parameter.
            :param hash_input: sha1 hash string
            :type hash_input: str
            :param extended_results: show extended response
            :type extended_results: bool
            :param classification: show only results of certain classification
            :type classification: str
            :param max_results: maximum number of results to be returned in the list
            :type max_results: int
            :return: list of results
            :rtype: list
        """
        if not isinstance(max_results, int):
            raise WrongInputError("max_results parameter must be integer.")

        results = []
        next_page_sha1 = None

        while True:
            response = self.get_similar_hashes(
                hash_input=hash_input,
                extended_results=extended_results,
                classification=classification,
                page_sha1=next_page_sha1,
                results_per_page=1000
            )

            response_json = response.json()

            sha1_list = response_json.get("rl").get("group_by_rha1").get("sha1_list", [])
            results.extend(sha1_list)

            next_page_sha1 = response_json.get("rl").get("group_by_rha1").get("next_page_sha1", None)

            if len(results) > max_results or not next_page_sha1:
                break

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

    def get_uri_index_aggregated(self, uri_input, classification=None, max_results=5000):
        """Accepts an email address, URL, DNS name or IPv4 string and returns a response.
        This method returns a list of results aggregated throughout the pages.
        A maximum number of desired results can be defined.
            :param uri_input: email address, URL, DNS name or IPv4 string
            :type uri_input: str
            :param classification: only samples of this classification will be returned
            :type classification: str
            :param max_results: maximum number of results to be returned in the list
            :type max_results: int
            :return: list of results
            :rtype: list
        """
        if not isinstance(max_results, int):
            raise WrongInputError("max_results parameter must be integer.")

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

            if len(results) > max_results or not next_page_sha1:
                break

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

    def search_aggregated(self, query_string, sorting_criteria=None, sorting_order="desc", max_results=5000):
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
            :param max_results: maximum results to be returned in the list; default value is 5000
            :type max_results: int
            :return: list of results
            :rtype: list
        """
        if not isinstance(max_results, int):
            raise WrongInputError("max_results parameter must be integer.")

        results = []
        next_page = 1
        more_pages = True

        while more_pages:
            response = self.search(
                query_string=query_string,
                sorting_criteria=sorting_criteria,
                sorting_order=sorting_order,
                page_number=next_page,
                records_per_page=10000
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


class ExpressionSearch(TiCloudAPI):
    """TCA-0306 - Expression Search with Statistics (Sample Search)"""

    __SINGLE_QUERY_ENDPOINT = "/api/sample/search/download/v1/query/date/{str_date}"

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
            :param date: return results from this date forward
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

        endpoint_base = self.__SINGLE_QUERY_ENDPOINT.format(
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

    def search_aggregated(self, query, date=None, max_results=5000):
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
            :param max_results: maximum results to be returned in the list; default value is 5000
            :type max_results: int
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(max_results, int):
            raise WrongInputError("max_results parameter must be integer.")

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
            if len(results) > max_results:
                break

        return results[:max_results]


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
        Request body format and response format can be defined.
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
            classification = str(classification).upper()
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
                                        analysis_id=None, max_results=5000):
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
            :param max_results: maximum results to be returned in the list
            :type max_results: int
            :return: list of results
            :rtype: list
        """
        if not isinstance(max_results, int):
            raise WrongInputError("max_results parameter must be integer.")

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
                results_per_page=1000
            )

            response_json = response.json()

            files = response_json.get("rl").get("files", [])
            results.extend(files)

            next_page = response_json.get("rl").get("next_page", None)

            if len(results) > max_results or not next_page:
                break

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

    def get_latest_url_analysis_feed_aggregated(self, max_results=5000):
        """Returns the latest URL analyses reports aggregated as list.
        Maximum desired number of results in the list can be defined with the 'max_results' parameter.
            :param max_results: maximum results to be returned in the list
            :type max_results: int
            :return: list of results
            :rtype: list
        """
        if not isinstance(max_results, int):
            raise WrongInputError("max_results parameter must be integer.")

        results = []
        next_page = ""

        while True:
            response = self.get_latest_url_analysis_feed(
                page_string=next_page,
                results_per_page=1000
            )

            response_json = response.json()

            urls = response_json.get("rl").get("urls", [])
            results.extend(urls)

            next_page = response_json.get("rl").get("next_page", None)

            if len(results) > max_results or not next_page:
                break

        return results[:max_results]

    def get_url_analysis_feed_from_date(self, time_format, start_time, page_string=None, results_per_page=1000):
        """Accepts time format and a start time and returns URL analyses reports from that defined time onward.
        A string designating a desired page of results can be provided as an optional parameter.
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param start_time: time from which to retrieve results onwards
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

    def get_url_analysis_feed_from_date_aggregated(self, time_format, start_time, max_results=5000):
        """Accepts time format and a start time and returns URL analyses reports
        from that defined time onward aggregated as a list.
        Maximum desired number of results in the list can be defined with the 'max_results' parameter.
            :param time_format: possible values: 'utc' or 'timestamp'
            :type time_format: str
            :param start_time: time from which to retrieve results onwards
            :type start_time: str
            :param max_results: maximum results to be returned in the list
            :type max_results: int
            :return: list of results
            :rtype: list
        """
        if not isinstance(max_results, int):
            raise WrongInputError("max_results parameter must be integer.")

        results = []
        next_page = ""

        while True:
            response = self.get_url_analysis_feed_from_date(
                time_format=time_format,
                start_time=start_time,
                page_string=next_page,
                results_per_page=1000
            )

            response_json = response.json()

            urls = response_json.get("rl").get("urls", [])
            results.extend(urls)

            next_page = response_json.get("rl").get("next_page", None)

            if len(results) > max_results or not next_page:
                break

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


class FileUpload(TiCloudAPI):
    """TCA-0202 and TCA-0203"""

    __UPLOAD_ENDPOINT = "/api/spex/upload"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(FileUpload, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                         allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def upload_sample_from_path(self, file_path, sample_name=None, sample_domain=None):
        """Accepts a file path string and uploads the desired file to the File Upload API.
            :param file_path: file path string
            :type file_path: str
            :param sample_name: optional name of the sample to be displayed in the cloud
            :type sample_name: str
            :param sample_domain: optional domain string of the sample to be displayed in the cloud
            :type sample_domain: str
            :return: response
            :rtype: requests.Response
        """
        if not isinstance(file_path, str):
            raise WrongInputError("file_path parameter must be integer.")

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
            sample_domain=sample_domain
        )

        return response

    def upload_sample_from_file(self, file_handle, sample_name=None, sample_domain=None):
        """Accepts an open file handle and uploads the desired file to the File Upload API.
            :param file_handle: open file
            :type file_handle: file or BinaryIO
            :param sample_name: optional name of the sample to be displayed in the cloud
            :type sample_name: str
            :param sample_domain: optional domain string of the sample to be displayed in the cloud
            :type sample_domain: str
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
            hashing_algorithm="sha1"
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
            sample_domain=sample_domain
        )

        return response

    def __upload_meta(self, url, sample_name, sample_domain):
        """Private method for setting up and uploading metadata of a sample uploaded to the File Upload API.
            :param url: URL used for sample upload
            :type url: str
            :param sample_name: optional name of the sample to be displayed in the cloud
            :type sample_name: str
            :param sample_domain: optional domain string of the sample to be displayed in the cloud
            :type sample_domain: str
            :return: response
            :rtype: requests.Response
        """
        meta_url = "{url}/meta".format(url=url)

        meta_xml = "<rl><properties><property><name>file_name</name><value>{sample_name}</value></property>" \
                   "</properties><domain>{domain}</domain></rl>".format(domain=sample_domain, sample_name=sample_name)

        response = self._post_request(
            url=meta_url,
            data=meta_xml
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


class DynamicAnalysis(TiCloudAPI):
    """TCA-0207 and TCA-0106"""

    __DETONATE_SAMPLE_ENDPOINT = "/api/dynamic/analysis/analyze/v1/query/json"
    __GET_RESULTS_ENDPOINT = "/api/dynamic/analysis/report/v1/query/sha1"

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):
        super(DynamicAnalysis, self).__init__(host, username, password, verify, proxies, user_agent=user_agent,
                                              allow_none_return=allow_none_return)

        self._url = "{host}{{endpoint}}".format(host=self._host)

    def detonate_sample(self, sample_sha1, platform):
        """Submits a sample available in the cloud for dynamic analysis and returns processing info.
            :param sample_sha1: SHA-1 hash of the sample
            :type sample_sha1: str
            :param platform: desired platform on which the sample will be detonated; see available platforms
            :type platform: str
            :return: response
            :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_sha1],
            allowed_hash_types=(SHA1,)
        )

        if platform not in AVAILABLE_PLATFORMS:
            raise WrongInputError("platform parameter must be one "
                                  "of the following values: {platforms}".format(platforms=AVAILABLE_PLATFORMS))

        url = self._url.format(endpoint=self.__DETONATE_SAMPLE_ENDPOINT)

        post_json = {"rl": {"sha1": sample_sha1, "platform": platform, "response_format": "json"}}

        response = self._post_request(
            url=url,
            post_json=post_json
        )

        self._raise_on_error(response)

        return response

    def get_dynamic_analysis_results(self, sample_hash, latest=False, analysis_id=None):
        """Returns dynamic analysis results for a desired sample.
        The analysis of the selected sample must be finished for the results to be available.
        :param sample_hash: SHA-1 hash of a desired sample
        :type sample_hash: str
        :param latest: return only the latest analysis results
        :type latest: bool
        :param analysis_id: return only the results of this analysis
        :type analysis_id: str
        :return: response
        :rtype: requests.Response
        """
        validate_hashes(
            hash_input=[sample_hash],
            allowed_hash_types=(SHA1,)
        )

        endpoint = "{endpoint_base}/{sample_hash}".format(
            endpoint_base=self.__GET_RESULTS_ENDPOINT,
            sample_hash=sample_hash
        )

        if latest:
            if analysis_id:
                raise WrongInputError("Can not use analysis_id because latest is being used.")

            if str(latest).lower() != "true":
                raise WrongInputError("latest parameter must be boolean.")

            endpoint = "{endpoint}/latest".format(endpoint=endpoint)

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
