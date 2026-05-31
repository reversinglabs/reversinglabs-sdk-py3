import io
import requests

from typing import Union
from time import sleep, time

from ReversingLabs.SDK.helper import DEFAULT_USER_AGENT, WrongInputError, NotFoundError
from ReversingLabs.SDK.ticloud import (FileAnalysis, DynamicAnalysis, FileDownload, YARAHunting, NetworkReputation,
                                       FileReputation, NewMalwareFilesFeed, MWPChangeEventsFeed, NewFilesFirstAndRescan,
                                       NewMalwareURIFeed, URLThreatIntelligence, DataChangeSubscription, AVScanners,
                                       DomainThreatIntelligence)
from ReversingLabs.SDK.a1000 import A1000


class AdvancedActions(object):
    """A class containing advanced and combined actions
    utilizing various different classes."""

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):

        self._conf = {
            "host": host,
            "username": username,
            "password": password,
            "verify": verify,
            "user_agent": user_agent,
            "proxies": proxies,
            "allow_none_return": allow_none_return
        }

        self._MALICIOUS = "MALICIOUS"
        self._SUSPICIOUS = "SUSPICIOUS"

    def enriched_file_analysis(self, sample_hash):
        """Accepts a sample hash and returns a TCA-0104 File Analysis report enriched with a TCA-0106 Dynamic Analysis
        report.
        If a dynamic analysis report does not exist for the given hash,
        the method returns a regular file analysis report.
        If not even a file analysis report exists for the given hash, the method returns an empty dict.
            :param sample_hash: sample hash
            :type sample_hash: str
            :return: file analysis report enriched with dynamic analysis
            :rtype: dict
        """
        rldata_client = FileAnalysis(**self._conf)
        da_client = DynamicAnalysis(**self._conf)

        try:
            rldata_response = rldata_client.get_analysis_results(
                hash_input=sample_hash
            )

        except NotFoundError:
            return {}

        try:
            da_response = da_client.get_dynamic_analysis_results(
                sample_hash=sample_hash
            )

        except NotFoundError:
            return rldata_response.json()

        da_report = da_response.json().get("rl", {}).get("report")
        if da_report:
            rldata_report = rldata_response.json()
            try:
                rldata_report["rl"]["sample"]["dynamic_analysis"]["report"] = da_report
            except KeyError:
                rldata_report["rl"]["sample"]["dynamic_analysis"] = {}
                rldata_report["rl"]["sample"]["dynamic_analysis"]["report"] = da_report

            return rldata_report

        return rldata_response.json()

    def full_file_analysis(self, sample_hash):
        """Combines File Reputation, File Analysis and Dynamic Analysis into one report.
        Returns a combined analysis report whose form depends on the availability of singular analysis reports.
            :param sample_hash: sample hash
            :type sample_hash: str
            :return: combined analysis report
            :rtype: dict
        """
        enriched_report = self.enriched_file_analysis(sample_hash)

        mwp_client = FileReputation(**self._conf)
        resp_json = mwp_client.get_file_reputation(sample_hash).json()

        if enriched_report:
            enriched_report["rl"]["sample"]["sample_reputation"] = resp_json.get("rl").get("malware_presence")

        return enriched_report


    @staticmethod
    def __get_yara_matches(starting_timestamp, current_timestamp, yara_client):
        """Private method for aggregating SHA1 hashes of found YARA matches.
            :param starting_timestamp: Starting time in the integer Unix timestamp format
            :type starting_timestamp: int
            :param current_timestamp: Current time in the integer Unix timestamp format
            :type current_timestamp: int
            :return: List of SHA1 strings
            :rtype: list
        """
        sha1_list = []

        while starting_timestamp < current_timestamp:
            resp = yara_client.yara_matches_feed("timestamp", starting_timestamp)

            entries = resp.json().get("rl", {}).get("feed", {}).get("entries", [])
            starting_timestamp = resp.json().get("rl", {}).get("feed", {}).get("last_timestamp")

            for entry in entries:
                sha1_list.append(entry.get("sha1"))

        return sha1_list

    def download_yara_matches(self, starting_timestamp):
        """Download all YARA matches from the defined timestamp to the current moment.
            :param starting_timestamp: Starting time in the integer Unix timestamp format
            :type starting_timestamp: int
        """
        yara_client = YARAHunting(**self._conf)
        file_dl_client = FileDownload(**self._conf)

        current_timestamp = int(time())

        matches_list = self.__get_yara_matches(starting_timestamp, current_timestamp, yara_client)

        for sha1 in matches_list:
            resp = file_dl_client.download_sample(sha1)

            with open(sha1, "wb") as file_handle:
                file_handle.write(resp.content)

    def email_file_reputation(self, email_hash):
        """This method accepts a hash string of an email file.
        If the email file has graphical attachments, the reputation of those attachments will be taken into account
        when returning the reputation verdict here.
        If at least one attachment is classified as malicious, the returned verdict will be "MALICIOUS".
        If there are no malicious attachments but there are suspicious ones, the returned verdict will be "SUSPICIOUS".
            :param email_hash: Email file hash
            :type email_hash: str
            :return: Reputation verdict
            :rtype: str
        """
        mwp_client = FileReputation(**self._conf)

        mwp_resp_json = mwp_client.get_file_reputation(email_hash).json()
        verdict = mwp_resp_json.get("rl").get("malware_presence").get("status").upper()

        if verdict == self._MALICIOUS:
            return verdict

        else:
            accepted_categories = ("https", "http")
            selected_uris = []

            rldata_client = FileAnalysis(**self._conf)
            net_rep_client = NetworkReputation(**self._conf)

            try:
                file_analysis_json = rldata_client.get_analysis_results(email_hash).json()

            except NotFoundError:
                return verdict

            computer_vision_entries = file_analysis_json.get("rl", {}).get("sample", {}).get("computer_vision_analysis", {}).get("entries", [])

            if computer_vision_entries:
                for entry in computer_vision_entries:
                    for result in entry.get("results", []):
                        if result.get("category") in accepted_categories:
                            selected_uris.append(result.get("value"))

            resp_json = net_rep_client.get_network_reputation(selected_uris).json()

            for entry in resp_json.get("rl", {}).get("entries", []):
                if entry.get("classification", "").upper() == self._MALICIOUS:
                    verdict = self._MALICIOUS
                    return verdict

                elif entry.get("classification", "").upper() == self._SUSPICIOUS:
                    verdict = self._SUSPICIOUS

            return verdict

    def enriched_malware_detection_feed(self, time_format, time_value, extended_reputation_results=False,
                                        sample_available=False, record_limit=1000):
        """Uses: TCF-0101, TCA-0101, TCA-0104
        This method works the same way as the pull_with_timestamp method from the ticloud.NewMalwareFilesFeed class
        but adds File Reputation and File Analysis data to each returned hash.
        Take note that if the feed returns thousands of hashes, this method will take a long time to finish since each
        hash needs to be queried for additional data.
        Also, the resulting dict may end up being very large.
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param extended_reputation_results: return extended File Reputation results
            :type extended_reputation_results: bool
            :param sample_available: get only samples available for download
            :type sample_available: bool
            :param record_limit: max number of records to be returned per page
            :type record_limit: int
            :return: malware detection feed dict
            :rtype: dict
        """
        feed = NewMalwareFilesFeed(**self._conf)
        reputation = FileReputation(**self._conf)
        analysis = FileAnalysis(**self._conf)

        feed_resp = feed.pull_with_timestamp(time_format, time_value, sample_available, record_limit)
        feed_json = feed_resp.json()

        sha1_list = []
        entries_dict = {}

        if feed_json.get("rl", {}).get("malware_detection_feed", {}).get("entries"):
            feed_entries = feed_json.get("rl").get("malware_detection_feed").get("entries")

            for entry in feed_entries:
                sha1_list.append(entry.get("sha1"))

                entries_dict[entry["sha1"]] = entry

            reputation_entries = []
            analysis_entries = []

            for batch_start in range(0, len(sha1_list), 100):
                batch = sha1_list[batch_start:batch_start + 100]

                reputation_json = reputation.get_file_reputation(
                    hash_input=batch,
                    extended_results=extended_reputation_results).json()
                reputation_entries.extend(reputation_json.get("rl", {}).get("entries", []))

                analysis_json = analysis.get_analysis_results(hash_input=batch).json()
                analysis_entries.extend(analysis_json.get("rl", {}).get("entries", []))

            for reputation_entry in reputation_entries:
                entries_dict[reputation_entry["sha1"]]["file_reputation"] = reputation_entry

            for analysis_entry in analysis_entries:
                entries_dict[analysis_entry["sha1"]]["file_analysis"] = analysis_entry

            feed_json["rl"]["malware_detection_feed"]["entries"] = entries_dict

        return feed_json

    def enriched_mwp_change_feed(self, time_format, time_value, extended_reputation_results=False,
                                 sample_available=False, record_limit=1000):
        """Uses: TCF-0111, TCA-0101, TCA-0104
        This method works the same way as the pull_with_timestamp method from the ticloud.MWPChangeEventsFeed class
        but adds File Reputation and File Analysis data to each returned hash.
        Take note that if the feed returns thousands of hashes, this method will take a long time to finish since each
        hash needs to be queried for additional data.
        Also, the resulting dict may end up being very large.
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param extended_reputation_results: return extended File Reputation results
            :type extended_reputation_results: bool
            :param sample_available: get only samples available for download
            :type sample_available: bool
            :param record_limit: max number of records to be returned per page
            :type record_limit: int
            :return: malware presence feed dict
            :rtype: dict
        """
        feed = MWPChangeEventsFeed(**self._conf)
        reputation = FileReputation(**self._conf)
        analysis = FileAnalysis(**self._conf)

        feed_resp = feed.pull_with_timestamp(time_format, time_value, sample_available, record_limit)
        feed_json = feed_resp.json()

        sha1_list = []
        entries_dict = {}

        if feed_json.get("rl", {}).get("mwp_change_events_feed", {}).get("entries"):
            feed_entries = feed_json.get("rl").get("mwp_change_events_feed").get("entries")

            for entry in feed_entries:
                sha1_list.append(entry.get("sha1"))

                entries_dict[entry["sha1"]] = entry

            reputation_entries = []
            analysis_entries = []

            for batch_start in range(0, len(sha1_list), 100):
                batch = sha1_list[batch_start:batch_start + 100]

                reputation_json = reputation.get_file_reputation(
                    hash_input=batch,
                    extended_results=extended_reputation_results).json()
                reputation_entries.extend(reputation_json.get("rl", {}).get("entries", []))

                analysis_json = analysis.get_analysis_results(hash_input=batch).json()
                analysis_entries.extend(analysis_json.get("rl", {}).get("entries", []))

            for reputation_entry in reputation_entries:
                entries_dict[reputation_entry["sha1"]]["file_reputation"] = reputation_entry

            for analysis_entry in analysis_entries:
                entries_dict[analysis_entry["sha1"]]["file_analysis"] = analysis_entry

            feed_json["rl"]["malware_detection_feed"]["entries"] = entries_dict

        return feed_json

    def enriched_new_files_feed(self, time_format, time_value, extended_reputation_results=False,
                                latest_dynamic_analysis=True, sample_available=False, record_limit=1000):
        """Uses: TCF-0108, TCA-0101, TCA-0104, TCA-0106
        This method works the same way as the feed_query method from the ticloud.NewFilesFirstAndRescan class
        but adds File Reputation, File Analysis and Dynamic Analysis data to each returned hash. In case the
        Dynamic Analysis report is not available for a hash, it will be omitted.
        Take note that if the feed returns thousands of hashes, this method will take a long time to finish since each
        hash needs to be queried for additional data.
        Also, the resulting dict may end up being very large.
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param extended_reputation_results: return extended File Reputation results
            :type extended_reputation_results: bool
            :param latest_dynamic_analysis: return latest Dynamic Analysis results
            :type latest_dynamic_analysis: bool
            :param sample_available: get only samples available for download
            :type sample_available: bool
            :param record_limit: max number of records to be returned per page
            :type record_limit: int
            :return: new files feed dict
            :rtype: dict
        """
        feed = NewFilesFirstAndRescan(**self._conf)
        reputation = FileReputation(**self._conf)
        analysis = FileAnalysis(**self._conf)
        dynamic = DynamicAnalysis(**self._conf)

        feed_resp = feed.feed_query(time_format, time_value, sample_available, record_limit)
        feed_json = feed_resp.json()

        sha1_list = []
        entries_dict = {}

        if feed_json.get("rl", {}).get("malware_scan_feed", {}).get("entries"):
            feed_entries = feed_json.get("rl").get("malware_scan_feed").get("entries")

            for entry in feed_entries:
                sha1_list.append(entry.get("sha1"))

                entries_dict[entry["sha1"]] = entry

            reputation_entries = []
            analysis_entries = []

            for batch_start in range(0, len(sha1_list), 100):
                batch = sha1_list[batch_start:batch_start + 100]

                reputation_json = reputation.get_file_reputation(
                    hash_input=batch,
                    extended_results=extended_reputation_results).json()
                reputation_entries.extend(reputation_json.get("rl", {}).get("entries", []))

                analysis_json = analysis.get_analysis_results(hash_input=batch).json()
                analysis_entries.extend(analysis_json.get("rl", {}).get("entries", []))

            for reputation_entry in reputation_entries:
                entries_dict[reputation_entry["sha1"]]["file_reputation"] = reputation_entry

            for analysis_entry in analysis_entries:
                entries_dict[analysis_entry["sha1"]]["file_analysis"] = analysis_entry

            for sha1 in sha1_list:
                try:
                    dynamic_json = dynamic.get_dynamic_analysis_results(sample_hash=sha1, latest=latest_dynamic_analysis).json()

                except NotFoundError:
                    continue

                entries_dict[sha1]["dynamic_analysis"] = dynamic_json.get("rl", {}).get("report")

            feed_json["rl"]["malware_detection_feed"]["entries"] = entries_dict

        return feed_json

    def enriched_network_iocs_feed_url_report(self, time_format, time_value):
        """Uses: TCF-0301, TCA-0403
        This method works the same way as the pull_with_timestamp method from the ticloud.NewMalwareURIFeed class
        but adds URL Threat Intelligence data to each returned URL.
        Take note that if the feed returns thousands of results, this method will take a long time to finish since each
        URL needs to be queried for additional data.
        Also, the resulting dict may end up being very large.
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :return: network IoCs feed dict
            :rtype: dict
        """
        feed = NewMalwareURIFeed(**self._conf)
        intel = URLThreatIntelligence(**self._conf)

        feed_resp = feed.pull_with_timestamp(time_format, time_value)
        feed_json = feed_resp.json()

        url_list = []
        entries_dict = {}

        if feed_json.get("rl", {}).get("malware_uri_feed", {}).get("entries"):
            feed_entries = feed_json.get("rl").get("malware_uri_feed").get("entries")

            for entry in feed_entries:
                url_list.append(entry.get("uri"))

                entries_dict[entry["uri"]] = entry

            report_entries = []

            for batch_start in range(0, len(url_list), 100):
                batch = url_list[batch_start:batch_start + 100]

                report_json = intel.get_url_report(url_input=batch).json()
                report_entries.extend(report_json.get("rl", {}).get("entries", []))

            for report_entry in report_entries:
                entries_dict[report_entry["requested_url"]]["url_report"] = report_entry

            feed_json["rl"]["malware_uri_feed"]["entries"] = entries_dict

        return feed_json

    def enriched_data_change_feed(self, time_format, time_value, events=None):
        """Uses: TCA-0206, TCA-0101, TCA-0103, TCA-0106
        This method works the same way as the continuous_data_change_feed method from the
        ticloud.DataChangeSubscription class but adds File Reputation, AV Scanner and Dynamic Analysis report data to
        each returned sample that had such data changes noted in the feed.
        Take note that if the feed returns thousands of results, this method will take a long time to finish since each
        sample needs to be queried for additional data.
        Also, the resulting dict may end up being very large.
            :param time_format: time format definition; possible values are 'timestamp' and 'utc'
            :type time_format: str
            :param time_value: time value string; accepted formats are Unix timestamp string and 'YYYY-MM-DDThh:mm:ss'
            :type time_value: str
            :param events: list of sections that will be included in the response; leaving it as None
            will return all available sections
            :type events: list[str]
            :return: data change feed dict
            :rtype: dict
        """
        feed = DataChangeSubscription(**self._conf)
        reputation = FileReputation(**self._conf)
        scanners = AVScanners(**self._conf)
        dynamic = DynamicAnalysis(**self._conf)

        feed_resp = feed.continuous_data_change_feed(time_format, time_value, events)
        feed_json = feed_resp.json()

        if feed_json.get("rl", {}).get("data_change_feed", {}).get("entries"):
            feed_entries = feed_json.get("rl").get("data_change_feed").get("entries")

            reputation_candidates = []
            scanners_candidates = []
            dynamic_candidates = []

            reputation_entries = []
            scanners_entries = []

            entries_dict = {}

            for entry in feed_entries:
                entries_dict[entry["sha1"]] = entry

                for section in entry.get("updated_sections", []):
                    if section == "xref":
                        scanners_candidates.append(entry.get("sha1"))

                    if section == "malware_presence":
                        reputation_candidates.append(entry.get("sha1"))

                    if section == "dynamic_analysis":
                        dynamic_candidates.append(entry.get("sha1"))

            for batch_start in range(0, len(reputation_candidates), 100):
                batch = reputation_candidates[batch_start:batch_start + 100]

                reputation_json = reputation.get_file_reputation(hash_input=batch).json()
                reputation_entries.extend(reputation_json.get("rl", {}).get("entries", []))

            for reputation_entry in reputation_entries:
                entries_dict[reputation_entry["sha1"]]["file_reputation"] = reputation_entry

            for batch_start in range(0, len(scanners_candidates), 100):
                batch = scanners_candidates[batch_start:batch_start + 100]

                scanners_json = scanners.get_scan_results(hash_input=batch).json()
                scanners_entries.extend(scanners_json.get("rl", {}).get("samples", []))

            for scanners_entry in scanners_entries:
                entries_dict[scanners_entry["sha1"]]["av_scanners"] = scanners_entry

            for sha1 in dynamic_candidates:
                try:
                    dynamic_json = dynamic.get_dynamic_analysis_results(sample_hash=sha1, latest=True).json()

                except NotFoundError:
                    continue

                entries_dict[sha1]["dynamic_analysis"] = dynamic_json.get("rl", {}).get("report")

            feed_json["rl"]["data_change_feed"]["entries"] = entries_dict

        return feed_json


class SpectraAssureClient(object):
    def __init__(self, host, token, organization, group, user_agent=DEFAULT_USER_AGENT, verify=True):
        self._host = host
        self._headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": user_agent
        }
        self._organization = organization
        self._group = group
        self._verify = verify

    def submit_package(self, file, filename, project, package, version):
        url = f"{self._host}/api/public/v1/scan/{self._organization}/{self._group}/pkg:rl/{project}/{package}@{version}"

        if isinstance(file, str):
            file_handle = open(file, "rb")

        elif isinstance(file, bytes) or isinstance(file, io.IOBase):
            file_handle = file

        else:
            raise WrongInputError(f"The file parameter must either be {str}, {bytes} or {io.IOBase} type.")

        self._headers["Content-Disposition"] = f"attachment; filename={filename}"
        self._headers["Content-Type"] = "application/octet-stream"

        response = requests.post(
            url=url,
            headers=self._headers,
            data=file_handle,
            verify=self._verify
        )

        if hasattr(file_handle, "read"):
            file_handle.close()

        return response

    def get_analysis_status(self, project, package, version):
        url = (f"{self._host}/api/public/v1/status/{self._organization}/{self._group}/"
               f"pkg:rl/{project}/{package}@{version}")

        response = requests.get(
            url=url,
            headers=self._headers,
            verify=self._verify
        )

        return response

    def get_analysis_report(self, report_type, project, package, version):
        url = (f"{self._host}/api/public/v1/report/{self._organization}/{self._group}/{report_type}/"
               f"pkg:rl/{project}/{package}@{version}")

        response = requests.get(
            url=url,
            headers=self._headers,
            verify=self._verify
        )

        return response


class SpectraAssureScenarios(object):
    """A class for scenarios that include RL Spectra Assure and other RL services from the RLSDK."""

    def __init__(self, spectra_assure_client: SpectraAssureClient, verify_certs=True):
        self._spectra_assure_client = spectra_assure_client
        self.verify_certs = verify_certs

    def __fetch_and_upload_to_assure(self, client: Union[A1000, FileDownload], file_hash, project,
                                     starting_version, max_version):
        file_content = client.download_sample(file_hash).content
        status_code = 409

        starting_version = int(starting_version * 10)
        max_version = int(max_version * 10)

        current_version = starting_version

        while status_code == 409:
            if current_version > max_version:
                break

            response = self._spectra_assure_client.submit_package(
                file=file_content,
                filename=file_hash,
                project=project,
                package=f"package-{file_hash}",
                version=float(current_version / 10)
            )

            status_code = response.status_code
            current_version += 1

        return float((current_version - 1) / 10)

    def __get_report_from_assure(self, file_hash, report_type, project, current_version, max_retries=6):
        if max_retries > 30:
            raise WrongInputError("Maximum number of fetch retries exceeded.")

        not_done = "version that is not done with analysis"

        response = self._spectra_assure_client.get_analysis_report(
            report_type=report_type,
            project=project,
            package=f"package-{file_hash}",
            version=current_version
        )

        retry_attempt = 1

        while not_done in response.text and retry_attempt <= max_retries:
            sleep(3)

            response = self._spectra_assure_client.get_analysis_report(
                report_type=report_type,
                project=project,
                package=f"package-{file_hash}",
                version=current_version
            )

            retry_attempt += 1

        return response

    def a1000_upload_to_assure(self, a1000_host, a1000_token, hash_list, project, starting_version=1.0, max_version=12.0,
                               get_analysis_report=False, report_type=None, max_retries=6) -> dict:
        """Fetches a list of samples defined in the hash_list from Spectra Analyze and
        submits them to Spectra Assure for analysis.
        Since Spectra Assure requires specifying the version of the sample (package),
        this method tries increasing the version of each sample from the list until it reaches
        a version that does not exist yet.
        You can specify the starting version and the maximum version to try with before backing off for
        the sample that is currently being uploaded.
            :param a1000_host: host of the desired Spectra Analyze instance, including the protocol prefix
            :type a1000_host: str
            :param a1000_token: authorization token of your Spectra Analyze account
            :type a1000_token: str
            :param hash_list: list containing the hashes of samples you want to upload to Spectra Assure
            :type hash_list: list[str]
            :param project: project name on Spectra Assure
            :type project: str
            :param starting_version: the starting version to try with for the current sample that is being uploaded
            :type starting_version: float
            :param max_version: the maximum version to try with before backing off for the current sample
            that is being uploaded
            :type max_version: float
            :param get_analysis_report: fetch the analysis report from Spectra Assure
            :type get_analysis_report: bool
            :param report_type: type of report to fetch
            :type report_type: str
            :param max_retries: maximum number of retries while trying to fetch the report before backing off
            :type max_retries: int
            :return: a dict of analysis reports
            :rtype: dict
        """
        if max_version > 12:
            raise WrongInputError("The max_version can not be higher than 12.")

        a1000_client = A1000(
            host=a1000_host,
            token=a1000_token,
            user_agent=DEFAULT_USER_AGENT,
            verify=self.verify_certs
        )

        reports = {}

        for file_hash in hash_list:
            current_version = self.__fetch_and_upload_to_assure(
                client=a1000_client,
                file_hash=file_hash,
                project=project,
                starting_version=starting_version,
                max_version=max_version
            )

            if get_analysis_report:
                response = self.__get_report_from_assure(
                    file_hash=file_hash,
                    report_type=report_type,
                    project=project,
                    current_version=current_version,
                    max_retries=max_retries
                )

                reports[file_hash] = response.json()

        return reports

    def ticloud_upload_to_assure(self, ticloud_host, ticloud_username, ticloud_password, hash_list, project,
                                 starting_version=1, max_version=12, get_analysis_report=False, report_type=None,
                                 max_retries=6) -> dict:
        """Fetches a list of samples defined in the hash_list from Spectra Intelligence and
        submits them to Spectra Assure for analysis.
        Since Spectra Assure requires specifying the version of the sample (package),
        this method tries increasing the version of each sample from the list until it reaches
        a version that does not exist yet.
        You can specify the starting version and the maximum version to try with before backing off for
        the sample that is currently being uploaded.
            :param ticloud_host: Spectra Intelligence host name
            :type ticloud_host: str
            :param ticloud_username: your Spectra Intelligence username
            :type ticloud_username: str
            :param ticloud_password: your Spectra Intelligence password
            :type ticloud_password: str
            :param hash_list: list containing the hashes of samples you want to upload to Spectra Assure
            :type hash_list: list[str]
            :param project: project name on Spectra Assure
            :type project: str
            :param starting_version: the starting version to try with for the current sample that is being uploaded
            :type starting_version: float
            :param max_version: the maximum version to try with before backing off for the current sample
            that is being uploaded
            :type max_version: float
            :param get_analysis_report: fetch the analysis report from Spectra Assure
            :type get_analysis_report: bool
            :param report_type: type of report to fetch
            :type report_type: str
            :param max_retries: maximum number of retries while trying to fetch the report before backing off
            :type max_retries: int
            :return: a dict of analysis reports
            :rtype: dict
        """
        download_client = FileDownload(
            host=ticloud_host,
            username=ticloud_username,
            password=ticloud_password,
            user_agent=DEFAULT_USER_AGENT,
            verify=self.verify_certs
        )

        reports = {}

        for file_hash in hash_list:
            current_version = self.__fetch_and_upload_to_assure(
                client=download_client,
                file_hash=file_hash,
                project=project,
                starting_version=starting_version,
                max_version=max_version
            )

            if get_analysis_report:
                response = self.__get_report_from_assure(
                    file_hash=file_hash,
                    report_type=report_type,
                    project=project,
                    current_version=current_version,
                    max_retries=max_retries
                )

                reports[file_hash] = response.json()

        return reports
