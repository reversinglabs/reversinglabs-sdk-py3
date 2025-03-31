import io
import requests

from typing import Union
from time import sleep

from ReversingLabs.SDK.helper import DEFAULT_USER_AGENT, WrongInputError
from ReversingLabs.SDK.ticloud import FileAnalysis, DynamicAnalysis, FileDownload
from ReversingLabs.SDK.a1000 import A1000


class AdvancedActions(object):
    """A class containing advanced and combined actions
    utilizing various different classes."""

    def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT,
                 allow_none_return=False):

        self._rldata_client = FileAnalysis(
            host=host,
            username=username,
            password=password,
            verify=verify,
            user_agent=user_agent,
            proxies=proxies,
            allow_none_return=allow_none_return
        )

        self._da_client = DynamicAnalysis(
            host=host,
            username=username,
            password=password,
            verify=verify,
            user_agent=user_agent,
            proxies=proxies,
            allow_none_return=allow_none_return
        )

    def enriched_file_analysis(self, sample_hash):
        """Accepts a sample hash and returns a TCA-0104 File Analysis report enriched with a TCA-0106 Dynamic Analysis
        report.
            :param sample_hash: sample hash
            :type sample_hash: str
            :return: file analysis report enriched with dynamic analysis
            :rtype: dict
        """
        da_response = self._da_client.get_dynamic_analysis_results(
            sample_hash=sample_hash
        )

        rldata_response = self._rldata_client.get_analysis_results(
            hash_input=sample_hash
        )

        da_report = da_response.json().get("rl", {}).get("report")
        if da_report:
            rldata_report = rldata_response.json()
            try:
                rldata_report["rl"]["sample"]["dynamic_analysis"]["report"] = da_report
            except KeyError:
                rldata_report["rl"]["sample"]["dynamic_analysis"] = {}
                rldata_report["rl"]["sample"]["dynamic_analysis"]["report"] = da_report

            return rldata_report

        return {}


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
