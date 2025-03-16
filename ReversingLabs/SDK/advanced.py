import io

import requests

from ReversingLabs.SDK.helper import DEFAULT_USER_AGENT, WrongInputError
from ReversingLabs.SDK.ticloud import FileAnalysis, DynamicAnalysis, AdvancedSearch, FileDownload
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


class SpectraAssureScenarios(object):
    """A class for scenarios that include RL Spectra Assure and other RL services from the RLSDK."""

    def __init__(self, spectra_assure_client, verify_certs=True):

        self._spectra_assure_client = spectra_assure_client
        self.verify_certs = verify_certs

    def a1000_upload_to_assure(self, a1000_host, a1000_token, file_hash, filename, project, package, version):
        a1000_client = A1000(
            host=a1000_host,
            token=a1000_token,
            user_agent=DEFAULT_USER_AGENT,
            verify=self.verify_certs
        )

        file_content = a1000_client.download_sample(sample_hash=file_hash).content

        response = self._spectra_assure_client.submit_package(
            file=file_content,
            filename=filename,
            project=project,
            package=package,
            version=version
        )

        return response

    def ticloud_upload_to_assure(self, ticloud_host, ticloud_username, ticloud_password, file_hash, filename, project,
                                 package, version):
        download_client = FileDownload(
            host=ticloud_host,
            username=ticloud_username,
            password=ticloud_password,
            user_agent=DEFAULT_USER_AGENT,
            verify=self.verify_certs
        )

        file_content = download_client.download_sample(hash_input=file_hash).content

        response = self._spectra_assure_client.submit_package(
            file=file_content,
            filename=filename,
            project=project,
            package=package,
            version=version
        )

        return response


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




