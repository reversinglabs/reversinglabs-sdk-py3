![ReversingLabs](https://raw.githubusercontent.com/reversinglabs/reversinglabs-sdk-py3/master/logo.jpg)

# ReversingLabsSDK

A Python SDK for ReversingLabs REST services (TitaniumCloud and appliances) - Python 3 version.

The idea behind this SDK is to enable easier out-of-the-box development of software integrations and automation services that need to interact with ReversingLabs.

The SDK consists of several modules, where each module represents either one ReversingLabs service, ReversingLabs appliance or the ReversingLabs TitaniumCloud.


## Module: a1000
A Python module representing the ReversingLabs A1000 malware analysis platform.
#### Class:
```python
class A1000(object)
def __init__(self, host, username, password, token, fields_v2, ticore_fields, wait_time_seconds, retries, verify, proxies, user_agent):
```

#### Parameters:
`host` - A1000 address  
`username` - A1000 username  
`password` - A1000 password  
`token` - A1000 user token for the REST API  
`fields_v2` - optional fields that will be returned in the analysis report  
`ticore_fields` - optional fields that will be returned in the report from the TitaniumScale endpoint  
`wait_time_seconds` - wait time between each report fetching retry  
`retries` - number of report fetching retries  
`verify` - verify SSL certificate  
`proxies` - optional proxies in use  
`user_agent` - optional user agent string  

> *NOTE!*  
The default means of authorization on the ReversingLabs A1000 REST API is the token.  
If username and password are used instead, a token fetching request will be done so the token can be used in further actions without the user explicitly providing the token. 

#### Class methods:
- `configuration_dump`
    - Returns the configuration of the instantiated A1000 object
- `test_connection`
    - Creates a request towards the A1000 Check Status API to test the connection with A1000
- `upload_sample_from_path`
    - Accepts a file path string and returns a response containing the analysis task ID
- `upload_sample_from_file`
    - Accepts a file open in 'rb' mode and returns a response containing the analysis task ID
- `upload_sample_from_url`
    - Accepts a url and returns a response containing the analysis task ID
- `check_submitted_url_status`
    - Accepts a task id returned by upload_sample_from_url and returns a response containing processing status and 
        report if the report is ready
- `get_submitted_url_report`
    - Accepts a task ID returned by upload_sample_from_url and returns a response
    - This method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready
- `upload_sample_from_url_and_get_report`
    - Accepts a url and returns a response containing the analysis report
    - The result fetching action of this method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready
- `get_summary_report_v2`
  - Accepts a single hash or a list of hashes and returns JSON containing a summary report for each of them
  -  This method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready
- `upload_sample_and_get_summary_report_v2`
  - Accepts either a file path string or an open file in 'rb' mode for file upload and returns a summary analysis
        report response
  - This method combines uploading a sample and obtaining the summary analysis report
  - The result fetching action of this method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready
- `get_detailed_report_v2`
  - Accepts a single hash or a list of hashes and returns a detailed analysis report for the selected samples
  - This method utilizes the set number of retries and wait time in seconds and times out if the
        analysis results are not ready
- `get_classification_v3`
  - Get classification for one sample
- `reanalyze_samples_v2`
  - Accepts a single hash or a list of hashes of various types and reanalyzes the corresponding sample(s)
  - This method can be used for reanalyzing a single sample or a batch of samples, depending on the data type
        passed
- `list_extracted_files_v2`
  - Get a list of all files TitaniumCore engine extracted from the requested sample during static analysis
- `list_extracted_files_v2_aggregated`
  - Get a list of all files TitaniumCore engine extracted from the requested sample during static analysis
  - Paging is done automatically and results from individual responses aggregated into one list and returned
- `download_extracted_files`
    - Accepts a single hash string and returns a downloadable archive file containing files extracted from the desired sample
- `download_sample`
    - Accepts a single hash string and returns a downloadable sample
- `delete_samples`
    - Accepts a single hash string or a list of hashes and deletes the corresponding samples from A1000
- `check_sample_removal_status_v2`
  - "Accepts the task ID returned by the bulk sample removal endpoint and returns a response that
        indicates if the removal request was finished successfully and if all samples have been deleted
- `create_pdf_report`
  - Accepts a single hash string and initiates the creation of a PDF analysis report for the requested sample.
        The response includes links to the pdf creation status endpoint and pdf download ednpoint for the requested
        sample
- `check_pdf_report_creation`
  - Accepts a single hash string that should correspond to the hash used in the request with
        create_pdf_report method. The response includes an informative message about the status of the PDF
        report previously requested
- `download_pdf_report`
  - Accepts a single hash string that should correspond to the hash used in the request with
        create_pdf_report method
- `get_titanium_core_report_v2`
  - Accepts a single hash string and gets the full TitaniumCore static analysis report for the requested sample.
        The requested sample must be present on the appliance. If the optional fields parameter is not provided in the
        request, all available parts of the static analysis report are returned in the response
- `create_dynamic_analysis_report`
  - Accepts a single hash string and initiates the creation of PDF or HTML reports for samples that have gone
        through dynamic analysis in the ReversingLabs Cloud Sandbox.
        The response includes links to the report creation status endpoint and report download ednpoint for the
        requested sample
- `check_dynamic_analysis_report_status`
  - Accepts a single hash string and report format parameters that should correspond to the parameters used in
        the request with create_dynamic_analysis_report method. The response includes an informative
        message about the status of the report previously requested
- `download_dynamic_analysis_report`
  - Accepts a single hash string and report format parameters that should correspond to the parameters used in
        the request with create_dynamic_analysis_report method
- `set_classification`
  - Accepts a single hash string, allows the user to set the classification of a sample, either in TitaniumCloud
        or locally on the A1000. Returns a response containing a new classification
- `delete_classification`
  - Accepts a single hash string, allows the user to delete the classification of a sample, either in
        TitaniumCloud or locally on the A1000
- `get_user_tags`
  - Accepts a single hash string and returns lists of existing user tags for the requested sample
- `post_user_tags`
  - Accepts a single hash string and adds one or more user tags to the requested sample
- `delete_user_tags`
  - Accepts a single hash string and removes one or more user tags from the requested sample
- `get_yara_rulesets_on_the_appliance_v2`
  - Retrieves a list of YARA rulesets that are on the A1000 appliance
  - The list can be filtered by several criteria (ruleset status, source, and owner) using optional parameters
- `get_yara_ruleset_contents`
  - Retrieves the full contents of the requested ruleset in raw text/plain format
  - All rulesets can be retrieved, regardless of their current status on the appliance (enabled, disabled…)
- `get_yara_ruleset_matches_v2`
  - Retrieves the list of YARA matches (both local and cloud) for requested rulesets
  - If multiple rulesets are provided in the request, only the samples that match all requested rulesets are listed in
        the response.
- `create_or_update_yara_ruleset`
  - Creates a new YARA ruleset if it doesn’t exist
  - If a ruleset with the specified name already exists, a new revision (update) of the ruleset is created
- `delete_yara_ruleset`
  - Deletes the specified YARA ruleset and its matches from the appliance
- `enable_or_disable_yara_ruleset`
  - Enables/disables ruleset on the appliance
  - Administrators can manage any ruleset while regular A1000 users can only manage their own rulesets
- `get_yara_ruleset_synchronization_time`
  - Gets information about the current synchronization status for TitaniumCloud-enabled rulesets
- `update_yara_ruleset_synchronization_time`
  - Updates the TitaniumCloud synchronization time for TitaniumCloud-enabled YARA rulesets
- `start_or_stop_yara_local_retro_scan`
  - Allows users to initiate the Local Retro scan on the A1000 appliance, and stop the Local Retro scan that is
        in progress on the appliance
- `get_yara_local_retro_scan_status`
  - Gets the status of Local Retro scan on the A1000 appliance
- `start_or_stop_yara_cloud_retro_scan`
  - Allows users to start and stop a Cloud Retro scan for a specified ruleset on the A1000 appliance, as well as
        to clear all Cloud Retro results for the ruleset
- `get_yara_cloud_retro_scan_status`
  - Gets the status of Cloud Retro for the specified YARA ruleset. The response indicates the
        current state of Cloud Retro       
- `advanced_search_v3`
  - Sends a query string to the A1000 Advanced Search API v3
- `advanced_search_v3_aggregated`
  - Sends a query string to the A1000 Advanced Search API v3
  - Paging is done automatically and results from individual
        responses aggregated into one list and returned
- `list_containers_for_hashes`
  - Gets a list of all top-level containers from which the requested sample has been extracted during analysis
  - This is a bulk API, meaning that a single request can be used to simultaneously query containers for multiple
        file hashes
- `network_url_report`
  - Accepts a URL string and returns a report about the requested URL
- `network_domain_report`
  - Accepts a domain string and returns a report about the requested domain
- `network_ip_addr_report`
  - Accepts an IP address string and returns a report about the requested IP address
- `network_ip_to_domain`
  - Accepts an IP address string and returns a list of IP-to-domain mappings
- `network_ip_to_domain_aggregated`
  - Accepts an IP address string and returns a list of IP-to-domain mappings. 
  - This method performs the paging automatically and returns a specified maximum number of records
- `network_urls_from_ip`
  - Accepts an IP address string and returns a list of URLs hosted on the requested IP address
- `network_urls_from_ip_aggregated`
  - Accepts an IP address string and returns a list of URLs hosted on the requested IP address
  - This method performs the paging automatically and returns a specified maximum number of records
- `network_files_from_ip`
  - Accepts an IP address string and returns a list of hashes and classifications for files found on the requested IP address
- `network_files_from_ip_aggregated`
  - Accepts an IP address string and returns a list of hashes and classifications for files found on the requested IP address
  - This method performs the paging automatically and returns a specified maximum number of records

***


## Module: ticloud
A Python module representing the ReversingLabs TitaniumCloud API-s.

Each class in this module represents one TitaniumCloud API and can be instantiated using the same set of parameters:
```python
def __init__(self, host, username, password, verify, proxies, user_agent, allow_none_return)
```
#### Parameters:
`host` - TitaniumCloud address  
`username` - TitaniumCloud username  
`password` - TitaniumCloud password  
`verify` - verify SSL certificate  
`proxies` - optional proxies in use  
`user_agent` - optional user agent string  
`allow_none_return` - if set to `True`, `404` response codes will return `None` instead of `NotFoundError`


#### Class:
```python
class FileReputation(TiCloudAPI)
```
#### Methods:
- `get_file_reputation`
    - Accepts a hash string or a list of hash strings and returns file reputation
    - Hash strings in a passed list must all be of the same hashing algorithm


#### Class:
```python
class AVScanners(TiCloudAPI)
```
#### Methods:
- `get_scan_results`
    - Accepts a hash string or a list of hash strings and returns AV scanner results
    - Hash strings in a passed list must all be of the same hashing algorithm


#### Class:
```python
class FileAnalysis(TiCloudAPI)
```
#### Methods:
- `get_analysis_results`
    - Accepts a hash string or a list of hash strings and returns extended file analysis
- `extract_uri_list_from_report`
    - Accepts a list of entries from the FileAnalysis report and returns a list of URI-s from those entries.
- `get_file_type`
    - Accepts a sample hash and returns the file type string


#### Class:
```python
class RHA1FunctionalSimilarity(TiCloudAPI)
```
#### Methods:
- `get_similar_hashes`
    - Accepts a hash string and returns a list of functionally similar hashes
    - Returns only one defined page of results using one request
- `get_similar_hashes_aggregated`
    - Accepts a hash string and returns a list of functionally similar hashes
    - Returns a list of results aggregated through multiple paginated requests


#### Class:
```python
class RHA1Analytics(TiCloudAPI)
```
#### Methods:
- `get_rha1_analytics`
    - Accepts one or more hash strings and returns a count of functionally similar hashes grouped by classification


#### Class:
```python
class URIStatistics(TiCloudAPI)
````
#### Methods:
- `get_uri_statistics`
    - Accepts a URI string and returns a count of files associated with that URI grouped by classification


#### Class:
```python
class URIIndex(TiCloudAPI)
````
#### Methods:
- `get_uri_index`
    - Accepts a URI string and returns a list of files associated with this URI
    - Returns only one defined page of results using one request
- `get_uri_index_aggregated`
    - Accepts a URI string and returns a list of files associated with this URI
    - Returns a list of results aggregated through multiple paginated requests


#### Class:
```python
class AdvancedSearch(TiCloudAPI)
````
#### Methods:
- `search`
    - Accepts a search query string and performs advanced search on the API
    - Returns only one defined page of results using one request
- `search_aggregated`
    - Accepts a search query string and performs advanced search on the API
    - Returns a list of results aggregated through multiple paginated requests


#### Class:
```python
class ExpressionSearch(TiCloudAPI)
````
#### Methods:
- `search`
    - Accepts a list containing the search query and performs expression search on the API
    - Returns only one defined page of results using one request
- `search_aggregated`
    - Accepts a list containing the search query and performs expression search on the API
    - Returns a list of results aggregated through multiple paginated requests
    
    
#### Class:
```python
class FileDownload(TiCloudAPI)
````
#### Methods:
- `get_download_status`
    - Accepts a hash string and returns the sample's availability for download
- `download_sample`
    - Accepts a hash string and downloads the related sample from TitaniumCloud
    
#### Class:
```python
class URLThreatIntelligence(TiCloudAPI)
````
#### Methods:
- `get_url_report`
    - Accepts a URL string and returns detailed URL analysis info
- `get_downloaded_files`
    - Accepts a URL string and returns a list of files downloaded from that URL
- `get_latest_url_analysis_feed`
    - Returns the latest URL analysis reports
    - Returns only one defined page of results using one request
- `get_latest_url_analysis_feed_aggregated`
    - Returns the latest URL analysis reports
    - Returns a list of results aggregated through multiple paginated requests
- `get_url_analysis_feed_from_date`
    - Accepts time format and a start time and returns URL analysis reports from that defined time onward
    - Returns only one defined page of results using one request
- `get_url_analysis_feed_from_date_aggregated`
    - Accepts time format and a start time and returns URL analysis reports from that defined time onward
    - Returns a list of results aggregated through multiple paginated requests

#### Class:
```python
class AnalyzeURL(TiCloudAPI)
````
#### Methods:
- `submit_url`
    - Sends a URL string for analysis and returns an analysis task ID

#### Class:
```python
class FileUpload(TiCloudAPI)
````
#### Methods:
- `upload_sample_from_path`
    - Accepts a file path string and uploads the desired file to the File Upload API
- `upload_sample_from_file`
    - Accepts an open file handle and uploads the desired file to the File Upload API

#### Class:
```python
class DeleteFile(TiCloudAPI)
````
#### Methods:
- `delete_samples`
  - Accepts a single hash string or a list of hash strings belonging to samples you want to delete from the cloud
  - You can only delete samples that were uploaded by the same cloud account

#### Class:
```python
class ReanalyzeFile(TiCloudAPI)
````
#### Methods:
- `reanalyze_samples`
  - Accepts a single hash string or a list of hash strings belonging to samples in the cloud you want to reanalyze
  - The samples need to be already present in the cloud in order to be reanalyzed

#### Class:
```python
class DynamicAnalysis(TiCloudAPI)
````
#### Methods:
- `detonate_sample`
    - Submits a sample available in the cloud for dynamic analysis and returns processing info
    - The sample needs to be available in TitaniumCloud beforehand
- `get_dynamic_analysis_results`
    - Returns dynamic analysis results for a desired sample
    - The analysis of the selected sample must be finished for the results to be available

#### Class:
```python
class CertificateIndex(TiCloudAPI)
````
#### Methods:
- `get_certificate_information`
    - Accepts a hash (thumbprint) and returns a list of SHA1 hashes for samples signed with the certificate matching the requested thumbprint
- `get_certificate_information_aggregated`
    - Accepts a hash (thumbprint) and returns a list of SHA1 hashes for samples signed with the certificate matching the requested thumbprint
    - This method automatically handles paging and returns a list of results instead of a Response object
    
#### Class:
```python
class CertificateAnalytics(TiCloudAPI)
````
#### Methods:
- `get_certificate_analytics`
    - Accepts a certificate hash thumbprint (hash string) and returns certificate analytics results

#### Class:
```python
class CertificateThumbprintSearch(TiCloudAPI)
````
#### Methods:
- `search_common_names`
    - Accepts a certificate common name and returns common names matching the request, along with the list of thumbprints of all the certificates sharing that common name
- `search_common_names_aggregated`
    - Accepts a certificate common name and returns common names matching the request, along with the list of thumbprints of all the certificates sharing that common name
    - This method automatically handles paging and returns a list of results instead of a Response object

#### Class:
```python
class RansomwareIndicators(TiCloudAPI)
````
#### Methods:
- `get_indicators`
    - Accepts a list of indicator type strings and integers for historical hours, health check and returning only freemium indicators. Returns indicators of ransomware and related tools

#### Class:
```python
class NewMalwareFilesFeed(ContinuousFeed)
````
#### Methods:
- `pull_with_timestamp`
    - Accepts a time format definition and a time value. Returns malware detections from the requested time
- `pull`
    - Returns a list of malware detections since the point in time set by the set_start method. If the user has not previously used this method, nor has the set_start method been called, it will return records starting with the current timestamp
- `set_start`
    - This method sets the starting time for the pull method

#### Class:
```python
class MWPChangeEventsFeed(ContinuousFeed)
````
#### Methods:
- `pull_with_timestamp`
    - Accepts a time format definition and a time value. Returns samples with a newly calculated or changed malware presence (MWP) classification and threat name from the requested time
- `pull`
    - Returns a list of classification and threat name changes since the point in time set by the set_start() method
- `set_start`
    - This method sets the starting time for the pull() method

#### Class:
```python
class NewMalwareURIFeed(TiCloudAPI)
````
#### Methods:
- `pull_with_timestamp`
    - Accepts a time format definition and a time value. Returns records with Ps, domains, URLs, emails, and sample hashes extracted from malware samples
- `pull_latest`
    - Returns a maximum of 1000 latest records with Ps, domains, URLs, emails, and sample hashes extracted from malware samples

#### Class:
```python
class ImpHashSimilarity(TiCloudAPI)
````
#### Methods:
- `get_imphash_index`
    - Accepts an imphash and returns a list of SHA-1 hashes of files sharing that imphash
- `get_imphash_index_aggregated`
    - Accepts an imphash and returns a list of SHA-1 hashes of files sharing that imphash
    - This method automatically handles paging and returns a list of results instead of a Response object

#### Class:
```python
class YARAHunting(TiCloudAPI)
````
#### Methods:
- `create_ruleset`
    - Creates a new YARA ruleset
    - The ruleset_text parameter needs to be a stringified YARA ruleset / a Unicode string
- `delete_ruleset`
    - Deletes a YARA ruleset
- `get_ruleset_info`
    - Get information for a specific YARA ruleset or all YARA rulesets in the collection
- `get_ruleset_text`
    - Get the text of a YARA ruleset
- `yara_matches_feed`
    - Returns a recordset of YARA ruleset matches in the specified time range

#### Class:
```python
class YARARetroHunting(TiCloudAPI)
````
#### Methods:
- `enable_retro_hunt`
    - Enables the retro hunt for the specified ruleset that has been submitted to TitaniumCloud prior to deployment of YARA retro
- `start_retro_hunt`
    - Starts the retro hunt for the specified ruleset
- `check_status`
    - Checks the retro hunt status for the specified ruleset
- `cancel_retro_hunt`
    - Cancels the retro hunt for the specified ruleset
- `yara_retro_matches_feed`
    - Returns a recordset of YARA ruleset matches in the specified time range

#### Class:
```python
class FileReputationUserOverride(TiCloudAPI)
````
#### Methods:
- `override_classification`
    - Accepts two parameters
      - A list of samples whose classification needs to be overriden
      - A list of samples whose classification override needs to me removed
- `list_active_overrides`
    - Accepts a hash type designation and returns the hashes of all currently active classification overrides for the current organization.
- `list_active_overrides_aggregated`
    - Accepts a hash type designation and returns the hashes of all currently active classification overrides for the current organization. This method does the paging action automatically and a maximum number of results returned in the list can be defined with the max_results parameter.

#### Class:
```python
class DomainThreatIntelligence(TiCloudAPI)
````
#### Methods:
- `get_domain_report`
    - Accepts a domain string and returns threat intelligence data for the submitted domain.
- `get_downloaded_files`
    - Accepts a domain string and retrieves a list of files downloaded from the submitted domain.
- `get_downloaded_files_aggregated`
  - Accepts a domain string and retrieves a list of files downloaded from the submitted domain. This method performs the paging automatically and returns a list of results. The maximum number of results to be returned can be set.
- `urls_from_domain`
  - Accepts a domain string and returns a list of URLs associated with the requested domain.
- `urls_from_domain_aggregated`
  - Accepts a domain string and returns a list of URLs associated with the requested domain. This method performs the paging automatically and returns a list of results. The maximum number of results to be returned can be set.
- `domain_to_ip_resolutions`
  - Accepts a domain string and returns a list of domain-to-IP mappings for the requested domain.
- `domain_to_ip_resolutions_aggregated`
  - Accepts a domain string and returns a list of domain-to-IP mappings for the requested domain. This method performs the paging automatically and returns a list of results. The maximum number of results to be returned can be set.
- `related_domains`
  - Accepts a domain string and returns a list of domains that have the same top parent domain as the requested domain.
- `related_domains_aggregated`
  - Accepts a domain string and returns a list of domains that have the same top parent domain as the requested domain. This method performs the paging automatically and returns a list of results. The maximum number of results to be returned can be set.

#### Class:
```python
class IPThreatIntelligence(TiCloudAPI)
````
#### Methods:
- `get_ip_report`
    - Accepts an IP address as a string and returns threat intelligence data for the submitted IP address.
- `get_downloaded_files`
    - Accepts an IP address as a string and returns a list of files downloaded from the submitted IP address.
- `get_downloaded_files_aggregated`
  - Accepts an IP address as a string and returns a list of files downloaded from the submitted IP address. This method performs the paging automatically and returns a list of results. The maximum number of results to be returned can be set.
- `urls_from_ip`
  - Accepts an IP address as a string and returns a list of URLs associated with the requested IP.
- `urls_from_ip_aggregated`
  - Accepts an IP address as a string and returns a list of URLs associated with the requested IP. This method performs the paging automatically and returns a list of results. The maximum number of results to be returned can be set.
- `ip_to_domain_resolutions`
  - Accepts an IP address as a string and returns a list of IP-to-domain mappings for the specified IP address.
- `ip_to_domain_resolutions_aggregated`
  - Accepts an IP address as a string and returns a list of IP-to-domain mappings for the specified IP address. This method performs the paging automatically and returns a list of results. The maximum number of results to be returned can be set.

#### Class:
```python
class FileAnalysisNonMalicious(TiCloudAPI)
````
#### Methods:
- `get_analysis_results`
    - Accepts a hash string or a list of hash strings and returns knowledge about the given samples if they are classified as goodware.

#### Class:
```python
class DataChangeSubscription(TiCloudAPI)
````
#### Methods:
- `subscribe`
  - Subscribes to a list of samples (hashes) for which the changed data (if there are any) will be delivered in the Data Change Feed.
- `unsubscribe`
    - Unsubscribes from a list of samples that the user was previously subscribed to.
- `set_start_time`
  - Sets the starting point for the DataChangeSubscription.pull_from_feed method.
- `pull_from_feed`
  - Returns a recordset with samples to which the user is subscribed. The starting point for this action is set using the DataChangeSubscription.set_start_time method. If the starting point is not set, this method will return records starting with the current timestamp. Every subsequent request will continue from the timestamp where the previous request ended.
- `continuous_data_change_feed`
  - Returns a recordset with samples to which the user is subscribed from the timestamp stated in the request onwards. To fetch the next recordset, use the last_timestamp value from the response and submit it in a new request as the time_value parameter.

#### Class:
```python
class NewMalwarePlatformFiltered(TiCloudAPI)
````
#### Methods:
- `feed_query`
    - Returns a list of malware samples optionally filtered by platform since the requested timestamp.
- `start_query`
    - Sets the starting timestamp for the pull_query.
- `pull_query`
    - Returns the list of malware samples optionally filtered by platform since a point in time set by the start_query.

#### Class:
```python
class CustomerUsage(TiCloudAPI)
````
#### Methods:
- `daily_usage`
    - Returns information about daily service usage for the TitaniumCloud account that sent the
        request.
- `monthly_usage`
    - Returns information about monthly service usage for the TitaniumCloud account that sent the
        request.
- `date_range_usage`
    - This method returns total usage for all product licenses with a fixed quota over a single date range.
- `active_yara_rulesets`
    - This method returns information about the number of active YARA rulesets for the TitaniumCloud
        account that sent the request.
- `quota_limits`
    - This method returns current quota limits for API-s accessible to the authenticated user.

#### Class:
```python
class NetworkReputation(TiCloudAPI)
````
#### Methods:
- `get_network_reputation`
    - Returns reputation information about queried URL-, domains and IP addresses.

#### Class:
```python
class NetworkReputationUserOverride(TiCloudAPI)
````
#### Methods:
- `reputation_override`
    - This method enables two actions in one request:
        1. Send a list of network locations whose classification needs to be overriden.
        2. Send a list of network locations whose classification override needs to be removed.
- `list_overrides`
    - Returns a list of overrides that the user has made.

#### Class:
```python
class TAXIIRansomwareFeed(TiCloudAPI)
````
#### Methods:
- `discovery_info`
    - Returns the information from the TAXII Server's discovery endpoint. 
    - The returned info shows the available api roots.
- `api_root_info`
    - Returns information about a specific api root.
- `collections_info`
    - Returns information about available collections in an api root.
- `get_objects`
    - Returns objects from a TAXII collection. 
    - Results can be filtered using several parameters.


***

## Module: tiscale
A Python module representing the ReversingLabs TitaniumScale malware analysis appliance.
#### Class:
```python
class TitaniumScale(object)
def __init__(self, host, token, wait_time_seconds, retries, verify, proxies, user_agent)
```
#### Parameters:
`host` - TitaniumScale address  
`token` - TitaniumScale user token for the REST API  
`wait_time_seconds` - wait time between each report fetching retry  
`retries` - number of report fetching retries  
`verify` - verify SSL certificate  
`proxies` - optional proxies in use  
`user_agent` - optional user agent string  

#### Methods:
- `upload_sample_from_path`
    - Accepts a file path string for file upload and returns a response containing the analysis task URL
- `upload_sample_from_file`
    - Accepts a file opened in 'rb' mode for file upload and returns a response containing the analysis task URL
- `get_results`
    - Accepts an analysis task URL and returns a file analysis summary or a full analysis report
    - This method utilizes the set number of retries and wait time in seconds to time out if the analysis results are not ready
- `upload_sample_and_get_results`
    - Accepts a file path string or an opened file in 'rb' mode for file upload and returns a file analysis summary or a full analysis report
    - This method combines uploading a sample and obtaining the analysis results
    - The result obtaining action of this method utilizes the set number of retries and wait time in seconds to time out if the analysis results are not ready
- `list_processing_tasks`
  - Lists processing tasks generated by file submission requests.
- `get_processing_task_info`
  - Retrieves information about a completed file processing task
- `delete_processing_task`
  - Deletes a processing task record from the system.
- `delete_multiple_tasks`
  - Deletes multiple task records from the system based on the time when they were submitted.
- `get_yara_id`
  - Retrieves the identifier of the current set of YARA rules on the TitaniumScale Worker instance.


***

## Module: clouddeepscan
Handles communication with Cloud Deep Scan API endpoints.

#### Class:
```python
class CloudDeepScan(object)
```

#### Parameters:
`token_endpoint` - token endpoint that is used to fetch authorization token  
`rest_hostname` - REST API hostname that is used as base URL to generate endpoints  
`client_id` - ID of OAuth2.0 client used for authorization  
`client_secret` - secret of OAuth2.0 client used for authorization  


#### Methods:
- `upload_sample`
    - Accepts a file path string of a file that should be scanned and optional configuration of how many part uploads to do concurrently, returns submission ID
- `fetch_submission`
    - Accepts submission ID and returns an instance of CloudDeepScanSubmissionStatus
- `fetch_submission_history`
    - Accepts either sample name or sample hash and returns list of CloudDeepScanSubmissionStatus objects
- `download_report`
    - Accepts sha1 hash of the sample and path of the output file where JSON report will be stored and stores report to that location

#### Class:
```python
class CloudDeepScanSubmissionStatus(object)
```

#### Parameters:
`id_` - submission ID of the submission  
`created_at` - datetime instance of time when submission is created  
`status` - submission status, can be one of: scanned, scanning, error
`report` - URL pointing to report location, None if status is not "scanned"

***

## Examples
#### A1000
```python
from ReversingLabs.SDK.a1000 import A1000

# Using username and password for authorization
a1000 = A1000(
    host="https://a1000.address",
    username="username",
    password="password",
    verify=True,
    wait_time_seconds=3,
    retries=10
)

response = a1000.upload_sample_and_get_summary_report_v2(
    file_path="/path/to/file.exe",
    retry=True,
    custom_filename="CustomName",
    tags="custom,tags,go,here",
)

json_report = response.json()
```

```python
from ReversingLabs.SDK.a1000 import A1000

# Using the token for authorization
a1000 = A1000(
    host="http://a1000.address",
    token="1js76asmklaslk288japj29s89z",
    verify=False,
    wait_time_seconds=2,
    retries=15
)

response = a1000.list_extracted_files_v2(
    sample_hash="cf23df2207d99a74fbe169e3eba035e633b65d94",
    page_size=30
)

json_report = response.json()
```

#### TitaniumCloud
```python
from ReversingLabs.SDK.ticloud import FileReputation, URIStatistics, FileDownload, FileUpload


host = "https://data.reversinglabs.com"
username = "username"
password = "password"
user_agent = "MyCustom App v0.0.1"



file_reputation = FileReputation(
    host=host,
    username=username,
    password=password,
    user_agent=user_agent
)

reputation = file_reputation.get_file_reputation(
    hash_input="cf23df2207d99a74fbe169e3eba035e633b65d94",
    extended_results=True,
    show_hashes_in_results=False
)



uri_statistics = URIStatistics(
    host=host,
    username=username,
    password=password,
    user_agent=user_agent
)

statistics = uri_statistics.get_uri_statistics(
    uri_input="youtube.com"
)



file_download = FileDownload(
    host=host,
    username=username,
    password=password,
    user_agent=user_agent
)

download = file_download.download_sample(
    hash_input="cf23df2207d99a74fbe169e3eba035e633b65d94"
)

with open("/path/to/file", "wb") as file_handle:
    file_handle.write(download.content)



file_upload = FileUpload(
    host=host,
    username=username,
    password=password,
    user_agent=user_agent
)

upload = file_upload.upload_sample_from_path(
    file_path="/path/to/file",
    sample_name="Custom Sample Name",
    sample_domain="webdomain.com"
)
```

#### TitaniumScale
```python
from ReversingLabs.SDK.tiscale import TitaniumScale


titanium_scale = TitaniumScale(
    host="https://tiscale.address",
    token="examplesecrettoken",  # replace with a proper token
    verify=True,
    wait_time_seconds=5,
    retries=6
)

results = titanium_scale.upload_sample_and_get_results(
    file_source=open("/path/to/file.exe", "rb"),
    full_report=True
)
```


#### CloudDeepScan
```python
from ReversingLabs.SDK.clouddeepscan import CloudDeepScan, CloudDeepScanException


cloud_deep_scan = CloudDeepScan(
    token_endpoint="https://exampletokenendpoint.reversinglabs.com/oauth2/token",
    rest_hostname="https://example.clouddeepscan.com",
    client_id="exampleclientid",
    client_secret="exampleclientsecret"
)
try:
    submission_id = cloud_deep_scan.upload_sample(sample_path="/path/to/file/suspicious_file.exe")
except CloudDeepScanException:
    pass

try:
    status_data = cloud_deep_scan.fetch_submission(submission_id=submission_id)  # Returns CloudDeepScanSubmissionStatus instance
    print(status_data.id)  # submission id
    print(str(status_data.created_at))  # datetime instance
    print(status_data.status)  # status
    print(status_data.report)  # URI path to the report file
except CloudDeepScanException:
    pass

try:
    submission_history = cloud_deep_scan.fetch_submission_history(sample_hash="0f5de47158e40b5d791cb3698b7dc599be21cf95")
    for submission_status in submission_history:
        print(submission_status.id)  # submission id
        print(str(submission_status.created_at))  # datetime instance
        print(submission_status.status)  # status
        print(submission_status.report)  # URI path to the report file
except CloudDeepScanException:
    pass

try:
    cloud_deep_scan.download_report(sample_hash="0f5de47158e40b5d791cb3698b7dc599be21cf95", report_output_path="reports/report1.json")  # report parent directory must exist
except CloudDeepScanException:
    pass
```
