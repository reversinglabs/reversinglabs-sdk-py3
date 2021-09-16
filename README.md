![ReversingLabs](https://raw.githubusercontent.com/reversinglabs/reversinglabs-sdk-py3/master/logo.jpg)

# ReversingLabsSDK

A Python SDK for ReversingLabs REST services (TitaniumCloud and appliances) - Python 3 version.

The idea behind this SDK is to enable easier out-of-the-box development of software integrations and automation services that need to interact with ReversingLabs.

The SDK consists of several modules, where each module represents one ReversingLabs service or ReversingLabs TitaniumCloud.

- [ReversingLabsSDK](https://github.com/reversinglabs/reversinglabs-sdk-py3#reversinglabssdk)
  * [Module: a1000](https://github.com/reversinglabs/reversinglabs-sdk-py3#module-a1000)
      - [Class A1000](https://github.com/reversinglabs/reversinglabs-sdk-py3#class)
      - [Parameters](https://github.com/reversinglabs/reversinglabs-sdk-py3#parameters)
      - [Methods](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-methods)
  * [Module: ticloud](https://github.com/reversinglabs/reversinglabs-sdk-py3#module-ticloud)
      - [Common Parameters](https://github.com/reversinglabs/reversinglabs-sdk-py3#parameters-1)
      - [Class FileReputation](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-1)
      - [Class AVScanners](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-2)
      - [Class FileAnalysis](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-3)
      - [Class RHA1FunctionalSimilarity](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-4)
      - [Class RHA1Analytics](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-5)
      - [Class URIStatistics](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-6)
      - [Class URIIndex](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-7)
      - [Class AdvancedSearch](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-8)
      - [Class ExpressionSearch](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-9)
      - [Class FileDownload](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-10)
      - [Class URLThreatIntelligence](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-11)
      - [Class AnalyzeURL](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-12)
      - [Class FileUpload](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-13)
      - [Class DynamicAnalysis](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-14)
      - [Class CertificateAnalytics](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-15)
  * [Module: tiscale](https://github.com/reversinglabs/reversinglabs-sdk-py3#module-tiscale)
      - [Class TitaniumScale](https://github.com/reversinglabs/reversinglabs-sdk-py3#class-13)
      - [Parameters](https://github.com/reversinglabs/reversinglabs-sdk-py3#parameters-2)
      - [Methods](https://github.com/reversinglabs/reversinglabs-sdk-py3#methods-12)
  * [Examples](https://github.com/reversinglabs/reversinglabs-sdk-py3#examples)



## Module: a1000
A Python module representing the ReversingLabs A1000 malware analysis platform.
#### Class:
```python
class A1000(object)
def __init__(self, host, username=None, password=None, token=None, fields=__FIELDS, wait_time_seconds=2, retries=10, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT):
```

#### Parameters:
`host` - A1000 address  
`username` - A1000 username  
`password` - A1000 password  
`token` - A1000 user token for the REST API  
`fields` - optional fields that will be returned in the analysis report  
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
- `get_results`
    - Accepts a list of hashes and returns a summary JSON report for each of them
    - This method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready
- `upload_sample_and_get_results`
    - Accepts a file path string or an opened file in 'rb' mode for file upload and returns an analysis report response
    - This method combines uploading a sample and obtaining the analysis results
    - The result fetching action of this method utilizes the set number of retries and wait time in seconds to time
        out if the analysis results are not ready
- `get_classification`
    - Accepts one or more sample hashes and returns their classification
- `reanalyze_samples`
    - Accepts a single hash or a list of hashes of the same type and reanalyzes the corresponding samples
- `get_extracted_files`
    - Accepts a sample hash and returns a list of all files TitaniumCore engine extracted from the requested sample during static analysis
- `download_extracted_files`
    - Accepts a single hash string and returns a downloadable archive file containing files extracted from the desired sample
- `delete_samples`
    - Accepts a single hash string or a list of hashes and deletes the corresponding samples from A1000
- `download_sample`
    - Accepts a single hash string and returns a downloadable sample
- `advanced_search`
    - Accepts a search query string and performs advanced search for local samples on A1000
    - Returns only one defined page of results using one request
- `advanced_search_aggregated`
    - Accepts a search query string and performs advanced search for local samples on A1000
    - Returns a list of results aggregated through multiple paginated requests
  

***


## Module: ticloud
A Python module representing the ReversingLabs TitaniumCloud API-s.

Each class in this module represents one TitaniumCloud API and can be instantiated using the same set of parameters:
```python
def __init__(self, host, username, password, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT, allow_none_return=False)
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
class CertificateAnalytics(TiCloudAPI)
````
#### Methods:
- `get_certificate_analytics`
    - Accepts a certificate hash thumbprint (hash string) and returns certificate analytics results

***

## Module: tiscale
A Python module representing the ReversingLabs TitaniumScale malware analysis appliance.
#### Class:
```python
class TitaniumScale(object)
def __init__(self, host, token, wait_time_seconds=2, retries=10, verify=True, proxies=None, user_agent=DEFAULT_USER_AGENT)
```
#### Parameters:
`host` - TitaniumScale address  
`token` - A1000 user token for the REST API  
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

response = a1000.upload_sample_and_get_results(
    file_path="/path/to/file.exe",
    retry=True,
    custom_filename="CustomName",
    tags="custom,tags,go,here",
)

json_report = response.json()
```

```python
from ReversingLabs.SDK.a1000 import A1000

# Using token for authorization
a1000 = A1000(
    host="http://a1000.address",
    token="1js76asmklaslk288japj29s89z",
    verify=False,
    wait_time_seconds=2,
    retries=15
)

response = a1000.get_extracted_files(
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
    token="js765akj329786afhg",
    verify=True,
    wait_time_seconds=5,
    retries=6
)

results = titanium_scale.upload_sample_and_get_results(
    file_source=open("/path/to/file.exe", "rb"),
    full_report=True
)
```