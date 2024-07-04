ReversingLabs SDK Change Log
=========

v1.2.2 (2022-10-19)
-------------------

#### Deprecations

- **a1000** module:
  - Deprecated the `get_results`, `upload_sample_and_get_results`, `get_classification`, `reanalyze_samples`, `get_extracted_files`, `advanced_search` and `advanced_search_aggregated` methods.
- Dropped support for Python 2.7
  - From this version on, the Python 2 version of the SDK (https://pypi.org/project/reversinglabs-sdk-py2/) will no longer be maintained.

#### Improvements

- **a1000** module:
  - Added the `get_summary_report_v2`, `upload_sample_and_get_summary_report_v2`, `get_detailed_report_v2`, `get_classification_v3`, `reanalyze_samples_v2`, `list_extracted_files_v2`, `list_extracted_files_v2_aggregated`, `check_sample_removal_status_v2`, `advanced_search_v2` and `advanced_search_v2_aggregated` methods.
  - The added methods correspond to the new v2 and v3 versions of A1000 API-s.

#### Bugfixes

- **helper** module:
  - Catching the `binascii.Error` in the `validate_hashes` function.


  
v1.3.0 (2022-11-16)
-------------------

#### Improvements

- **ticloud** module:
  - Added the `DeleteFile`, `ReanalyzeFile`, `CertificateIndex`, `CertificateThumbprintSearch`, `NewMalwareFilesFeed`, `MWPChangeEventsFeed` and `NewMalwareURIFeed` classes.
  - Several feed classes now extend the new `ContinuousFeed` parent class.
- **a1000** module:
  - Added the `upload_sample_from_url`, `check_submitted_url_status`, `get_submitted_url_report`, `upload_sample_from_url_and_get_report`, `get_summary_report_v2`, `get_user_tags_for_a_sample`, `post_user_tags`, `delete_user_tags`, `create_pdf_report`, `check_pdf_report_creation`, `download_pdf_report`, `get_titanium_core_report_for_a_sample_v2`, `create_dynamic_analysis_report`, `check_dynamic_analysis_report_status`, `download_dynamic_analysis_report, set_classification`, `delete_classification`, `get_yara_rulesets_on_the_appliance_v2`, `get_yara_ruleset_contents`, `get_yara_ruleset_matches_v2`, `create_or_update_yara_ruleset`, `delete_yara_ruleset`, `enable_or_disable_yara_ruleset`, `get_yara_ruleset_synchronization_time`, `update_yara_ruleset_synchronization_time`, `start_or_stop_yara_local_retro_scan`, `get_yara_local_retro_scan_status`, `start_or_stop_yara_cloud_retro_scan`, `get_yara_cloud_retro_scan_status` and `list_containers_for_hashes` methods.
  - Added the `archive_password` and `rl_cloud_sandbox_platform` parameters into the `upload_sample_from_path` and `upload_sample_from_file` methods.
- **helper** module:
  - Added the `BadGatewayError` exception class.
  - Adjusted the message of the `TooManyRequestsError` exception class to reflect quota limit breached situations.



v1.4.0 (2023-01-04)
-------------------

#### Improvements

- **ticloud** module:
  - Added the `ImpHashSimilarity`, `YARAHunting` and `YARARetroHunting` classes.
- **a1000** module:
  - Added the `network_url_report`, `network_domain_report`, `network_ip_addr_report`, `network_ip_to_domain`, `network_urls_from_ip` and `network_files_from_ip` methods.
  - Added the `ticloud` parameter into the `advanced_search_v2` and `advanced_search_v2_aggregated` methods.



v2.0.0 (2023-02-27)
-------------------

#### Improvements

- Added a new module for using the **ReversingLabs Cloud Deep Scan** service called **clouddeepscan**.
- **clouddeepscan** module:
  - Class `CloudDeepScan` methods: `upload_sample`, `fetch_submission`, `fetch_submission_history`, `download_report`



v2.1.0 (2023-03-31)
-------------------

#### Deprecations

- **ticloud** module:
  - Deprecated the `ranalyze_samples` method of the `ReanalyzeFile` class. **This method will be removed** from the SDK in the future **September 2023.** release. A new method called `reanalyze_samples` of the same `ReanalyzeFile` class should be used instead.

#### Improvements

- **ticloud** module:
  - Added the `FileReputationUserOverride`, `DomainThreatIntelligence` and `IPThreatIntelligence` classes.
  - Included an adjustable `results_per_page` parameter into several methods that perform paging automatically.
  - The `detonate_sample` method of the `DynamicAnalysis` class now also accepts `"macos11"` as the `platform` parameter.
  - The `detonate_sample` method of the `DynamicAnalysis` class now accepts the `internet_simulation` parameter.
- **a1000** module:
  - All sample submission methods now also accept `"macos_11"` as the `rl_cloud_sandbox_platform` parameter.
- **tiscale** module:
  - Added the `list_processing_tasks`, `get_processing_task_info`, `delete_processing_task`, `delete_multiple_tasks` and `get_yara_id` methods.
  - Added support for the `custom_token`, `user_data` and `custom_data` parameters in existing sample upload methods.

#### Bugfixes
- **a1000** module:
  - Leaving the `fields` parameter in the `get_titanium_core_report_v2` method as None now results in requesting all the available fields instead of throwing an exception.



v2.1.1 (2023-04-05)
-------------------

#### Improvements

- **ticloud** module:
  - Added the `FileAnalysisNonMalicious` and `DataChangeSubscription` classes.
  - The `FileUpload` class methods now also use `subscribe`, `archive_type` and `archive_passoword` parameters.

---



v2.1.2 (2023-05-15)
-------------------

#### Improvements

- **a1000** module:
  - Added paging parameters to the Network Threat Intelligence methods: `network_ip_to_domain`, `network_urls_from_ip` and `network_files_from_ip`
  - Added auto paging versions of the same methods: `network_ip_to_domain_aggregated`, `network_urls_from_ip_aggregated` and `network_files_from_ip_aggregated`

---



v2.2.0 (2023-06-23)
-------------------

#### Improvements

- **ticloud** module:
  - Added the `NewMalwarePlatformFiltered` class.

---



v2.3.0 (2023-09-29)
-------------------

#### Improvements

- **ticloud** module:
  - Added the `CustomerUsage`, `NetworkReputation`, `NetworkReputationUserOverride` and `TAXIIRansomwareFeed` classes.
  - The `DynamicAnalysis` class methods now also support `windows11` and `linux` as a platform.
  - The `DynamicAnalysis` class methods now also support detonating .zip file archives and fetching the analysis results for the same.
- **a1000** module:
  - Added the `advanced_search_v3` and `advanced_search_v3_aggregated` methods.

#### Deprecations

- **a1000** module:
  - Deprecated the `advanced_search_v2` and `advanced_search_v2_aggregated` methods.

#### Removals

- **ticloud** module:
  - Removed the `ReanalyzeFile.ranalyze_samples` method.
- **a1000** module:
  - Removed the `get_results`, `upload_sample_and_get_results`, `get_classification`, `reanalyze_samples`, `get_extracted_files`, `advanced_search` and `advanced_search_aggregated` methods.

---


v2.4.0 (2023-12-29) - [YANKED]
-------------------

**Note:** Contains breaking changes in the `ExpressionSearch` class. We recommend using **v2.4.2**

#### Improvements

- **ticloud** module:
  - Added the `NewFilesFirstScan`, `NewFilesFirstAndRescan`, `FilesWithDetectionChanges`, `CvesExploitedInTheWild`, `NewExploitOrCveSamplesFoundInWildHourly`, `NewExploitAndCveSamplesFoundInWildDaily`, `NewWhitelistedFiles`, `ChangesWhitelistedFiles`, `MalwareFamilyDetection`, `ExpressionSearch`, `VerticalFeedStatistics` and `VerticalFeedSearch` classes.
  - The following changes were made to the `DynamicAnalysis` class:
    - Added `windows11` and `linux` to available Dynamic Analysis platforms.
    - Added the `detonate_url` method.
    - The `get_dynamic_analysis_results` method now supports `url` analysis results.

- Added TitaniumCloud API codes to the README for better correspondence and orientation.
---


v2.4.1 (2024-01-11) - [YANKED]
-------------------

**Note:** Contains breaking changes in the `ExpressionSearch` class. We recommend using **v2.4.2**

#### Improvements

- **ticloud** module:
  - The `get_dynamic_analysis_results` method of the `DynamicAnalysis` class now also supports using a URL-s SHA-1 hash for fetching the URL dynamic analysis results. 

- Error handling: Custom error classes now also carry the original response object. Users can now reach the original status code, error message and all other response properties using the caught error's `response_object` property. 
---


v2.4.2 (2024-01-22)
-------------------

All changes are calculated against **v2.3.0**

#### Improvements
- **ticloud** module:
  - Added the `NewFilesFirstScan`, `NewFilesFirstAndRescan`, `FilesWithDetectionChanges`, `CvesExploitedInTheWild`, `NewExploitOrCveSamplesFoundInWildHourly`, `NewExploitAndCveSamplesFoundInWildDaily`, `NewWhitelistedFiles`, `ChangesWhitelistedFiles`, `MalwareFamilyDetection`, `ExpressionSearch`, `VerticalFeedStatistics` and `VerticalFeedSearch` classes.
  - The following changes were made to the `DynamicAnalysis` class:
    - Added `windows11` and `linux` to available Dynamic Analysis platforms.
    - Added the `detonate_url` method.
    - The `get_dynamic_analysis_results` method now supports fetching the URL dynamic analysis results using the URL string or its SHA-1 hash as a parameter.

- Added TitaniumCloud API codes to the README for better correspondence and orientation.
- Error handling: Custom error classes now also carry the original response object. Users can now reach the original status code, error message and all other response properties using the caught error's `response_object` property. 


v2.4.3 (2024-02-07)
-------------------

#### Improvements
- Python package dependencies are now set to the following values:
  - `requests>=2.28.2`
  - `urllib3>=1.26.14`


v2.5.0 (2024-03-30)
-------------------

#### Removals
- **a1000** module:
  - Removed the `a1000.A1000.advanced_search_v2` method.

#### Improvements
- Added unit tests.
- Added CI/CD (Actions) workflows for running unit tests and publishing the package to PyPI.
- **ticloud** module:
  - `md5` and `sha256` can now be used in `DynamicAnalysis.get_dynamic_analysis_results` for fetching sample analysis results.


v2.5.1 (2024-04-02)
-------------------

#### Improvements
- Updated the README with an example of error handling.


2.5.2 (2024-04-30)
-------------------

#### Improvements
- **a1000** module:
  - The function for checking file analysis status is now public. It is called `file_analysis_status`.


2.5.3 (2024-05-08)
-------------------

#### Bugfixes
- **ticloud** module:
  - The classification override parameter in the `override_classification` method of the `FileReputationUserOverride` now works as expected due to a payload fix.

#### Removals
- **clouddeepscan** module:
  - Dropped support for the clouddeepscan module. As of this version, the module is removed from the SDK.


2.5.4 (2024-05-09)
-------------------

#### Improvements
- Updated the Python package dependencies to:
  - `requests>=2.31.0`
  - `urllib3>=2.0.7`


2.5.5 (2024-05-15)
-------------------

#### Bugfixes
- **a1000** module:
  - Changed the `risk_score` parameter's type hint from `str` to `int` in `set_classification` method's docstring.


2.5.6 (2024-05-23)
-------------------

#### Improvements
- **a1000** module:
  - Reintroduced the `a1000.A1000.advanced_search_v2` method. This method will remain in the DEPRECATED state until its permanent removal from the SDK. The permanent removal date will be announced in the CHANGELOG's "Scheduled removals" section. In the meantime, the use of `a1000.A1000.advanced_search_v3` is highly advised.


2.6.0 (2024-06-28)
-------------------

#### Improvements
- **ticloud** module:
  - Added the following text to the docstrings for the `ticloud.URLThreatIntelligence.get_url_analysis_feed_from_date` and `ticloud.URLThreatIntelligence.get_url_analysis_feed_from_date_aggregated` methods: "It is possible to list analyses up to 90 days into the past."
  - Added the `get_objects_aggregated` method to the `TAXIIRansomwareFeed` class.
  - The `ticloud.DynamicAnalysis.detonate_sample` method now has a `sample_hash` parameter that accepts SHA-1, SHA-256 and MD5 hashes. See the Deprecations section for more info.
  - The `ticloud.DynamicAnalysis.detonate_sample` method now has a `sample_name` parameter that enable the user to define a custom sample name.
  - Added the option to fetch all results in auto paging (aggregating) methods. From now on, in such methods, setting the `max_results` parameter to None returns all results.

- **a1000** module:
  - The `get_yara_ruleset_matches_v2` method now also accepts a list u of multiple ruleset names as the `ruleset_name` parameter.
  - Added the `upload_sample_and_get_detailed_report_v2` method.
  - Added the option to fetch all results in auto paging (aggregating) methods. From now on, in such methods, setting the `max_results` parameter to None returns all results.

#### Deprecations
- **ticloud** module:
  - The `sample_sha1` parameter of the `ticloud.DynamicAnalysis.detonate_sample` method is deprecated and will be removed in 6 months. Use the `sample_hash` parameter instead.


### Scheduled removals
- **December 2024.**:
  - In the `ticloud.DynamicAnalysis.detonate_sample` method the `sample_sha1` parameter will be removed.


2.6.1 (2024-07-03)
-------------------

#### Improvements
- Added more unit tests for all currently available modules.