ReversingLabs SDK Change Log
=========
v1.2.2 (2022-10-19)
-------------------

#### Deprecations

- **a1000** module:
  - Deprecated the `get_results`, `upload_sample_and_get_results`, `get_classification`, `reanalyze_samples`, `get_extracted_files`, `advanced_search` and `advanced_search_aggregated` methods.
- Dropped support for Python 2.7
  - From this version on, the Python 2 version of the SDK (https://pypi.org/project/reversinglabs-sdk-py2/) will no longer be maintained.

#### Changes

- **a1000** module:
  - Added the `get_summary_report_v2`, `upload_sample_and_get_summary_report_v2`, `get_detailed_report_v2`, `get_classification_v3`, `reanalyze_samples_v2`, `list_extracted_files_v2`, `list_extracted_files_v2_aggregated`, `check_sample_removal_status_v2`, `advanced_search_v2` and `advanced_search_v2_aggregated` methods.
  - The added methods correspond to the new v2 and v3 versions of A1000 API-s.
- **helper** module:
  - Catching the `binascii.Error` in the `validate_hashes` function.


  
v1.3.0 (2022-11-16)
-------------------

#### Changes

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

#### Changes

- **ticloud** module:
  - Added the `ImpHashSimilarity`, `YARAHunting` and `YARARetroHunting` classes.
- **a1000** module:
  - Added the `network_url_report`, `network_domain_report`, `network_ip_addr_report`, `network_ip_to_domain`, `network_urls_from_ip` and `network_files_from_ip` methods.
  - Added the `ticloud` parameter into the `advanced_search_v2` and `advanced_search_v2_aggregated` methods.
