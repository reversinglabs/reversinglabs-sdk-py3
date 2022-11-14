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
  - Added the `get_summary_report_v2`, `upload_sample_and_get_summary_report_v2`, `get_detailed_report_v2`, `get_classification_v3`, `reanalyze_samples_v2`, `list_extracted_files_v2`, `list_extracted_files_v2_aggregated`, `check_sample_removal_status_v2`, `advanced_search_v2`, `advanced_search_v2_aggregated`
  - The added methods correspond to the new v2 and v3 versions of A1000 API-s.
- **helper** module:
  - Catching the `binascii.Error` in the `validate_hashes` function.


  
v1.3.0 (2022-11-dd)
-------------------

#### Changes

- **ticloud** module:
  - Added the `DeleteFile`, `ReanalyzeFile`, `CertificateIndex`, `CertificateThumbprintSearch` classes.