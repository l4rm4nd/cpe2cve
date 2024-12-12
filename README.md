# cpe2cve 🔍🛡️

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)


## Description

This a Python script that retrieves and organizes Common Vulnerabilities and Exposures (CVE) data related to a given Common Platform Enumeration (CPE). The script uses the National Vulnerability Database (NVD) API to fetch relevant information and presents it in a sorted order based on severity.

## Features

- Fetches CVE data for a given CPE.
- Sorts CVEs by severity in descending order.
- Displays CVE details, including ID, score, severity and NIST NVD URL.

## Usage

### Prerequisites

- Python 3.x
- Requests library (install using `pip install requests`)

````bash
usage: cpe2cve.py [-h] -c CPE -k API_KEY [-n NUM_RESULTS]

Get and sort CVEs from a CPE

options:
  -h, --help            show this help message and exit
  -c CPE, --cpe CPE     CPE from which to retrieve CVEs
  -k API_KEY, --api-key API_KEY
                        API key for NIST NVD API
  -n NUM_RESULTS, --num-results NUM_RESULTS
                        Number of CVEs to print (default: 25)
````

### Example

```bash
python3 cpe2cve.py -c cpe:2.3:a:apache:http_server:2.4.54 -k 1234567-1234-abcd-efgh-9873210
```

Replace the example CPE with your specific CPE for analysis.

Replace the example API key with your personal NIST NVD API key. You can request one [here](https://nvd.nist.gov/developers/request-an-api-key).

## Sample Output

```bash
[1] ID: CVE-2016-1908, Score: 9.8, Severity: CRITICAL (CVSS v3.1) - https://nvd.nist.gov/vuln/detail/CVE-2016-1908
[2] ID: CVE-2023-38408, Score: 9.8, Severity: CRITICAL (CVSS v3.1) - https://nvd.nist.gov/vuln/detail/CVE-2023-38408
[3] ID: CVE-2016-10012, Score: 7.8, Severity: HIGH (CVSS v3.0) - https://nvd.nist.gov/vuln/detail/CVE-2016-10012
[4] ID: CVE-2020-15778, Score: 7.8, Severity: HIGH (CVSS v3.1) - https://nvd.nist.gov/vuln/detail/CVE-2020-15778
[5] ID: CVE-2016-10708, Score: 7.5, Severity: HIGH (CVSS v3.0) - https://nvd.nist.gov/vuln/detail/CVE-2016-10708
```

## Contributing

If you find any issues or have suggestions for improvements, please open an issue or create a pull request. Contributions are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
