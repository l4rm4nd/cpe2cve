# Author: LRVT

import argparse
import requests
import re

# Function to retrieve CVE data for a given CPE
def get_cve_data(cpe, api_key):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": api_key}
    query_params = {
        "cpeName": cpe,
        "resultsPerPage": 250
    }
    
    try:
        response = requests.get(base_url, headers=headers, params=query_params)
        response.raise_for_status()
        cve_data = response.json()
        return cve_data.get("vulnerabilities", [])
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"Other error occurred: {err}")
    return []

# Function to retrieve the CVE ID from a CVE object
def get_cve_id(cve):
    return cve.get("cve", {}).get("id", "N/A")

# Function to generate a CVE link
def get_cve_link(cve_id):
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

# Function to retrieve the CVSS score and version from a CVE object
def get_cve_score_and_version(cve):
    metrics_sets = cve.get("cve", {}).get("metrics", {})
    for version in ["3.1", "3.0", "2.0"]:
        metrics_key = f"cvssMetricV{version.replace('.', '')}"
        if metrics_key in metrics_sets:
            metrics = metrics_sets[metrics_key][0]
            cvss_data = metrics.get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")
            if score is not None and severity is not None:
                return float(score), severity, version
    return None, None, None

# Main function for parsing command-line arguments and processing CVEs
def main():
    parser = argparse.ArgumentParser(description="Get and sort CVEs from a CPE")
    parser.add_argument("-c", "--cpe", required=True, help="CPE from which to retrieve CVEs")
    parser.add_argument("-k", "--api-key", required=True, help="API key for NIST NVD API")
    parser.add_argument("-n", "--num-results", type=int, default=25, help="Number of CVEs to print (default: 25)")

    args = parser.parse_args()

    cve_data = get_cve_data(args.cpe, args.api_key)

    # Filter and sort the CVEs by score in descending order
    filtered_cve = [
        cve for cve in cve_data if get_cve_score_and_version(cve)[0] is not None
    ]

    sorted_cve = sorted(
        filtered_cve, 
        key=lambda cve: get_cve_score_and_version(cve)[0],
        reverse=True
    )

    # Limit to the number of results specified by the user
    limited_cve = sorted_cve[:args.num_results]

    print()

    # Print the sorted CVEs with links
    for i, cve in enumerate(limited_cve, 1):
        cve_id = get_cve_id(cve)
        score, severity, version = get_cve_score_and_version(cve)
        cve_link = get_cve_link(cve_id)
        print(f"[{i}] ID: {cve_id}, Score: {score}, Severity: {severity} (CVSS v{version}) - {cve_link}")

if __name__ == "__main__":
    main()
