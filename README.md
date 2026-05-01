# hmpps-snyk-discovery

Service that will run Snyk image scans on HMPPS container images and pushes the results into the service catalogue where they can be displayed in developer portal 

The app does the following:
- Retrieves a list of all components (microservices) from the service catalogue.
- For each component it fetches container image details for each environment.
- It then runs the Snyk container image scan and updates the service catalogue with can results. 

Results are visible via the developer portal, e.g.

https://developer-portal.hmpps.service.justice.gov.uk/components/snyk

## Snyk output shape stored in Service Catalogue

Scan records now store Snyk-native vulnerability data under `scan_summary.scan_result.snyk-vulns` and aggregate counts under `scan_summary.summary.snyk`.

Example:

```json
{
	"scan_summary": {
		"scan_result": {
			"snyk-vulns": [
				{
					"id": "SNYK-ALPINE319-OPENSSL-1234567",
					"title": "OpenSSL Out-of-Bounds Read",
					"severity": "HIGH",
					"packageName": "openssl",
					"packageManager": "apk",
					"version": "3.1.5-r0",
					"fixedIn": ["3.1.5-r2"],
					"description": "A vulnerability was discovered in OpenSSL...",
					"exploitMaturity": "proof-of-concept",
					"isUpgradable": true,
					"isPatchable": false,
					"cvssScore": 7.5,
					"cve": ["CVE-2025-0001"],
					"from": [
						"docker-image|ghcr.io/ministryofjustice/example:1.2.3",
						"openssl@3.1.5-r0"
					],
					"url": "https://security.snyk.io/vuln/SNYK-ALPINE319-OPENSSL-1234567"
				}
			]
		},
		"summary": {
			"snyk": {
				"severity": {
					"CRITICAL": 0,
					"HIGH": 1,
					"MEDIUM": 0,
					"LOW": 0,
					"UNKNOWN": 0
				},
				"fixable": {
					"fixable": 1,
					"not_fixable": 0
				},
				"total": 1
			}
		}
	}
}
```
