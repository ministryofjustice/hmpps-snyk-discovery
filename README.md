# hmpps-snyk-discovery

Service that will run Snyk image scans on HMPPS container images and pushes the results into the service catalogue where they can be displayed in developer portal 

The app does the following:
- Retrieves a list of all components (microservices) from the service catalogue.
- For each component it fetches container image details for each environment.
- It then runs the Snyk container image scan and updates the service catalogue with can results. 

Results are visible via the developer portal, e.g.

https://developer-portal.hmpps.service.justice.gov.uk/components/snyk

## Local Testing Modes

Test without proxy (local only):

```bash
unset HTTPS_PROXY HTTP_PROXY NO_PROXY https_proxy http_proxy no_proxy
export ALLOW_NO_PROXY_LOCAL=true
uv run python -u snyk_discovery.py -i
```

## Service Catalogue table structure

This branch stores scan and vulnerability data in two tables and performs a final
end-of-job enrichment step to attach CVE details to each scan record.

### `snyk-scans`

One record per scanned image/environment. Key fields:

- `name`
- `build_image_tag`
- `image_id`
- `scan_status`
- Severity counters:
	- `critical_fixable`, `critical_unfixable`
	- `high_fixable`, `high_unfixable`
	- `medium_fixable`, `medium_unfixable`
	- `low_fixable`, `low_unfixable`
	- `unknown_fixable`, `unknown_unfixable`
- `snyk_ids` (array of Snyk issue IDs)
- `snyk_cves` (JSON array of `{snyk_id, cves}` added at end of job)

Example:

```json
{
	"name": "hmpps-education-employment-ui",
	"build_image_tag": "2026-05-22.318.c84ac66",
	"scan_status": "Succeeded",
	"image_id": "ghcr.io/ministryofjustice/hmpps-education-employment-ui:2026-05-22.318.c84ac66",
	"critical_fixable": 0,
	"critical_unfixable": 0,
	"high_fixable": 2,
	"high_unfixable": 0,
	"medium_fixable": 0,
	"medium_unfixable": 0,
	"low_fixable": 0,
	"low_unfixable": 0,
	"unknown_fixable": 0,
	"unknown_unfixable": 0,
	"snyk_ids": [
		"SNYK-UPSTREAM-NODE-15764932",
		"SNYK-UPSTREAM-NODE-15764510"
	],
	"snyk_cves": [
		{
			"snyk_id": "SNYK-UPSTREAM-NODE-15764932",
			"cves": ["CVE-2024-22020"]
		},
		{
			"snyk_id": "SNYK-UPSTREAM-NODE-15764510",
			"cves": []
		}
	]
}
```

### `snyk-vulnerabilities`

One record per `snyk_id`, enriched/merged across scans. Key fields:

- `snyk_id`
- `title`
- `description`
- `severity`
- `cves`
- `published_date`
- `fix_available`
- `affected_package_name`
- `affected_versions`
- `fixed_versions`
- `cvss_score`
- `exploit_maturity`

Example:

```json
{
	"snyk_id": "SNYK-UPSTREAM-NODE-15764932",
	"title": "Access Restriction Bypass",
	"description": "...",
	"severity": "MEDIUM",
	"cves": ["CVE-2024-22020"],
	"published_date": "2024-07-09",
	"fix_available": "True",
	"affected_package_name": "node",
	"affected_versions": ["20.11.1"],
	"fixed_versions": ["18.20.4", "20.15.1", "22.4.1"],
	"cvss_score": 6.9,
	"exploit_maturity": "Not Defined"
}
```
