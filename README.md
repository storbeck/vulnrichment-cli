# vulnrichment-cli

## What It Does
This tool fetches enriched CVE data directly from the CISA Vulnrichment GitHub repo. It can also generate a Markdown report for a given CVE.

![Report Preview](preview.png?raw=true "Report")

## Setup
Build:
```bash
go build vulnrichment.go
```

## Usage
Run the tool with a CVE ID to fetch data:
```bash
./vulnrichment CVE-YYYY-NNNN
```
To generate a detailed report in Markdown format, use the `--report` flag:
```bash
./vulnrichment --report CVE-YYYY-NNNN
```
Accepts piped input
```bash
echo CVE-2024-3931 | ./vulnrichment --report
```

```markdown
# CVE Detailed Report
## CVE ID: CVE-2024-3931
### State: PUBLISHED
### Published on: 2024-04-18T00:00:04.983Z
### Description
- A vulnerability was found in Totara LMS 18.0.1 Build 20231128.01. It has been rated as problematic. Affected by this issue is some unknown functionality of the file admin/roles/check.php of the component Profile Handler. The manipulation of the argument ID Number leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-261368. NOTE: The vendor was contacted early about this disclosure but did not respond in any way. (en)
- Eine problematische Schwachstelle wurde in Totara LMS 18.0.1 Build 20231128.01 ausgemacht. Betroffen davon ist ein unbekannter Prozess der Datei admin/roles/check.php der Komponente Profile Handler. Durch Manipulieren des Arguments ID Number mit unbekannten Daten kann eine cross site scripting-Schwachstelle ausgenutzt werden. Die Umsetzung des Angriffs kann dabei über das Netzwerk erfolgen. Der Exploit steht zur öffentlichen Verfügung. (de)
### Affected Components
- Vendor: Totara
- Product: LMS
- Version: 18.0.1 Build 20231128.01
- Status: affected
- Module: Profile Handler
### Problem Types
- CWE-79: CWE-79 Cross Site Scripting (en)
### CVSS Scores
- CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N, Score: 3.5, Severity: LOW
- CVSS v3.0: CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N, Score: 3.5, Severity: LOW
- CVSS v2.0: AV:N/AC:L/Au:S/C:N/I:P/A:N, Score: 4.0
### CPEs
- CPE: cpe:2.3:a:totara:enterprise_lms:*:*:*:*:*:*:*:*, Vendor: totara, Product: enterprise_lms, Version: *
### References
- [VDB-261368 | Totara LMS Profile check.php cross site scripting](https://vuldb.com/?id.261368) (vdb-entry, technical-description)
- [VDB-261368 | CTI Indicators (IOB, IOC, TTP, IOA)](https://vuldb.com/?ctiid.261368) (signature, permissions-required)
### Timeline
- 2024-04-17T00:00:00.000Z: Advisory disclosed (en)
- 2024-04-17T02:00:00.000Z: VulDB entry created (en)
- 2024-04-17T19:02:53.000Z: VulDB entry last update (en)
```
