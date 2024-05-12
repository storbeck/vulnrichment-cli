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

## Example
### Report
```bash
$ ./vulnrichment --report CVE-2024-3931
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
### json
```bash
$ ./vulnrichment CVE-2015-2051
```
```json
{
  "containers": {
    "cna": {
      "affected": [
        {
          "product": "n/a",
          "vendor": "n/a",
          "versions": [
            {
              "status": "affected",
              "version": "n/a"
            }
          ]
        }
      ],
      "datePublic": "2015-02-13T00:00:00",
      "descriptions": [
        {
          "lang": "en",
          "value": "The D-Link DIR-645 Wired/Wireless Router Rev. Ax with firmware 1.04b12 and earlier allows remote attackers to execute arbitrary commands via a GetDeviceSettings action to the HNAP interface."
        }
      ],
      "problemTypes": [
        {
          "descriptions": [
            {
              "description": "n/a",
              "lang": "en",
              "type": "text"
            }
          ]
        }
      ],
      "providerMetadata": {
        "dateUpdated": "2016-12-29T18:57:01",
        "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
        "shortName": "mitre"
      },
      "references": [
        {
          "tags": [
            "x_refsource_CONFIRM"
          ],
          "url": "http://securityadvisories.dlink.com/security/publication.aspx?name=SAP10051"
        },
        {
          "name": "37171",
          "tags": [
            "exploit",
            "x_refsource_EXPLOIT-DB"
          ],
          "url": "https://www.exploit-db.com/exploits/37171/"
        },
        {
          "name": "72623",
          "tags": [
            "vdb-entry",
            "x_refsource_BID"
          ],
          "url": "http://www.securityfocus.com/bid/72623"
        },
        {
          "name": "74870",
          "tags": [
            "vdb-entry",
            "x_refsource_BID"
          ],
          "url": "http://www.securityfocus.com/bid/74870"
        }
      ],
      "x_legacyV4Record": {
        "CVE_data_meta": {
          "ASSIGNER": "cve@mitre.org",
          "ID": "CVE-2015-2051",
          "STATE": "PUBLIC"
        },
        "affects": {
          "vendor": {
            "vendor_data": [
              {
                "product": {
                  "product_data": [
                    {
                      "product_name": "n/a",
                      "version": {
                        "version_data": [
                          {
                            "version_value": "n/a"
                          }
                        ]
                      }
                    }
                  ]
                },
                "vendor_name": "n/a"
              }
            ]
          }
        },
        "data_format": "MITRE",
        "data_type": "CVE",
        "data_version": "4.0",
        "description": {
          "description_data": [
            {
              "lang": "eng",
              "value": "The D-Link DIR-645 Wired/Wireless Router Rev. Ax with firmware 1.04b12 and earlier allows remote attackers to execute arbitrary commands via a GetDeviceSettings action to the HNAP interface."
            }
          ]
        },
        "problemtype": {
          "problemtype_data": [
            {
              "description": [
                {
                  "lang": "eng",
                  "value": "n/a"
                }
              ]
            }
          ]
        },
        "references": {
          "reference_data": [
            {
              "name": "http://securityadvisories.dlink.com/security/publication.aspx?name=SAP10051",
              "refsource": "CONFIRM",
              "url": "http://securityadvisories.dlink.com/security/publication.aspx?name=SAP10051"
            },
            {
              "name": "37171",
              "refsource": "EXPLOIT-DB",
              "url": "https://www.exploit-db.com/exploits/37171/"
            },
            {
              "name": "72623",
              "refsource": "BID",
              "url": "http://www.securityfocus.com/bid/72623"
            },
            {
              "name": "74870",
              "refsource": "BID",
              "url": "http://www.securityfocus.com/bid/74870"
            }
          ]
        }
      }
    },
    "adp": [
      {
        "metrics": [
          {
            "cvssV3_1": {
              "scope": "UNCHANGED",
              "version": "3.1",
              "baseScore": 8.8,
              "attackVector": "ADJACENT",
              "baseSeverity": "HIGH",
              "vectorString": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "integrityImpact": "HIGH",
              "userInteraction": "NONE",
              "attackComplexity": "LOW",
              "availabilityImpact": "HIGH",
              "privilegesRequired": "NONE",
              "confidentialityImpact": "HIGH"
            }
          },
          {
            "other": {
              "type": "ssvc",
              "content": {
                "id": "CVE-2015-2051",
                "role": "CISA Coordinator",
                "options": [
                  {
                    "Exploitation": "active"
                  },
                  {
                    "Automatable": "no"
                  },
                  {
                    "Technical Impact": "total"
                  }
                ],
                "version": "2.0.3",
                "timestamp": "2024-05-02T18:31:27.959147Z"
              }
            }
          },
          {
            "other": {
              "type": "kev",
              "content": {
                "dateAdded": "2022-02-10",
                "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2015-2051"
              }
            }
          }
        ],
        "affected": [
          {
            "cpes": [
              "cpe:2.3:h:dlink:dir-645:*:*:*:*:*:*:*:*"
            ],
            "vendor": "dlink",
            "product": "dir-645",
            "versions": [
              {
                "status": "affected",
                "version": "*",
                "versionType": "custom",
                "lessThanOrEqual": "1.04b12"
              }
            ],
            "defaultStatus": "unknown"
          },
          {
            "cpes": [
              "cpe:2.3:o:dlink:dir-645_firmware:1.03:*:*:*:*:*:*:*"
            ],
            "vendor": "dlink",
            "product": "dir-645_firmware",
            "versions": [
              {
                "status": "affected",
                "version": "1.03",
                "versionType": "custom",
                "lessThanOrEqual": "1.04b12"
              }
            ],
            "defaultStatus": "unknown"
          }
        ],
        "problemTypes": [
          {
            "descriptions": [
              {
                "lang": "en",
                "type": "CWE",
                "cweId": "CWE-77",
                "description": "CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')"
              }
            ]
          }
        ],
        "providerMetadata": {
          "shortName": "CISAADP",
          "orgId": "8c464350-323a-4346-a867-fc54517fa145",
          "dateUpdated": "2024-05-02T18:40:39.885Z"
        }
      }
    ]
  },
  "cveMetadata": {
    "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
    "assignerShortName": "mitre",
    "cveId": "CVE-2015-2051",
    "datePublished": "2015-02-23T17:00:00",
    "dateReserved": "2015-02-23T00:00:00",
    "dateUpdated": "2016-12-29T18:57:01",
    "state": "PUBLISHED"
  },
  "dataType": "CVE_RECORD",
  "dataVersion": "5.0"
}
```
