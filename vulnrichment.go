package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// CVEData represents the structure of the CVE JSON data
type CVEData struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	CveMetadata struct {
		CveId             string `json:"cveId"`
		AssignerOrgId     string `json:"assignerOrgId"`
		State             string `json:"state"`
		AssignerShortName string `json:"assignerShortName"`
		DateReserved      string `json:"dateReserved"`
		DatePublished     string `json:"datePublished"`
		DateUpdated       string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			ProviderMetadata struct {
				OrgId       string `json:"orgId"`
				ShortName   string `json:"shortName"`
				DateUpdated string `json:"dateUpdated"`
			} `json:"providerMetadata"`
			Title        string `json:"title"`
			ProblemTypes []struct {
				Descriptions []struct {
					Type        string `json:"type"`
					CweId       string `json:"cweId"`
					Lang        string `json:"lang"`
					Description string `json:"description"`
				} `json:"descriptions"`
			} `json:"problemTypes"`
			Affected []struct {
				Vendor   string `json:"vendor"`
				Product  string `json:"product"`
				Versions []struct {
					Version string `json:"version"`
					Status  string `json:"status"`
				} `json:"versions"`
				Modules []string `json:"modules"`
			} `json:"affected"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics []struct {
				CvssV3_1 struct {
					Version      string  `json:"version"`
					BaseScore    float64 `json:"baseScore"`
					VectorString string  `json:"vectorString"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssV3_1"`
				CvssV3_0 struct {
					Version      string  `json:"version"`
					BaseScore    float64 `json:"baseScore"`
					VectorString string  `json:"vectorString"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssV3_0"`
				CvssV2_0 struct {
					Version      string  `json:"version"`
					BaseScore    float64 `json:"baseScore"`
					VectorString string  `json:"vectorString"`
				} `json:"cvssV2_0"`
			} `json:"metrics"`
			Timeline []struct {
				Time  string `json:"time"`
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"timeline"`
			References []struct {
				Url  string   `json:"url"`
				Name string   `json:"name"`
				Tags []string `json:"tags"`
			} `json:"references"`
		} `json:"cna"`
		ADP []struct {
			Metrics []struct {
				Other struct {
					Type    string `json:"type"`
					Content struct {
						Exploitation string `json:"Exploitation,omitempty"`
					} `json:"content"`
				} `json:"other"`
			} `json:"metrics"`
			Affected []struct {
				Cpes     []string `json:"cpes"`
				Vendor   string   `json:"vendor"`
				Product  string   `json:"product"`
				Versions []struct {
					Status          string `json:"status"`
					Version         string `json:"version"`
					VersionType     string `json:"versionType"`
					LessThanOrEqual string `json:"lessThanOrEqual"`
				} `json:"versions"`
				DefaultStatus string `json:"defaultStatus"`
			} `json:"affected"`
			ProviderMetadata struct {
				ShortName   string `json:"shortName"`
				OrgId       string `json:"orgId"`
				DateUpdated string `json:"dateUpdated"`
			} `json:"providerMetadata"`
		} `json:"adp"`
	} `json:"containers"`
}

func main() {
	reportFlag := flag.Bool("report", false, "Generate a detailed report in Markdown format")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		fmt.Println("Usage: ./vulnrichment [--report] CVE-YYYY-NNNN")
		os.Exit(1)
	}

	cve := args[0]
	_, _, _, url := parseCVE(cve)

	// Fetch the file content using HTTP GET
	response, err := http.Get(url)
	if err != nil {
		fmt.Printf("Failed to retrieve the CVE file: %v\n", err)
		os.Exit(1)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		fmt.Printf("Failed to find the CVE file, received status code: %d\n", response.StatusCode)
		os.Exit(1)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Failed to read the CVE file content: %v\n", err)
		os.Exit(1)
	}

	if *reportFlag {
		generateReport(body)
	} else {
		fmt.Println(string(body))
	}
}

func parseCVE(cve string) (year string, id string, dir string, url string) {
	parts := strings.Split(cve, "-")
	if len(parts) != 3 {
		fmt.Println("Invalid CVE format. Please use CVE-YYYY-NNNN format.")
		os.Exit(1)
	}

	year = parts[1]
	id = parts[2]

	if strings.HasPrefix(id, "1") {
		dir = "1xxx"
	} else if strings.HasPrefix(id, "2") {
		dir = "2xxx"
	} else {
		fmt.Println("Unsupported CVE ID range. This example only supports IDs starting with 1 or 2.")
		os.Exit(1)
	}

	url = fmt.Sprintf("https://raw.githubusercontent.com/cisagov/vulnrichment/develop/%s/%s/%s.json", year, dir, cve)
	return
}

func generateReport(data []byte) {
	var cveData CVEData
	err := json.Unmarshal(data, &cveData)
	if err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("# CVE Detailed Report")
	fmt.Printf("## CVE ID: %s\n", cveData.CveMetadata.CveId)
	fmt.Printf("### State: %s\n", cveData.CveMetadata.State)
	fmt.Printf("### Published on: %s\n", cveData.CveMetadata.DatePublished)

	fmt.Println("### Description")
	for _, desc := range cveData.Containers.CNA.Descriptions {
		fmt.Printf("- %s (%s)\n", desc.Value, desc.Lang)
	}

	fmt.Println("### Affected Components")
	for _, aff := range cveData.Containers.CNA.Affected {
		fmt.Printf("- Vendor: %s\n- Product: %s\n", aff.Vendor, aff.Product)
		for _, ver := range aff.Versions {
			fmt.Printf("- Version: %s\n- Status: %s\n", ver.Version, ver.Status)
		}
		for _, mod := range aff.Modules {
			fmt.Printf("- Module: %s\n", mod)
		}
	}

	fmt.Println("### Problem Types")
	for _, prob := range cveData.Containers.CNA.ProblemTypes {
		for _, desc := range prob.Descriptions {
			fmt.Printf("- %s: %s (%s)\n", desc.CweId, desc.Description, desc.Lang)
		}
	}

	fmt.Println("### CVSS Scores")
	for _, met := range cveData.Containers.CNA.Metrics {
		if met.CvssV3_1.BaseScore != 0 {
			fmt.Printf("- CVSS v3.1: %s, Score: %.1f, Severity: %s\n", met.CvssV3_1.VectorString, met.CvssV3_1.BaseScore, met.CvssV3_1.BaseSeverity)
		}
		if met.CvssV3_0.BaseScore != 0 {
			fmt.Printf("- CVSS v3.0: %s, Score: %.1f, Severity: %s\n", met.CvssV3_0.VectorString, met.CvssV3_0.BaseScore, met.CvssV3_0.BaseSeverity)
		}
		if met.CvssV2_0.BaseScore != 0 {
			fmt.Printf("- CVSS v2.0: %s, Score: %.1f\n", met.CvssV2_0.VectorString, met.CvssV2_0.BaseScore)
		}
	}

	fmt.Println("### CPEs")
	for _, adp := range cveData.Containers.ADP {
		for _, aff := range adp.Affected {
			fmt.Printf("- CPE: %s, Vendor: %s, Product: %s, Version: %s\n", strings.Join(aff.Cpes, ", "), aff.Vendor, aff.Product, aff.Versions[0].Version)
		}
	}

	fmt.Println("### References")
	for _, ref := range cveData.Containers.CNA.References {
		fmt.Printf("- [%s](%s) (%s)\n", ref.Name, ref.Url, strings.Join(ref.Tags, ", "))
	}

	fmt.Println("### Timeline")
	for _, t := range cveData.Containers.CNA.Timeline {
		fmt.Printf("- %s: %s (%s)\n", t.Time, t.Value, t.Lang)
	}
}
