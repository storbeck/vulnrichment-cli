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
	Containers struct {
		CNA struct {
			DatePublic   string `json:"datePublic"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			References []struct {
				URL  string   `json:"url"`
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

	fmt.Println("# CVE Report")
	fmt.Printf("## CVE ID: %s\n", cveData.Containers.CNA.Descriptions[0].Value)
	fmt.Printf("### Date Published: %s\n", cveData.Containers.CNA.DatePublic)
	fmt.Println("### Description")
	for _, desc := range cveData.Containers.CNA.Descriptions {
		fmt.Printf("- %s\n", desc.Value)
	}
	fmt.Println("### References")
	for _, ref := range cveData.Containers.CNA.References {
		fmt.Printf("- [%s](%s)\n", ref.URL, ref.URL)
	}
	if len(cveData.Containers.ADP) > 0 && len(cveData.Containers.ADP[0].Metrics) > 0 {
		fmt.Println("### Exploitation Status")
		for _, metric := range cveData.Containers.ADP[0].Metrics {
			if metric.Other.Type == "ssvc" {
				if metric.Other.Content.Exploitation != "" {
					fmt.Printf("- Exploitation: %s\n", metric.Other.Content.Exploitation)
				} else {
					fmt.Println("- Exploitation: N/A")
				}
			}
		}
	}
}
