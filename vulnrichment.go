package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./vulnrichment CVE-YYYY-NNNN")
		os.Exit(1)
	}

	cve := os.Args[1]
	parts := strings.Split(cve, "-")
	if len(parts) != 3 {
		fmt.Println("Invalid CVE format. Please use CVE-YYYY-NNNN format.")
		os.Exit(1)
	}

	year := parts[1]
	id := parts[2]

	// Determine the directory based on the CVE ID
	var dir string
	if strings.HasPrefix(id, "1") {
		dir = "1xxx"
	} else if strings.HasPrefix(id, "2") {
		dir = "2xxx"
	} else {
		fmt.Println("Unsupported CVE ID range. This example only supports IDs starting with 1 or 2.")
		os.Exit(1)
	}

	// Construct the URL to the raw JSON file in the GitHub repo
	url := fmt.Sprintf("https://raw.githubusercontent.com/cisagov/vulnrichment/develop/%s/%s/%s.json", year, dir, cve)

	// Fetch the file content using HTTP GET
	response, err := http.Get(url)
	if err != nil {
		fmt.Println("Failed to retrieve the CVE file:", err)
		os.Exit(1)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		fmt.Println("Failed to find the CVE file, received status code:", response.StatusCode)
		os.Exit(1)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Failed to read the CVE file content:", err)
		os.Exit(1)
	}

	fmt.Println(string(body))
}
