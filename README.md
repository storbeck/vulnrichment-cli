# Vulnrichment

## What It Does
This tool fetches enriched CVE data directly from the CISA Vulnrichment GitHub repo. It can also generate a Markdown report for a given CVE.

## Setup
1. **Build:**
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