![cap](https://github.com/user-attachments/assets/c4a89d51-37fe-454a-b2ce-f641bfab7011)
# WordPress Vulnerability Scanner

This tool scans WordPress sites for potential security vulnerabilities without exploiting them. It can identify common security issues, plugins, and themes, and automatically fetches CVE vulnerability data to provide detailed information about known security issues.

## Features

- Detects WordPress installations and version information
- Scans for common WordPress security misconfigurations
- Identifies installed plugins and themes
- **Automatically fetches CVE vulnerability data** for WordPress core, plugins, and themes
- Provides CVSS scores and detailed vulnerability information with references
- Supports scanning multiple sites from a list file
- Multi-threaded for faster scanning
- Generates comprehensive reports of findings with vulnerability details

## Requirements

- Python 3.6+
- Required Python packages:
  - requests
  - argparse
  - urllib3
  - concurrent.futures (included in Python standard library)

## Installation

1. Make sure you have Python 3.6 or higher installed
2. Install required packages:

```
pip install -r requirements.txt
```

Or install packages individually:

```
pip install requests urllib3 argparse
```

## Usage

### Scanning a single site

```
python wp_vulnerability_scanner.py -u example.com
```

### Scanning multiple sites from a list

Create a text file (e.g., `sites.txt`) with one URL per line:

```
example1.com
example2.com
example3.com
```

Then run:

```
python wp_vulnerability_scanner.py -l sites.txt
```

### Adjusting thread count for multiple scans

```
python wp_vulnerability_scanner.py -l sites.txt -t 10
```

### Using an NVD API Key for enhanced CVE data fetching

For better rate limits and more reliable CVE data, you can obtain an API key from the [NVD website](https://nvd.nist.gov/developers/request-an-api-key) and use it with the scanner:

```
python wp_vulnerability_scanner.py -u example.com -k YOUR_NVD_API_KEY
```

Or with a list of sites:

```
python wp_vulnerability_scanner.py -l sites.txt -k YOUR_NVD_API_KEY
```

## Output

The scanner will display results in the console and save a detailed report to a text file (default: `vuln.txt`). The report includes:

- WordPress version information
- Detected configuration issues
- List of detected plugins and themes
- CVE vulnerability details including:
  - CVE IDs
  - CVSS scores
  - Vulnerability descriptions
  - References to security advisories and patches

## Disclaimer

This tool is intended for legitimate security testing and vulnerability assessment of websites you own or have permission to test. Always obtain proper authorization before scanning any website. Unauthorized scanning may violate computer crime laws.

## Legal Notice

This tool is provided for educational and legitimate security testing purposes only. The author is not responsible for any misuse or damage caused by this tool.
