![cap](https://github.com/user-attachments/assets/c4a89d51-37fe-454a-b2ce-f641bfab7011)

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
python r3z.py -u example.com
```
```
python r3z.py -l sites.txt
```
```
python r3z.py -l sites.txt -t 10
```
```
python r3z.py -l sites.txt -k YOUR_NVD_API_KEY
```## Disclaimer

This tool is intended for legitimate security testing and vulnerability assessment of websites you own or have permission to test. Always obtain proper authorization before scanning any website. Unauthorized scanning may violate computer crime laws.

## Legal Notice

This tool is provided for educational and legitimate security testing purposes only. The author is not responsible for any misuse or damage caused by this tool.
