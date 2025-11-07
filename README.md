
# HTML-Analyzer
![Logo](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExZHRjbjZrcGJtZjl4dGRpYmt4b2FodzBwazJwZ3hxdWkxMGZkbTI3byZlcD12MV9naWZzX3NlYXJjaCZjdD1n/l3vRfNA1p0rvhMSvS/giphy.gif)

![Static Badge](https://img.shields.io/badge/Made_in-KSA-orange)

Python tool for web security reconnaissance, extracting external endpoints, form data, and hidden API keys from local or live HTML pages.

## About HTML-Analyzer

- Supports analyzing local HTML files or live URLs.
- Extracts all external links from scripts, images, iframes, and stylesheets.
- Detects API keys, tokens, and secrets using regex patterns.
- Finds and categorizes external domains with trust hints.
- Extracts all form fields and user input elements.
- Parses HTML comments for hidden information.
- Saves detailed reports in TXT and CSV formats.
- Automatically organizes outputs in html_analysis_output/.
- Handles network and parsing errors gracefully.
- Simple, fast, and built with clean Python libraries (requests, bs4, pandas).


## Installation
Download or clone this repo

```bash
  git clone https://github.com/snoopzx/HTML-Analyzer
  cd HTML-Analyzer
  pip install -r requirements.txt
```
## Usage
URL Analyze
```bash
python HTML-Analyzer.py -u #or --url https://google.com
```
HTML File Analyze
```bash
python HTML-Analyzer.py -f #or --file google.html #or File Path
```

## License
Educational and authorized security research use only. See LICENSE file.
[MIT](https://choosealicense.com/licenses/mit/)

