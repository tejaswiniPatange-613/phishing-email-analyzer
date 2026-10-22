# Phishing Email Analyzer

A Python-based cybersecurity project that analyzes `.eml` email files for potential phishing indicators. It includes a command-line interface (CLI) and a Flask-based web interface.

## Features

- Analyze email sender and Reply-To information
- Inspect SPF, DKIM, and DMARC authentication information when available
- Detect suspicious phrases
- Extract URLs and flag potentially suspicious URL patterns
- Identify selected HTML-related indicators
- Calculate a risk score and risk level
- Generate security recommendations
- Upload `.eml` files through a simple web interface
- Validate file extensions, empty uploads, and file size
- Run automated unit tests for the analyzer and web interface

## Technologies Used

- Python
- Flask
- HTML and CSS
- Python `email` package
- Python `unittest` framework

## Project Structure

```text
PhishingEmailAnalyzer/
├── app.py
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
├── samples/
│   └── test_email.eml
├── reports/
│   └── test_email_report.json
├── templates/
│   ├── index.html
│   └── results.html
└── tests/
    ├── test_analyzer.py
    └── test_web_app.py
```

## Requirements

- Python 3.10 or later recommended
- pip

## Installation

Clone the repository and open its directory:

```bash
git clone https://github.com/tejaswiniPatange-613/phishing-email-analyzer.git
cd phishing-email-analyzer
```

Install the dependencies:

```bash
python -m pip install -r requirements.txt
```

On Windows, you can use `py` instead of `python`.

## Run the Web Interface

Start the Flask application:

```bash
python app.py
```

Open this address in your browser:

```text
http://127.0.0.1:5000
```

Select an `.eml` file and click **Analyze Email** to view the analysis report.

The web interface accepts files up to 2 MB. Uploaded email content is processed in memory by the web route; it is not saved as an uploaded file by that route.

The built-in Flask server is intended for local development and testing, not production deployment.

## Run the Command-Line Analyzer

The original CLI remains available:

```bash
python main.py samples/test_email.eml
```

Use the command supported by your current `main.py` if its arguments differ. The CLI can generate a JSON report using the existing analyzer functionality.

## Run the Tests

Run all automated tests:

```bash
python -m unittest discover -s tests -v
```

The test suite covers the original analyzer and the web interface, including valid uploads and common validation errors.

## Security Notes

- A flagged indicator does not prove an email is malicious.
- Missing authentication results mean the status is unknown, not necessarily failed.
- Do not open suspicious URLs directly.
- Analyze only email files you are authorized to inspect.
- The local development server should not be exposed to untrusted networks.

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes. Automated findings should be reviewed alongside other evidence before making security decisions.