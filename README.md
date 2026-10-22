
# Phishing Email Analyzer

A Python-based cybersecurity tool that analyzes `.eml` email files and identifies common indicators associated with phishing attempts. It examines sender information, Reply-To mismatches, reported email authentication results, suspicious phrases, URLs, and basic HTML link mismatches.

The analyzer generates a heuristic risk score and saves its findings as a JSON report for further investigation.

## Features

- **Email parsing:** Extracts sender, subject, Reply-To, and message content from `.eml` files.
- **Sender analysis:** Checks for basic sender-address formatting concerns.
- **Reply-To analysis:** Flags potential domain mismatches between the sender and Reply-To address.
- **Authentication analysis:** Reads reported SPF, DKIM, and DMARC results from `Authentication-Results` headers.
- **Suspicious phrase detection:** Identifies predefined phrases commonly associated with phishing attempts.
- **URL analysis:** Flags URLs containing IP addresses, known URL shorteners, and other basic indicators.
- **HTML link analysis:** Checks for potential mismatches between visible link text and hyperlink destinations.
- **Risk assessment:** Calculates a rule-based risk score and classifies the result as Low, Medium, or High.
- **Recommendations:** Provides investigation guidance based on detected indicators.
- **JSON reporting:** Saves analysis results for review and documentation.
- **Automated testing:** Includes unit tests for key detection and reporting functions.

## Technologies Used

- Python
- Python standard library
- Email parsing (`email`)
- Regular expressions (`re`)
- URL parsing (`urllib.parse`)
- HTML parsing (`html.parser`)
- JSON reporting (`json`)
- Unit testing (`unittest`)

No third-party Python packages are required.

## Project Structure

~~~text
PhishingEmailAnalyzer/
|-- main.py
|-- README.md
|-- .gitignore
|-- samples/
|   `-- test_email.eml
|-- reports/
|   `-- test_email_report.json
`-- tests/
    `-- test_analyzer.py
~~~

## Requirements

- Python 3.10 or newer
- Windows, Linux, or macOS
- Git for version control and GitHub publishing

## How to Run

### 1. Clone the repository

~~~bash
git clone https://github.com/YOUR_USERNAME/phishing-email-analyzer.git
cd phishing-email-analyzer
~~~

Replace `YOUR_USERNAME` with your GitHub username.

### 2. Analyze the sample email

On Windows:

~~~powershell
py main.py
~~~

On systems where `py` is unavailable:

~~~bash
python main.py
~~~

### 3. Analyze another email file

~~~powershell
py main.py path\to\email.eml
~~~

Replace the example path with the path to your local `.eml` file.

### 4. Run the automated tests

~~~powershell
py -m unittest discover -s tests -v
~~~

The test suite covers suspicious phrases, URLs, sender information, Reply-To mismatches, authentication results, HTML links, recommendations, and JSON report generation.

## Example Output

The included synthetic sample email produces a **Medium** risk classification with a score of **5/10**.

Detected indicators include:

- Suspicious wording related to account verification.
- A URL containing an IP address.
- A URL using a known shortening service.
- Missing authentication results, leaving SPF, DKIM, and DMARC status unknown.

The score is a heuristic indicator, not a probability that an email is malicious.

## How It Works

1. Loads and parses the `.eml` message.
2. Extracts relevant headers and message content.
3. Checks sender details and Reply-To information.
4. Reads available authentication results from message headers.
5. Searches message content for suspicious phrases and URL indicators.
6. Inspects available HTML hyperlinks for basic mismatches.
7. Calculates a rule-based risk score and generates recommendations.
8. Saves the findings to a JSON report.

## Limitations

- Detection uses predefined rules and does not use a trained machine-learning model.
- SPF, DKIM, and DMARC results are read from available headers; the tool does not independently verify these protocols.
- Missing authentication information is treated as unknown, not as proof of failure.
- HTML analysis is basic and does not execute JavaScript or render a browser page.
- The risk score is heuristic and may produce false positives or miss sophisticated phishing attempts.
- The tool does not open URLs, query live threat-intelligence services, or automatically block emails.

Use the results as supporting evidence for an investigation, not as a final verdict.

## Safe Testing

The included email is a synthetic test sample intended for learning and demonstration. Its URLs are indicators for analysis and should not be opened.

For real investigations, follow organizational policies and use approved, isolated analysis environments.

## Future Improvements

- Integration with approved threat-intelligence services.
- More comprehensive email-header analysis.
- Additional URL and domain reputation checks.
- Configurable detection rules and risk weights.
- HTML and text report export.
- Expanded test coverage.

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes. It does not guarantee phishing detection and should not replace established email security controls or analyst judgment.
