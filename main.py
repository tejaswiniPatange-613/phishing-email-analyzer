
import argparse
import ipaddress
import json
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_EMAIL_PATH = Path("samples/test_email.eml")
REPORT_DIR = Path("reports")

SUSPICIOUS_PHRASES = [
    "urgent",
    "verify your account",
    "click here",
    "account suspended",
    "confirm your password",
    "immediate action required",
]

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
}

AUTH_METHODS = ("spf", "dkim", "dmarc")


class EmailHTMLParser(HTMLParser):
    """Extract hyperlinks and their displayed text from HTML email."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.current_link = None
        self.visible_text = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        if tag.lower() == "a":
            self.current_link = {
                "url": attributes.get("href", ""),
                "text": "",
            }
            self.links.append(self.current_link)

    def handle_data(self, data):
        if self.current_link is not None:
            self.current_link["text"] += data

        self.visible_text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a":
            self.current_link = None


def load_email(email_path):
    """Read and parse an email file."""
    if not email_path.is_file():
        raise FileNotFoundError(
            f"Email file not found: {email_path}"
        )

    raw_email = email_path.read_bytes().lstrip(b"\r\n")
    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_email)

    if not message.keys():
        raise ValueError(
            "The file does not appear to contain email headers."
        )

    return message


def analyze_sender(sender):
    """Check basic formatting indicators in the sender address."""
    findings = []
    display_name, address = parseaddr(sender)

    if not address or "@" not in address:
        findings.append(
            "Sender email address is missing or could not be parsed."
        )
        return findings

    if address.count("@") != 1:
        findings.append(
            "Sender email address has an unusual format."
        )
        return findings

    local_part, domain = address.rsplit("@", 1)

    if not local_part or not domain or "." not in domain:
        findings.append(
            "Sender email address may be malformed."
        )
        return findings

    if any(character.isspace() for character in address):
        findings.append(
            "Sender email address contains whitespace."
        )

    if display_name and address.lower() in display_name.lower():
        findings.append(
            "Display name repeats the full sender address."
        )

    return findings


def analyze_reply_to(sender, reply_to):
    """Flag Reply-To addresses that use a different domain."""
    findings = []

    if not reply_to:
        return findings

    _, sender_address = parseaddr(sender)
    _, reply_address = parseaddr(reply_to)

    if "@" not in sender_address or "@" not in reply_address:
        findings.append(
            "Could not reliably compare the From and Reply-To addresses."
        )
        return findings

    sender_domain = sender_address.rsplit("@", 1)[1].lower().rstrip(".")
    reply_domain = reply_address.rsplit("@", 1)[1].lower().rstrip(".")

    if sender_domain != reply_domain:
        findings.append(
            f"Reply-To domain '{reply_domain}' differs from "
            f"sender domain '{sender_domain}'. Investigate this mismatch."
        )

    return findings


def analyze_authentication(message):
    """Extract reported SPF, DKIM, and DMARC results from headers."""
    headers = message.get_all("Authentication-Results", [])
    findings = []
    results = {method: [] for method in AUTH_METHODS}

    if not headers:
        return {
            "results": results,
            "findings": [
                "No Authentication-Results header was found. "
                "Authentication status is unknown."
            ],
        }

    for header in headers:
        value = str(header).lower()

        for method in AUTH_METHODS:
            pattern = (
                rf"(?<![\w-]){method}\s*=\s*"
                rf"(pass|fail|softfail|neutral|none|"
                rf"temperror|permerror)"
            )

            for result in re.findall(pattern, value):
                if result not in results[method]:
                    results[method].append(result)

    for method, reported_results in results.items():
        if not reported_results:
            findings.append(
                f"No {method.upper()} result was recognized "
                "in the Authentication-Results headers."
            )
        elif "fail" in reported_results:
            findings.append(
                f"{method.upper()} has a reported fail result."
            )
        elif "permerror" in reported_results:
            findings.append(
                f"{method.upper()} has a reported permanent error."
            )
        elif "temperror" in reported_results:
            findings.append(
                f"{method.upper()} has a reported temporary error."
            )
        elif "softfail" in reported_results:
            findings.append(
                f"{method.upper()} has a reported softfail result."
            )
        elif "pass" in reported_results:
            findings.append(
                f"{method.upper()} has a reported pass result."
            )
        else:
            findings.append(
                f"{method.upper()} result: "
                f"{', '.join(reported_results)}."
            )

    findings.append(
        "Reported header results are not independently verified."
    )

    return {
        "results": results,
        "findings": findings,
    }


def get_email_content(message):
    """Extract plain text, HTML content, and HTML hyperlinks."""
    plain_parts = []
    html_parts = []

    for part in message.walk():
        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()

        if content_type not in {"text/plain", "text/html"}:
            continue

        try:
            content = part.get_content()
        except (LookupError, UnicodeError, ValueError):
            continue

        if not isinstance(content, str):
            continue

        if content_type == "text/plain":
            plain_parts.append(content)
        else:
            html_parts.append(content)

    html_links = []
    html_findings = []
    html_visible_text = []

    for html_content in html_parts:
        parser = EmailHTMLParser()

        try:
            parser.feed(html_content)
            parser.close()
        except Exception:
            html_findings.append(
                "Some HTML content could not be fully parsed."
            )
            continue

        html_links.extend(parser.links)
        html_visible_text.extend(parser.visible_text)

    body = "\n".join(plain_parts)

    if not body and html_visible_text:
        body = "\n".join(html_visible_text)

    for link in html_links:
        destination = link["url"].strip()
        displayed_text = link["text"].strip()

        if not destination:
            html_findings.append(
                "An HTML hyperlink has no destination."
            )
            continue

        parsed_destination = urlparse(destination)

        if (
            parsed_destination.scheme.lower() in {"http", "https"}
            and parsed_destination.hostname
            and displayed_text
        ):
            displayed_url = re.search(
                r"https?://[^\s]+",
                displayed_text,
                re.IGNORECASE,
            )

            if displayed_url:
                displayed_parsed = urlparse(
                    displayed_url.group(0).rstrip(".,!?;:)")
                )

                displayed_host = (
                    displayed_parsed.hostname or ""
                ).lower().rstrip(".")

                destination_host = (
                    parsed_destination.hostname or ""
                ).lower().rstrip(".")

                if displayed_host != destination_host:
                    html_findings.append(
                        "Displayed link text points to a different "
                        "host than the actual HTML link destination."
                    )

    return body, html_parts, html_links, html_findings


def analyze_urls(body, html_links):
    """Extract URLs and flag basic suspicious URL indicators."""
    url_pattern = r'https?://[^\s<>"\']+'
    extracted_urls = re.findall(url_pattern, body, re.IGNORECASE)

    for link in html_links:
        destination = link["url"].strip()

        if destination.lower().startswith(("http://", "https://")):
            extracted_urls.append(destination)

    unique_urls = []
    seen_urls = set()

    for found_url in extracted_urls:
        url = found_url.rstrip(".,!?;:)")
        if url not in seen_urls:
            unique_urls.append(url)
            seen_urls.add(url)

    url_findings = []
    ip_url_count = 0
    shortener_count = 0

    for url in unique_urls:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        if not hostname:
            url_findings.append(
                f"Could not determine hostname: {url}"
            )
            continue

        hostname = hostname.lower().rstrip(".")

        try:
            ipaddress.ip_address(hostname)
            ip_url_count += 1
            url_findings.append(
                f"URL uses an IP address instead of a domain: {url}"
            )
        except ValueError:
            pass

        if hostname in URL_SHORTENERS:
            shortener_count += 1
            url_findings.append(
                f"URL uses a common shortening service: {url}"
            )

        if "@" in parsed_url.netloc:
            url_findings.append(
                f"URL contains '@', which may obscure its destination: {url}"
            )

        if hostname.startswith("xn--") or ".xn--" in hostname:
            url_findings.append(
                f"URL contains an internationalized domain label "
                f"that merits inspection: {url}"
            )

    return unique_urls, url_findings, ip_url_count, shortener_count


def generate_recommendations(results):
    """Suggest investigation steps based on detected indicators."""
    recommendations = []
    authentication = results["authentication_analysis"]
    auth_results = authentication["results"]

    failed_statuses = {
        "fail", "softfail", "permerror", "temperror"
    }

    auth_concerns = any(
        any(status in failed_statuses for status in statuses)
        for statuses in auth_results.values()
    )

    had_indicators = bool(
        results["sender_findings"]
        or results["reply_to_findings"]
        or results["phrase_findings"]
        or results["url_findings"]
        or results["html_findings"]
        or auth_concerns
    )

    if results["sender_findings"]:
        recommendations.append(
            "Review the sender address and display name. "
            "Confirm the sender through a trusted channel if necessary."
        )

    if results["reply_to_findings"]:
        recommendations.append(
            "Investigate the From and Reply-To mismatch. "
            "Verify the intended reply address independently."
        )

    if results["phrase_findings"]:
        recommendations.append(
            "Review suspicious wording in context. "
            "Keywords alone do not prove phishing."
        )

    if results["url_findings"] or results["html_findings"]:
        recommendations.append(
            "Investigate flagged URLs and HTML links without opening "
            "them directly. Use approved security tools or an isolated "
            "analysis environment."
        )

    for method, reported_results in auth_results.items():
        if any(status in failed_statuses for status in reported_results):
            recommendations.append(
                f"Review the reported {method.upper()} result using "
                "trusted mail-server logs and authentication data."
            )

    if not any(auth_results.values()):
        recommendations.append(
            "Authentication status is unknown. Review trusted "
            "mail-server logs; missing headers do not prove failure."
        )

    if not had_indicators:
        recommendations.append(
            "No configured indicators were detected. Continue normal "
            "security review; this result does not guarantee that "
            "the email is safe."
        )

    recommendations.append(
        "Correlate findings with other evidence before deciding "
        "whether to quarantine, block, or escalate the email."
    )

    return recommendations


def analyze_email(message):
    """Analyze sender, headers, content, URLs, and risk indicators."""
    sender = message.get("From", "Unknown")
    subject = message.get("Subject", "No subject")
    reply_to = message.get("Reply-To", "")

    sender_findings = analyze_sender(sender)
    reply_to_findings = analyze_reply_to(sender, reply_to)
    authentication = analyze_authentication(message)

    body, html_parts, html_links, html_findings = get_email_content(
        message
    )

    text_to_check = f"{subject}\n{body}".lower()

    phrase_findings = [
        f"Suspicious phrase detected: '{phrase}'"
        for phrase in SUSPICIOUS_PHRASES
        if phrase in text_to_check
    ]

    urls, url_findings, ip_url_count, shortener_count = analyze_urls(
        body, html_links
    )

    failed_auth_count = sum(
        1
        for method_results in authentication["results"].values()
        if any(
            result in {"fail", "permerror"}
            for result in method_results
        )
    )

    reply_mismatch_count = len(reply_to_findings)
    html_mismatch_count = sum(
        "different host" in finding.lower()
        for finding in html_findings
    )

    score = min(
        len(phrase_findings)
        + len(sender_findings)
        + 2 * ip_url_count
        + shortener_count
        + 2 * failed_auth_count
        + reply_mismatch_count
        + html_mismatch_count,
        10,
    )

    if score <= 2:
        risk_level = "Low"
    elif score <= 5:
        risk_level = "Medium"
    else:
        risk_level = "High"

    results = {
        "sender": sender,
        "subject": subject,
        "reply_to": reply_to or "Not specified",
        "sender_findings": sender_findings,
        "reply_to_findings": reply_to_findings,
        "authentication_analysis": authentication,
        "phrase_findings": phrase_findings,
        "urls": urls,
        "url_findings": url_findings,
        "html_findings": list(dict.fromkeys(html_findings)),
        "html_links_found": len(html_links),
        "risk_score": score,
        "risk_level": risk_level,
    }

    results["recommendations"] = generate_recommendations(results)
    return results


def save_report(results, email_path):
    """Save analysis results as a JSON report."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report_path = REPORT_DIR / f"{email_path.stem}_report.json"

    report = {
        "analysis_time_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "source_file": str(email_path),
        "email_analysis": results,
        "disclaimer": (
            "This is a rule-based demonstration, not a definitive "
            "phishing detector. Risk scores are heuristic. Reported "
            "authentication results are not independently verified. "
            "A low score does not guarantee that an email is safe."
        ),
    }

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    return report_path


def display_results(results, report_path):
    """Display analysis results in the terminal."""
    print("===== PHISHING EMAIL ANALYZER =====")
    print(f"Sender: {results['sender']}")
    print(f"Subject: {results['subject']}")
    print(f"Reply-To: {results['reply_to']}")

    print("\n===== SENDER ANALYSIS =====")
    if results["sender_findings"]:
        for finding in results["sender_findings"]:
            print(f"[!] {finding}")
    else:
        print("[+] No basic sender-format concerns detected.")

    print("\n===== REPLY-TO ANALYSIS =====")
    if results["reply_to_findings"]:
        for finding in results["reply_to_findings"]:
            print(f"[!] {finding}")
    else:
        print("[+] No Reply-To domain mismatch detected.")

    print("\n===== AUTHENTICATION ANALYSIS =====")
    authentication = results["authentication_analysis"]

    for method, reported_results in authentication["results"].items():
        if reported_results:
            print(f"{method.upper()}: {', '.join(reported_results)}")
        else:
            print(f"{method.upper()}: Unknown")

    for finding in authentication["findings"]:
        print(f"[!] {finding}")

    print("\n===== PHRASE ANALYSIS =====")
    if results["phrase_findings"]:
        for finding in results["phrase_findings"]:
            print(f"[!] {finding}")
    else:
        print("[+] No configured suspicious phrases detected.")

    print("\n===== URL ANALYSIS =====")
    if results["urls"]:
        for url in results["urls"]:
            print(f"URL found: {url}")

        for finding in results["url_findings"]:
            print(f"[!] {finding}")
    else:
        print("[+] No URLs found in the email content.")

    print("\n===== HTML ANALYSIS =====")
    print(f"HTML hyperlinks found: {results['html_links_found']}")

    if results["html_findings"]:
        for finding in results["html_findings"]:
            print(f"[!] {finding}")
    else:
        print("[+] No configured HTML link mismatches detected.")

    print("\n===== RISK ASSESSMENT =====")
    print(f"Risk score: {results['risk_score']}/10")
    print(f"Risk level: {results['risk_level']}")

    print("\n===== RECOMMENDATIONS =====")
    for number, recommendation in enumerate(
        results["recommendations"], start=1
    ):
        print(f"{number}. {recommendation}")

    print("\n===== REPORT =====")
    print(f"JSON report saved to: {report_path.resolve()}")
    print("\nNote: Indicators are clues, not proof of phishing.")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze an .eml file for basic phishing indicators."
    )
    parser.add_argument(
        "email_file",
        nargs="?",
        default=str(DEFAULT_EMAIL_PATH),
        help="Path to an .eml file (default: samples/test_email.eml)",
    )

    args = parser.parse_args()
    email_path = Path(args.email_file)

    message = load_email(email_path)
    results = analyze_email(message)
    report_path = save_report(results, email_path)
    display_results(results, report_path)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"Error: {error}")
