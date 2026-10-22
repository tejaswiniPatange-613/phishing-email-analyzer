
from io import BytesIO
from email import policy
from email.parser import BytesParser
from pathlib import Path

from flask import Flask, render_template, request

from main import analyze_email


app = Flask(__name__)

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB
ALLOWED_EXTENSION = ".eml"


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded_file = request.files.get("email_file")

    if uploaded_file is None or not uploaded_file.filename:
        return render_template(
            "index.html",
            error="Please select an email file before analyzing."
        ), 400

    filename = Path(uploaded_file.filename).name

    if Path(filename).suffix.lower() != ALLOWED_EXTENSION:
        return render_template(
            "index.html",
            error="Invalid file type. Please upload an .eml file."
        ), 400

    raw_email = uploaded_file.stream.read(MAX_FILE_SIZE + 1)

    if not raw_email:
        return render_template(
            "index.html",
            error="The uploaded file is empty."
        ), 400

    if len(raw_email) > MAX_FILE_SIZE:
        return render_template(
            "index.html",
            error="The file is too large. Maximum size is 2 MB."
        ), 400

    try:
        message = BytesParser(
            policy=policy.default
        ).parsebytes(raw_email.lstrip(b"\r\n"))

        if not message.keys():
            return render_template(
                "index.html",
                error="The file does not contain recognizable email headers."
            ), 400

        results = analyze_email(message)

    except (ValueError, UnicodeError) as error:
        return render_template(
            "index.html",
            error=f"Unable to analyze this email: {error}"
        ), 400

    return render_template(
        "results.html",
        results=results,
        filename=filename
    )


if __name__ == "__main__":
    app.run(debug=False)
