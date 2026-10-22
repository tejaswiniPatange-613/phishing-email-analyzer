import io
import unittest

from app import app


class TestPhishingEmailWebApp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_homepage_loads(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Phishing Email Analyzer", response.data)

    def test_valid_eml_upload(self):
        email_content = (
            b"From: Security Team <security@example.test>\r\n"
            b"To: user@example.test\r\n"
            b"Subject: Test Email\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"This is a test email."
        )

        response = self.client.post(
            "/analyze",
            data={
                "email_file": (
                    io.BytesIO(email_content),
                    "test_email.eml",
                )
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Analysis Results", response.data)
        self.assertIn(b"Test Email", response.data)

    def test_rejects_wrong_file_extension(self):
        response = self.client.post(
            "/analyze",
            data={
                "email_file": (
                    io.BytesIO(b"This is not an email."),
                    "wrong_file.txt",
                )
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Invalid file type", response.data)

    def test_rejects_empty_file(self):
        response = self.client.post(
            "/analyze",
            data={
                "email_file": (
                    io.BytesIO(b""),
                    "empty.eml",
                )
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"uploaded file is empty", response.data.lower())

    def test_rejects_file_larger_than_2_mb(self):
        large_content = b"A" * (2 * 1024 * 1024 + 1)

        response = self.client.post(
            "/analyze",
            data={
                "email_file": (
                    io.BytesIO(large_content),
                    "large.eml",
                )
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"file is too large", response.data.lower())

    def test_rejects_email_without_headers(self):
        response = self.client.post(
            "/analyze",
            data={
                "email_file": (
                    io.BytesIO(b"This file has no email headers."),
                    "no_headers.eml",
                )
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(
            b"does not contain recognizable email headers",
            response.data,
        )


if __name__ == "__main__":
    unittest.main()
