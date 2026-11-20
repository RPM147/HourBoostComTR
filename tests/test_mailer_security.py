import html
import unittest
from unittest import mock

import mailer


class MailerSecurityTests(unittest.TestCase):
    def test_username_is_html_escaped_in_every_email_template(self):
        username = '<a href="https://phishing.example">Verify now</a>&"\''
        escaped_username = html.escape(username, quote=True)
        email_cases = (
            (
                "verification",
                mailer.send_verification_email,
                ("victim@example.com", username, "verification-token"),
            ),
            (
                "welcome",
                mailer.send_welcome_email,
                ("victim@example.com", username),
            ),
            (
                "password_reset",
                mailer.send_password_reset_email,
                ("victim@example.com", username, "reset-token"),
            ),
            (
                "email_change",
                mailer.send_email_change_email,
                ("victim@example.com", username, "email-change-token"),
            ),
        )

        for case_name, sender, args in email_cases:
            for lang in ("tr", "en"):
                with self.subTest(email=case_name, lang=lang):
                    with mock.patch.object(
                        mailer, "send_email", return_value=True
                    ) as send_email:
                        self.assertTrue(sender(*args, lang=lang))

                    send_email.assert_called_once()
                    html_body = send_email.call_args.args[2]
                    self.assertIn(escaped_username, html_body)
                    self.assertNotIn(username, html_body)
                    self.assertNotIn(
                        '<a href="https://phishing.example">', html_body
                    )

    def test_action_tokens_are_only_placed_in_url_fragments(self):
        token = "A" * 43
        email_cases = (
            (mailer.send_verification_email, "verify-email"),
            (mailer.send_password_reset_email, "reset-password"),
            (mailer.send_email_change_email, "confirm-email-change"),
        )

        for sender, path in email_cases:
            for lang in ("tr", "en"):
                with self.subTest(path=path, lang=lang):
                    with (
                        mock.patch.object(
                            mailer,
                            "SITE_URL",
                            "https://hourboost.example",
                        ),
                        mock.patch.object(
                            mailer,
                            "send_email",
                            return_value=True,
                        ) as send_email,
                    ):
                        self.assertTrue(sender(
                            "victim@example.com",
                            "victim",
                            token,
                            lang=lang,
                        ))

                    html_body = send_email.call_args.args[2]
                    query = "?lang=en" if lang == "en" else ""
                    expected_url = (
                        f"https://hourboost.example/{path}{query}#token={token}"
                    )
                    self.assertIn(expected_url, html_body)
                    self.assertNotIn(f"/{path}/{token}", html_body)
                    self.assertNotIn(token, expected_url.split("#", 1)[0])


if __name__ == "__main__":
    unittest.main()
