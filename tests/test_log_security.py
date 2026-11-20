import io
import json
import logging
import runpy
import unittest

from log_security import (
    JSONSafeAtoms,
    SingleLineFormatter,
    SingleLineLogFilter,
    protect_handler,
    protect_logger,
)


class LogSecurityTests(unittest.TestCase):
    def _protected_logger(self, name):
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.filters.clear()
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        protect_logger(logger)
        return logger, handler, output

    def test_exception_trace_is_preserved_as_one_physical_line(self):
        logger, _handler, output = self._protected_logger(
            "tests.log_security.exception"
        )

        def explode():
            try:
                raise KeyError("first\r\nFORGED")
            except KeyError as cause:
                raise RuntimeError("second\u0085\u2028\u2029FORGED") from cause

        try:
            explode()
        except RuntimeError:
            logger.exception("operation failed\nINJECTED")

        rendered = output.getvalue()
        self.assertEqual(len(rendered.splitlines()), 1, rendered)
        self.assertIn("Traceback (most recent call last)", rendered)
        self.assertIn("The above exception was the direct cause", rendered)
        self.assertIn("KeyError", rendered)
        self.assertIn("RuntimeError", rendered)
        self.assertIn("explode", rendered)
        self.assertIn(r"\r\nFORGED", rendered)
        self.assertIn(r"\u0085\u2028\u2029FORGED", rendered)

    def test_stack_info_and_mapping_args_are_single_line(self):
        logger, _handler, output = self._protected_logger(
            "tests.log_security.stack"
        )
        logger.warning(
            "user=%(user)s",
            {"user": "alpha\nbeta"},
            stack_info=True,
        )
        rendered = output.getvalue()
        self.assertEqual(len(rendered.splitlines()), 1, rendered)
        self.assertIn(r"alpha\nbeta", rendered)
        self.assertIn("Stack (most recent call last)", rendered)
        self.assertIn("test_stack_info_and_mapping_args_are_single_line", rendered)

    def test_protection_is_idempotent(self):
        logger, handler, _output = self._protected_logger(
            "tests.log_security.idempotent"
        )
        protect_logger(logger)
        protect_handler(handler)
        protect_handler(handler)

        self.assertEqual(
            sum(isinstance(item, SingleLineLogFilter) for item in logger.filters),
            1,
        )
        self.assertIsInstance(handler.formatter, SingleLineFormatter)
        self.assertNotIsInstance(handler.formatter.base_formatter, SingleLineFormatter)

    def test_json_safe_atoms_produce_valid_single_line_gunicorn_json(self):
        config = runpy.run_path("gunicorn_config.py")
        atoms = JSONSafeAtoms({
            "t": "[29/Aug/2026:20:00:00 +0300]",
            "p": "<123>",
            "m": "GET",
            "U": '/probe\r\nforged"\\\u0085\u2028\u2029',
            "s": "200",
            "B": "12",
            "L": "0.001234",
        })
        rendered = config["access_log_format"] % atoms

        self.assertEqual(len(rendered.splitlines()), 1, rendered)
        payload = json.loads(rendered)
        self.assertEqual(payload["path"], '/probe\r\nforged"\\\u0085\u2028\u2029')
        self.assertNotIn("?", payload["path"])
        self.assertEqual(atoms["missing"], "-")


if __name__ == "__main__":
    unittest.main()
