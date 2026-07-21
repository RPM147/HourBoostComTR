import logging
from collections.abc import Mapping


_LINE_SEPARATOR_ESCAPES = str.maketrans({
    "\r": r"\r",
    "\n": r"\n",
    "\v": r"\v",
    "\f": r"\f",
    "\u0085": r"\u0085",
    "\u2028": r"\u2028",
    "\u2029": r"\u2029",
})


def _escape_line_separators(value):
    if isinstance(value, str):
        return value.translate(_LINE_SEPARATOR_ESCAPES)
    if isinstance(value, BaseException):
        return str(value).translate(_LINE_SEPARATOR_ESCAPES)
    return value


class SingleLineLogFilter(logging.Filter):
    """Keep untrusted log messages and interpolation arguments on one line."""

    def filter(self, record):
        record.msg = _escape_line_separators(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(
                _escape_line_separators(value) for value in record.args
            )
        elif isinstance(record.args, Mapping):
            record.args = {
                key: _escape_line_separators(value)
                for key, value in record.args.items()
            }
        return True


def protect_logger(logger):
    if not any(isinstance(item, SingleLineLogFilter) for item in logger.filters):
        logger.addFilter(SingleLineLogFilter())
    return logger
