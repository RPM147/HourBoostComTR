import copy
import json
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
    """Escape separators in messages before ordinary logging interpolation."""

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


class SingleLineFormatter(logging.Formatter):
    """Render a complete record, including tracebacks, as one physical line.

    The wrapped formatter still receives the original ``exc_info`` and
    ``stack_info``.  We escape its final rendering instead of deleting exception
    metadata or flattening it into ``record.msg``.  A copy prevents one handler's
    cached ``exc_text`` from changing another handler's view of the record.
    """

    def __init__(self, base_formatter=None):
        super().__init__()
        self.base_formatter = base_formatter or logging.Formatter()

    def format(self, record):
        rendered = self.base_formatter.format(copy.copy(record))
        return _escape_line_separators(rendered)


def protect_handler(handler):
    """Install the one-line formatter once while preserving the base format."""

    current = handler.formatter or logging.Formatter()
    if not isinstance(current, SingleLineFormatter):
        handler.setFormatter(SingleLineFormatter(current))
    return handler


def protect_logger(logger):
    if not any(isinstance(item, SingleLineLogFilter) for item in logger.filters):
        logger.addFilter(SingleLineLogFilter())

    # Module loggers normally propagate to root.  Wrap both explicit and root
    # handlers so exception/stack output cannot bypass the message filter.
    seen = set()
    for handler in (*logger.handlers, *logging.getLogger().handlers):
        identity = id(handler)
        if identity not in seen:
            protect_handler(handler)
            seen.add(identity)
    return logger


class JSONSafeAtoms(dict):
    """Gunicorn-compatible atom mapping with JSON-safe string values.

    Gunicorn's built-in ``SafeAtoms`` escapes only double quotes.  PATH_INFO is
    decoded before the ``U`` atom is built, so encoded control characters could
    otherwise create forged access-log lines.  This class deliberately has no
    Gunicorn import, keeping normal application/tests portable on Windows.
    """

    def __init__(self, atoms):
        super().__init__()
        for key, value in atoms.items():
            if isinstance(value, str):
                self[key] = json.dumps(value, ensure_ascii=True)[1:-1]
            else:
                self[key] = value

    def __getitem__(self, key):
        lookup = key.lower() if key.startswith("{") else key
        return super().get(lookup, "-")
