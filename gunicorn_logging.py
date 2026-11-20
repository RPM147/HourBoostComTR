"""Gunicorn-only logging adapter.

Do not import this module from the Flask application: Gunicorn depends on
POSIX-only modules such as ``fcntl``.  The portable JSON atom implementation
lives in ``log_security.py`` and is unit-tested independently.
"""

from gunicorn.glogging import Logger

from log_security import JSONSafeAtoms


class HourBoostLogger(Logger):
    atoms_wrapper_class = JSONSafeAtoms
