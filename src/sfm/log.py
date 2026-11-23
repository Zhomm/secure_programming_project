import json
import logging
import logging.handlers
import os
import re
import time

LOG_NAME = "sfm.log"
MAX_BYTES = 1024 * 1024
BACKUP_COUNT = 3
MAX_STR_LEN = 80

ALLOWED_FIELDS = frozenset(
    {"user", "file_id", "size", "count", "command", "error", "reason", "signal", "code"}
)
_USER_RE = re.compile(r"[A-Za-z0-9_-]{3,32}")

_LEVELS = {
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}


class _PrivateRotatingHandler(logging.handlers.RotatingFileHandler):

    def _open(self):
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.baseFilename, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            return os.fdopen(fd, self.mode, encoding=self.encoding)
        except BaseException:
            os.close(fd)
            raise


_logger = logging.getLogger("sfm.audit")
_logger.setLevel(logging.INFO)
_logger.propagate = False 
_current_path = None


def _log_path():
    from . import storage
    return storage.ensure_base_dir() / LOG_NAME


def _attach(path) -> None:
    global _current_path
    if _current_path == str(path):
        return
    for h in list(_logger.handlers):
        _logger.removeHandler(h)
        h.close()
    handler = _PrivateRotatingHandler(
        path, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)
    _current_path = str(path)


def _clean(key, value):
    if key == "user":
        return value if isinstance(value, str) and _USER_RE.fullmatch(value) else "<invalid>"
    if isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, str):
        return value[:MAX_STR_LEN]
    return None


def event(name: str, level: str = "info", **fields) -> None:
    try:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": level,
            "event": name,
            "pid": os.getpid(),
        }
        for key, value in fields.items():
            if key not in ALLOWED_FIELDS:
                continue
            cleaned = _clean(key, value)
            if cleaned is not None:
                record[key] = cleaned
        _attach(_log_path())
        _logger.log(_LEVELS.get(level, logging.INFO), json.dumps(record, separators=(",", ":")))
    except Exception:
        pass
