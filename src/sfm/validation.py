""" input validation for paths and command arguments."""

import re
from pathlib import Path

MAX_PATH_LEN = 4096
MAX_FILE_SIZE = 100 * 1024 * 1024      
USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128


class ValidationError(Exception):
    """Raised when an input is rejected (generic message)."""


def _check_raw_path(raw: str) -> None:
    if not isinstance(raw, str) or not raw:
        raise ValidationError("invalid path")
    
    #exclude input as safe.txt\x00../../etc/passwd
    if "\x00" in raw:
        raise ValidationError("invalid path")
    if len(raw) > MAX_PATH_LEN:
        raise ValidationError("invalid path")


def validate_username(username: str) -> str:
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise ValidationError(
            "invalid username (3-32 chars: letters, digits, '_' or '-')"
        )
    return username


#check_strength=True only at registration, not at login
def validate_password(password: str, check_strength: bool = False) -> str:
    if not isinstance(password, str) or not password:
        raise ValidationError("invalid password")
    if len(password) > MAX_PASSWORD_LEN:
        raise ValidationError("invalid password")
    if check_strength and len(password) < MIN_PASSWORD_LEN:
        raise ValidationError(
            f"password must be at least {MIN_PASSWORD_LEN} characters"
        )
    return password


def validate_source_path(raw: str) -> Path:
    _check_raw_path(raw)
    try:
        path = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValidationError("invalid path")

    if not path.is_file():
        raise ValidationError("not a regular file")
    if path.stat().st_size > MAX_FILE_SIZE:
        raise ValidationError("file too large")
    return path


def validate_dest_path(raw: str, force: bool = False) -> Path:
    _check_raw_path(raw)
    candidate = Path(raw).expanduser()
    if candidate.name in ("", ".", ".."):
        raise ValidationError("invalid path")

    try:
        parent = candidate.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValidationError("invalid path")
    if not parent.is_dir():
        raise ValidationError("invalid path")

    dest = parent / candidate.name
    if (dest.exists() or dest.is_symlink()) and not force:
        raise ValidationError("destination already exists (use --force)")
    return dest
