""" input validation for paths and command arguments."""
import os
import re
from pathlib import Path

MAX_PATH_LEN = 4096
MAX_NAME_LEN = 255
MAX_FILE_SIZE = 100 * 1024 * 1024      
USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128


class ValidationError(Exception):
    """Raised when an input is rejected (generic message)."""


def _has_control_chars(text: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in text)


def _check_raw_path(raw: str) -> None:
    if not isinstance(raw, str) or not raw:
        raise ValidationError("invalid path")
    if _has_control_chars(raw):
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
def validate_password(password, check_strength: bool = False):
    if isinstance(password, str):
        size = chars = len(password)
    elif isinstance(password, (bytes, bytearray)):
        size = len(password)
        chars = sum(1 for b in password if (b & 0xC0) != 0x80)
    else:
        raise ValidationError("invalid password")
    if not size or chars > MAX_PASSWORD_LEN or size > 4 * MAX_PASSWORD_LEN:
        raise ValidationError("invalid password")
    if check_strength and chars < MIN_PASSWORD_LEN:
        raise ValidationError(
            f"password must be at least {MIN_PASSWORD_LEN} characters"
        )
    return password

def validate_source_path(raw: str) -> Path:
    _check_raw_path(raw)
    candidate = Path(raw).expanduser()
    try:
        is_link = candidate.is_symlink()
        path = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValidationError("invalid path")
    if is_link:
        raise ValidationError("symbolic links are not accepted")

    if _has_control_chars(path.name):
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

    if len(os.fsencode(candidate.name)) > MAX_NAME_LEN:
        raise ValidationError("invalid path")

    try:
        parent = candidate.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValidationError("invalid path")
    if not parent.is_dir():
        raise ValidationError("invalid path")
    
    dest = parent / candidate.name
    try:
        taken = dest.exists() or dest.is_symlink()
    except OSError:                       # e.g. file name too long
        raise ValidationError("invalid path")
    if taken and not force:
        raise ValidationError("destination already exists (use --force)")
    return dest
