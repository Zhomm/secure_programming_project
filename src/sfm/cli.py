"""Command-line interface for sfm."""

import argparse
import getpass
import sys
import signal
import contextlib

from . import auth, log, secmem, validation, vault


def _ask_password(confirm: bool = False) -> bytearray:
    first = secmem.read_password("Password: ")
    if not confirm:
        return first
    second = bytearray()
    try:
        second = secmem.read_password("Repeat password: ")
        if first != second:
            raise validation.ValidationError("passwords do not match")
        return first
    except BaseException:
        secmem.wipe(first)
        raise
    finally:
        secmem.wipe(second)


@contextlib.contextmanager
def _session(args):
    username = validation.validate_username(args.user)
    password = _ask_password()
    try:
        validation.validate_password(password)
        kek = auth.login(username, password)
    finally:
        secmem.wipe(password)
    try:
        yield username, kek
    finally:
        secmem.wipe(kek)


def cmd_register(args) -> int:
    username = validation.validate_username(args.username)
    password = _ask_password(confirm=True)
    try:
        validation.validate_password(password, check_strength=True)
        auth.register(username, password)
    finally:
        secmem.wipe(password)
    print(f"User '{username}' created.")
    return 0

def _printable(text: str) -> str:
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in text)

def cmd_encrypt(args) -> int:
    with _session(args) as (username, kek):
        file_id = vault.encrypt_file(username, kek, args.path)
    print(f"Encrypted. File ID: {file_id}")
    return 0


def cmd_decrypt(args) -> int:
    with _session(args) as (username, kek):
        vault.decrypt_file(username, kek, args.id, args.output, args.force)
    print("Decrypted.")
    return 0


def cmd_list(args) -> int:
    with _session(args) as (username, kek):
        files = vault.list_files(username, kek)
    if not files:
        print("No files in the vault.")
        return 0
    print(f"{'ID':>4}  NAME")
    for file_id, name in files:
        print(f"{file_id:>4}  {_printable(name)}")
    return 0

def cmd_delete(args) -> int:
    with _session(args) as (username, kek):
        vault.delete_file(username, kek, args.id)
        print("Deleted.")
    return 0

def _on_terminate(signum, frame):
    sys.exit(128 + signum)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sfm", description="Secure File Manager: encrypted per-user vault."
    )
    parser.add_argument("--user", metavar="NAME",
                        help="account to use (required except for 'register')")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("register", help="create a new user")
    p.add_argument("username")
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("encrypt", help="encrypt a file into the vault")
    p.add_argument("path", help="file to encrypt")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="decrypt a vault file to a destination")
    p.add_argument("id", type=int, help="file ID (see 'list')")
    p.add_argument("-o", "--output", required=True, help="destination path")
    p.add_argument("--force", action="store_true",
                   help="overwrite the destination if it exists")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("list", help="list your files")
    p.set_defaults(func=cmd_list)
    
    p = sub.add_parser("delete", help="securely delete a file from the vault")
    p.add_argument("id", type=int, help="file ID (see 'list')")
    p.set_defaults(func=cmd_delete)

    return parser


def main(argv=None) -> int:
    secmem.harden_process()
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _on_terminate)

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "register" and not args.user:
        parser.error("--user is required for this command")

    command = args.command
    try:
        return args.func(args)
    except (validation.ValidationError, auth.AuthError, vault.VaultError) as e:
        log.event("command_failed", level="warning", command=command,
                  error=type(e).__name__, reason=str(e))
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):        # Ctrl+C, or Ctrl+D at the password prompt
        log.event("aborted", level="warning", command=command, signal=int(signal.SIGINT))
        print("\nAborted.", file=sys.stderr)
        return 130
    except SystemExit as e:
        log.event("terminated", level="warning", command=command, code=e.code)
        raise
    except Exception as e:
        log.event("internal_error", level="error", command=command, error=type(e).__name__)
        print("Error: internal error", file=sys.stderr)
        return 2
    
if __name__ == "__main__":
    sys.exit(main())
