"""Command-line interface for sfm."""

import argparse
import getpass
import sys

from . import auth, validation, vault


def _ask_password(confirm: bool = False) -> str:
    password = getpass.getpass("Password: ")
    if confirm and password != getpass.getpass("Repeat password: "):
        raise validation.ValidationError("passwords do not match")
    return password


def _login(args) -> tuple[str, bytes]:
    username = validation.validate_username(args.user)
    password = validation.validate_password(_ask_password())
    return username, auth.login(username, password)


def cmd_register(args) -> int:
    username = validation.validate_username(args.username)
    password = validation.validate_password(
        _ask_password(confirm=True), check_strength=True
    )
    auth.register(username, password)
    print(f"User '{username}' created.")
    return 0


def cmd_encrypt(args) -> int:
    username, kek = _login(args)
    file_id = vault.encrypt_file(username, kek, args.path)
    print(f"Encrypted. File ID: {file_id}")
    return 0


def cmd_decrypt(args) -> int:
    username, kek = _login(args)
    vault.decrypt_file(username, kek, args.id, args.output, args.force)
    print("Decrypted.")
    return 0


def cmd_list(args) -> int:
    username, kek = _login(args)
    files = vault.list_files(username, kek)
    if not files:
        print("No files in the vault.")
        return 0
    print(f"{'ID':>4}  NAME")
    for file_id, name in files:
        print(f"{file_id:>4}  {name}")
    return 0

def cmd_delete(args) -> int:
    username, kek = _login(args)
    vault.delete_file(username, kek, args.id)
    print("Deleted.")
    return 0

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
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "register" and not args.user:
        parser.error("--user is required for this command")

    try:
        return args.func(args)
    except (validation.ValidationError, auth.AuthError, vault.VaultError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130
    except Exception:
        print("Error: internal error", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
