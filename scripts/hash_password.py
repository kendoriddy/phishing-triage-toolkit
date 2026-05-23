#!/usr/bin/env python3
"""Generate a password hash for WEB_AUTH_PASSWORD_HASH."""

import getpass
import sys

from werkzeug.security import generate_password_hash


def main() -> None:
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm: ")
    if password != confirm:
        print("Passwords do not match.", file=sys.stderr)
        sys.exit(1)
    print("\nAdd to your .env or Vercel environment variables:\n")
    print(f"WEB_AUTH_PASSWORD_HASH={generate_password_hash(password)}")


if __name__ == "__main__":
    main()
