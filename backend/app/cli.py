import argparse
import getpass

from app.core.config import settings
from app.persistence.db import initialize_database
from app.services.auth import (
    MIN_PASSWORD_LENGTH,
    bootstrap_admin,
    reset_analyst_password,
)


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "reset-analyst-password",
        help="Reset the configured local analyst account password.",
    )
    bootstrap = subparsers.add_parser(
        "bootstrap-admin",
        help="Create the first administrator without storing the password.",
    )
    bootstrap.add_argument("--username", default="admin")
    bootstrap.add_argument("--email")
    args = parser.parse_args()

    if args.command == "reset-analyst-password":
        initialize_database()
        password = getpass.getpass("New analyst password: ")
        confirmation = getpass.getpass("Confirm analyst password: ")
        if password != confirmation:
            parser.error("Passwords do not match.")
        if len(password) < MIN_PASSWORD_LENGTH:
            parser.error(
                f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
            )
        try:
            reset_analyst_password(password)
        except (RuntimeError, ValueError) as error:
            parser.error(str(error))
        print(f"Password reset for analyst account '{settings.analyst_username}'.")
        return 0
    if args.command == "bootstrap-admin":
        initialize_database()
        password = getpass.getpass("Administrator password: ")
        confirmation = getpass.getpass("Confirm administrator password: ")
        if password != confirmation:
            parser.error("Passwords do not match.")
        try:
            bootstrap_admin(args.username, password, args.email)
        except (RuntimeError, ValueError) as error:
            parser.error(str(error))
        print("Initial administrator created.")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
