#!/usr/bin/env python3
"""Set the agent's login password (the one you type when connecting Claude / ChatGPT).
Only its scrypt hash is stored, in MCP_ADMIN_PASSWORD_HASH of the env file.

    set_password.py --env /etc/opsgate/env --random     generate a strong password and print it
    set_password.py --env /etc/opsgate/env              ask for one (twice)
    set_password.py --env /etc/opsgate/env --stdin      read it from stdin (installers)
Then restart the agent: systemctl restart opsgate (the opsgate command does it for you).
"""
import argparse
import getpass
import secrets
import sqlite3
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import envfile  # noqa: E402
from oauth import hash_password  # noqa: E402

MIN = 12


def random_password() -> str:
    alphabet = string.ascii_letters + string.digits
    groups = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4)]
    return "-".join(groups)  # e.g. h7Kq2-9xLmP-a3RtZ-Q8wVe: easy to read and type, ~119 bits


def revoke_sessions(db: Path) -> None:
    """A new password signs out every app: issued codes and tokens are deleted (clients stay registered)."""
    if not db.exists():
        return
    con = sqlite3.connect(str(db))
    try:
        for table in ("pending", "codes", "access", "refresh"):
            con.execute(f"DELETE FROM {table}")
        con.commit()
    except sqlite3.Error:
        pass
    finally:
        con.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", required=True, help="env file to update")
    ap.add_argument("--state-dir", default="/var/lib/opsgate",
                    help="sign out every connected app (deletes issued OAuth tokens in oauth.db)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--random", action="store_true")
    g.add_argument("--stdin", action="store_true")
    a = ap.parse_args()
    if a.random:
        pw = random_password()
    elif a.stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass(f"New password (at least {MIN} characters): ")
        if pw != getpass.getpass("Repeat it: "):
            print("The passwords do not match.", file=sys.stderr)
            return 1
    if len(pw) < MIN:
        print(f"Too short: use at least {MIN} characters.", file=sys.stderr)
        return 1
    p = Path(a.env)
    envfile.write(p, envfile.set_values(envfile.read(p), {"MCP_ADMIN_PASSWORD_HASH": hash_password(pw)}))
    revoke_sessions(Path(a.state_dir) / "oauth.db")
    if a.random:
        print(pw)
    return 0


if __name__ == "__main__":
    sys.exit(main())
