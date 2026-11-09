#!/usr/bin/env python3
"""Two-step verification for the agent's login page (used by `sudo opsgate 2fa`).

    totp_setup.py new                prints a new secret, its otpauth link and a QR code for the terminal
    totp_setup.py check SECRET CODE  exit 0 if CODE is valid for SECRET
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import totp  # noqa: E402


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "new":
        host = sys.argv[2] if len(sys.argv) > 2 else "server"
        secret = totp.new_secret()
        link = totp.uri(host, secret, "OpsGate")
        print(secret)
        print(link, file=sys.stderr)
        try:
            import segno
            segno.make(link, error="m").terminal(out=sys.stderr, compact=True)
        except Exception:  # noqa: BLE001 - the key and link above are enough
            pass
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "check":
        return 0 if totp.verify(sys.argv[2], sys.argv[3], 0) is not None else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
