#!/usr/bin/env python3
"""Query the restricted mailbox bridge without exposing the app password."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys


SOCKET = os.environ.get("AGENTIC_MAIL_SOCKET", "/run/agentic-mail/mail.sock")


def call(request: dict) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(90)
        connection.connect(SOCKET)
        connection.sendall((json.dumps(request) + "\n").encode("utf-8"))
        with connection.makefile("rb") as reader:
            return json.loads(reader.readline())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("health")
    sub.add_parser("check")
    find = sub.add_parser("find")
    find.add_argument("--host", required=True, help="Exact verified target hostname")
    find.add_argument("--after", required=True, help="UTC timestamp after owned signup submission")
    opening = sub.add_parser("open")
    opening.add_argument("--host", required=True)
    opening.add_argument("--handle", required=True)
    opening.add_argument("--confirm-owned-signup", action="store_true", required=True)
    args = vars(parser.parse_args())
    result = call(args)
    print(json.dumps(result))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
