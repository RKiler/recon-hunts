"""Restricted, domain-scoped credential storage for interactive hunt runs."""

from __future__ import annotations

import os
import json
import re
import secrets
import stat
from pathlib import Path


SECRET_DIR = Path(os.getenv("HUNT_CREDENTIAL_DIR", "/app/hunt_credentials"))
WORKER_SECRET_DIR = Path("/root/codex_artifacts/hunt_credentials")
IMPORT_DISPLAY_ROOT = WORKER_SECRET_DIR / "imports"
IMPORT_DIR = SECRET_DIR / "imports"
SAFE_FILE = re.compile(r"[0-9a-f]{32}\.secret\Z")
SAFE_HEADER = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,79}\Z")


def read_login_file(path_value: str, import_dir: Path = IMPORT_DIR,
                    display_root: Path = IMPORT_DISPLAY_ROOT) -> str:
    supplied = Path(str(path_value or ""))
    if (supplied.parent != display_root or not supplied.name.endswith(".json")
            or supplied.name.startswith(".") or len(supplied.name) > 128):
        raise ValueError(f"Credential file must be a .json file directly under {display_root}")
    if not import_dir.is_dir() or import_dir.is_symlink() or import_dir.stat().st_mode & 0o077:
        raise RuntimeError("Credential import directory is unavailable or too permissive")
    try:
        directory_fd = os.open(import_dir, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ValueError("Credential import directory cannot be opened") from exc
    try:
        try:
            file_fd = os.open(supplied.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        except OSError as exc:
            raise ValueError("Credential file cannot be opened from the import directory") from exc
        try:
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("Credential file must be an owned regular file")
            if info.st_size > 16384:
                raise ValueError("Credential file must be at most 16 KiB")
            if info.st_mode & 0o077:
                try:
                    os.fchmod(file_fd, stat.S_IMODE(info.st_mode) & ~0o077)
                except OSError as exc:
                    raise ValueError("Credential file permissions could not be made private") from exc
            raw = os.read(file_fd, 16385)
        finally:
            os.close(file_fd)
    finally:
        os.close(directory_fd)
    if len(raw) > 16384:
        raise ValueError("Credential file must be at most 16 KiB")
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Credential file must contain a JSON object") from exc
    return normalize_login(data)


def normalize_login(data: dict) -> str:
    if not isinstance(data, dict) or not all(isinstance(key, str) for key in data):
        raise ValueError("Credential file must contain a JSON object")
    normalized = {key.casefold(): value for key, value in data.items()}
    identifier_keys = {"email", "username"}.intersection(normalized)
    if len(data) != 2 or len(normalized) != 2 or len(identifier_keys) != 1 or "password" not in normalized:
        raise ValueError("Credential file must contain only email or username, plus password")
    identifier_key = identifier_keys.pop()
    identifier, password = normalized[identifier_key], normalized["password"]
    invalid_identifier = (
        not isinstance(identifier, str)
        or not identifier
        or len(identifier) > 254
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in identifier)
    )
    invalid_email = identifier_key == "email" and (
        "@" not in identifier or any(ch.isspace() for ch in identifier)
    )
    if (invalid_identifier or invalid_email or not isinstance(password, str)
            or not password or len(password) > 4096 or any(ch in password for ch in "\r\n\0")):
        raise ValueError("Credential file has an invalid username/email or password format")
    return json.dumps({identifier_key: identifier, "password": password}, ensure_ascii=True)


def validate_credential(domain: str, payload: dict, import_dir: Path = IMPORT_DIR,
                        display_root: Path = IMPORT_DISPLAY_ROOT) -> dict:
    alias = str(payload.get("alias") or "").strip()
    role = str(payload.get("role") or "").strip()
    tenant = str(payload.get("tenant") or "").strip()
    host = str(payload.get("host") or "").lower().strip().rstrip(".")
    kind = str(payload.get("credential_type") or "cookie").lower().strip()
    header_name = str(payload.get("header_name") or "").strip()
    secret = str(payload.get("secret") or "").strip()
    if not alias or len(alias) > 80 or any(ord(ch) < 32 for ch in alias):
        raise ValueError("Account alias must be 1-80 printable characters")
    if len(role) > 100 or len(tenant) > 100 or any(ord(ch) < 32 for ch in role + tenant):
        raise ValueError("Role and tenant must be short printable labels")
    if host != domain and not host.endswith("." + domain):
        raise ValueError("Credential host must belong to the selected root domain")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
        raise ValueError("Enter an exact hostname, not a URL or wildcard")
    if kind not in {"cookie", "bearer", "header", "login_file", "manual_login"}:
        raise ValueError("Unsupported credential type")
    if kind == "header" and (not SAFE_HEADER.fullmatch(header_name) or header_name.lower() in {"host", "cookie", "authorization"}):
        raise ValueError("Enter a valid custom header name")
    if kind == "login_file":
        header_name = ""
        if payload.get("credential_path") and (
                payload.get("email") or payload.get("username") or payload.get("password")):
            raise ValueError("Provide either an owned login file or username/email and password")
        secret = (read_login_file(payload.get("credential_path"), import_dir, display_root)
                  if payload.get("credential_path") else
                  normalize_login({
                      "username" if payload.get("username") else "email":
                          payload.get("username") or payload.get("email"),
                      "password": payload.get("password"),
                  }))
    elif kind == "manual_login":
        if (payload.get("credential_path") or payload.get("email") or payload.get("username")
                or payload.get("password") or secret):
            raise ValueError("Manual VNC login does not accept credential material")
        header_name = ""
        secret = "manual-login"
    elif kind != "header":
        header_name = "Cookie" if kind == "cookie" else "Authorization"
    if not secret or len(secret) > 16384 or any(ch in secret for ch in "\r\n\0"):
        raise ValueError("Credential value must be a single line of at most 16 KiB")
    if kind == "bearer" and secret.lower().startswith("bearer "):
        secret = secret[7:].strip()
    if kind == "cookie" and secret.lower().startswith("cookie:"):
        secret = secret[7:].strip()
    return {"alias": alias, "role": role, "tenant": tenant, "host": host,
            "credential_type": kind, "header_name": header_name, "secret": secret}


def write_secret(value: str, directory: Path = SECRET_DIR) -> str:
    if not directory.is_dir() or directory.is_symlink():
        raise RuntimeError("Hunt credential store is unavailable")
    if directory.stat().st_mode & 0o077:
        raise RuntimeError("Hunt credential store permissions are too broad")
    name = f"{secrets.token_hex(16)}.secret"
    path = directory / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return name


def remove_secret(name: str, directory: Path = SECRET_DIR) -> None:
    if not SAFE_FILE.fullmatch(name):
        raise ValueError("Invalid credential file reference")
    (directory / name).unlink(missing_ok=True)
