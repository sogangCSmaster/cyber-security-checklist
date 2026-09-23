#!/usr/bin/env python3
"""Turn a fixture directory into a real repository the scanner can be pointed at.

Fixture files never contain a real-shaped credential: GitHub push protection would reject them,
and secret scanners would alert on this repository forever. They hold placeholders instead, which
are filled in only in the temporary copy:

    {{secret:NAME}}      a credential built here from harmless parts (see TOKENS)
    {{char:200B}}        an invisible Unicode character, by code point

Paths are renamed so that this repository's own .gitignore, editors and agents leave the
fixtures alone (a fixture's .vscode/tasks.json would otherwise run on folder open):

    dot-env              -> .env
    dot-github/...       -> .github/...
    name.pem.fixture     -> name.pem              (this repository ignores *.pem)
    name.ts.untracked    -> name.ts               written, never committed
    history/<path>       -> <path>                committed, then deleted: it lives only in history

Usage:
    python3 tests/fixtures/materialize.py <fixture> <destination> [--no-git]
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import string
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ALNUM = string.ascii_letters + string.digits


def noise(seed: str, n: int, alphabet: str = ALNUM) -> str:
    """Deterministic, random-looking text: stable across runs, never a real credential."""
    out, i = "", 0
    while len(out) < n:
        digest = hashlib.sha256(f"{seed}:{i}".encode()).digest()
        out += "".join(alphabet[b % len(alphabet)] for b in digest)
        i += 1
    return out[:n]


def b64url(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")


def jwt(role: str) -> str:
    claims = {"iss": "supabase", "ref": "abcdefghijklmnop", "role": role, "iat": 1700000000, "exp": 2000000000}
    return ".".join([b64url({"alg": "HS256", "typ": "JWT"}), b64url(claims), noise("sig-" + role, 43, ALNUM + "_-")])


def private_key() -> str:
    body = base64.b64encode(hashlib.sha512(b"fixture-key").digest() * 6).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "\n".join(["-----BEGIN " + "RSA PRIVATE KEY-----", *lines, "-----END " + "RSA PRIVATE KEY-----"])


# Every prefix is split so that no line of this file matches a credential pattern.
TOKENS = {
    "openai": "sk-" + "proj-" + noise("openai", 48, ALNUM + "_-"),
    "anthropic": "sk-" + "ant-" + "api03-" + noise("anthropic", 93, ALNUM + "_-") + "AA",
    "stripe_live": "sk" + "_live_" + noise("stripe", 99),
    "github_pat": "github" + "_pat_" + noise("github", 82, ALNUM + "_"),
    "ghp": "gh" + "p_" + noise("ghp", 36),
    "aws_key_id": "AK" + "IA" + noise("aws", 16, string.ascii_uppercase + string.digits),
    "google_key": "AI" + "za" + noise("google", 35, ALNUM + "_-"),
    "google_key_firebase": "AI" + "za" + noise("firebase", 35, ALNUM + "_-"),
    "hex32": noise("hex", 32, "0123456789abcdef"),
    "db_password": noise("db", 20),
    "service_jwt": jwt("service_" + "role"),
    "anon_jwt": jwt("anon"),
    "private_key": private_key(),
}

PLACEHOLDER = re.compile(r"\{\{(secret|char):([A-Za-z0-9_]+)\}\}")


def fill(text: str) -> str:
    def sub(m: "re.Match[str]") -> str:
        kind, name = m.groups()
        return TOKENS[name] if kind == "secret" else chr(int(name, 16))
    return PLACEHOLDER.sub(sub, text)


def target_path(rel: Path) -> Path:
    parts = ["." + p[4:] if p.startswith("dot-") else p for p in rel.parts]
    name = parts[-1]
    for suffix in (".fixture", ".untracked"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return Path(*parts[:-1], name)


def git(dest: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=dest, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def materialize(fixture: str, dest: Path, use_git: bool = True) -> Path:
    source = HERE / fixture
    if not source.is_dir():
        raise SystemExit(f"no fixture named {fixture}")
    dest.mkdir(parents=True, exist_ok=True)
    history, untracked = [], []
    for path in sorted(p for p in source.rglob("*") if p.is_file()):
        rel = path.relative_to(source)
        in_history = rel.parts[0] == "history"
        out = dest / target_path(Path(*rel.parts[1:]) if in_history else rel)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(fill(path.read_text(encoding="utf-8")), encoding="utf-8")
        if in_history:
            history.append(out)
        elif path.name.endswith(".untracked"):
            untracked.append(out)
    if not use_git:
        for out in history:
            out.unlink()
        return dest
    git(dest, "init", "-q", "-b", "main")
    git(dest, "config", "user.email", "fixture@example.com")
    git(dest, "config", "user.name", "fixture")
    git(dest, "config", "commit.gpgsign", "false")
    if history:
        git(dest, "add", "-f", "--", *[str(p.relative_to(dest)) for p in history])
        git(dest, "commit", "-q", "-m", "an early commit that held a secret")
        git(dest, "rm", "-q", "--", *[str(p.relative_to(dest)) for p in history])
        git(dest, "commit", "-q", "-m", "remove the secret (it stays in history)")
    git(dest, "add", "-A")
    if untracked:
        git(dest, "reset", "-q", "--", *[str(p.relative_to(dest)) for p in untracked])
    git(dest, "commit", "-q", "-m", "fixture")
    return dest


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 2:
        raise SystemExit(__doc__)
    if Path(args[1]).exists() and any(Path(args[1]).iterdir()):
        raise SystemExit(f"{args[1]} exists and is not empty")
    print(materialize(args[0], Path(args[1]).resolve(), "--no-git" not in sys.argv))
