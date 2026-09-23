#!/usr/bin/env python3
"""The mechanical half of a breach-driven security audit.

Finds candidates for the failures that recur in the incident corpus — committed secrets,
tables without row-level security, SQL built from strings, unsafe CI workflows — and reports
every check as ``ran``, ``not-run`` or ``error``. A check that could not run is never reported
as clean. That was the failure of the grep commands this script replaces: they sent errors to
/dev/null and piped everything through ``head``, so a broken check looked like a clean one.

It finds candidates. It does not decide. Every finding is a line for a reviewer to read, and
secret values are masked so the report can be pasted without leaking them a second time.

    scan.py                      the whole repository
    scan.py --path src/api       only files under a path
    scan.py --diff origin/main   files changed since the merge base, each finding marked
                                 introduced or pre-existing
    scan.py --bundle auto        also scan built client bundles (.next/static, dist, ...)
    scan.py --audit              also run whichever dependency auditors are installed
    scan.py --gate               add the ship-gate evidence table
    scan.py --hook               PostToolUse hook mode: reads the hook's JSON on stdin
    scan.py --list-checks

A line containing ``security-checklist: allow`` is skipped. That marker is for people; an
agent should fix the finding or explain it, never add the marker on its own.

Standard library only; Python 3.8 or later.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import re
import shutil
import subprocess
import sys
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

VERSION = "0.2.0"
ALLOW_MARKER = "security-checklist: allow"
MAX_FILE_BYTES = 2_000_000
MAX_BUNDLE_FILE_BYTES = 30_000_000
MAX_LINE_CHARS = 4_000
MAX_FILES = 60_000
HISTORY_BYTE_CAP = 80_000_000
SEVERITIES = ("high", "medium", "low", "info")
RANK = {s: i for i, s in enumerate(SEVERITIES)}

EXCLUDED_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "bower_components", "jspm_packages", "vendor",
    ".venv", "venv", "virtualenv", "__pycache__", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "site-packages", "dist", "build", "out", ".next",
    ".nuxt", ".output", ".svelte-kit", ".vercel", ".netlify", ".turbo", ".cache",
    ".parcel-cache", ".angular", ".expo", ".docusaurus", "storybook-static", "coverage",
    ".nyc_output", "target", ".gradle", "Pods", "DerivedData", ".terraform", ".serverless",
    ".aws-sam", ".dart_tool", ".pub-cache", "elm-stuff",
})
# Client bundles worth scanning after a build. Server bundles are left out on purpose: a
# server is allowed to hold secrets, a browser is not.
BUNDLE_DIRS = (
    ".next/static", "out", "dist", "build", ".output/public", ".svelte-kit/output/client",
    "public/build", "www", "storybook-static",
)
LOCKFILES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "bun.lockb", "poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "Gemfile.lock",
    "go.sum", "Cargo.lock", "composer.lock",
})

CODE_EXT = frozenset({
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro",
    ".py", ".rb", ".go", ".java", ".kt", ".kts", ".scala", ".php", ".cs", ".rs", ".swift",
    ".m", ".dart", ".ex", ".exs", ".clj", ".sh", ".bash", ".zsh", ".ps1", ".lua", ".pl",
    ".groovy",
})
MARKUP_EXT = frozenset({
    ".html", ".htm", ".ejs", ".hbs", ".handlebars", ".erb", ".twig", ".liquid", ".njk",
    ".jinja", ".jinja2", ".j2", ".mustache", ".pug", ".jsp", ".cshtml", ".razor",
})
CONFIG_EXT = frozenset({
    ".json", ".jsonc", ".json5", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".tf", ".tfvars", ".hcl", ".xml", ".plist", ".gradle", ".env", ".rules",
})
DOC_EXT = frozenset({".md", ".mdc", ".mdx", ".txt", ".rst", ".adoc"})
SKIP_EXT = frozenset({".svg", ".map", ".snap", ".lock", ".log", ".csv", ".tsv", ".ipynb"})

I = re.IGNORECASE


# ---------------------------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------------------------

@dataclass
class Finding:
    check: str
    controls: Tuple[str, ...]
    severity: str
    file: str
    line: Optional[int]
    message: str
    excerpt: str = ""
    introduced: Optional[bool] = None

    def as_dict(self) -> dict:
        return {
            "check": self.check, "controls": list(self.controls), "severity": self.severity,
            "file": self.file, "line": self.line, "message": self.message,
            "excerpt": self.excerpt, "introduced": self.introduced,
        }


@dataclass
class Result:
    status: str                       # ran | not-run | error
    detail: str = ""


class SourceFile:
    """A file in scope, read lazily and at most once."""

    def __init__(self, root: Path, rel: str, status: str, limit: int = MAX_FILE_BYTES):
        self.rel = rel
        self.path = root / rel
        self.status = status          # tracked | untracked | ignored | unknown | bundle | hook
        self.name = rel.rsplit("/", 1)[-1]
        self.ext = os.path.splitext(self.name)[1].lower()
        self._limit = limit
        self._text: Optional[str] = None
        self._lines: Optional[List[str]] = None
        self._lower: Optional[str] = None

    def text(self) -> str:
        if self._text is None:
            self._text = ""
            try:
                if self.path.stat().st_size <= self._limit:
                    raw = self.path.read_bytes()
                    if b"\x00" not in raw[:8192]:
                        self._text = raw.decode("utf-8", errors="replace")
            except OSError:
                pass
        return self._text

    def lower(self) -> str:
        if self._lower is None:
            self._lower = self.text().lower()
        return self._lower

    def lines(self) -> List[str]:
        if self._lines is None:
            self._lines = self.text().splitlines()
        return self._lines

    @property
    def is_env(self) -> bool:
        return self.name == ".env" or self.name.startswith(".env.") or self.name.endswith(".env")

    @property
    def is_example(self) -> bool:
        return bool(re.search(r"(?:\.|_|-)(?:example|sample|template|dist|defaults?)(?:\.|$)", self.name, I))

    @property
    def is_code(self) -> bool:
        return self.ext in CODE_EXT

    @property
    def is_markup(self) -> bool:
        return self.ext in MARKUP_EXT

    @property
    def is_config(self) -> bool:
        return self.ext in CONFIG_EXT or self.is_env

    @property
    def is_doc(self) -> bool:
        return self.ext in DOC_EXT

    @property
    def is_test(self) -> bool:
        return is_test_path(self.rel)


class Context:
    def __init__(self, root: Path):
        self.root = root
        self.git = False
        self.files: List[SourceFile] = []       # in scope for content checks
        self.every: List[SourceFile] = []       # every repository file, for repo-level checks
        self.ignored_env: List[SourceFile] = [] # ignored .env files: where secrets belong, but
                                                # a public-prefixed variable in one still ships
        self.bundle: List[SourceFile] = []
        self.bundle_dirs: List[str] = []
        self.tracked: Set[str] = set()          # every tracked path, lockfiles included
        self.scope = "whole repository"
        self.repo_scope = True                  # repo-level checks run only on a full scan
        self.merge_base: Optional[str] = None
        self.added: Optional[Dict[str, Optional[Set[int]]]] = None
        self.signals: Dict[str, object] = {}
        self.notes: List[str] = []

    def rel_exists(self, rel: str) -> bool:
        return (self.root / rel).exists()


def git(root: Path, *args: str, timeout: int = 120) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["git", "-c", "core.quotePath=false", *args], cwd=str(root),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


TEST_PATH = re.compile(
    r"(^|/)(tests?|spec|specs|__tests__|__mocks__|fixtures?|mocks?|e2e|cypress|playwright)(/|$)|[._-](test|spec)\.[a-z]+$", I)


def is_test_path(rel: str) -> bool:
    return bool(TEST_PATH.search(rel))


def excluded(rel: str) -> bool:
    parts = rel.split("/")
    return any(p in EXCLUDED_DIRS for p in parts[:-1])


def skip_name(name: str) -> bool:
    low = name.lower()
    return (
        name in LOCKFILES or low.endswith((".min.js", ".min.css", ".min.mjs"))
        or os.path.splitext(low)[1] in SKIP_EXT
    )


# ---------------------------------------------------------------------------------------------
# Helpers shared by the checks
# ---------------------------------------------------------------------------------------------

def shannon(value: str) -> float:
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def mask(value: str) -> str:
    value = value.strip()
    return f"{value[:4]}…({len(value)} chars)" if len(value) > 4 else "…"


PLACEHOLDER_WORDS = (
    "changeme", "change_me", "change-me", "your_", "your-", "yourkey", "yoursecret",
    "your_password", "example", "placeholder", "dummy", "sample", "redacted", "xxxx", "****",
    "...", "<", ">", "${", "{{", "insert_", "insert-", "replace_me", "replaceme", "notreal",
    "not_real", "not-a-real", "todo",
)


def looks_random(value: str) -> bool:
    """Generated key material mixes letters and digits; slugs and prose do not."""
    return len(value) >= 32 and bool(re.search(r"\d", value)) and bool(re.search(r"[A-Za-z]", value)) \
        and not re.fullmatch(r"[a-z]+(?:[-_][a-z0-9]+)*", value)


def is_placeholder(value: str) -> bool:
    low = value.lower()
    return any(w in low for w in PLACEHOLDER_WORDS) or len(set(value)) <= 3


SECRET_SHAPES: List[Tuple[str, "re.Pattern[str]", str]] = [
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("Anthropic API key", re.compile(r"\bsk-ant-[a-z]+\d*-[A-Za-z0-9_-]{20,}"), "high"),
    ("OpenAI-style secret key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"), "high"),
    ("Stripe live secret key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}"), "high"),
    ("Stripe test secret key", re.compile(r"\b[rs]k_test_[A-Za-z0-9]{16,}"), "medium"),
    ("Stripe webhook secret", re.compile(r"\bwhsec_[A-Za-z0-9+/=]{24,}"), "high"),
    ("Supabase secret key", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}"), "high"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"), "high"),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}"), "high"),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), "high"),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "high"),
    ("Slack webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/-]{20,}"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"), "medium"),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}"), "high"),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), "high"),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "high"),
    ("PyPI token", re.compile(r"\bpypi-AgE[A-Za-z0-9_-]{50,}"), "high"),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), "high"),
    ("Private key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"), "high"),
]
CONN_STRING = re.compile(
    r"\b[a-z][a-z0-9+.-]{1,20}://(?P<user>[^\s:/@'\"`]+):(?P<pw>[^\s/@'\"`]{3,})@(?P<host>[^\s/'\"`:?#]+)"
)
LOCAL_HOST = re.compile(r"^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|[a-z][a-z0-9_-]*)$", I)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.(?P<payload>eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}")
# Substrings every credential shape above contains, lowercased. Checking these with `in` first is
# what keeps a scan of a million lines to seconds; running the patterns on every line is not.
SECRET_HINTS = (
    "akia", "asia", "sk-", "_live_", "_test_", "whsec_", "sb_secret", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
    "github_pat", "glpat-", "xox", "hooks.slack", "aiza", "gocspx", "sg.", "npm_", "pypi-", "hf_",
    "private key", "://", "eyj",
)


def has_secret_hint(low: str) -> bool:
    return any(h in low for h in SECRET_HINTS)


def jwt_claims(payload: str) -> dict:
    try:
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


@dataclass
class SecretHit:
    label: str
    value: str
    severity: str
    controls: Tuple[str, ...] = ("CRED-01",)
    note: str = ""


def secret_hits(line: str, context_lower: str = "") -> List[SecretHit]:
    """Every credential-shaped value on a line, most specific label first."""
    hits: List[SecretHit] = []
    taken: List[Tuple[int, int]] = []

    def free(span: Tuple[int, int]) -> bool:
        return all(span[1] <= a or span[0] >= b for a, b in taken)

    for label, pattern, severity in SECRET_SHAPES:
        for m in pattern.finditer(line):
            value = m.group(0)
            if not free(m.span()) or is_placeholder(value):
                continue
            if label == "OpenAI-style secret key" and not looks_random(value.split("-", 2)[-1]):
                continue          # a slug such as sk-telecom-usim-breach, not a key
            note = ""
            if label == "Google API key":
                if re.search(r"authdomain|firebase|projectid|messagingsenderid", context_lower):
                    severity, note = "low", "Firebase web API keys are public by design; the Firebase rules, not the key, must protect the data"
                else:
                    note = "if this is a Gemini, Maps or other billable server key it is a secret; a browser key must be restricted to your referrers and APIs"
            taken.append(m.span())
            hits.append(SecretHit(label, value, severity, note=note))
    for m in CONN_STRING.finditer(line):
        pw, host = m.group("pw"), m.group("host")
        if not free(m.span()) or is_placeholder(pw) or pw.lower() in {
            "password", "pass", "passwd", "pwd", "secret", "postgres", "root", "admin", "user",
            "username", "test", "mypassword", "dbpass",
        } or re.search(r"[${}<>%*]", pw):
            continue
        taken.append(m.span())
        if LOCAL_HOST.match(host):
            hits.append(SecretHit("Connection string with a password (local host)", pw, "low",
                                  note="a local development credential; it must not be the one production uses"))
        else:
            hits.append(SecretHit("Connection string with a password", pw, "high"))
    for m in JWT.finditer(line):
        if not free(m.span()):
            continue
        claims = jwt_claims(m.group("payload"))
        role = str(claims.get("role", ""))
        if role in {"anon", "authenticated"} or claims.get("sub") == "1234567890":
            continue              # publishable Supabase anon key, or the jwt.io sample token
        taken.append(m.span())
        if role == "service_role":
            hits.append(SecretHit("Supabase service_role key", m.group(0), "high", ("CRED-01", "DATA-05"),
                                  "it bypasses row-level security entirely"))
        else:
            hits.append(SecretHit("JSON Web Token", m.group(0), "medium",
                                  note="a bearer credential until it expires"))
    return hits


def mask_line(line: str) -> str:
    values = {hit.value for hit in secret_hits(line)}
    values.update(m.group("value") for m in ASSIGN.finditer(line) if plausible_secret(m.group("value")))
    for value in sorted(values, key=len, reverse=True):
        line = line.replace(value, mask(value))
    return line


def excerpt(line: str, limit: int = 160) -> str:
    text = mask_line(line.strip())
    return text if len(text) <= limit else text[: limit - 1] + "…"


COMMENT_START = ("#", "//", "/*", "*", "<!--", "--")


def is_comment(line: str) -> bool:
    """A whole-line comment: examples in comments are not code. Secrets are checked regardless."""
    return line.lstrip().startswith(COMMENT_START)


def outside_strings(text: str) -> str:
    """The code on a line with string contents removed, keeping interpolations.

    `console.log("password reset")` keeps no "password"; `log(f"pw={password}")` and
    `log(`pw=${password}`)` keep the interpolated name. Scanned left to right, so a closing quote
    is never mistaken for an opening one.
    """
    out: List[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c not in "\"'`":
            out.append(c)
            i += 1
            continue
        j, prefix = i - 1, ""
        while j >= 0 and text[j] in "fFrRbBuU" and len(prefix) < 2:
            prefix, j = text[j] + prefix, j - 1
        if prefix and j >= 0 and (text[j].isalnum() or text[j] == "_"):
            prefix = ""               # the tail of an identifier, not a string prefix
        k = i + 1
        while k < n and text[k] != c:
            k += 2 if text[k] == "\\" else 1
        body = text[i + 1:k]
        if c == "`":
            kept = " ".join(re.findall(r"\$\{([^}]*)\}", body))
        elif "f" in prefix.lower():
            kept = " ".join(re.findall(r"\{([^}]*)\}", body))
        else:
            kept = ""
        out.append(c + kept + c)
        i = k + 1
    return "".join(out)


# ---------------------------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------------------------

@dataclass
class Check:
    id: str
    controls: Tuple[str, ...]
    title: str
    run: Callable[[Context], List[Finding]]
    repo_level: bool = False
    hook: bool = False
    gate: Tuple[str, ...] = ()
    needs: str = ""                   # a flag the check needs, such as "audit" or "bundle"


CHECKS: List[Check] = []


def check(id: str, controls: Sequence[str], title: str, repo_level: bool = False,
          hook: bool = False, gate: Sequence[str] = (), needs: str = ""):
    def register(fn: Callable[[Context], List[Finding]]):
        CHECKS.append(Check(id, tuple(controls), title, fn, repo_level, hook, tuple(gate), needs))
        return fn
    return register


@dataclass
class Rule:
    """A line-level pattern: fast enough to run on every line of a large repository."""
    patterns: Sequence[str]
    severity: str
    message: str
    files: Callable[[SourceFile], bool]
    hints: Sequence[str]
    exclude: Sequence[str] = ()
    flags: int = 0
    strip_strings: bool = False       # in code files, match only outside string literals

    def __post_init__(self):
        self._pats = [re.compile(p, self.flags) for p in self.patterns]
        self._excl = [re.compile(p, self.flags) for p in self.exclude]
        self._hints = tuple(h.lower() for h in self.hints)

    def scan(self, f: SourceFile) -> List[Tuple[int, str]]:
        if not self.files(f) or (self._hints and not any(h in f.lower() for h in self._hints)):
            return []
        out = []
        strip = self.strip_strings and f.is_code
        for i, line in enumerate(f.lines(), 1):
            if len(line) > MAX_LINE_CHARS or ALLOW_MARKER in line or is_comment(line):
                continue
            low = line.lower()
            if self._hints and not any(h in low for h in self._hints):
                continue
            subject = outside_strings(line) if strip else line
            if any(p.search(subject) for p in self._pats) and not any(e.search(line) for e in self._excl):
                out.append((i, line))
        return out


def rule_check(id: str, controls: Sequence[str], title: str, rules: Sequence[Rule],
               hook: bool = False, gate: Sequence[str] = ()) -> None:
    def run(ctx: Context) -> List[Finding]:
        found: List[Finding] = []
        for f in ctx.files:
            seen: Set[int] = set()
            for rule in rules:
                for lineno, line in rule.scan(f):
                    if lineno in seen:
                        continue
                    seen.add(lineno)
                    found.append(Finding(id, tuple(controls), rule.severity, f.rel, lineno,
                                         rule.message, excerpt(line)))
        return found
    CHECKS.append(Check(id, tuple(controls), title, run, False, hook, tuple(gate)))


def code(f: SourceFile) -> bool:
    return f.is_code


def code_or_markup(f: SourceFile) -> bool:
    return f.is_code or f.is_markup


def schema_file(f: SourceFile) -> bool:
    return f.ext in {".sql", ".prisma"} or bool(re.search(
        r"(^|/)(models?|schemas?|entities|entity|migrations?|db)(/|\.|$)|\.entity\.[jt]s$|schema\.[jt]s$|models?\.py$",
        f.rel, I))


# ---------------------------------------------------------------------------------------------
# Secrets — CRED-01, CRED-02, CRED-03, CRED-05
# ---------------------------------------------------------------------------------------------

def status_suffix(f: SourceFile) -> str:
    if f.status == "tracked":
        return " — committed, so rotate it; deleting the line does not remove it from history"
    if f.status == "untracked":
        return " — not committed yet, but not ignored either: the next `git add .` commits it"
    if f.status == "unknown":
        return " — not a git repository, so whether it is committed could not be checked"
    return ""                         # ignored, bundle, or a file the hook just saw written


@check("secret-shape", ["CRED-01", "CRED-02"], "Credential-shaped values: API keys, tokens, private keys, service_role JWTs, passwords in connection strings",
       hook=True, gate=["G1"])
def check_secret_shape(ctx: Context) -> List[Finding]:
    found = []
    for f in ctx.files:
        low = f.lower()
        if not has_secret_hint(low):
            continue
        for i, line in enumerate(f.lines(), 1):
            if len(line) > MAX_LINE_CHARS or ALLOW_MARKER in line or not has_secret_hint(line.lower()):
                continue
            for hit in secret_hits(line, low):
                severity, note = hit.severity, hit.note
                if f.is_doc and not f.is_env:
                    severity, note = "low", "in documentation — confirm it is an example, not a live value"
                elif f.is_test and severity == "high" and hit.label != "Private key":
                    severity = "medium"
                msg = f"{hit.label} {mask(hit.value)}" + (f" — {note}" if note else "")
                if severity != "low":
                    msg += status_suffix(f)
                found.append(Finding("secret-shape", hit.controls, severity, f.rel, i, msg, excerpt(line)))
    return found


ASSIGN = re.compile(r"""
    (?P<name>[A-Za-z0-9_.\-]*?(?:api[_.\-]?key|apikey|secret|token|passw(?:or)?d|passwd|pwd|passphrase
        |private[_.\-]?key|access[_.\-]?key|client[_.\-]?secret|auth[_.\-]?key|credential)[A-Za-z0-9_.\-]*)
    ["']?\s*(?::=|=>|=|:)\s*
    (?P<q>["'`]?)
    (?P<value>[^\s"'`,;\\)]{8,})
""", I | re.X)
NAME_NOT_SECRET = re.compile(
    r"(?:url|uri|endpoint|path|file|filename|name|type|header|length|len|size|ttl|expiry|expires|expiresin|"
    r"expiresat|prefix|id|ids|field|label|placeholder|regex|pattern|policy|min|max|hint|message|msg|error|"
    r"input|confirm|confirmation|reset|hash|hashed|count|limit|mode|kind|format|version|env|var|param|query|"
    r"storagekey|cookiename|headername|location|key_name|keyname|provider|strategy|algorithm|alg|scope|scopes)$",
    I,
)


DEFAULT_PASSWORDS = frozenset({
    "admin", "password", "123456", "12345678", "changeme", "root", "test", "secret", "admin123",
    "password123", "qwerty", "letmein",
})


ASSIGN_HINTS = ("key", "secret", "token", "passw", "pwd", "passphrase", "credential")


def plausible_secret(value: str) -> bool:
    v = value.strip()
    low = v.lower()
    if len(v) < 8 or v[0] in "$%{<[(@&*#/.!:":
        return False
    if low.startswith(("process.env", "os.environ", "os.getenv", "env(", "env.", "import.meta", "secrets.",
                       "vault:", "ssm:", "arn:", "http://", "https://", "file:", "sha256-", "sha384-", "sha512-")):
        return False
    if is_placeholder(v) or low in DEFAULT_PASSWORDS:
        return False
    if re.fullmatch(r"[a-z]+(?:[_.:\-][a-z]+)*", v) or re.fullmatch(r"[A-Z]+(?:_[A-Z0-9]+)*", v):
        return False                  # words and CONSTANT_NAMES, not secrets
    if re.fullmatch(r"[a-z]+(?:[A-Z][a-z0-9]*)+", v) or re.fullmatch(r"[\d.,_]+[a-z]{0,3}", v):
        return False                  # camelCase identifiers, numbers and durations
    return len(set(v)) >= 5 and shannon(v) >= 2.8


def assignment_hits(line: str, f: SourceFile) -> List[Tuple[str, str]]:
    hits = []
    for m in ASSIGN.finditer(line):
        name, q, value = m.group("name"), m.group("q"), m.group("value")
        bare = re.sub(r"[^a-z0-9]", "", name.lower())
        if NAME_NOT_SECRET.search(bare):
            continue
        if q:
            if line[m.end("value"):m.end("value") + 1] != q:
                continue              # "abc${x}" — an interpolation, not a literal
        elif not (f.is_env or f.is_config):
            continue                  # in code, an unquoted value is an expression
        if plausible_secret(value):
            hits.append((name, value))
    return hits


@check("secret-assignment", ["CRED-01"], "Literal values assigned to names like password, secret, token, api_key",
       hook=True, gate=["G1"])
def check_secret_assignment(ctx: Context) -> List[Finding]:
    found = []
    for f in ctx.files:
        if f.status == "ignored" or f.is_doc or f.is_example or not (f.is_code or f.is_config or f.is_markup):
            continue
        if not any(w in f.lower() for w in ASSIGN_HINTS):
            continue
        for i, line in enumerate(f.lines(), 1):
            low = line.lower()
            if len(line) > MAX_LINE_CHARS or ALLOW_MARKER in line or not any(w in low for w in ASSIGN_HINTS):
                continue
            if has_secret_hint(low) and secret_hits(line):
                continue              # secret-shape already reports this line
            for name, value in assignment_hits(line, f):
                severity = "low" if f.is_test else "medium"
                found.append(Finding("secret-assignment", ("CRED-01",), severity, f.rel, i,
                                     f"`{name.strip(chr(34) + chr(39))}` holds a literal {mask(value)} — confirm it is not a real credential"
                                     + status_suffix(f), excerpt(line)))
                break
    return found


PUBLIC_PREFIX = r"(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|STORYBOOK_|PUBLIC_)"
SENSITIVE_WORD = (
    r"(?:SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|PASSWD|ADMIN_KEY|ADMIN_TOKEN|DATABASE_URL|DB_URL|"
    r"DB_PASS|OPENAI|ANTHROPIC|RESEND|SENDGRID|TWILIO_AUTH|AWS_SECRET|STRIPE_SECRET|SK_LIVE|WEBHOOK_SECRET|"
    r"JWT_SECRET|SIGNING_KEY)"
)
CLIENT_ENV = re.compile(rf"\b{PUBLIC_PREFIX}[A-Z0-9_]*{SENSITIVE_WORD}[A-Z0-9_]*\b")
PUBLIC_HINTS = ("PUBLIC_", "VITE_", "REACT_APP_", "GATSBY_", "STORYBOOK_")


@check("client-env-secret", ["CRED-02"], "Secret-named variables under a prefix the build ships to the browser (NEXT_PUBLIC_, VITE_, …)",
       hook=True, gate=["G1", "G6"])
def check_client_env(ctx: Context) -> List[Finding]:
    found = []
    seen: Set[Tuple[str, str]] = set()
    for f in list(ctx.files) + (ctx.ignored_env if ctx.repo_scope else []):
        if f.is_doc or not any(p in f.text() for p in PUBLIC_HINTS):
            continue
        for i, line in enumerate(f.lines(), 1):
            if ALLOW_MARKER in line or not any(p in line for p in PUBLIC_HINTS):
                continue
            for m in CLIENT_ENV.finditer(line):
                if (f.rel, m.group(0)) in seen:
                    continue
                seen.add((f.rel, m.group(0)))
                found.append(Finding("client-env-secret", ("CRED-02",), "high", f.rel, i,
                                     f"`{m.group(0)}` is compiled into the client bundle, where anyone can read it — "
                                     "a secret must never carry a public prefix", excerpt(line)))
    return found


SECRET_FILE = re.compile(
    r"(^|/)(\.env(\.[\w.-]+)?|[^/]*\.(pem|key|p12|pfx|jks|keystore|ppk)|id_(rsa|dsa|ecdsa|ed25519)|"
    r"[^/]*service[-_]?account[^/]*\.json|credentials\.json|\.htpasswd|\.pgpass|\.netrc)$", I)


def secret_file_kind(rel: str, text: str) -> Optional[str]:
    """Why a path is a secret file, or None if it is not one (or only a template)."""
    if not SECRET_FILE.search(rel) or re.search(r"(?:\.|_|-)(?:example|sample|template|dist|defaults?)$", rel, I):
        return None
    name = rel.rsplit("/", 1)[-1].lower()
    if name.endswith(".pem") and "PRIVATE KEY" not in text:
        return None                   # a certificate, which is public
    if name.startswith(".env") or name.endswith(".env"):
        values = [ln.split("=", 1)[1].strip().strip("'\"") for ln in text.splitlines()
                  if "=" in ln and not ln.lstrip().startswith("#")]
        real = [v for v in values if v and not is_placeholder(v) and v.lower() not in {"true", "false", "development", "production", "test"}]
        return "an environment file with values" if real else "an environment file (values look empty or placeholder)"
    return "a key or credential file"


@check("tracked-secret-file", ["CRED-05", "CRED-01"], "Environment, key and credential files committed to git, and .env missing from .gitignore",
       gate=["G1"])
def check_tracked_secret_file(ctx: Context) -> List[Finding]:
    found = []
    candidates = ctx.files if not ctx.repo_scope else ctx.every
    for f in candidates:
        if f.status not in {"tracked", "unknown"}:
            continue
        kind = secret_file_kind(f.rel, f.text())
        if kind:
            severity = "low" if "placeholder" in kind else "high"
            found.append(Finding("tracked-secret-file", ("CRED-05", "CRED-01"), severity, f.rel, None,
                                 f"{kind} is committed — anything in it is in every clone and in history; "
                                 "rotate what it held, untrack it, and ship a .env.example instead", ""))
    if ctx.git and ctx.repo_scope:
        probes = (".env", ".env.local", ".env.production") if ctx.rel_exists("package.json") else (".env",)
        for probe in probes:
            code_, _, _ = git(ctx.root, "check-ignore", "--no-index", "-q", probe)
            if code_ == 1:
                found.append(Finding("tracked-secret-file", ("CRED-05",), "medium", ".gitignore", None,
                                     f"`{probe}` is not ignored — the next `git add .` commits it", ""))
                break
    return found


@check("history-secret", ["CRED-03", "CRED-01"], "Secrets and secret files anywhere in git history, including ones since deleted",
       repo_level=True, gate=["G1"])
def check_history(ctx: Context) -> List[Finding]:
    if not ctx.git:
        raise NotRun("not a git repository")
    code_, _, _ = git(ctx.root, "rev-parse", "--verify", "-q", "HEAD")
    if code_ != 0:
        raise NotRun("the repository has no commits yet")
    found: List[Finding] = []
    rev = [f"{ctx.merge_base}..HEAD"] if ctx.merge_base else ["--all"]
    tracked_now = {f.rel for f in ctx.every if f.status == "tracked"}

    code_, out, err = git(ctx.root, "log", *rev, "--relative", "--diff-filter=A", "--name-only", "--format=@@%h", timeout=300)
    if code_ != 0:
        raise CheckError(f"git log failed: {err.strip().splitlines()[0] if err.strip() else code_}")
    commit = ""
    reported: Set[str] = set()
    for line in out.splitlines():
        if line.startswith("@@"):
            commit = line[2:]
            continue
        rel = line.strip()
        if not rel or rel in tracked_now or rel in reported or excluded(rel) or not SECRET_FILE.search(rel):
            continue
        prefix = ctx.signals.get("git_prefix") or ""
        c2, blob, _ = git(ctx.root, "show", f"{commit}:{prefix}{rel}")
        kind = secret_file_kind(rel, blob if c2 == 0 else "PRIVATE KEY\nX=value-not-read")
        if not kind or "placeholder" in kind:
            continue
        reported.add(rel)
        found.append(Finding("history-secret", ("CRED-03", "CRED-01"), "high", rel, None,
                             f"{kind} was committed in {commit} and later removed — it is still in history; "
                             "rotate what it held (deleting the file is not a fix)", ""))

    try:
        proc = subprocess.Popen(
            ["git", "-c", "core.quotePath=false", "log", *rev, "--relative", "-p", "--no-color", "--no-ext-diff",
             "-U0", "--format=@@%h"],
            cwd=str(ctx.root), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise CheckError(f"git log -p failed: {exc}")
    current_tree = {f.rel: f for f in ctx.every}
    seen_values: Set[str] = set()
    consumed = 0
    commit, path = "", ""
    assert proc.stdout is not None
    for raw in proc.stdout:
        consumed += len(raw)
        if consumed > HISTORY_BYTE_CAP:
            proc.kill()
            ctx.notes.append("history-secret: stopped after 80 MB of history; older commits were not scanned")
            break
        line = raw.decode("utf-8", "replace").rstrip("\n")
        if line.startswith("@@") and not line.startswith("@@ "):
            commit = line[2:]
        elif line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else ""
        elif line.startswith("+") and path and path not in reported and not excluded(path) and not skip_name(path.rsplit("/", 1)[-1]):
            body = line[1:]
            if len(body) > MAX_LINE_CHARS or ALLOW_MARKER in body or not has_secret_hint(body.lower()):
                continue
            for hit in secret_hits(body):
                if hit.value in seen_values or hit.severity == "low":
                    continue
                seen_values.add(hit.value)
                live = current_tree.get(path)
                if live is not None and live.status == "tracked" and hit.value in live.text():
                    continue          # still committed: secret-shape reports it where it stands
                found.append(Finding("history-secret", ("CRED-03", "CRED-01"), "high", path, None,
                                     f"{hit.label} {mask(hit.value)} entered history in {commit} and is no longer in "
                                     "the file — it is still in every clone; treat it as leaked and rotate it", ""))
    proc.wait()
    return found


@check("bundle-secret", ["CRED-02", "CRED-01"], "Credentials inside built client bundles and source maps (needs --bundle)",
       repo_level=True, gate=["G1"], needs="bundle")
def check_bundle(ctx: Context) -> List[Finding]:
    if not ctx.bundle_dirs:
        raise NotRun("no build output scanned — build the app, then pass --bundle auto (or a directory)")
    found: Dict[Tuple[str, str], Finding] = {}
    step = 200_000
    for f in ctx.bundle:
        text = f.text()
        if not text or not (has_secret_hint(f.lower()) or any(p in text for p in PUBLIC_HINTS)):
            continue
        low = f.lower()
        for start in range(0, len(text), step):
            chunk = text[start:start + step + 400]      # overlap, so a value on a boundary is seen
            for hit in secret_hits(chunk, low):
                if hit.severity == "low" or (f.rel, hit.value) in found:
                    continue
                line = text.count("\n", 0, start + chunk.find(hit.value)) + 1
                controls = tuple(dict.fromkeys(hit.controls + ("CRED-02",)))
                found[(f.rel, hit.value)] = Finding("bundle-secret", controls, hit.severity, f.rel, line,
                                                    f"{hit.label} {mask(hit.value)} is in a file the browser downloads")
            for m in CLIENT_ENV.finditer(chunk):
                if (f.rel, m.group(0)) not in found:
                    line = text.count("\n", 0, start + m.start()) + 1
                    found[(f.rel, m.group(0))] = Finding("bundle-secret", ("CRED-02",), "high", f.rel, line,
                                                         f"`{m.group(0)}` is referenced in the client bundle")
    return list(found.values())


# ---------------------------------------------------------------------------------------------
# Data layer — DATA-01, DATA-03, DATA-05, DATA-06, DATA-07, DATA-14, OBSV-04
# ---------------------------------------------------------------------------------------------

IDENT = r'(?:"[^"]+"|[A-Za-z_][\w$]*)'
QUALIFIED = rf"{IDENT}(?:\s*\.\s*{IDENT})?"
CREATE_TABLE = re.compile(
    rf"\bcreate\s+(?:or\s+replace\s+)?(?P<mod>(?:(?:global|local)\s+)?(?:temp|temporary)\s+|unlogged\s+)?"
    rf"table\s+(?:if\s+not\s+exists\s+)?(?P<name>{QUALIFIED})", I)
ALTER_RLS = re.compile(
    rf"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?P<name>{QUALIFIED})\s+"
    rf"(?P<action>enable|disable|force|no\s+force)\s+row\s+level\s+security", I)
CREATE_POLICY = re.compile(rf"\bcreate\s+policy\s+(?:\"[^\"]*\"|[\w$]+)\s+on\s+(?P<name>{QUALIFIED})(?P<body>[^;]*)", I)
SQL_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)


def table_key(raw: str) -> Tuple[str, str]:
    parts = [p.strip().strip('"').lower() for p in re.split(r"\s*\.\s*", raw.strip())]
    return ("public", parts[0]) if len(parts) == 1 else (parts[0], parts[1])


def strip_sql_comments(text: str) -> str:
    return SQL_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def rls_findings(files: Sequence[SourceFile], client_db: bool) -> List[Finding]:
    created: Dict[Tuple[str, str], Tuple[str, int]] = {}
    state: Dict[Tuple[str, str], str] = {}
    policies: Dict[Tuple[str, str], int] = Counter()
    found: List[Finding] = []
    for f in sorted(files, key=lambda x: x.rel):
        text = strip_sql_comments(f.text())
        for m in CREATE_TABLE.finditer(text):
            if m.group("mod") and "temp" in m.group("mod").lower():
                continue
            key = table_key(m.group("name"))
            created.setdefault(key, (f.rel, text.count("\n", 0, m.start()) + 1))
        for m in ALTER_RLS.finditer(text):
            action = m.group("action").lower()
            if action in {"enable", "disable"}:
                state[table_key(m.group("name"))] = action
            elif action == "force":
                state.setdefault(table_key(m.group("name")), "enable")
        for m in CREATE_POLICY.finditer(text):
            key = table_key(m.group("name"))
            policies[key] += 1
            body = re.sub(r"\s+", " ", m.group("body").lower())
            line = text.count("\n", 0, m.start()) + 1
            command = (re.search(r"\bfor (select|insert|update|delete|all)\b", body) or [None, "all"])[1]
            roles = (re.search(r"\bto ([\w, ]+?)(?: using| with|$)", body) or [None, "public"])[1]
            if roles.strip() == "service_role":
                continue
            if re.search(r"using\s*\(\s*true\s*\)|with check\s*\(\s*true\s*\)", body):
                if command == "select":
                    severity, what = "medium", "every row is readable by " + ("every signed-in user" if "authenticated" in roles else "anyone with the anon key")
                else:
                    severity, what = "high", f"any caller can {command if command != 'all' else 'read and write'} every row"
                found.append(Finding("rls", ("DATA-01",), severity, f.rel, line,
                                     f"policy on {key[1]} uses `true`: {what} — `USING (true)` is not a policy unless the table is public on purpose", ""))
            elif re.search(r"using\s*\(\s*(?:\(\s*select\s+)?auth\.uid\(\)\s*\)?\s+is\s+not\s+null\s*\)|using\s*\(\s*auth\.role\(\)\s*=\s*'authenticated'\s*\)", body):
                found.append(Finding("rls", ("DATA-01", "API-01"), "medium", f.rel, line,
                                     f"policy on {key[1]} admits every signed-in user, not the row's owner — scope it to `auth.uid() = <owner column>`", ""))
    for key, (rel, line) in sorted(created.items()):
        schema, name = key
        if schema != "public" or state.get(key) == "enable":
            continue
        disabled = state.get(key) == "disable"
        severity = "high" if client_db else "low"
        why = ("clients query this database directly, so every row is readable with the anon key" if client_db
               else "only a finding if clients query the database directly (Supabase, PostgREST, Hasura)")
        verb = "has row-level security disabled" if disabled else "is created without row-level security"
        found.append(Finding("rls", ("DATA-01",), severity, rel, line,
                             f"table `{name}` {verb} — {why}; enable it in the same migration, default-deny, scoped to `auth.uid()`", ""))
    for key, (rel, line) in sorted(created.items()):
        if key[0] == "public" and state.get(key) == "enable" and not policies.get(key):
            found.append(Finding("rls", ("DATA-01",), "info", rel, line,
                                 f"table `{key[1]}` has row-level security with no policy — clients see nothing; fine if intended", ""))
    return found


@check("rls", ["DATA-01", "API-01"], "Tables without row-level security, `USING (true)` policies, and policies that admit any signed-in user",
       hook=True, gate=["G2"])
def check_rls(ctx: Context) -> List[Finding]:
    sql = [f for f in ctx.every if f.ext == ".sql"]     # judge a table across every migration
    if not sql:
        raise NotRun("no .sql files")
    found = rls_findings(sql, bool(ctx.signals.get("client_db")))
    in_scope = {f.rel for f in ctx.files}
    return [x for x in found if x.file in in_scope]


FIREBASE_RULES = [
    Rule([r"\ballow\s+(?:read|write|get|list|create|update|delete)(?:\s*,\s*(?:read|write|get|list|create|update|delete))*\s*(?::\s*if\s+true\s*;|;)"],
         "high", "rule allows access unconditionally — anyone on the internet can use it",
         lambda f: f.ext == ".rules" or f.name in {"firestore.rules", "storage.rules"}, ["allow"]),
    Rule([r"\bif\s+request\.time\s*<\s*timestamp\.date\s*\("],
         "high", "test-mode rule: open to everyone until the date passes",
         lambda f: f.ext == ".rules" or f.name in {"firestore.rules", "storage.rules"}, ["request.time"]),
    Rule([r"\ballow\s+[\w, ]+:\s*if\s+request\.auth\s*!=\s*null\s*;"],
         "medium", "any signed-in user can use every document — check ownership (`request.auth.uid == resource.data.<owner>`)",
         lambda f: f.ext == ".rules" or f.name in {"firestore.rules", "storage.rules"}, ["request.auth"]),
    Rule([r"\"\.(?:read|write)\"\s*:\s*(?:true|\"true\")"],
         "high", "Realtime Database rule is `true`: open to everyone",
         lambda f: f.name.endswith(".rules.json") or f.name == "database.rules.json", [".read", ".write"]),
]
rule_check("firebase-rules", ["DATA-01", "DATA-03"], "Firebase rules that allow everyone, test-mode rules, and auth-only rules", FIREBASE_RULES,
           hook=True, gate=["G2"])


CLIENT_DIRECTIVE = re.compile(r"""^\s*['"]use client['"]""", re.M)
SERVER_PATH = re.compile(
    r"(^|/)(api|server|servers|backend|functions|lambda|lambdas|workers?|jobs|cron|scripts|migrations|seeds?|"
    r"prisma|db|database|edge|trpc)(/|$)|\.server\.[jt]sx?$|(^|/)route\.[jt]s$|(^|/)middleware\.[jt]s$|"
    r"(^|/)actions?\.[jt]s$", I)
CLIENT_PATH = re.compile(r"(^|/)(components|hooks|public|static|frontend|client|ui|views|widgets)(/|$)", I)
AGENT_CONFIG = re.compile(
    r"(^|/)(\.mcp\.json|mcp\.json|\.cursor/mcp\.json|\.vscode/mcp\.json|claude_desktop_config\.json|"
    r"\.claude/settings(\.local)?\.json|\.gemini/settings\.json|\.codex/config\.toml|\.windsurf/mcp_config\.json)$", I)
SERVICE_ROLE = re.compile(r"service[_-]?role|SUPABASE_SERVICE_KEY|serviceRoleKey|SUPABASE_SECRET_KEY", I)
SERVICE_ROLE_HINTS = ("service_role", "service-role", "servicerole", "supabase_service_key", "supabase_secret_key")


def is_client_file(ctx: Context, f: SourceFile) -> bool:
    if CLIENT_DIRECTIVE.search(f.text()[:2000]):
        return True
    if f.ext in {".vue", ".svelte"} and not SERVER_PATH.search(f.rel):
        return True
    if f.ext not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".vue", ".svelte"} or SERVER_PATH.search(f.rel):
        return False
    if ctx.signals.get("spa") and re.search(r"(^|/)src/", f.rel):
        return True
    return bool(CLIENT_PATH.search(f.rel))


@check("service-role", ["DATA-05", "AGENT-02"], "service_role and admin database keys referenced from client code or agent configuration",
       hook=True, gate=["G6"])
def check_service_role(ctx: Context) -> List[Finding]:
    found = []
    for f in ctx.files:
        if f.is_env or f.is_doc or f.ext == ".sql" or not any(h in f.lower() for h in SERVICE_ROLE_HINTS):
            continue
        agent = bool(AGENT_CONFIG.search(f.rel))
        if not (agent or f.is_code or f.is_config or f.is_markup):
            continue
        client = not agent and is_client_file(ctx, f)
        if not (agent or client) and (SERVER_PATH.search(f.rel) or f.ext not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".json"}):
            continue
        for i, line in enumerate(f.lines(), 1):
            if ALLOW_MARKER in line or not any(h in line.lower() for h in SERVICE_ROLE_HINTS):
                continue
            if agent:
                sev, msg, ctl = "high", "an agent or MCP configuration holds the service_role key — agents get task-scoped credentials, never one that bypasses row-level security", ("AGENT-02", "DATA-05")
            elif client:
                sev, msg, ctl = "high", "service_role referenced from client-side code — it bypasses row-level security, and everything the browser runs is public", ("DATA-05",)
            else:
                sev, msg, ctl = "medium", "service_role referenced here — confirm this file only ever runs on a server and never returns the key or unfiltered rows to a caller", ("DATA-05",)
            found.append(Finding("service-role", ctl, sev, f.rel, i, msg, excerpt(line)))
            break
    return found


PASSWORD_WORD = re.compile(r"passw(?:or)?d|\bpwd\b|passphrase", I)
PASSWORD_HINTS = ("passw", "pwd", "passphrase")
HASH_HINTS = ("md5", "sha1", "sha2", "sha5", "createhash", "digest", "encrypt")
FAST_HASH = re.compile(
    r"createHash\(\s*['\"](?:md5|sha1|sha256|sha512)['\"]|hashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512)\b|"
    r"(?<![\w.])(?:md5|sha1|sha256|sha512)\s*\(|DigestUtils\.(?:md5|sha1|sha256)\w*\(|"
    r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1|SHA-?256)\"|crypto\.subtle\.digest\(|"
    r"(?<![\w.])(?:encrypt|aes_encrypt|AES\.encrypt|CryptoJS\.AES\.encrypt)\s*\(", I)


@check("weak-password-hash", ["DATA-06", "CRYPTO-01"], "Passwords run through a fast hash (MD5, SHA-*) or reversible encryption",
       hook=True, gate=["G10"])
def check_password_hash(ctx: Context) -> List[Finding]:
    found = []
    for f in ctx.files:
        low = f.lower()
        if not f.is_code or not any(w in low for w in PASSWORD_HINTS) or not any(h in low for h in HASH_HINTS):
            continue
        lines = f.lines()
        for i, line in enumerate(lines, 1):
            if ALLOW_MARKER in line or not any(h in line.lower() for h in HASH_HINTS) or not FAST_HASH.search(line):
                continue
            same = bool(PASSWORD_WORD.search(outside_strings(line)))
            near = same or any(PASSWORD_WORD.search(outside_strings(lines[j])) for j in range(max(0, i - 3), min(len(lines), i + 2)))
            if not near:
                continue
            reversible = re.search(r"encrypt", line, I)
            msg = ("password encrypted reversibly — one stolen key reveals every password; hash it with argon2id, scrypt or bcrypt"
                   if reversible else "password hashed with a fast hash — crackable at billions of guesses a second; use argon2id, scrypt or bcrypt")
            found.append(Finding("weak-password-hash", ("DATA-06", "CRYPTO-01"), "high" if same else "medium",
                                 f.rel, i, msg, excerpt(line)))
    return found


CARD_RULES = [
    Rule([r"\b(?:cvv2?|cvc2?|card_?security_?code|card_?verification(?:_?value|_?code)?)\b"], "high",
         "card security code stored — never keep it after authorization (PCI DSS); let the processor handle it",
         schema_file, ["cvv", "cvc", "security_code", "securitycode", "verification"], flags=I),
    Rule([r"\b(?:card_?number|card_?no|cc_?number|credit_?card_?number|full_?pan|primary_?account_?number)\b"], "high",
         "card number column — collect cards in the processor's hosted fields and keep only its token and the last four digits",
         schema_file, ["card", "cc_", "pan"], flags=I),
]
rule_check("card-data", ["DATA-14"], "Card numbers and card security codes in a schema", CARD_RULES, hook=True, gate=["G10"])

HIGH_HARM = [
    Rule([r"\b(?:ssn|social_?security(?:_?number)?|rrn|resident_?(?:registration|number|no)|jumin|passport(?:_?(?:no|number))?|"
          r"drivers?_?licen[cs]e(?:_?(?:no|number))?|national_?id|tax_?id|iban|bank_?account(?:_?(?:no|number))?|"
          r"account_?number|routing_?number|diagnos\w*|medical_?record\w*|health_?record\w*|biometric\w*|"
          r"fingerprint\w*|face_?(?:template|embedding)\w*)\b"], "info",
         "high-harm field — confirm the application encrypts it before it reaches the database, with a key the database credential cannot read",
         schema_file, ["ssn", "social", "rrn", "resident", "jumin", "passport", "licen", "national", "tax", "iban",
                       "account", "routing", "diagnos", "medical", "health", "biometric", "fingerprint", "face"], flags=I),
]
rule_check("high-harm-field", ["DATA-07", "CRYPTO-08"], "Inventory of national-ID, bank, health and biometric fields (each needs application-level encryption)",
           HIGH_HARM, gate=["G10"])

LOG_CALL = re.compile(r"(?:console\.(?:log|info|debug|warn|error|trace)|logger\.\w+|logging\.\w+|\blog\.\w+|\bprint|\bputs|"
                      r"\bprintln|System\.out\.print\w*|fmt\.Print\w*)\s*\(")
LOGGED_SECRET = re.compile(r"req\.body|request\.(?:body|json|data|form|headers|get_json)|\bpassword\b|\bpasswd\b|\bsecret\b|"
                           r"\bauthorization\b|\bcookies?\b|\bapi_?key\b|\b(?:access_?|refresh_?|id_?|auth_?)?token\b|\bssn\b|"
                           r"\bcard_?number\b|\bcvv\b", I)


@check("sensitive-logging", ["OBSV-04", "DATA-13"], "Request bodies, passwords and tokens written to logs", gate=["G10"])
def check_sensitive_logging(ctx: Context) -> List[Finding]:
    found = []
    for f in ctx.files:
        if not f.is_code or not any(h in f.lower() for h in ("log", "print", "puts", "fmt.")):
            continue
        for i, line in enumerate(f.lines(), 1):
            low = line.lower()
            if not ("log" in low or "print" in low or "puts" in low) or len(line) > MAX_LINE_CHARS \
                    or ALLOW_MARKER in line or is_comment(line):
                continue
            m = LOG_CALL.search(line)
            # Only what is passed to the call, with string contents removed: "password reset
            # requested" is a message, `password` is the value.
            if m and LOGGED_SECRET.search(outside_strings(line[m.end():])):
                found.append(Finding("sensitive-logging", ("OBSV-04", "DATA-13"), "medium", f.rel, i,
                                     "logs a request body, header, password or token — logs outlive the request and reach more people than the database",
                                     excerpt(line)))
    return found


# ---------------------------------------------------------------------------------------------
# Injection and unsafe input — INPUT-01..08, WEB-06, FILE-05, API-03
# ---------------------------------------------------------------------------------------------

# Text that is shaped like a statement, not a log line that happens to say "update".
SQL_SHAPE = r"(?=[^\"']*(?i:select\b[^\"']*\bfrom\b|insert\s+into\b|update\s+\S+\s+set\b|delete\s+from\b))"
SQL_SHAPE_TEMPLATE = r"(?=[^`]*(?i:select\b[^`]*\bfrom\b|insert\s+into\b|update\s+\S+\s+set\b|delete\s+from\b))"
QUERY_CALL = r"\b(?:execute|executemany|executescript|exec_driver_sql|raw|text|read_sql(?:_query)?|query|mogrify)\s*\(\s*"
# One whole string literal: the same quote opens and closes it, so `'%s'` inside SQL text is not
# mistaken for the end of the string.
LITERAL = r"(?P<q>[\"'])(?:\\.|(?!(?P=q)).)*(?P=q)"
SQL_RULES = [
    Rule([QUERY_CALL + r"(?:rf|fr|f|Rf|fR|rF|Fr|F|RF|FR)[\"']"], "high",
         "SQL built with an f-string — pass values as bound parameters", code, ["execute", "query", "raw", "text(", "read_sql", "mogrify"]),
    Rule([QUERY_CALL + LITERAL + r"\s*%\s*[\w(\[{]"], "high",
         "SQL built with % formatting — use the driver's parameters, `execute(sql, (value,))`", code, ["%"]),
    Rule([QUERY_CALL + LITERAL + r"\s*\.format\s*\("], "high",
         "SQL built with .format() — pass values as bound parameters", code, [".format"]),
    Rule([r"\b(?:execute|executemany|executeQuery|executeUpdate|prepareStatement|createQuery|createNativeQuery|query|queryRaw|"
          r"raw|exec|Exec|Query|QueryRow|QueryContext|ExecContext|find_by_sql|where|order)\s*\(\s*" + LITERAL + r"\s*\+\s*[\w$(]"],
         "high", "SQL concatenated with a value — use bound parameters", code, ["+"]),
    Rule([r"(?:\b(?:execute|query|raw|unsafe)|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*`"
          r"(?=[^`]*\b(?i:select|insert|update|delete|with|create|drop|alter|merge|call)\b)[^`]*\$\{"], "high",
         "SQL built from a template literal — use a tagged template (`sql`...``, `$queryRaw`...``) or bound parameters",
         code, ["${"]),
    Rule([r"\b(?:Query|QueryRow|Exec|QueryContext|ExecContext|QueryRowContext|Raw)\s*\([^)]*fmt\.Sprintf\("], "high",
         "SQL built with fmt.Sprintf — use placeholders", code, ["sprintf"]),
    Rule([r"\b(?:where|find_by_sql|execute|select|order|group|having|joins|pluck|exec_query)\s*\(\s*\"[^\"]*#\{"], "high",
         "SQL interpolated with #{} — use placeholders or a hash condition", lambda f: f.ext == ".rb", ["#{"]),
    Rule([r"(?:mysqli_query|mysql_query|pg_query|->query|->exec)\s*\([^;]*(?:\$_(?:GET|POST|REQUEST|COOKIE)\b|\"\s*\.\s*\$)"], "high",
         "SQL built from request data — use a prepared statement", lambda f: f.ext == ".php", ["query", "exec"]),
    Rule([r"=\s*(?:rf|fr|f|F)[\"']" + SQL_SHAPE + r"[^\"']*\{",
          r"=\s*`" + SQL_SHAPE_TEMPLATE + r"[^`]*\$\{",
          r"=\s*(?=[\"'])" + SQL_SHAPE.replace("(?=", "(?=.") + LITERAL + r"\s*(?:\+\s*[\w$(]|%\s*[\w(\[{]|\.format\s*\()"],
         "medium", "SQL text assembled from values before it reaches the query call — confirm it ends up as bound parameters",
         code, ["select", "insert", "update", "delete"]),
]
rule_check("sql-string-building", ["INPUT-01"], "SQL built by f-strings, %, .format, concatenation or template literals (DB-API `%s` parameters are not flagged)",
           SQL_RULES, hook=True)

RAW_UNSAFE = [
    Rule([r"\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(", r"\bsql\.unsafe\s*\(", r"\bsequelize\.literal\s*\(\s*`[^`]*\$\{"], "medium",
         "unsafe raw-query API — confirm every value reaches it as a bound parameter", code, ["unsafe", "literal"],
         exclude=[r"(?:\$queryRawUnsafe|\$executeRawUnsafe|\bunsafe)\s*\(\s*`[^`]*\$\{"]),   # sql-string-building reports these
    Rule([r"\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|deleteOne|deleteMany|updateOne|updateMany|countDocuments|aggregate)\s*\(\s*(?:req|request)\.(?:body|query)\b"],
         "high", "request object used directly as a query filter — `{\"$ne\": null}` matches every record (NoSQL injection)",
         code, ["req.", "request."]),
]
rule_check("sql-raw-unsafe", ["INPUT-01", "INPUT-02"], "Unsafe raw-query APIs and request objects passed straight into a NoSQL filter", RAW_UNSAFE, hook=True)

CMD_RULES = [
    Rule([r"subprocess\.\w+\([^)]*shell\s*=\s*True", r"\bos\.(?:system|popen)\s*\("], "medium",
         "shell command — if any part comes from input, it is command injection; pass an argument list without a shell",
         lambda f: f.ext == ".py", ["subprocess", "os.system", "os.popen"]),
    Rule([r"\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)"], "high",
         "shell command built from a value — use execFile/spawn with an argument array", code, ["exec"]),
    Rule([r"\b(?:shell_exec|system|passthru|popen|proc_open)\s*\([^)]*\$"], "medium",
         "shell command built from a variable — use escapeshellarg or avoid the shell", lambda f: f.ext == ".php", ["exec", "system", "passthru", "popen"]),
    Rule([r"\bsystem\s*\(\s*\"[^\"]*#\{", r"`[^`]*#\{[^}]*\}[^`]*`"], "medium",
         "shell command interpolated with #{}", lambda f: f.ext == ".rb", ["#{"]),
]
rule_check("command-injection", ["INPUT-01", "INPUT-02"], "Shell commands built from values", CMD_RULES)

SSRF_RULES = [
    Rule([r"(?:\bfetch|\baxios(?:\.(?:get|post|put|request))?|\bgot|\bneedle|\bhttps?\.get|\burlopen|\burllib\.request\.urlopen|"
          r"\brequests\.(?:get|post|put|head|request)|\bhttpx\.(?:get|post|request)|\bhttp\.(?:Get|Post))\s*\(\s*[^,)]*?"
          r"(?:req\.(?:query|body|params)|request\.(?:args|form|json|GET|POST|query_params|data)|params\[|searchParams\.get\()"],
         "medium", "outbound request to a URL taken from the request — allowlist destinations and block 169.254.169.254 (Capital One)",
         code, ["req.", "request.", "params[", "searchparams"]),
]
rule_check("ssrf", ["INPUT-04", "CLOUD-02"], "Outbound requests built from request input (server-side request forgery)", SSRF_RULES)

HTML_RULES = [
    Rule([r"dangerouslySetInnerHTML", r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)(?!\s*[\"'`]\s*[\"'`])", r"insertAdjacentHTML\s*\(",
          r"\bv-html\s*=", r"\{@html\s", r"\|\s*safe\b", r"\bmark_safe\s*\(", r"\.html_safe\b", r"<%==",
          r"document\.write(?:ln)?\s*\(", r"bypassSecurityTrust\w*\s*\("],
         "medium", "renders raw HTML — if any of it comes from users it is stored XSS; sanitize with a vetted library or render as text",
         code_or_markup, ["innerhtml", "outerhtml", "insertadjacenthtml", "v-html", "@html", "safe", "<%==", "document.write", "bypasssecuritytrust"],
         strip_strings=True),
]
rule_check("unsafe-html", ["WEB-06", "INPUT-03"], "Raw HTML rendering: dangerouslySetInnerHTML, innerHTML, v-html, |safe", HTML_RULES)

DYNAMIC_RULES = [
    Rule([r"(?<![.\w$])eval\s*\(\s*[^)\s]", r"\bnew\s+Function\s*\(", r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]", r"\bvm\.runIn\w*Context\s*\("],
         "medium", "evaluates a string as code — never with anything derived from input", code, ["eval", "function", "settimeout", "setinterval", "runin"]),
    Rule([r"(?<![.\w])exec\s*\(\s*(?!\s*\))"], "medium", "Python exec() — never with anything derived from input",
         lambda f: f.ext == ".py", ["exec"]),
    Rule([r"\bpickle\.loads?\s*\(", r"\bcPickle\.loads?\s*\(", r"\bmarshal\.loads\s*\(", r"\bjsonpickle\.decode\s*\(",
          r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?C?SafeLoader)", r"\btorch\.load\s*\((?![^)]*weights_only\s*=\s*True)",
          r"\bObjectInputStream\s*\(", r"\bunserialize\s*\(\s*\$_", r"require\(\s*['\"]node-serialize['\"]\s*\)"],
         "medium", "deserializes data that can execute code — never on anything a user or a network can supply",
         code, ["pickle", "marshal", "jsonpickle", "yaml.load", "torch.load", "objectinputstream", "unserialize", "node-serialize"]),
]
rule_check("dynamic-code", ["INPUT-06"], "eval, new Function, exec, and deserializers that execute code (pickle, yaml.load, ObjectInputStream)", DYNAMIC_RULES)

PATH_RULES = [
    Rule([r"(?:\bopen|readFile(?:Sync)?|createReadStream|writeFile(?:Sync)?|sendFile|send_file|res\.download|unlink(?:Sync)?|"
          r"path\.(?:join|resolve)|os\.path\.join|FileResponse|File\.(?:read|open)|fs\.\w+)\s*\([^;\n]*?"
          r"(?:req\.(?:params|query|body)|request\.(?:args|form|GET|POST|json|query_params|data|files)|params\[)"],
         "medium", "file path built from request input — path traversal (`../`); map ids to files server-side instead",
         code, ["req.", "request.", "params["], exclude=[r"send_from_directory"]),
    Rule([r"\bres\.redirect\s*\([^;\n]*?(?:req|request)\.(?:query|body|params)", r"\bredirect\s*\([^;\n]*?request\.(?:args|GET|form)"],
         "medium", "redirect target taken from the request — an open redirect; allowlist destinations",
         code, ["redirect"]),
]
rule_check("path-and-redirect", ["FILE-05", "INPUT-08"], "File paths and redirect targets taken from request input", PATH_RULES)

MASS_RULES = [
    Rule([r"\b(?:create|createMany|update|updateMany|upsert|insert|insertOne|insertMany|updateOne|findOneAndUpdate|"
          r"findByIdAndUpdate|findOrCreate|build|save|merge|assign)\s*\((?:[^;]*?(?:(?:data|values|attributes|\$set)\s*:\s*|,\s*))?"
          r"\s*(?:\{\s*\.\.\.\s*)?(?:req|request|ctx\.request)\.body\b(?!\s*\.)",
          r"\bnew\s+[A-Z]\w*\s*\(\s*(?:req|request)\.body\s*\)"],
         "medium", "writes the whole request body to a record — a client can set role, owner, price or balance; allowlist the fields",
         code, ["req.body", "request.body"]),
    Rule([r"\*\*\s*request\.(?:data|json|form|POST|GET|get_json\(\s*\))"], "medium",
         "unpacks the whole request into a model — allowlist the fields a client may set", lambda f: f.ext == ".py", ["**request"]),
    Rule([r"\bfields\s*=\s*['\"]__all__['\"]"], "medium",
         "serializer or form exposes every model field as writable — list the fields explicitly",
         lambda f: f.ext == ".py", ["__all__"]),
    Rule([r"\bparams\.permit!", r"\.(?:new|create|update|update_attributes|assign_attributes)\s*\(\s*params\[:\w+\]\s*\)"], "medium",
         "mass assignment from params — use strong parameters with an explicit permit list", lambda f: f.ext == ".rb", ["params"]),
]
rule_check("mass-assignment", ["API-03"], "Whole request bodies written to records (mass assignment)", MASS_RULES, hook=True, gate=["G4"])


# ---------------------------------------------------------------------------------------------
# Dependencies and supply chain — DEPS-01, DEPS-02, DEPS-06, DEPS-07
# ---------------------------------------------------------------------------------------------

def manifests(ctx: Context, name: str) -> List[SourceFile]:
    return [f for f in ctx.every if f.name == name]


def has_lock_near(ctx: Context, rel: str, names: Sequence[str]) -> Optional[str]:
    """A lockfile in the manifest's directory or any ancestor (workspaces share one)."""
    directory = rel.rsplit("/", 1)[0] if "/" in rel else ""
    while True:
        for n in names:
            candidate = f"{directory}/{n}" if directory else n
            if ctx.rel_exists(candidate):
                return candidate
        if not directory:
            return None
        directory = directory.rsplit("/", 1)[0] if "/" in directory else ""


def json_file(f: SourceFile) -> dict:
    try:
        data = json.loads(f.text() or "{}")
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


def workflow_files(ctx: Context) -> List[SourceFile]:
    return [f for f in ctx.every if re.search(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", f.rel)]


@check("lockfile", ["DEPS-01"], "Manifests without a committed lockfile, unpinned Python requirements, and CI installs that ignore the lockfile",
       repo_level=True, gate=["G7"])
def check_lockfile(ctx: Context) -> List[Finding]:
    found = []
    js_locks = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
    pairs = [("package.json", js_locks), ("pyproject.toml", ("poetry.lock", "uv.lock", "pdm.lock")),
             ("Pipfile", ("Pipfile.lock",)), ("Gemfile", ("Gemfile.lock",)), ("go.mod", ("go.sum",)),
             ("composer.json", ("composer.lock",))]
    for manifest, locks in pairs:
        for f in manifests(ctx, manifest):
            if manifest == "package.json" and not re.search(r'"(?:dev)?[dD]ependencies"\s*:\s*\{\s*"', f.text()):
                continue
            if manifest == "pyproject.toml" and not re.search(r"^\s*dependencies\s*=|\[tool\.poetry\.dependencies\]", f.text(), re.M):
                continue
            if manifest == "go.mod" and "require" not in f.text():
                continue
            lock = has_lock_near(ctx, f.rel, locks)
            if lock is None:
                found.append(Finding("lockfile", ("DEPS-01",), "high", f.rel, None,
                                     "no lockfile — every install resolves whatever versions exist that day, including a compromised one published an hour ago", ""))
            elif ctx.git and lock not in ctx.tracked:
                found.append(Finding("lockfile", ("DEPS-01",), "high", lock, None,
                                     "lockfile exists but is not committed — CI and teammates resolve fresh versions", ""))
    for f in ctx.every:
        if re.fullmatch(r"requirements[\w.-]*\.txt", f.name) and not has_lock_near(ctx, f.rel, ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock")):
            loose = [ln.strip() for ln in f.lines()
                     if ln.strip() and not ln.strip().startswith(("#", "-", "git+", "http")) and "==" not in ln and " @ " not in ln]
            if loose:
                found.append(Finding("lockfile", ("DEPS-01",), "medium", f.rel, None,
                                     f"{len(loose)} requirement(s) not pinned with == (e.g. `{loose[0][:40]}`) — pin them, or lock with uv/poetry/pip-tools", ""))
    for wf in workflow_files(ctx):
        for i, line in enumerate(wf.lines(), 1):
            if re.search(r"\bnpm\s+(?:install|i)\b(?!\s+[\w@])", line) and not re.search(r"\bnpm\s+(?:install|i)\s+-g\b", line):
                found.append(Finding("lockfile", ("DEPS-01",), "medium", wf.rel, i,
                                     "CI runs `npm install`, which may rewrite the lockfile — use `npm ci`", excerpt(line)))
    return found


@check("install-scripts", ["DEPS-02"], "Dependency install scripts enabled (the s1ngularity and Shai-Hulud payloads ran from postinstall)",
       repo_level=True, gate=["G7"])
def check_install_scripts(ctx: Context) -> List[Finding]:
    roots = [f for f in manifests(ctx, "package.json") if re.search(r'"(?:dev)?[dD]ependencies"\s*:\s*\{\s*"', f.text())]
    if not roots:
        raise NotRun("no npm-style package.json with dependencies")
    npmrc = "\n".join(f.text() for f in ctx.every if f.name == ".npmrc")
    yarnrc = "\n".join(f.text() for f in ctx.every if f.name == ".yarnrc.yml")
    if re.search(r"^\s*ignore-scripts\s*=\s*true\b", npmrc, re.M | I) or re.search(r"^\s*enableScripts\s*:\s*false\b", yarnrc, re.M):
        return []
    if any(ctx.rel_exists(n) for n in ("bun.lock", "bun.lockb")):
        return []                     # bun runs dependency lifecycle scripts only for trustedDependencies
    for f in roots:
        pm = str(json_file(f).get("packageManager", ""))
        m = re.match(r"pnpm@(\d+)", pm)
        if m and int(m.group(1)) >= 10:
            return []                 # pnpm 10 blocks dependency build scripts unless allowlisted
    ci_installs = [(wf, i, line) for wf in workflow_files(ctx) for i, line in enumerate(wf.lines(), 1)
                   if re.search(r"\b(?:npm\s+(?:ci|install|i)|pnpm\s+(?:install|i)|yarn\s+install)\b|^\s*(?:-\s+)?run:\s*yarn\s*$", line)
                   and not line.strip().startswith("#")]
    unguarded = [x for x in ci_installs if "--ignore-scripts" not in x[2]]
    where = ("on every developer machine and in CI" if unguarded or not ci_installs
             else "on developer machines (CI passes --ignore-scripts)")
    return [Finding("install-scripts", ("DEPS-02",), "high" if unguarded or not ci_installs else "medium", roots[0].rel, None,
                    f"dependency install scripts run {where} — commit `ignore-scripts=true` in .npmrc (a setting in your own "
                    "~/.npmrc protects nobody else) and allowlist the few packages that need a build step", "")]


EXTERNAL_SCRIPT = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*[\"']?(?P<url>(?:https?:)?//[^\"'\s>]+)[^>]*>", I | re.S)
KNOWN_BAD_HOSTS = re.compile(r"(?:^|\.)(?:polyfill\.io|polyfill\.com|polyfillcache\.com|bootcss\.com|bootcdn\.net|staticfile\.org|staticfile\.net)$", I)
MUST_LOAD_LIVE = re.compile(r"(?:^|\.)(?:js\.stripe\.com|www\.google\.com|www\.gstatic\.com|challenges\.cloudflare\.com|accounts\.google\.com|apis\.google\.com|js\.hcaptcha\.com|www\.paypal\.com|appleid\.cdn-apple\.com)$", I)


@check("external-script", ["DEPS-06", "VENDOR-05"], "Scripts loaded from hosts you do not control, and without subresource integrity",
       hook=True, gate=["G14"])
def check_external_script(ctx: Context) -> List[Finding]:
    found = []
    for f in ctx.files:
        if not (f.is_markup or f.ext in {".jsx", ".tsx", ".vue", ".svelte", ".astro", ".php"}) or "<script" not in f.lower():
            continue
        text = f.text()
        for m in EXTERNAL_SCRIPT.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            if ALLOW_MARKER in f.lines()[line - 1]:
                continue
            host = re.sub(r"^(?:https?:)?//", "", m.group("url")).split("/")[0].split(":")[0]
            if KNOWN_BAD_HOSTS.search(host):
                found.append(Finding("external-script", ("DEPS-06",), "high", f.rel, line,
                                     f"script from {host} — polyfill.io was sold and served malware to 100,000+ sites; self-host it", excerpt(m.group(0))))
            elif "integrity=" in m.group(0).lower():
                continue
            elif MUST_LOAD_LIVE.search(host):
                found.append(Finding("external-script", ("VENDOR-05",), "low", f.rel, line,
                                     f"script from {host} — expected to load live; keep it off pages that do not need it", excerpt(m.group(0))))
            else:
                found.append(Finding("external-script", ("DEPS-06", "VENDOR-05"), "medium", f.rel, line,
                                     f"script from {host} with no integrity hash — whoever controls that host controls your page; self-host or pin with SRI",
                                     excerpt(m.group(0))))
    return found


def run_tool(cmd: Sequence[str], cwd: Path, timeout: int = 180) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(list(cmd), cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def audit_counts(tool: str, code_: int, out: str, err: str) -> Dict[str, int]:
    """Severity counts from `npm audit --json` or `pnpm audit --json`; raises when the audit did not run."""
    first = (err or out).strip().splitlines()[0] if (err or out).strip() else f"exit {code_}"
    try:
        data = json.loads(out)
    except ValueError:
        raise CheckError(f"{tool} failed: {first}")
    if not isinstance(data, dict) or "error" in data or "metadata" not in data:
        detail = data.get("error", {}).get("summary") if isinstance(data, dict) and isinstance(data.get("error"), dict) else first
        raise CheckError(f"{tool} failed: {detail}")
    counts = data["metadata"].get("vulnerabilities", {})
    return {k: int(counts.get(k, 0) or 0) for k in ("critical", "high", "moderate", "low")}


@check("dependency-audit", ["DEPS-07"], "Known-vulnerable dependencies, via npm audit, pnpm audit, pip-audit or osv-scanner (needs --audit)",
       repo_level=True, gate=["G7"], needs="audit")
def check_dependency_audit(ctx: Context) -> List[Finding]:
    found: List[Finding] = []
    ran: List[str] = []
    skipped: List[str] = []
    if shutil.which("osv-scanner"):
        code_, out, err = run_tool(["osv-scanner", "--format", "json", "-r", "."], ctx.root, 300)
        try:
            data = json.loads(out or "{}")
            vulns = sum(len(p.get("vulnerabilities", [])) for r in data.get("results", []) for p in r.get("packages", []))
            ran.append("osv-scanner")
            if vulns:
                found.append(Finding("dependency-audit", ("DEPS-07",), "high", ".", None,
                                     f"osv-scanner: {vulns} known vulnerabilities across the lockfiles", ""))
        except ValueError:
            raise CheckError(f"osv-scanner failed: {(err or out).strip().splitlines()[0] if (err or out).strip() else code_}")
        return found
    for lock, tool, cmd in (("package-lock.json", "npm audit", ["npm", "audit", "--json", "--omit=dev"]),
                            ("pnpm-lock.yaml", "pnpm audit", ["pnpm", "audit", "--json", "--prod"])):
        if not ctx.rel_exists(lock):
            continue
        if not shutil.which(cmd[0]):
            skipped.append(f"{cmd[0]} is not installed")
            continue
        counts = audit_counts(tool, *run_tool(cmd, ctx.root))
        ran.append(tool)
        serious = counts["critical"] + counts["high"]
        if serious or counts["moderate"]:
            found.append(Finding("dependency-audit", ("DEPS-07",), "high" if serious else "medium", lock, None,
                                 f"{tool}: " + ", ".join(f"{n} {k}" for k, n in counts.items()), ""))
    reqs = [f for f in ctx.every if re.fullmatch(r"requirements[\w.-]*\.txt", f.name)]
    if reqs:
        if shutil.which("pip-audit"):
            code_, out, err = run_tool(["pip-audit", "-f", "json", "-r", reqs[0].rel], ctx.root, 300)
            try:
                data = json.loads(out)
                deps = data.get("dependencies", data) if isinstance(data, dict) else data
                vulns = sum(len(d.get("vulns", [])) for d in deps if isinstance(d, dict))
                ran.append("pip-audit")
                if vulns:
                    found.append(Finding("dependency-audit", ("DEPS-07",), "high", reqs[0].rel, None,
                                         f"pip-audit: {vulns} known vulnerabilities", ""))
            except (ValueError, AttributeError):
                raise CheckError(f"pip-audit failed: {(err or out).strip().splitlines()[0] if (err or out).strip() else code_}")
        else:
            skipped.append("pip-audit is not installed")
    if not ran:
        raise NotRun("; ".join(skipped) or "no supported lockfile, or no auditor installed (osv-scanner covers every ecosystem)")
    if skipped:
        ctx.notes.append("dependency-audit: " + "; ".join(skipped))
    return found


# ---------------------------------------------------------------------------------------------
# Agents — AGENT-02, AGENT-04, AGENT-08, AGENT-09
# ---------------------------------------------------------------------------------------------

ALWAYS_INVISIBLE = re.compile("[\u202a-\u202e\u2066-\u2069\u2061-\u2064\U000e0000-\U000e007f]")
CODE_INVISIBLE = re.compile("[\u200b\u200e\u200f\u2060\u180e\u00ad]|(?<!^)\ufeff")


@check("invisible-unicode", ["AGENT-09"], "Bidi controls, Unicode tag characters and zero-width characters (Trojan Source, hidden prompt injection)",
       hook=True, gate=["G16"])
def check_invisible(ctx: Context) -> List[Finding]:
    found = []
    for f in ctx.files:
        text = f.text()
        if not text or text.isascii():
            continue
        strict = f.is_code or f.is_config or bool(AGENT_CONFIG.search(f.rel)) or re.search(
            r"(^|/)(AGENTS|CLAUDE|GEMINI)\.md$|(^|/)\.cursor/rules/|\.cursorrules$|\.windsurfrules$|\.clinerules$|copilot-instructions\.md$", f.rel)
        for i, line in enumerate(f.lines(), 1):
            chars = ALWAYS_INVISIBLE.findall(line) or (CODE_INVISIBLE.findall(line if i > 1 else line.lstrip("\ufeff")) if strict else [])
            if not chars or ALLOW_MARKER in line:
                continue
            names = sorted({f"U+{ord(c):04X} {unicodedata.name(c, 'UNNAMED')}" for c in chars})
            tag = any(0xE0000 <= ord(c) <= 0xE007F for c in chars)
            bidi = any(0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069 for c in chars)
            severity = "high" if tag or bidi else "medium"
            why = ("tag characters can carry instructions a model reads and a human cannot see" if tag
                   else "bidirectional controls make code read differently from how it runs" if bidi
                   else "invisible characters change what code does without changing how it looks")
            found.append(Finding("invisible-unicode", ("AGENT-09",), severity, f.rel, i,
                                 f"{', '.join(names)} — {why}", excerpt(line.encode("ascii", "backslashreplace").decode())))
    return found


@check("agent-config", ["AGENT-08", "AGENT-04", "AGENT-05"], "Repository agent configuration that runs code: auto-run tasks, hooks, blanket permissions, unpinned MCP servers",
       hook=True, gate=["G16"])
def check_agent_config(ctx: Context) -> List[Finding]:
    found = []
    for f in ctx.files:
        rel = f.rel
        text = f.text()
        if rel.endswith(".vscode/tasks.json") and re.search(r'"runOn"\s*:\s*"folderOpen"', text):
            line = next(i for i, ln in enumerate(f.lines(), 1) if "folderOpen" in ln)
            found.append(Finding("agent-config", ("AGENT-08",), "high", rel, line,
                                 "a task runs automatically when the folder is opened — opening this repository runs its code", ""))
        if re.search(r"(^|/)\.devcontainer/.*\.json$", rel):
            for i, ln in enumerate(f.lines(), 1):
                if re.search(r'"(?:initializeCommand|onCreateCommand|postCreateCommand|postStartCommand|postAttachCommand)"', ln):
                    found.append(Finding("agent-config", ("AGENT-08",), "low", rel, i,
                                         "devcontainer lifecycle command runs on build or attach — review changes to it like code", excerpt(ln)))
        if re.search(r"(^|/)\.claude/settings(\.local)?\.json$", rel):
            data = json_file(f)
            allow = ((data.get("permissions") or {}).get("allow") or []) if isinstance(data.get("permissions"), dict) else []
            blanket = [a for a in allow if isinstance(a, str) and re.fullmatch(r"Bash(?:\(\*\)|\(\s*\*\s*\))?", a.strip())]
            if blanket:
                found.append(Finding("agent-config", ("AGENT-08", "AGENT-06"), "medium", rel, None,
                                     "allows every shell command without asking — scope Bash rules to the commands the project needs", ""))
            if data.get("hooks"):
                found.append(Finding("agent-config", ("AGENT-08",), "low", rel, None,
                                     "defines hooks that run shell commands automatically — review changes to them like code", ""))
        if AGENT_CONFIG.search(rel) and rel.endswith(".json"):
            found.extend(mcp_findings(f))
    return found


def line_of(f: SourceFile, needle: str) -> Optional[int]:
    return next((i for i, ln in enumerate(f.lines(), 1) if needle in ln), None)


def mcp_findings(f: SourceFile) -> List[Finding]:
    """Unpinned and unencrypted MCP servers in an agent configuration file."""
    data = json_file(f)
    servers = data.get("mcpServers") or data.get("servers") or {}
    found = []
    if not isinstance(servers, dict):
        return found
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        command = os.path.basename(str(spec.get("command", "")))
        args = [str(a) for a in spec.get("args", []) if isinstance(a, (str, int))]
        if command in {"npx", "bunx", "pnpx", "uvx", "pipx"} or (command == "pnpm" and "dlx" in args):
            package = next((a for a in args if not a.startswith("-") and a not in {"dlx", "run"}), "")
            bare = package.lstrip("@")
            pinned = bool(re.search(r"@\d|==\d", bare)) if command != "uvx" else "==" in package or "@" in bare
            if package and not pinned:
                found.append(Finding("agent-config", ("AGENT-04",), "medium", f.rel, line_of(f, package),
                                     f"MCP server `{name}` runs the latest published `{package}` on every start — pin a version "
                                     "(postmark-mcp turned malicious in a later release)", ""))
        url = str(spec.get("url", ""))
        if url.startswith("http://") and not re.match(r"http://(?:localhost|127\.0\.0\.1|\[::1\])", url):
            found.append(Finding("agent-config", ("AGENT-05",), "medium", f.rel, line_of(f, url),
                                 f"MCP server `{name}` is reached over plain HTTP — use HTTPS and authentication", ""))
    return found


# ---------------------------------------------------------------------------------------------
# CI/CD — CICD-01, CICD-04 (tj-actions/changed-files, s1ngularity)
# ---------------------------------------------------------------------------------------------

UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|comment\.body|"
    r"review\.body|review_comment\.body|pages\.[^}]*page_name|commits\.[^}]*(?:message|author\.(?:email|name))|"
    r"head_commit\.(?:message|author\.(?:email|name))|discussion\.(?:title|body)|workflow_run\.(?:head_branch|display_title|"
    r"head_commit\.message))|github\.head_ref)\s*\}\}")
USES = re.compile(r"^\s*(?:-\s+)?uses\s*:\s*['\"]?(?P<action>[^'\"\s#@]+)@(?P<ref>[^'\"\s#]+)")
CHECKOUT_HEAD = re.compile(r"\bref\s*:\s*['\"]?\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|github\.event\.pull_request\.merge_commit_sha)")


def script_lines(lines: List[str]):
    """Yield (line number, text) for every line inside a `run:` or `script:` value."""
    block_indent: Optional[int] = None
    for i, line in enumerate(lines, 1):
        m = re.match(r"^(\s*)(?:-\s+)?(run|script)\s*:\s*(.*)$", line)
        if m:
            rest = m.group(3).strip()
            if rest[:1] in {"|", ">"}:
                block_indent = len(m.group(1))
            else:
                block_indent = None
                yield i, line
            continue
        if block_indent is not None:
            if not line.strip():
                continue
            if len(line) - len(line.lstrip()) > block_indent:
                yield i, line
            else:
                block_indent = None


@check("workflow", ["CICD-01", "CICD-04"], "GitHub Actions: pull_request_target, attacker text in run steps, actions pinned to tags, token permissions",
       hook=True, gate=["G7"])
def check_workflows(ctx: Context) -> List[Finding]:
    found = []
    for f in ctx.files:
        if not re.search(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", f.rel):
            continue
        text, lines = f.text(), f.lines()
        for i, line in script_lines(lines):
            if UNTRUSTED_EXPR.search(line) and ALLOW_MARKER not in line:
                found.append(Finding("workflow", ("CICD-04", "CICD-01"), "high", f.rel, i,
                                     "attacker-controlled text (a title, branch name or comment) is pasted into a script — pass it through `env:` and quote it",
                                     excerpt(line)))
        if re.search(r"^\s*pull_request_target\b|\bon\s*:\s*\[?[^\n#]*\bpull_request_target\b", text, re.M):
            line = next(i for i, ln in enumerate(lines, 1) if "pull_request_target" in ln)
            if CHECKOUT_HEAD.search(text):
                found.append(Finding("workflow", ("CICD-01", "CICD-04"), "high", f.rel, line,
                                     "pull_request_target checks out the pull request's code — a fork's code runs with your secrets and a write token", ""))
            else:
                found.append(Finding("workflow", ("CICD-01", "CICD-04"), "medium", f.rel, line,
                                     "pull_request_target runs with secrets and a write token on fork pull requests — confirm nothing from the PR reaches a script (s1ngularity started here)", ""))
        for i, line in enumerate(lines, 1):
            if ALLOW_MARKER in line:
                continue
            if re.match(r"^\s*(?:-\s+)?uses\s*:\s*['\"]?docker://", line):
                if "@sha256:" not in line:
                    found.append(Finding("workflow", ("CICD-04",), "low", f.rel, i, "container action pinned to a tag — pin the image digest", excerpt(line)))
                continue
            m = USES.match(line)
            if not m:
                continue
            action, ref = m.group("action"), m.group("ref")
            if action.startswith(("./", ".\\")) or re.fullmatch(r"[0-9a-f]{40}", ref):
                continue
            owner = action.split("/")[0].lower()
            first_party = owner in {"actions", "github"}
            why = "" if first_party else " (tj-actions/changed-files rewrote its tags to steal CI secrets)"
            found.append(Finding("workflow", ("CICD-04",), "low" if first_party else "medium", f.rel, i,
                                 f"`{action}@{ref}` is pinned to a movable tag — pin the full commit SHA{why}", excerpt(line)))
        if re.search(r"^\s*permissions\s*:\s*write-all\b", text, re.M):
            found.append(Finding("workflow", ("CICD-04",), "medium", f.rel, None, "`permissions: write-all` — grant each job only what it needs", ""))
        elif not re.search(r"^\s*permissions\s*:", text, re.M):
            found.append(Finding("workflow", ("CICD-04",), "low", f.rel, None,
                                 "no `permissions:` block — the token gets the repository default, which may be read-write (it was, in s1ngularity)", ""))
    return found


# ---------------------------------------------------------------------------------------------
# Cloud, configuration and exposure — CLOUD-03, DATA-03, DATA-04, LEAK-03, CRYPTO-04
# ---------------------------------------------------------------------------------------------

def iac(f: SourceFile) -> bool:
    return f.ext in {".json", ".tf", ".hcl", ".yaml", ".yml", ".ts", ".py", ".js"} and not f.is_test


IAM_RULES = [
    Rule([r"\"Action\"\s*:\s*(?:\"\*\"|\[\s*\"\*\"\s*\])", r"\bactions\s*=\s*\[\s*\"\*\"\s*\]", r"\bactions\s*:\s*\[\s*['\"]\*['\"]\s*\]"], "high",
         "IAM policy allows every action — scope it to the calls the role makes", iac, ["action"]),
    Rule([r"\"Action\"\s*:\s*(?:\"[a-z0-9-]{2,}:\*\"|\[[^\]]*\"[a-z0-9-]{2,}:\*\")",
          r"\bactions?\s*[:=]\s*\[[^\]]*[\"'][a-z0-9-]{2,}:\*[\"']"], "medium",
         "IAM policy allows every action of a service (e.g. s3:*) — list the actions", iac, [":*"], flags=I),
    Rule([r"\broles/(?:owner|editor)\b"], "medium", "project-wide owner/editor role — grant a narrower role",
         lambda f: f.ext in {".tf", ".yaml", ".yml", ".json"}, ["roles/"]),
]
rule_check("iam-wildcard", ["CLOUD-03"], "IAM policies with wildcard actions and project-wide roles", IAM_RULES, gate=["G13"])

STORAGE_RULES = [
    Rule([r"\bacl\s*=\s*\"public-read(?:-write)?\"", r"\"Principal\"\s*:\s*(?:\"\*\"|\{\s*\"AWS\"\s*:\s*\"\*\"\s*\})",
          r"\"allUsers\"|\"allAuthenticatedUsers\"", r"\bpublicly_accessible\s*=\s*true"], "high",
         "storage or database made public — every object is readable by anyone who finds the name (Tea app, 2025)",
         lambda f: f.ext in {".tf", ".json", ".yaml", ".yml", ".hcl"}, ["public", "principal", "allusers", "allauthenticatedusers"]),
    Rule([r"\b(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false"], "medium",
         "S3 public-access block turned off — leave it on at the account and the bucket", lambda f: f.ext in {".tf", ".hcl"}, ["public"]),
    Rule([r"createBucket\s*\([^)]*public\s*:\s*true", r"insert\s+into\s+storage\.buckets[^;]*\btrue\b"], "medium",
         "public storage bucket — confirm every object in it is meant to be world-readable; serve the rest through signed URLs",
         lambda f: f.is_code or f.ext == ".sql", ["createbucket", "storage.buckets"], flags=I),
]
rule_check("public-storage", ["DATA-03", "CLOUD-01", "FILE-04"], "Public buckets, public ACLs, wildcard principals and publicly accessible databases", STORAGE_RULES, gate=["G3"])

DB_PORT_LIST = ("5432", "3306", "27017", "6379", "9200", "9300", "5984", "8086", "9042", "11211", "7474", "7687",
                "26257", "1433", "1521", "8123")
DB_PORTS = "(?:" + "|".join(DB_PORT_LIST) + ")"
EXPOSURE_RULES = [
    Rule([rf"^\s*-\s*[\"']?(?:0\.0\.0\.0:)?{DB_PORTS}(?::\d+)?[\"']?\s*(?:#.*)?$"], "medium",
         "database port published on every interface of the host — bind it to 127.0.0.1 or leave it unpublished",
         lambda f: bool(re.search(r"(^|/)(docker-)?compose[\w.-]*\.ya?ml$", f.rel)), DB_PORT_LIST),
    Rule([r"^\s*bind\s+0\.0\.0\.0\b", r"^\s*protected-mode\s+no\b", r"\bbindIp\s*:\s*0\.0\.0\.0", r"\bnetwork\.host\s*:\s*0\.0\.0\.0",
          r"\blisten_addresses\s*=\s*'\*'"], "medium",
         "datastore listens on every interface — Exactis and Ecuador lost hundreds of millions of records to exactly this",
         lambda f: f.is_config, ["0.0.0.0", "protected-mode", "listen_addresses"]),
]
rule_check("datastore-exposure", ["DATA-04", "CLOUD-08"], "Datastores bound to every interface or published from docker compose", EXPOSURE_RULES, gate=["G3"])


@check("open-security-group", ["DATA-04", "CLOUD-08"], "Security groups open to 0.0.0.0/0 on database or admin ports", gate=["G3"])
def check_security_groups(ctx: Context) -> List[Finding]:
    found = []
    for f in ctx.files:
        if f.ext not in {".tf", ".hcl", ".json", ".yaml", ".yml"} or "0.0.0.0/0" not in f.text() and "::/0" not in f.text():
            continue
        lines = f.lines()
        for i, line in enumerate(lines, 1):
            if "0.0.0.0/0" not in line and "::/0" not in line:
                continue
            window = "\n".join(lines[max(0, i - 12):i + 12])
            port = re.search(rf"(?:from_port|to_port|FromPort|ToPort|port)[\"']?\s*[=:]\s*[\"']?(22|3389|{DB_PORTS})\b", window)
            if port:
                found.append(Finding("open-security-group", ("DATA-04", "CLOUD-08"), "high", f.rel, i,
                                     f"port {port.group(1)} open to the whole internet — put it behind a VPN or bastion", excerpt(line)))
    return found


DEBUG_RULES = [
    Rule([r"^\s*DEBUG\s*=\s*True\b"], "medium", "Django DEBUG=True — serves stack traces, settings and SQL to anyone who triggers an error",
         lambda f: bool(re.search(r"settings[\w/]*\.py$", f.rel)) and not re.search(r"(dev|local|test)", f.rel, I), ["debug"]),
    Rule([r"\bapp\.run\s*\([^)]*debug\s*=\s*True"], "medium",
         "Flask debug mode — the Werkzeug debugger executes code for whoever reaches it", lambda f: f.ext == ".py", ["debug"]),
    Rule([r"\bres\.(?:send|json)\s*\([^)]*\b(?:err|error|e)\.stack\b", r"\bstatus\s*\(\s*\d+\s*\)\s*\.(?:send|json)\s*\([^)]*\.stack\b",
          r"(?:\breturn\b|jsonify\s*\(|Response\s*\(|make_response\s*\()[^#\n]*traceback\.format_exc\s*\(\s*\)"], "medium",
         "stack trace returned to the caller — log it, return a generic error", code, ["stack", "traceback"],
         exclude=[r"\blog(?:ger)?\.", r"console\."]),
    Rule([r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*[\"']?\*"], "high",
         "every Spring actuator endpoint exposed — heapdump and env leak secrets", lambda f: f.is_config, ["management"]),
    Rule([r"server\.error\.include-stacktrace\s*[=:]\s*always"], "medium", "stack traces included in error responses",
         lambda f: f.is_config, ["include-stacktrace"]),
]
rule_check("debug-exposure", ["LEAK-03", "API-07"], "Debug modes and stack traces that reach callers", DEBUG_RULES)

TLS_RULES = [
    Rule([r"\bverify\s*=\s*False\b", r"\brejectUnauthorized\s*:\s*false\b", r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
          r"\bInsecureSkipVerify\s*:\s*true\b", r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:0|false)", r"ssl\._create_unverified_context",
          r"\bcheck_hostname\s*=\s*False\b", r"\bstrictSSL\s*:\s*false\b", r"\bALLOW_ALL_HOSTNAME_VERIFIER\b",
          r"android:usesCleartextTraffic\s*=\s*\"true\"", r"NSAllowsArbitraryLoads</key>\s*<true\s*/>"],
         "medium", "TLS certificate validation disabled or cleartext allowed — anyone on the path can read and change the traffic",
         lambda f: f.is_code or f.is_config, ["verify", "rejectunauthorized", "tls_reject", "insecureskipverify", "ssl_verify",
                                              "unverified", "check_hostname", "strictssl", "allow_all", "cleartext", "arbitraryloads"]),
]
rule_check("tls-verification", ["CRYPTO-04", "MOBILE-02"], "Disabled certificate validation and cleartext traffic", TLS_RULES, hook=True)


# ---------------------------------------------------------------------------------------------
# Browser trust — WEB-01, WEB-05, AUTH-04
# ---------------------------------------------------------------------------------------------

@check("csp", ["WEB-01"], "Content-Security-Policy that allows any script: `*`, 'unsafe-inline' without a nonce, 'unsafe-eval', or CSP turned off",
       hook=True, gate=["G17"])
def check_csp(ctx: Context) -> List[Finding]:
    found = []
    defined = False
    for f in ctx.files:
        if not (f.is_code or f.is_config or f.is_markup) or f.is_test:
            continue
        low = f.lower()
        if "script-src" not in low and "default-src" not in low and "contentsecuritypolicy" not in low and "scriptsrc" not in low:
            continue
        for i, line in enumerate(f.lines(), 1):
            if ALLOW_MARKER in line or is_comment(line):
                continue
            l = line.lower()
            if re.search(r"contentsecuritypolicy\s*:\s*false", l):
                found.append(Finding("csp", ("WEB-01",), "high", f.rel, i, "Content-Security-Policy turned off", excerpt(line)))
                continue
            directives = {m.group(1): m.group(2).split() for m in re.finditer(r"\b(script-src-elem|script-src|default-src)\s+([^;\"`]*)", l)}
            if directives:
                defined = True
                sources = directives.get("script-src") or directives.get("script-src-elem") or directives.get("default-src") or []
                has_nonce = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-", "'strict-dynamic'")) for s in sources)
                bad = [s for s in sources if s in {"*", "http:", "https:", "data:", "'unsafe-eval'"} or (s == "'unsafe-inline'" and not has_nonce)]
                if bad:
                    found.append(Finding("csp", ("WEB-01",), "high", f.rel, i,
                                         f"script sources include {', '.join(bad)} — injected script runs anyway; use a per-response nonce with 'strict-dynamic' (roll out as Report-Only first)",
                                         excerpt(line)))
            m = re.search(r"scriptsrc\s*:\s*\[([^\]]*)\]", l)
            if m:
                defined = True
                if re.search(r"'unsafe-inline'|'unsafe-eval'|[\"']\*[\"']", m.group(1)) and "nonce" not in m.group(1):
                    found.append(Finding("csp", ("WEB-01",), "high", f.rel, i,
                                         "scriptSrc allows inline or eval'd script — use nonces (roll out as Report-Only first)", excerpt(line)))
    if not defined and any(f.is_markup or f.ext in {".jsx", ".tsx", ".vue", ".svelte"} for f in ctx.files) and ctx.repo_scope:
        found.append(Finding("csp", ("WEB-01",), "info", ".", None,
                             "no Content-Security-Policy found in the repository — check the live response headers; it may be set at the CDN", ""))
    return found


COOKIE_FLAG_OFF = re.compile(r"\bhttpOnly\s*:\s*false\b|\bsecure\s*:\s*false\b|SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False|"
                             r"CSRF_COOKIE_SECURE\s*=\s*False|\bhttponly\s*=\s*False\b", I)
COOKIE_CONTEXT = re.compile(r"cookie|session|samesite|httponly|maxage|max_age", I)
SCRIPT_TOKEN = re.compile(r"\blocalStorage\.setItem\s*\(\s*['\"`][^'\"`]*(?:token|jwt|session|auth)|\bdocument\.cookie\s*=\s*[^;]*(?:token|jwt|session)", I)


@check("cookie-flags", ["WEB-05", "AUTH-04"], "Cookies without Secure/HttpOnly and session tokens kept where script can read them", gate=["G17"])
def check_cookies(ctx: Context) -> List[Finding]:
    found = []
    for f in ctx.files:
        if not f.is_code or f.is_test:
            continue
        low = f.lower()
        if not ("false" in low or "localstorage" in low or "document.cookie" in low):
            continue
        lines = f.lines()
        for i, line in enumerate(lines, 1):
            if ALLOW_MARKER in line or is_comment(line):
                continue
            if COOKIE_FLAG_OFF.search(line):
                window = "\n".join(lines[max(0, i - 7):i + 6])
                # `secure: false` also configures SMTP STARTTLS; only a cookie context counts
                if COOKIE_CONTEXT.search(window) and not re.search(r"NODE_ENV|\bdev(?:elopment)?\b|localhost", line, I):
                    found.append(Finding("cookie-flags", ("WEB-05", "AUTH-04"), "medium", f.rel, i,
                                         "cookie without Secure or HttpOnly — script can read it, or it travels in the clear", excerpt(line)))
            elif SCRIPT_TOKEN.search(line):
                found.append(Finding("cookie-flags", ("AUTH-04",), "low", f.rel, i,
                                     "session token kept where script can read it — any XSS takes the session; prefer an HttpOnly cookie", excerpt(line)))
    return found


# ---------------------------------------------------------------------------------------------
# Authentication surface — LEAK-01, AUTH-13, AUTH-14, CRED-10, AUTH-06
# ---------------------------------------------------------------------------------------------

ENUM_RULES = [
    Rule([r"[\"'`][^\"'`]*\b(?:user|account|email|e-mail|username|member)\b[^\"'`]*\b(?:not\s+found|does\s*n[o']?t\s+exist|"
          r"not\s+registered|no\s+such\s+(?:user|account)|is\s+not\s+registered)\b[^\"'`]*[\"'`]",
          r"[\"'`][^\"'`]*\bno\s+(?:user|account)\s+(?:found|exists|with)\b[^\"'`]*[\"'`]",
          r"[\"'`][^\"'`]*\b(?:incorrect|wrong|invalid)\s+password\b(?!\s+(?:reset|link|token|format|length|policy|requirements?))[^\"'`]*[\"'`]",
          r"[\"'`][^\"'`]*\b(?:email|username|account|user)\b[^\"'`]*\b(?:already\s+(?:exists|registered|taken|in\s+use)|is\s+(?:already\s+)?taken)\b[^\"'`]*[\"'`]"],
         "medium", "message says whether an account exists — login, signup and reset must give one neutral answer (and take the same time)",
         lambda f: (f.is_code or f.ext in {".json", ".yml", ".yaml"}) and not f.is_test,
         ["password", "not found", "exist", "registered", "taken", "in use", "no user", "no account"], flags=I),
]
rule_check("enumeration-message", ["LEAK-01", "AUTH-13"], "Messages that reveal whether an account exists", ENUM_RULES, gate=["G18"])

DEFAULT_ACCOUNT = [
    Rule([r"passw(?:or)?d[\"']?\s*[:=]\s*[\"'](?:" + "|".join(sorted(DEFAULT_PASSWORDS)) + r")[\"']"],
         "high", "a default password ships in the code — force a unique one at first use",
         lambda f: (f.is_code or f.is_config or f.ext == ".sql") and not f.is_test, ["passw"], flags=I),
    Rule([r"(?:user_?name|login|email)[\"']?\s*[:=]\s*[\"'](?:admin|root|administrator|superuser|test|demo)(?:@[^\"']*)?[\"']"], "medium",
         "a predictable privileged or test account is created — no `admin`, `root` or `test` in production",
         lambda f: bool(re.search(r"(^|/)(seeds?|fixtures?|migrations?|bootstrap)(/|\.|[_-])|seed\w*\.\w+$|(^|/)init[_-]?db|\.sql$", f.rel, I))
         and not f.is_doc, ["admin", "root", "superuser", "test", "demo"], flags=I),
]
rule_check("default-credential", ["AUTH-14", "CRED-10"], "Predictable admin/test accounts and default passwords", DEFAULT_ACCOUNT, hook=True, gate=["G18"])

AUTH_WORDS = ("login", "log-in", "signin", "sign-in", "signup", "sign-up", "register", "forgot", "reset", "otp", "magic-link", "verify")
AUTH_ROUTE = re.compile(r"(?:post|get|put|route|path|router\.\w+|app\.\w+|@\w+\.(?:post|route|get))\s*\(\s*[\"'`][^\"'`]*(?:login|log-in|signin|sign-in|signup|sign-up|register|forgot|reset|otp|magic-link|verify)", I)
LIMITERS = re.compile(r"express-rate-limit|rate-limiter-flexible|@upstash/ratelimit|slowapi|flask[-_]limiter|django[-_]ratelimit|rack-attack|@nestjs/throttler|throttle|ratelimit|rate_limit|limiter", I)


@check("rate-limit", ["AUTH-06", "API-05"], "Authentication routes with no rate-limiting library in sight", repo_level=True, gate=["G9"])
def check_rate_limit(ctx: Context) -> List[Finding]:
    routes = []
    for f in ctx.every:
        if not f.is_code or f.is_test or not any(w in f.lower() for w in AUTH_WORDS):
            continue
        for i, line in enumerate(f.lines(), 1):
            if AUTH_ROUTE.search(line):
                routes.append((f.rel, i))
        if re.search(r"(^|/)(?:api/)?(?:auth/)?(?:login|signin|signup|register|reset-password|forgot-password)/route\.[jt]s$|(^|/)pages/api/(?:auth/)?(?:login|signin|signup|register)\.[jt]s$", f.rel):
            routes.append((f.rel, None))
    if not routes:
        raise NotRun("no authentication routes found in this code (managed auth, or not recognized)")
    limited = any(LIMITERS.search(f.text()) for f in ctx.every if f.is_code or f.name in {"package.json", "requirements.txt", "pyproject.toml", "Gemfile"})
    if limited:
        return []
    rel, line = routes[0]
    return [Finding("rate-limit", ("AUTH-06", "API-05"), "medium", rel, line,
                    f"{len(routes)} authentication route(s) and no rate-limiting library — confirm limits exist at the edge or in the auth provider", "")]


# ---------------------------------------------------------------------------------------------
# Inventories for the ship gate: uploads, monitoring, disclosure
# ---------------------------------------------------------------------------------------------

UPLOAD_RULES = [
    Rule([r"\bmulter\s*\(", r"\bupload\.(?:single|array|fields|any)\s*\(", r"\bformidable\b", r"\bbusboy\b", r"\brequest\.files\b",
          r"\bUploadFile\b", r"\bcreatePresignedPost\b", r"\bPutObjectCommand\b", r"\.storage\s*\.\s*from\s*\([^)]*\)\s*\.upload\s*\(",
          r"\buploadBytes(?:Resumable)?\s*\(", r"from\s+['\"]@vercel/blob['\"]", r"\bUploadThing\b|\bcreateUploadthing\b"],
         "info", "upload handler — confirm it requires a session, validates content, and stores files privately behind signed URLs",
         code, ["multer", "upload", "formidable", "busboy", "request.files", "presigned", "putobject", "@vercel/blob"]),
]
rule_check("upload-handler", ["FILE-01", "FILE-02", "FILE-04"], "Inventory of upload handlers (each needs auth, content validation, private storage)", UPLOAD_RULES, gate=["G3"])

MONITORING = re.compile(r"@sentry/|sentry[-_]sdk|dd-trace|datadog|newrelic|@opentelemetry/|opentelemetry-|\bpino\b|\bwinston\b|bunyan|structlog|loguru|logtail|@axiomhq|honeybadger|rollbar|bugsnag|@vercel/otel|posthog-node", I)


@check("monitoring", ["OBSV-01", "OBSV-02"], "Inventory: is any logging or error-monitoring SDK present?", repo_level=True, gate=["G8"])
def check_monitoring(ctx: Context) -> List[Finding]:
    names = {"package.json", "requirements.txt", "pyproject.toml", "Gemfile", "go.mod", "composer.json", "Pipfile"}
    hits = sorted({m.group(0).lower() for f in ctx.every if f.name in names for m in MONITORING.finditer(f.text())})
    if hits:
        return [Finding("monitoring", ("OBSV-01",), "info", ".", None,
                        f"found {', '.join(hits[:6])} — whether auth failures, access denials and bulk reads alert anyone still needs a person to confirm", "")]
    return [Finding("monitoring", ("OBSV-01", "OBSV-02"), "low", ".", None,
                    "no logging or error-monitoring SDK in the manifests — someone must say where auth failures and bulk reads are recorded, and who is alerted", "")]


@check("disclosure", ["OBSV-06"], "Inventory: a SECURITY.md or security.txt so outsiders can report a vulnerability", repo_level=True, gate=["G15"])
def check_disclosure(ctx: Context) -> List[Finding]:
    if any(re.search(r"(^|/)SECURITY\.md$|(^|/)\.well-known/security\.txt$", f.rel, I) for f in ctx.every):
        return []
    return [Finding("disclosure", ("OBSV-06",), "low", ".", None,
                    "no SECURITY.md or /.well-known/security.txt — publish how an outsider reports a vulnerability", "")]


# ---------------------------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------------------------

class NotRun(Exception):
    pass


class CheckError(Exception):
    pass


def detect_signals(ctx: Context) -> None:
    manifests_text = "\n".join(f.text() for f in ctx.every if f.name in {"package.json", "requirements.txt", "pyproject.toml", "Pipfile"})
    client_db = (
        ctx.rel_exists("supabase/config.toml") or ctx.rel_exists("supabase/migrations")
        or bool(re.search(r"@supabase/(?:supabase-js|ssr|auth-helpers)|postgrest|hasura|\bsupabase\b", manifests_text, I))
    )
    if not client_db:
        client_db = any("supabase.co" in f.text() or "SUPABASE_URL" in f.text() for f in ctx.every if f.is_env or f.is_code)
    ctx.signals["client_db"] = client_db
    has_next = any(re.search(r"(^|/)next\.config\.(?:js|mjs|ts|cjs)$", f.rel) for f in ctx.every)
    ctx.signals["spa"] = not has_next and (
        any(re.search(r"(^|/)vite\.config\.(?:js|mjs|ts|cjs)$", f.rel) for f in ctx.every)
        or bool(re.search(r'"react-scripts"|"@angular/core"', manifests_text))
    )


def list_files(ctx: Context) -> None:
    root = ctx.root
    code_, inside, _ = git(root, "rev-parse", "--is-inside-work-tree")
    statuses: Dict[str, str] = {}
    if code_ == 0 and inside.strip() == "true":
        ctx.git = True
        _, prefix, _ = git(root, "rev-parse", "--show-prefix")   # non-empty when scanning a subdirectory
        ctx.signals["git_prefix"] = prefix.strip()
        _, tracked, _ = git(root, "ls-files", "-z")
        _, others, _ = git(root, "ls-files", "-z", "--others", "--exclude-standard")
        _, ignored, _ = git(root, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory", "--no-empty-directory")
        for rel in filter(None, tracked.split("\0")):
            statuses[rel] = "tracked"
            ctx.tracked.add(rel)
        for rel in filter(None, others.split("\0")):
            statuses.setdefault(rel, "untracked")
        for entry in filter(None, ignored.split("\0")):
            # Ignored files are where secrets belong, so only ignored .env files are kept: a
            # public-prefixed variable in one still ends up in the browser bundle.
            if not entry.endswith("/"):
                if re.search(r"(^|/)\.env(\.|$)|\.env$", entry):
                    statuses.setdefault(entry, "ignored")
            elif not excluded(entry + "x"):
                for dirpath, dirnames, filenames in os.walk(root / entry):
                    dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
                    for n in filenames:
                        if n == ".env" or n.startswith(".env.") or n.endswith(".env"):
                            statuses.setdefault(Path(dirpath, n).relative_to(root).as_posix(), "ignored")
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
            for n in filenames:
                statuses[Path(dirpath, n).relative_to(root).as_posix()] = "unknown"
    count = 0
    for rel, status in sorted(statuses.items()):
        if excluded(rel) or skip_name(rel.rsplit("/", 1)[-1]) or not (root / rel).is_file():
            continue
        count += 1
        if count > MAX_FILES:
            ctx.notes.append(f"stopped listing at {MAX_FILES} files; the rest were not scanned")
            break
        f = SourceFile(root, rel, status)
        (ctx.ignored_env if status == "ignored" else ctx.every).append(f)


def parse_diff(ctx: Context, base: str) -> None:
    code_, mb, err = git(ctx.root, "merge-base", base, "HEAD")
    if code_ != 0:
        raise SystemExit(f"scan.py: cannot find the merge base of {base} and HEAD: {err.strip()}")
    ctx.merge_base = mb.strip()
    code_, out, err = git(ctx.root, "diff", "--relative", "--no-color", "--no-ext-diff", "-U0", "--diff-filter=AMR", ctx.merge_base)
    if code_ != 0:
        raise SystemExit(f"scan.py: git diff failed: {err.strip()}")
    added: Dict[str, Optional[Set[int]]] = {}
    current = None
    for line in out.splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else None
            if current:
                added.setdefault(current, set())
        elif line.startswith("@@") and current:
            m = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) or "1")
                added[current].update(range(start, start + count))  # type: ignore[union-attr]
    for f in ctx.every:
        if f.status == "untracked":
            added[f.rel] = None       # a new file: every line is introduced
    ctx.added = added


def select_scope(ctx: Context, paths: Sequence[str], base: Optional[str]) -> None:
    if base:
        if not ctx.git:
            raise SystemExit("scan.py: --diff needs a git repository")
        parse_diff(ctx, base)
        assert ctx.added is not None
        ctx.files = [f for f in ctx.every if f.rel in ctx.added]
        ctx.scope = f"changes since {base} (merge base {(ctx.merge_base or '?')[:10]})"
        ctx.repo_scope = False
    elif paths:
        norm = []
        for p in paths:
            candidate = Path(p)
            if candidate.is_absolute():
                try:
                    candidate = candidate.resolve().relative_to(ctx.root)
                except ValueError:
                    raise SystemExit(f"scan.py: {p} is outside {ctx.root}")
            rel = os.path.normpath(candidate.as_posix()).replace("\\", "/")
            norm.append("" if rel == "." else rel)
        ctx.files = [f for f in ctx.every if any(n == "" or f.rel == n or f.rel.startswith(n + "/") for n in norm)]
        ctx.scope = "paths: " + ", ".join(paths)
        ctx.repo_scope = "" in norm
    else:
        ctx.files = list(ctx.every)


def collect_bundle(ctx: Context, spec: Sequence[str]) -> None:
    dirs = [d for d in BUNDLE_DIRS if (ctx.root / d).is_dir()] if list(spec) == ["auto"] else list(spec)
    for d in dirs:
        base = ctx.root / d
        if not base.is_dir():
            ctx.notes.append(f"bundle directory {d} does not exist")
            continue
        ctx.bundle_dirs.append(d)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [x for x in dirnames if x not in {"node_modules", ".git", "cache"}]
            for n in filenames:
                if os.path.splitext(n)[1].lower() in {".js", ".mjs", ".cjs", ".map", ".html", ".json", ".txt"}:
                    rel = Path(dirpath, n).relative_to(ctx.root).as_posix()
                    ctx.bundle.append(SourceFile(ctx.root, rel, "bundle", MAX_BUNDLE_FILE_BYTES))


def run_checks(ctx: Context, only: Optional[Set[str]], flags: Set[str], hook: bool = False) -> Tuple[List[Finding], Dict[str, Result]]:
    findings: List[Finding] = []
    results: Dict[str, Result] = {}
    for chk in CHECKS:
        if only and chk.id not in only:
            continue
        if hook and not chk.hook:
            continue
        if chk.needs and chk.needs not in flags:
            if chk.needs == "bundle":
                results[chk.id] = Result("not-run", "no build output scanned — build the app, then pass --bundle auto")
            else:
                results[chk.id] = Result("not-run", f"pass --{chk.needs} to run it")
            continue
        # Repository-wide checks are out of scope for --path; history still runs for --diff,
        # limited to the commits since the merge base.
        if chk.repo_level and not ctx.repo_scope and not chk.needs and not (chk.id == "history-secret" and ctx.merge_base):
            results[chk.id] = Result("not-run", "repository-level check; outside a --path or --diff scope")
            continue
        try:
            out = chk.run(ctx)
        except NotRun as exc:
            results[chk.id] = Result("not-run", str(exc))
            continue
        except CheckError as exc:
            results[chk.id] = Result("error", str(exc))
            continue
        except Exception as exc:      # noqa: BLE001 - a crashed check must be reported, not hidden
            results[chk.id] = Result("error", f"{type(exc).__name__}: {exc}")
            continue
        for x in out:
            # Test and fixture code is full of deliberate bad examples. A secret there is still a
            # leak, so the secret checks keep their own severity; everything else drops to low.
            if not x.check.startswith(("secret-", "history-", "tracked-", "bundle-")) and is_test_path(x.file) \
                    and RANK[x.severity] < RANK["low"]:
                x.severity, x.message = "low", x.message + " (test or fixture code)"
        if ctx.added is not None:
            for x in out:
                if x.file in ctx.added:
                    lines = ctx.added[x.file]
                    x.introduced = True if lines is None else (x.line in lines if x.line else None)
        findings.extend(out)
        results[chk.id] = Result("ran")
    findings.sort(key=lambda x: (RANK[x.severity], x.check, x.file, x.line or 0))
    return findings, results


GATES = [
    ("G1", "Secrets unreachable", "scanner"), ("G2", "Row-level security", "scanner"),
    ("G3", "Public surface", "scanner + enumerate what is live"), ("G4", "Per-object authorization", "trace three endpoints by hand"),
    ("G5", "MFA on every path to production", "ask the user"), ("G6", "Admin keys server-side", "scanner"),
    ("G7", "Pinned deps, install scripts off", "scanner"), ("G8", "Someone would notice", "ask the user; scanner inventories SDKs"),
    ("G9", "Rate limits", "scanner + read the auth routes"), ("G10", "Stored passwords and personal data", "scanner + read the schema"),
    ("G11", "Backups restore-tested", "ask the user"), ("G12", "High-harm data deleted after use", "read the retention code or ask"),
    ("G13", "No wildcard IAM", "scanner"), ("G14", "Third-party scripts pinned", "scanner"),
    ("G15", "Owner and disclosure path", "ask the user; scanner checks SECURITY.md"), ("G16", "Agents cannot exfiltrate", "scanner + read the agent wiring"),
    ("G17", "CSP, HSTS, cookies", "scanner + read the live headers"), ("G18", "No enumeration, no admin to find", "scanner + time the login"),
]


def render_text(ctx: Context, findings: List[Finding], results: Dict[str, Result], max_per_check: int, gate: bool) -> str:
    out = []
    counts = Counter(x.severity for x in findings)
    out.append(f"security-checklist scan {VERSION} · {ctx.root}")
    out.append(f"scope: {ctx.scope} · {len(ctx.files)} files" + ("" if ctx.git else " · not a git repository"))
    if ctx.bundle_dirs:
        out.append(f"bundles: {', '.join(ctx.bundle_dirs)} ({len(ctx.bundle)} files)")
    out.append("excluded: node_modules, vendor, .git, build output (dist, build, .next, …), lockfiles, minified and binary files")
    out.append("")
    summary = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s]) or "none"
    out.append(f"FINDINGS ({len(findings)}: {summary}) — candidates to confirm by reading the code; secret values are masked")
    shown: Counter = Counter()
    hidden: Counter = Counter()
    for x in findings:
        if max_per_check and shown[x.check] >= max_per_check:
            hidden[x.check] += 1
            continue
        shown[x.check] += 1
        loc = f"{x.file}:{x.line}" if x.line else x.file
        tag = ""
        if x.introduced is True:
            tag = " [introduced]"
        elif x.introduced is False:
            tag = " [pre-existing]"
        out.append(f"  {x.severity:<6} {'/'.join(x.controls):<18} {x.check:<20} {loc}{tag}")
        out.append(f"         {x.message}")
        if x.excerpt:
            out.append(f"         > {x.excerpt}")
    for chk, n in sorted(hidden.items()):
        out.append(f"  … {n} more from {chk} (rerun with --only {chk} --max-per-check 0)")
    out.append("")
    out.append("CHECKS")
    per_check = Counter(x.check for x in findings)
    for chk in CHECKS:
        r = results.get(chk.id)
        if not r:
            continue
        detail = f"{per_check[chk.id]} finding(s)" if r.status == "ran" else r.detail
        out.append(f"  {r.status:<8} {chk.id:<20} {detail}")
    blind = [c for c, r in results.items() if r.status != "ran"]
    if blind:
        out.append("")
        out.append("NOT CHECKED: " + ", ".join(blind))
        out.append("Report these as not checked. A check that did not run is not a clean result.")
    if gate:
        out.append("")
        out.append("GATE EVIDENCE (what the scanner saw; the verdict is still yours)")
        by_gate: Dict[str, List[Check]] = {}
        for chk in CHECKS:
            for g in chk.gate:
                by_gate.setdefault(g, []).append(chk)
        for g, title, how in GATES:
            chks = by_gate.get(g, [])
            ran = [c.id for c in chks if results.get(c.id) and results[c.id].status == "ran"]
            missing = [c.id for c in chks if not results.get(c.id) or results[c.id].status != "ran"]
            n = sum(per_check[c] for c in ran)
            evidence = f"{n} finding(s) from {', '.join(ran)}" if ran else "no scanner evidence"
            if missing:
                evidence += f"; not run: {', '.join(missing)}"
            out.append(f"  {g:<4} {title:<36} {evidence} — {how}")
    for note in ctx.notes:
        out.append(f"note: {note}")
    return "\n".join(out)


def render_json(ctx: Context, findings: List[Finding], results: Dict[str, Result]) -> str:
    return json.dumps({
        "version": VERSION, "root": str(ctx.root), "scope": ctx.scope, "git": ctx.git,
        "files_scanned": len(ctx.files), "bundle_dirs": ctx.bundle_dirs,
        "checks": {k: {"status": v.status, "detail": v.detail} for k, v in results.items()},
        "findings": [x.as_dict() for x in findings], "notes": ctx.notes,
    }, indent=2)


# ---------------------------------------------------------------------------------------------
# Hook mode — runs after Claude writes or edits a file
# ---------------------------------------------------------------------------------------------

def hook_main() -> int:
    if os.environ.get("SECURITY_CHECKLIST_HOOK", "").lower() in {"0", "off", "false", "no"}:
        return 0
    try:
        payload = json.loads(sys.stdin.read(5_000_000) or "{}")
    except ValueError:
        return 0
    tool = payload.get("tool_name", "")
    data = payload.get("tool_input") or {}
    if tool not in {"Write", "Edit", "MultiEdit"} or not data.get("file_path"):
        return 0
    path = Path(data["file_path"])
    cwd = Path(payload.get("cwd") or os.getcwd())
    if not path.is_absolute():
        path = cwd / path
    try:
        path = path.resolve()
        if not path.is_file() or path.stat().st_size > 1_000_000:
            return 0
    except OSError:
        return 0
    code_, top, _ = git(path.parent, "rev-parse", "--show-toplevel")
    root = Path(top.strip()).resolve() if code_ == 0 else cwd.resolve()
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        root, rel = path.parent, path.name
    if excluded(rel) or skip_name(path.name):
        return 0

    if tool == "Write":
        new_text = str(data.get("content") or data.get("new_string") or "")
    elif tool == "Edit":
        new_text = str(data.get("new_string") or "")
    else:
        new_text = "\n".join(str(e.get("new_string") or "") for e in data.get("edits") or [] if isinstance(e, dict))
    new_lines = {ln.strip() for ln in new_text.splitlines() if ln.strip()}
    if not new_lines:
        return 0

    ctx = Context(root)
    ctx.git = code_ == 0
    f = SourceFile(root, rel, "hook")
    if f.is_doc and not f.is_env:
        return 0
    only = None
    if ctx.git and git(root, "check-ignore", "-q", rel)[0] == 0:
        if not f.is_env:
            return 0
        only = {"client-env-secret"}  # an ignored .env is where secrets belong, unless the prefix ships them
    ctx.files = [f]
    ctx.every = [f]
    ctx.repo_scope = False
    # At write time a migration is judged on its own: row-level security belongs in the same
    # migration that creates the table.
    ctx.signals["client_db"] = "supabase" in rel.lower() or (root / "supabase").is_dir()
    ctx.signals["spa"] = any((root / n).exists() for n in ("vite.config.ts", "vite.config.js", "vite.config.mjs")) and not any(
        (root / n).exists() for n in ("next.config.js", "next.config.mjs", "next.config.ts"))
    try:
        findings, _ = run_checks(ctx, only, set(), hook=True)
    except Exception:                 # noqa: BLE001 - a hook must never break the session
        return 0
    lines = f.lines()
    relevant = [x for x in findings if x.severity in {"high", "medium"}
                and (x.line is None or (0 < x.line <= len(lines) and lines[x.line - 1].strip() in new_lines))]
    if not relevant:
        return 0
    out = [f"security-checklist: {len(relevant)} finding(s) in {rel} from the change just made (write-time check)"]
    for x in relevant[:12]:
        where = f"line {x.line}" if x.line else "file"
        out.append(f"  [{x.severity}] {x.check} ({'/'.join(x.controls)}) {where}: {x.message}")
    out.append("Fix these now, or tell the user why one is a false positive. Do not add a suppression marker yourself.")
    print("\n".join(out), file=sys.stderr)
    return 2


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="repository root to scan (default: current directory)")
    parser.add_argument("--path", action="append", default=[], help="limit file checks to this path (repeatable)")
    parser.add_argument("--diff", metavar="BASE", help="limit to files changed since the merge base with BASE")
    parser.add_argument("--bundle", action="append", default=[], metavar="DIR", help="scan built client bundles; 'auto' finds them")
    parser.add_argument("--audit", action="store_true", help="run the dependency auditors that are installed (uses the network)")
    parser.add_argument("--gate", action="store_true", help="add the ship-gate evidence table")
    parser.add_argument("--only", action="append", default=[], metavar="CHECK", help="run only these checks (repeatable)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--max-per-check", type=int, default=25, help="findings shown per check in text output (0 = all)")
    parser.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if any finding is at least this severe")
    parser.add_argument("--list-checks", action="store_true")
    parser.add_argument("--hook", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.hook:
        return hook_main()
    if args.list_checks:
        for chk in CHECKS:
            extra = f" (needs --{chk.needs})" if chk.needs else ""
            print(f"{chk.id:<20} {'/'.join(chk.controls):<26} {chk.title}{extra}")
        return 0

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"scan.py: {root} is not a directory", file=sys.stderr)
        return 3
    known = {c.id for c in CHECKS}
    unknown = [c for c in args.only if c not in known]
    if unknown:
        print(f"scan.py: unknown check(s): {', '.join(unknown)} — see --list-checks", file=sys.stderr)
        return 3
    ctx = Context(root)
    list_files(ctx)
    detect_signals(ctx)
    select_scope(ctx, args.path, args.diff)
    flags = set()
    if args.bundle:
        collect_bundle(ctx, args.bundle)
        flags.add("bundle")
    if args.audit:
        flags.add("audit")
    findings, results = run_checks(ctx, set(args.only) or None, flags)
    if args.format == "json":
        print(render_json(ctx, findings, results))
    else:
        print(render_text(ctx, findings, results, args.max_per_check, args.gate))
    if args.fail_on and any(RANK[x.severity] <= RANK[args.fail_on] for x in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
