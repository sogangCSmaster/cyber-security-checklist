"""Regression tests for skills/security-audit/scripts/scan.py.

The grep commands the scanner replaced failed silently: a pattern that matched nothing looked
exactly like a clean repository. These tests pin both directions — what must be found and what
must not — against fixtures materialized from tests/fixtures/, plus a table of single lines.

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN = ROOT / "skills" / "security-audit" / "scripts" / "scan.py"
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

import materialize  # noqa: E402

_spec = importlib.util.spec_from_file_location("scan", SCAN)
scan = importlib.util.module_from_spec(_spec)
sys.modules["scan"] = scan            # dataclasses resolve annotations through sys.modules
_spec.loader.exec_module(scan)  # type: ignore[union-attr]

MIGRATION = "supabase/migrations/20250101000000_init.sql"
WORKFLOW = ".github/workflows/pr.yml"


def run(root: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCAN), "--root", str(root), *args],
                          capture_output=True, text=True, env=env, timeout=300)


def scan_json(root: Path, *args: str) -> dict:
    proc = run(root, "--format", "json", *args)
    if proc.returncode != 0:
        raise AssertionError(f"scan.py exited {proc.returncode}: {proc.stderr}")
    return json.loads(proc.stdout)


class FixtureCase(unittest.TestCase):
    fixture = ""
    root: Path
    report: dict

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = materialize.materialize(cls.fixture, Path(cls._tmp.name) / cls.fixture)
        cls.report = scan_json(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def line(self, rel: str, number: int) -> str:
        return (self.root / rel).read_text(encoding="utf-8").splitlines()[number - 1]

    def matching(self, check, rel, text=None, severity=None, report=None):
        out = []
        for f in (report or self.report)["findings"]:
            if (check and f["check"] != check) or f["file"] != rel or (severity and f["severity"] != severity):
                continue
            if text is not None and (not f["line"] or text not in self.line(rel, f["line"])):
                continue
            out.append(f)
        return out

    def assert_found(self, expected):
        for check, rel, text, severity in expected:
            with self.subTest(check=check, file=rel, text=text):
                hits = self.matching(check, rel, text)
                self.assertTrue(hits, f"{check} did not report {rel} {text!r}")
                self.assertIn(severity, {h["severity"] for h in hits}, f"{check} {rel} {text!r}: wrong severity {hits}")

    def assert_not_found(self, unexpected):
        for check, rel, text in unexpected:
            with self.subTest(check=check, file=rel, text=text):
                self.assertEqual(self.matching(check, rel, text), [], f"{check or 'a check'} wrongly reported {rel} {text!r}")


class VulnerableNextTest(FixtureCase):
    fixture = "vulnerable-next"

    def test_finds_what_is_there(self):
        self.assert_found([
            ("secret-shape", ".env", "SUPABASE_SERVICE_ROLE_KEY", "high"),
            ("secret-shape", ".env", "OPENAI_API_KEY", "high"),
            ("secret-shape", ".env", "STRIPE_SECRET_KEY", "high"),
            ("secret-shape", ".env", "DATABASE_URL", "high"),
            ("secret-shape", ".mcp.json", "--service-role-key", "high"),
            ("secret-shape", "scripts/tmp-debug.ts", "const token", "high"),
            ("secret-shape", "src/config/keys.ts", "stripeKey", "high"),
            ("secret-shape", "src/config/keys.ts", "githubToken", "high"),
            ("secret-shape", "src/config/keys.ts", "mapsKey", "medium"),
            ("secret-shape", "src/config/firebase.ts", "apiKey", "low"),
            ("secret-assignment", "src/config/keys.ts", "export const apiKey", "medium"),
            ("client-env-secret", ".env.local", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY", "high"),
            ("tracked-secret-file", ".env", None, "high"),
            ("tracked-secret-file", ".gitignore", None, "medium"),
            ("history-secret", "deploy.pem", None, "high"),
            ("history-secret", "src/legacy.ts", None, "high"),
            ("rls", MIGRATION, "CREATE TABLE public.profiles", "high"),
            ("rls", MIGRATION, '"anyone inserts"', "high"),
            ("rls", MIGRATION, '"read all"', "medium"),
            ("rls", MIGRATION, '"signed in"', "medium"),
            ("card-data", MIGRATION, "card_number", "high"),
            ("card-data", MIGRATION, "cvv", "high"),
            ("high-harm-field", MIGRATION, "passport_number", "info"),
            ("firebase-rules", "database.rules.json", '".read": true', "high"),
            ("firebase-rules", "firestore.rules", "allow read: if true", "high"),
            ("firebase-rules", "firestore.rules", "request.time <", "high"),
            ("firebase-rules", "firestore.rules", "request.auth != null", "medium"),
            ("service-role", ".mcp.json", "--service-role-key", "high"),
            ("service-role", "src/lib/supabaseBrowser.ts", "SUPABASE_SERVICE_ROLE_KEY", "high"),
            ("service-role", "lib/db.ts", "SUPABASE_SERVICE_ROLE_KEY", "medium"),
            ("weak-password-hash", "pages/api/login.ts", 'createHash("sha256")', "high"),
            ("sensitive-logging", "pages/api/login.ts", '"login attempt", req.body', "medium"),
            ("enumeration-message", "pages/api/login.ts", "User not found", "medium"),
            ("enumeration-message", "pages/api/login.ts", "Incorrect password", "medium"),
            ("rate-limit", "pages/api/login.ts", None, "medium"),
            ("sql-string-building", "pages/api/search.ts", "ILIKE", "high"),
            ("ssrf", "pages/api/search.ts", "fetch(req.query.url", "medium"),
            ("mass-assignment", "pages/api/profile.ts", "data: req.body", "medium"),
            ("command-injection", "pages/api/files.ts", "exec(`convert", "high"),
            ("path-and-redirect", "pages/api/files.ts", "readFileSync", "medium"),
            ("path-and-redirect", "pages/api/files.ts", "res.redirect", "medium"),
            ("unsafe-html", "components/Comment.tsx", "dangerouslySetInnerHTML", "medium"),
            ("cookie-flags", "lib/session.ts", "httpOnly: false", "medium"),
            ("cookie-flags", "lib/session.ts", "secure: false", "medium"),
            ("cookie-flags", "components/Session.tsx", "localStorage", "low"),
            ("dynamic-code", "src/utils/run.ts", "eval(userInput)", "medium"),
            ("tls-verification", "src/utils/tls.ts", "NODE_TLS_REJECT_UNAUTHORIZED", "medium"),
            ("invisible-unicode", "src/utils/role.ts", "isAdmin", "high"),
            ("invisible-unicode", "src/utils/role.ts", "export const role", "medium"),
            ("csp", "next.config.js", "unsafe-eval", "high"),
            ("external-script", "app/layout.tsx", "polyfill.io", "high"),
            ("external-script", "app/layout.tsx", "unpkg.com", "medium"),
            ("external-script", "app/layout.tsx", "js.stripe.com", "low"),
            ("lockfile", "package.json", None, "high"),
            ("lockfile", WORKFLOW, "npm install", "medium"),
            ("install-scripts", "package.json", None, "high"),
            ("workflow", WORKFLOW, "pull_request_target", "high"),
            ("workflow", WORKFLOW, "github.event.pull_request.title", "high"),
            ("workflow", WORKFLOW, "tj-actions/changed-files@v44", "medium"),
            ("workflow", WORKFLOW, "actions/checkout@v4", "low"),
            ("agent-config", ".vscode/tasks.json", '"runOn"', "high"),
            ("agent-config", ".mcp.json", "@supabase/mcp-server-supabase", "medium"),
            ("agent-config", ".mcp.json", "http://tools.example.net", "medium"),
            ("default-credential", "scripts/seed.ts", 'password: "admin123"', "high"),
            ("default-credential", "scripts/seed.ts", '{ email: "admin@example.com" }', "medium"),
            ("datastore-exposure", "docker-compose.yml", '"5432:5432"', "medium"),
            ("open-security-group", "infra/main.tf", "0.0.0.0/0", "high"),
            ("public-storage", "infra/main.tf", "public-read", "high"),
            ("iam-wildcard", "infra/main.tf", 'actions   = ["*"]', "high"),
            ("monitoring", ".", None, "low"),
            ("disclosure", ".", None, "low"),
        ])

    def test_leaves_alone_what_is_fine(self):
        self.assert_not_found([
            ("secret-shape", ".env", "NEXT_PUBLIC_SUPABASE_ANON_KEY"),   # publishable by design
            (None, ".env.local", "ANTHROPIC_API_KEY"),                   # an ignored file is where secrets belong
            (None, ".env.example", None),
            (None, "lib/mailer.ts", None),                               # `secure: false` there is SMTP STARTTLS
            ("service-role", "src/lib/server/admin.ts", None),
            ("sensitive-logging", "pages/api/login.ts", "Invalid password reset"),
            ("enumeration-message", "pages/api/login.ts", "Invalid password reset"),
            ("sql-string-building", "pages/api/search.ts", "$1"),
            ("sql-string-building", "pages/api/files.ts", None),         # a shell command, not SQL
            ("mass-assignment", "pages/api/profile.ts", "const { name } = req.body"),
            ("dynamic-code", "src/utils/run.ts", "$eval"),
            ("rls", MIGRATION, "commented_out"),
            ("rls", MIGRATION, "scratch"),
            ("rls", MIGRATION, "audit_log"),
            ("secret-assignment", "src/config/keys.ts", "PASSWORD_MIN_LENGTH"),
            ("secret-assignment", "src/config/keys.ts", "tokenType"),
            ("secret-assignment", "scripts/seed.ts", None),              # default-credential owns this line
            ("datastore-exposure", "docker-compose.yml", "127.0.0.1:6379"),
        ])
        lines = sorted(f["line"] for f in self.matching("external-script", "app/layout.tsx"))
        self.assertEqual(lines, [7, 8, 14], "the script with an integrity hash must not be reported")
        self.assertEqual(len(self.matching("history-secret", "deploy.pem")), 1)

    def test_ignores_dependencies_and_build_output(self):
        stray = [f for f in self.report["findings"] if f["file"].startswith(("node_modules/", ".next/"))]
        self.assertEqual(stray, [])

    def test_never_prints_a_secret(self):
        text = run(self.root, "--max-per-check", "0").stdout + json.dumps(self.report)
        for name, value in materialize.TOKENS.items():
            probe = value.splitlines()[1] if name == "private_key" else value
            with self.subTest(token=name):
                self.assertNotIn(probe[:12] if name == "hex32" else probe, text)

    def test_every_check_reports_a_status(self):
        checks = self.report["checks"]
        self.assertEqual(set(checks), {c.id for c in scan.CHECKS})
        self.assertTrue(all(c["status"] in {"ran", "not-run", "error"} for c in checks.values()))
        self.assertEqual(checks["bundle-secret"]["status"], "not-run")
        self.assertIn("--bundle", checks["bundle-secret"]["detail"])
        self.assertEqual(checks["dependency-audit"]["status"], "not-run")
        text = run(self.root).stdout
        self.assertIn("NOT CHECKED: bundle-secret, dependency-audit", text)
        self.assertIn("not a clean result", text)

    def test_bundle_scan_finds_what_the_browser_downloads(self):
        report = scan_json(self.root, "--bundle", "auto", "--only", "bundle-secret")
        self.assertEqual(report["checks"]["bundle-secret"]["status"], "ran")
        messages = [f["message"] for f in report["findings"] if f["file"] == ".next/static/chunks/app.js"]
        self.assertTrue(any("service_role" in m for m in messages), messages)
        self.assertTrue(any("Stripe live secret key" in m for m in messages), messages)

    def test_gate_table_covers_every_gate(self):
        text = run(self.root, "--gate").stdout
        for n in range(1, 19):
            self.assertRegex(text, rf"\n  G{n}\s")

    def test_path_scope_stays_inside_the_path(self):
        report = scan_json(self.root, "--path", "pages")
        self.assertTrue(report["findings"])
        self.assertTrue(all(f["file"].startswith("pages/") for f in report["findings"]))
        for repo_level in ("lockfile", "install-scripts", "history-secret", "monitoring", "disclosure"):
            self.assertEqual(report["checks"][repo_level]["status"], "not-run", repo_level)


class VulnerableFlaskTest(FixtureCase):
    fixture = "vulnerable-flask"

    def test_finds_what_is_there(self):
        self.assert_found([
            ("secret-assignment", "app.py", "API_KEY =", "medium"),
            ("sql-string-building", "app.py", 'execute(f"SELECT', "high"),
            ("sql-string-building", "app.py", "% request.args", "high"),
            ("sql-string-building", "app.py", ".format(request.args", "high"),
            ("sql-string-building", "app.py", 'query = f"DELETE', "medium"),
            ("weak-password-hash", "app.py", "hashlib.md5", "high"),
            ("sensitive-logging", "app.py", "print(request.headers)", "medium"),
            ("ssrf", "app.py", "requests.get(request.args", "medium"),
            ("tls-verification", "app.py", "verify=False", "medium"),
            ("dynamic-code", "app.py", "pickle.loads", "medium"),
            ("dynamic-code", "app.py", "unsafe = yaml.load", "medium"),
            ("command-injection", "app.py", "shell=True", "medium"),
            ("path-and-redirect", "app.py", "open(os.path.join", "medium"),
            ("path-and-redirect", "app.py", "redirect(request.args", "medium"),
            ("debug-exposure", "app.py", "app.run(debug=True)", "medium"),
            ("debug-exposure", "settings.py", "DEBUG = True", "medium"),
            ("mass-assignment", "serializers.py", "__all__", "medium"),
            ("mass-assignment", "serializers.py", "**request.data", "medium"),
            ("rate-limit", "app.py", '"/register"', "medium"),
            ("lockfile", "requirements.txt", None, "medium"),
        ])

    def test_leaves_alone_what_is_fine(self):
        self.assert_not_found([
            ("sql-string-building", "app.py", "%s\", (user_id,)"),       # DB-API parameters
            ("sql-string-building", "app.py", "'%s'\", (user_id,)"),     # still parameters, quotes and all
            ("sql-string-building", "app.py", 'note = f"update'),        # a sentence, not SQL
            ("secret-assignment", "app.py", 'SECRET_KEY = "dev"'),
            ("secret-assignment", "app.py", "TOKEN_URL"),
            ("secret-assignment", "app.py", "max_tokens"),
            ("secret-assignment", "app.py", "tokenizer"),
            ("dynamic-code", "app.py", "Loader=yaml.SafeLoader"),
            ("dynamic-code", "app.py", "safe_load"),
            ("path-and-redirect", "app.py", "send_from_directory"),
            (None, ".env", None),                                        # ignored: where secrets belong
            ("tracked-secret-file", ".gitignore", None),
        ])
        committed_dependency = [f for f in self.report["findings"] if f["file"].startswith("node_modules/")]
        self.assertEqual(committed_dependency, [], "committed node_modules is still dependency code")
        self.assertEqual(self.report["checks"]["install-scripts"]["status"], "not-run")

    def test_diff_scope_separates_introduced_from_pre_existing(self):
        git = lambda *a: subprocess.run(["git", *a], cwd=self.root, check=True, capture_output=True)  # noqa: E731
        git("checkout", "-q", "-b", "feature")
        with open(self.root / "app.py", "a", encoding="utf-8") as fh:
            fh.write('\n\ndef extra(cursor, x):\n    cursor.execute(f"SELECT 2 FROM t WHERE x = {x}")\n')
        git("commit", "-q", "-am", "add a query")
        (self.root / "new_module.py").write_text('def q(c, v):\n    c.execute(f"SELECT 3 FROM t WHERE v = {v}")\n')
        try:
            report = scan_json(self.root, "--diff", "main")
            sql = {(f["file"], f["line"]): f["introduced"] for f in report["findings"] if f["check"] == "sql-string-building"}
            added_line = len((self.root / "app.py").read_text().splitlines())
            self.assertIs(sql[("app.py", added_line)], True)
            self.assertIs(sql[("app.py", 28)], False, "the f-string query on line 28 predates the branch")
            self.assertIs(sql[("new_module.py", 2)], True)
            self.assertNotIn("settings.py", {f["file"] for f in report["findings"]})
            self.assertEqual(report["checks"]["history-secret"]["status"], "ran")
            self.assertEqual(report["checks"]["lockfile"]["status"], "not-run")
        finally:
            (self.root / "new_module.py").unlink()
            git("checkout", "-q", "main")


class CleanAppTest(FixtureCase):
    fixture = "clean-app"

    def test_no_false_alarms(self):
        serious = [f for f in self.report["findings"] if f["severity"] in {"high", "medium", "low"}]
        self.assertEqual(serious, [], json.dumps(serious, indent=1))
        self.assertEqual([(f["check"], f["severity"]) for f in self.report["findings"]], [("monitoring", "info")])

    def test_every_check_ran_or_says_why_not(self):
        for check, result in self.report["checks"].items():
            with self.subTest(check=check):
                self.assertIn(result["status"], {"ran", "not-run"})
                if result["status"] == "not-run":
                    self.assertTrue(result["detail"])

    def test_without_git_history_is_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = materialize.materialize("clean-app", Path(tmp) / "plain", use_git=False)
            report = scan_json(root)
            self.assertFalse(report["git"])
            self.assertEqual(report["checks"]["history-secret"]["status"], "not-run")
            self.assertIn("not a git repository", report["checks"]["history-secret"]["detail"])


class HookTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = materialize.materialize("clean-app", Path(self._tmp.name) / "repo")

    def tearDown(self):
        self._tmp.cleanup()

    def hook(self, tool: str, rel: str, content: str, tool_input: dict | None = None, env: dict | None = None):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        payload = {"hook_event_name": "PostToolUse", "tool_name": tool, "cwd": str(self.root),
                   "tool_input": {"file_path": str(path), **(tool_input or {"content": content})}}
        return subprocess.run([sys.executable, str(SCAN), "--hook"], input=json.dumps(payload),
                              capture_output=True, text=True, env={**os.environ, **(env or {})}, timeout=60)

    def test_a_written_secret_is_reported_masked(self):
        token = materialize.TOKENS["stripe_live"]
        proc = self.hook("Write", "src/pay.ts", f'export const key = "{token}";\n')
        self.assertEqual(proc.returncode, 2)
        self.assertIn("secret-shape", proc.stderr)
        self.assertNotIn(token, proc.stderr)

    def test_only_the_edit_is_judged(self):
        before = 'db.query(`SELECT * FROM t WHERE id = ${id}`);\n'
        proc = self.hook("Edit", "src/q.ts", before + "export const ok = 1;\n",
                         {"old_string": "", "new_string": "export const ok = 1;"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc = self.hook("Edit", "src/q.ts", before, {"old_string": "", "new_string": before.strip()})
        self.assertEqual(proc.returncode, 2)
        self.assertIn("sql-string-building", proc.stderr)

    def test_multiedit_and_migrations(self):
        sql = "create table public.posts (id bigint primary key, body text);\n"
        proc = self.hook("MultiEdit", "supabase/migrations/003_posts.sql", sql,
                         {"edits": [{"old_string": "", "new_string": sql}]})
        self.assertEqual(proc.returncode, 2)
        self.assertIn("rls", proc.stderr)
        safe = sql + "alter table public.posts enable row level security;\n"
        proc = self.hook("Write", "supabase/migrations/004_posts.sql", safe)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_ignored_env_files_hold_secrets_but_not_public_prefixes(self):
        token = materialize.TOKENS["stripe_live"]
        self.assertEqual(self.hook("Write", ".env.local", f"STRIPE_SECRET_KEY={token}\n").returncode, 0)
        proc = self.hook("Write", ".env.local", f"NEXT_PUBLIC_STRIPE_SECRET_KEY={token}\n")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("client-env-secret", proc.stderr)

    def test_quiet_when_off_or_irrelevant(self):
        token = materialize.TOKENS["stripe_live"]
        self.assertEqual(self.hook("Write", "a.ts", f'const k = "{token}";', env={"SECURITY_CHECKLIST_HOOK": "off"}).returncode, 0)
        self.assertEqual(self.hook("Read", "b.ts", f'const k = "{token}";').returncode, 0)
        self.assertEqual(self.hook("Write", "README.md", "a note\n").returncode, 0)
        bad = subprocess.run([sys.executable, str(SCAN), "--hook"], input="not json", capture_output=True, text=True)
        self.assertEqual(bad.returncode, 0)


def single_file(filename: str, text: str, check: str) -> list:
    """Run one check against a directory holding one file."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp, filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        ctx = scan.Context(Path(tmp).resolve())
        scan.list_files(ctx)
        scan.detect_signals(ctx)
        scan.select_scope(ctx, [], None)
        found, results = scan.run_checks(ctx, {check}, set())
        assert results[check].status == "ran", results[check]
        return found


T = materialize.TOKENS
LINES = [
    # (check, file, line, should it be reported?)
    ("secret-shape", "a.ts", f'const k = "{T["anthropic"]}";', True),
    ("secret-shape", "a.ts", f'const k = "{T["openai"]}";', True),
    ("secret-shape", "a.py", f'KEY = "{T["aws_key_id"]}"', True),
    ("secret-shape", "a.ts", 'const k = "AKIA' + 'IOSFODNN7EXAMPLE";', False),   # AWS's documentation example
    ("secret-shape", "a.ts", 'const k = "sk-your-openai-key-goes-here";', False),
    ("secret-shape", "a.md", "[record](2025.md#i2025q2-03-sk-telecom-usim-authentication-key-breach)", False),
    ("secret-shape", ".env", f"NEXT_PUBLIC_SUPABASE_ANON_KEY={T['anon_jwt']}", False),
    ("secret-shape", "a.ts", "const t = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
     + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';", False),   # the jwt.io sample token
    ("secret-shape", ".env", "DATABASE_URL=postgres://postgres:postgres@localhost:5432/app", False),
    ("secret-shape", "a.ts", f'const k = "{T["stripe_live"]}"; // security-checklist: allow', False),
    ("secret-assignment", "a.py", 'password = "Tr0ub4dor&3xK9q"', True),
    ("secret-assignment", "config.yml", "api_key: 9f8e7d6c5b4a39281706f5e4", True),
    ("secret-assignment", "a.py", 'password = os.environ["DB_PASSWORD"]', False),
    ("secret-assignment", "a.ts", "const apiKey = process.env.API_KEY;", False),
    ("secret-assignment", "deploy.yml", "api_key: ${{ secrets.API_KEY }}", False),
    ("secret-assignment", "a.py", 'PASSWORD_REGEX = "^(?=.*[A-Z]).{12,}$"', False),
    ("secret-assignment", "a.html", '<input name="token" value="{{ csrf_token }}">', False),
    ("client-env-secret", "a.ts", "process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY", True),
    ("client-env-secret", ".env.example", "VITE_OPENAI_API_KEY=", True),
    ("client-env-secret", "a.ts", "process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY", False),
    ("client-env-secret", "a.ts", "process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY", False),
    ("sql-string-building", "a.ts", 'db.query("SELECT * FROM t WHERE id = " + id);', True),
    ("sql-string-building", "a.ts", "knex.raw(`SELECT * FROM t WHERE id = ${id}`);", True),
    ("sql-string-building", "a.go", 'db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %s", id))', True),
    ("sql-string-building", "a.rb", "User.where(\"name = '#{params[:name]}'\")", True),
    ("sql-string-building", "a.php", "mysqli_query($c, \"SELECT * FROM t WHERE id = \" . $_GET['id']);", True),
    ("sql-string-building", "a.ts", "await sql`SELECT * FROM t WHERE id = ${id}`;", False),
    ("sql-string-building", "a.ts", "await prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}`;", False),
    ("sql-string-building", "a.rb", 'User.where("name = ?", name)', False),
    ("sql-string-building", "a.ts", "await client.query(`{ viewer { login } }`);", False),
    ("sql-raw-unsafe", "a.ts", "await prisma.$queryRawUnsafe(query, id);", True),
    ("sql-raw-unsafe", "a.ts", "await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE id = ${id}`);", False),
    ("mass-assignment", "a.ts", "await User.create(req.body);", True),
    ("mass-assignment", "a.ts", "Object.assign(user, req.body);", True),
    ("mass-assignment", "a.ts", "const doc = new Order(req.body);", True),
    ("mass-assignment", "a.ts", "await User.create({ name: req.body.name });", False),
    ("weak-password-hash", "a.ts", "const h = createHash('md5').update(password).digest('hex');", True),
    ("weak-password-hash", "a.ts", "const h = await bcrypt.hash(password, 12);", False),
    ("rls", "m.sql", "create table notes (id int);\nalter table notes enable row level security;\ncreate policy p on notes using(true);", True),
    ("csp", "a.js", "\"default-src *; img-src *\"", True),
    ("csp", "a.js", "\"default-src *; script-src 'self' 'nonce-abc'\"", False),
    ("csp", "a.js", "\"img-src * data:\"", False),
    ("workflow", ".github/workflows/a.yml", "on: issues\njobs:\n  a:\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n", True),
    ("workflow", ".github/workflows/a.yml", "on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: ./local-action\n", False),
    ("invisible-unicode", "AGENTS.md", "Be helpful." + "".join(chr(0xE0000 + ord(c)) for c in "hi"), True),
    ("invisible-unicode", "README.md", "a\u200bb", False),
    ("invisible-unicode", "README.md", "a\u202eb", True),
    ("invisible-unicode", "notes.md", "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645", False),
    ("invisible-unicode", "a.ts", 'const family = "\U0001F468\u200d\U0001F469\u200d\U0001F467";', False),
    ("enumeration-message", "a.ts", 'throw new Error("Email already registered");', True),
    ("enumeration-message", "a.ts", 'throw new Error("No account found with that email");', True),
    ("enumeration-message", "a.ts", 'throw new Error("Invalid email or password");', False),
    ("enumeration-message", "a.ts", 'throw new Error("Invalid password reset token");', False),
    ("agent-config", ".claude/settings.json", '{"permissions": {"allow": ["Bash"]}}', True),
    ("agent-config", ".claude/settings.json", '{"permissions": {"allow": ["Bash(npm test *)"]}}', False),
    ("iam-wildcard", "policy.json", '{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}', True),
    ("iam-wildcard", "stack.ts", 'new PolicyStatement({ actions: ["dynamodb:*"], resources: ["*"] });', True),
    ("iam-wildcard", "archive.py", "with TarFile.open(src, 'r:*') as tf:", False),
    ("debug-exposure", "views.py", 'return jsonify({"error": traceback.format_exc()}), 500', True),
    ("debug-exposure", "loader.py", "message = 'Failed: %s' % (traceback.format_exc(),)", False),
    ("sensitive-logging", "a.py", 'logger.info(f"login for {password}")', True),
    ("sensitive-logging", "a.py", 'logger.info("password reset requested")', False),
]


class PatternTest(unittest.TestCase):
    def test_single_lines(self):
        for check, filename, text, expected in LINES:
            with self.subTest(check=check, text=text[:60]):
                found = single_file(filename, text, check)
                self.assertEqual(bool(found), expected, [f.message for f in found])

    def test_masking(self):
        token = T["github_pat"]
        masked = scan.excerpt(f'const t = "{token}"; const password = "Tr0ub4dor&3xK9q";')
        self.assertNotIn(token, masked)
        self.assertNotIn("Tr0ub4dor&3xK9q", masked)
        self.assertIn("gith…(93 chars)", masked)

    def test_strings_are_not_code(self):
        self.assertEqual(scan.outside_strings('log("password reset").update(password)'), 'log("").update(password)')
        self.assertEqual(scan.outside_strings('log(f"pw={password}")'), 'log(f"password")')
        self.assertEqual(scan.outside_strings("log(`t=${token}`)"), "log(`token`)")


class RepositoryTest(unittest.TestCase):
    def test_controls_exist(self):
        defined = set()
        for path in (ROOT / "checklist").glob("*.md"):
            defined.update(re.findall(r"^### ([A-Z]+-\d+)$", path.read_text(encoding="utf-8"), re.M))
        used = {c for chk in scan.CHECKS for c in chk.controls}
        self.assertEqual(used - defined, set())

    def test_skill_paths_exist(self):
        for skill in (ROOT / "skills").glob("*/SKILL.md"):
            for rel in re.findall(r"\$\{CLAUDE_SKILL_DIR\}/([\w./-]+)", skill.read_text(encoding="utf-8")):
                with self.subTest(skill=skill.parent.name, path=rel):
                    self.assertTrue((skill.parent / rel).resolve().exists(), rel)

    def test_skills_name_real_checks(self):
        """A skill that cites a scanner check as evidence must cite one that exists."""
        known = {c.id for c in scan.CHECKS}
        prose = {"unsafe-inline", "unsafe-eval", "secure-by-default", "security-audit", "ship-gate"}
        for name in ("security-audit", "ship-gate"):
            text = (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
            for token in set(re.findall(r"`([a-z]+(?:-[a-z]+)+)`", text)) - prose:
                with self.subTest(skill=name, check=token):
                    self.assertIn(token, known)

    def test_no_silent_greps_left(self):
        """The failure this repository had: a check whose errors go to /dev/null looks clean."""
        docs = list((ROOT / "skills").glob("*/SKILL.md")) + list((ROOT / "checklist").glob("*.md")) + \
            [ROOT / "vulnerabilities.md", *(ROOT / "prompts").glob("*")]
        for doc in docs:
            text = doc.read_text(encoding="utf-8")
            with self.subTest(doc=doc.name):
                self.assertNotRegex(text, r"grep -[a-zA-Z]*P\b", "grep -P is missing on macOS and needs a UTF-8 locale")
                self.assertNotRegex(text, r"\| *tail[^|\n]*\|\|", "`a | tail || b` never runs b")
                self.assertNotIn('"create table"', text, "SQL keywords are case-insensitive")


if __name__ == "__main__":
    unittest.main()
