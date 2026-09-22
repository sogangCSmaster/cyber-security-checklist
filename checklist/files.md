# FILE · Uploads, storage, and serving

An upload is untrusted input that gets *stored* and often *served back*, which makes it three
problems at once: an access-control problem (who may upload), a content problem (what the file is),
and a storage problem (where it lands and who can read it). AI-generated backends tend to get the
happy path — the file uploads, a URL comes back — and none of the three checks.

← [Back to the checklist](../checklist.md) · Related: [`DATA`](./data.md), [`WEB`](./web.md), [`INPUT`](./input.md), [`AUTH`](./authentication.md)

---

### FILE-01
**P0 · code** — Every upload endpoint requires authentication and authorization. An anonymous request cannot write to your storage.

- **Why:** a self-test of a real platform found `/api/upload` accepting **unauthenticated** multipart uploads and returning `200` — anyone on the internet could write files into the app's storage. An open write endpoint is abused for malware hosting, for defacement, and to fill (and bill) your storage.
- **Detect:** for every upload/create-file route, confirm the auth middleware runs *before* the body is read. Grep for multipart/form handlers and trace back to the auth check.
- **Fix:** require a valid session and check the caller may upload in this context (this album, this ticket) before accepting bytes.
- **Verify:** a test POSTs a file with no credentials and asserts `401`.
- **Probe:** [playbook §5](./probe-playbook.md#5--upload-probing--unauthenticated-writes-and-where-the-file-lands-worked-example) — a single marker file confirms it; stop there.

### FILE-02
**P1 · code** — Uploads are validated by actual content, allowlisted by type, and never served in a way the browser will execute. HTML and SVG are never served from the app's own origin.

- **Why:** an upload endpoint that accepts `.html` or `.svg` and serves it from your domain turns "upload" into **stored XSS** — an `.svg` is a document that can carry `<script>`, and the browser runs it in your origin, with your users' sessions. Extension checks alone are bypassed by renaming; content-type from the client is attacker-controlled.
- **Detect:** read the upload handler — does it trust the client-supplied filename/extension/content-type? Is there any path where user files are served under the app origin with a renderable content-type?
- **Fix:** detect type from content (magic bytes), allowlist the types you actually need, store with a generated name and no user-controlled extension, and serve user files from a separate origin (a sandbox domain or bucket host) with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`. See [`WEB-06`](./web.md#web-06).
- **Verify:** upload a file whose bytes are HTML/SVG but whose name says `.png`, and confirm it is rejected or served as an inert download from a non-app origin.
- **Probe:** [playbook §5](./probe-playbook.md#5--upload-probing--unauthenticated-writes-and-where-the-file-lands-worked-example).

### FILE-03
**P1 · code** — Uploads have size and resource limits; decompression and image processing are bounded.

- **Why:** an unbounded upload is a cheap denial-of-service and a storage-cost attack; a "zip bomb" or a decompression-heavy image can exhaust memory on the server that processes it. Related: [`LOGIC-05`](./logic.md#logic-05).
- **Detect:** check for a maximum body size at the proxy and app, and limits on any decompression or image-resize step.
- **Fix:** enforce a maximum size before buffering the whole body; cap dimensions and decompression ratios; process untrusted media out of the request path.
- **Verify:** upload a file over the limit and confirm early rejection, not an out-of-memory.

### FILE-04
**P0 · config** — Uploaded files are stored private by default and served through short-lived, per-object signed URLs — never from a world-readable bucket.

- **Why:** Tea, 2025 — a storage bucket left publicly readable exposed 13,000 government IDs and selfies and 1.1M private messages. A hotel check-in system, 2026 — 1M passports and licences. In the upload worked example, the endpoint returned a public bucket URL and fetching it with no credentials returned the file — the two failures compound.
- **Detect:** enumerate every bucket/container the app writes to, including ones from earlier versions, and read its public-access setting; check whether upload responses hand back a directly-fetchable public URL.
- **Fix:** block public access at the bucket level; serve each file via a signed URL scoped to that object, read-only, expiring in minutes ([`CLOUD-04`](./cloud.md#cloud-04)).
- **Verify:** take a stored file's canonical URL and fetch it with no credentials — it must be denied; the app's signed URL must work and then expire.
- **Probe:** [playbook §5](./probe-playbook.md#5--upload-probing--unauthenticated-writes-and-where-the-file-lands-worked-example).

### FILE-05
**P1 · code** — File paths are never built from user input. Filenames are sanitized; downloads are scoped to an allowed directory or a database-keyed object.

- **Why:** path traversal — a `../../` in a filename or a download parameter reads or writes outside the intended directory (config files, other users' uploads, application source). It appears repeatedly in file-handling CVEs.
- **Detect:** grep for file operations that concatenate user input into a path — `open(dir + name)`, `sendFile(req.query.path)`, `path.join(base, userInput)` without normalization + containment.
- **Fix:** never pass user input as a path; look files up by an opaque key in a database that maps to a server-chosen path; if you must use a name, canonicalize and assert the result stays within the base directory.
- **Verify:** request a download with `..%2f..%2fetc%2fpasswd`-style input and confirm it is refused, not resolved.
- **Probe:** try traversal sequences in any `path`/`file`/`name` parameter ([playbook §8](./probe-playbook.md#8--rate-limits-method-tampering-and-the-checks-that-only-exist-on-the-happy-path)).

### FILE-06
**P2 · code** — Metadata is stripped from uploads; user-supplied documents are not rendered server-side without sandboxing.

- **Why:** images carry EXIF GPS ([`LEAK-06`](./leakage.md#leak-06)); server-side rendering or thumbnailing of untrusted documents (Office, PDF, SVG) has its own injection and SSRF history.
- **Detect:** check whether uploads are stripped of metadata and whether any server-side render/convert step runs on untrusted files.
- **Fix:** strip metadata on ingest; render untrusted documents in a sandbox with no network, or not at all.
- **Verify:** confirm a stored image has no EXIF, and that the render path has no outbound network.
