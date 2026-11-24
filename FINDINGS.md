# Security and code review findings

Review of `geea-develop/job-finder-2` (fork of `YoadBarok/job-finder`), commit `ca8bb2b` (Job Finder 1.0.0).

Diff-based Security Review / Bugbot tools reported an empty branch diff on clean `main`; this document is a **full-tree** audit and code review.

**Verdict (code review):** REQUEST CHANGES  
**Security summary:** Critical 0 · High 3 · Medium 3 · Low 2

---

## Threat model (short)

| Boundary | Untrusted input | Main risks |
|---|---|---|
| ATS JSON / career pages / pasted jobs | Titles, HTML/text, URLs | Prompt injection → agent misuse; phishing apply links |
| User `search.json` / `companies.json` | Regexes, slugs | ReDoS / self-DoS; bad eligibility |
| CLI `--data`, `--claude-settings`, job folders | Paths | Arbitrary local writes; Claude Code permission widening |
| Claude agent tools | Model follows skill vs posting | Over-privileged shell if skill ignored |

---

## Security findings

### [HIGH] Prompt injection via job postings into the agent loop

- **Location:** `plugins/job-finder/skills/job-finder/SKILL.md`, `scripts/poll_boards.py` (full `text` in `candidates/*.json`), `references/sourcing.md`
- **Description:** Full job descriptions are persisted and re-read by Claude for scoring/tailoring. A malicious posting can embed instructions. Defenses are largely prompt-level.
- **Impact:** Agent may write outside the intended folder, create a phishing apply kit, or run shell steps the user did not intend.
- **Recommendation:** Keep skill rules; add mechanical guardrails — refuse `--data` unless the folder has a valid Job Finder marker; allowlist apply URL hosts; never pass raw posting text into tool/command construction.

### [HIGH] `apply_kit.py` accepts any `https://` URL (phishing webloc)

- **Location:** `plugins/job-finder/skills/job-finder/scripts/apply_kit.py`
- **Description:** Blocks non-HTTPS and CRLF/`<>"`, but not destination. Confirmed: `https://evil.example/phish` writes a working `Apply.webloc` / `Apply.url`.
- **Impact:** One-click shortcut can send the user to a credential-harvesting page with their CV.
- **Recommendation:** Allowlist ATS hosts (Ashby, Lever, Greenhouse, Workday, etc.) or require explicit user confirmation of the domain.

### [HIGH] Arbitrary `--data` write path (no folder attestation)

- **Location:** `poll_boards.py`, `track.py`, `apply_kit.py` (only `configure.py` refuses repo-internal paths)
- **Description:** Confirmed: `poll_boards.py --data <empty-dir>` creates `<dir>/candidates/<date>.json` with no check that the directory is a configured job-search folder.
- **Impact:** Prompt-injected or mistaken `--data` can write into unexpected trees the agent can access.
- **Recommendation:** Shared helper requiring `criteria.md` to start with `# Job search criteria` (same marker as discovery) before any write; optionally require path == configured `dataDir`.

### [MEDIUM] `configure.py` mutates any `--claude-settings` JSON

- **Location:** `scripts/configure.py`
- **Description:** Appends broad Bash allows (`python3 …/scripts/*`, `node …/scripts/*`, `pdftotext *`, `pdftoppm *`) and `additionalDirectories` to an arbitrary settings file path.
- **Impact:** Privilege expansion for Claude Code beyond the current project if a wrong path is passed.
- **Recommendation:** Only write `cwd/.claude/settings.local.json` (or require that suffix under cwd). Narrow allow rules where possible.

### [MEDIUM] User-controlled regex compilation (ReDoS / silent filter bugs)

- **Location:** `poll_boards.py` (`titleExclude` / `titleRequireAny` / `titleInclude`)
- **Description:** Patterns are compiled as regex (documented in `search.json`). Pathological patterns can hang the poller; typos silently drop jobs.
- **Recommendation:** Escape by default; optional `re:` prefix; clear compile errors.

### [MEDIUM] Dependency / converter surface

- **Location:** `doctor.py` (`npm install --prefix ~/.cache/job-finder docx`); `to_pdf.py` (LibreOffice)
- **Description:** Doctor fix string does not pin `docx`; LibreOffice parses DOCX (historical CVE surface).
- **Recommendation:** Pin `docx` version; avoid feeding untrusted third-party DOCX to `to_pdf.py`.

### [LOW] Home-directory discovery walk

- **Location:** `jf_config.py` `find_data_folders`
- **Description:** Walks common roots reading the first line of `criteria.md`. `os.walk` does not follow symlinks by default.
- **Recommendation:** Prefer configured path; treat `~` as last resort; cap runtime.

### [LOW] Eligibility substring false positive (integrity)

- **Location:** `poll_boards.py` home match uses `h in p`
- **Description:** `"India"` matches `"Indiana"` → group **A**. More correctness than classic vuln, but can push bad applications.
- **Recommendation:** Word-bounded home match (same as `authorized`).

### Security positives

- Never apply/submit; job text treated as untrusted in skill + `SECURITY.md`
- SSRF constrained: fixed ATS URL templates + slug allowlist
- Apply kit HTTPS + CRLF rejection; webloc XML escaped; CSV formula neutralization; `umask(0o077)`
- Template CV refused by `build_cv.js`; repo PII guard test; data folder refused inside git by `configure.py`

---

## Code review findings

### Critical

- **`poll_boards.py` — home-country substring match**  
  `any(h in p for h in home_l)` treats `"India"` as matching `"Indiana"`, `"OR"` as matching `"Oregon"`. Auth matching already uses word boundaries; home should too. Add regression tests.

### Important

- **`poll_boards.py` always exits 0** even when boards fail — scheduled digests can look successful with empty/partial candidates. Return non-zero when errors occurred or no board succeeded.
- **`check_cv.py` page count** via `/Type\s*/Page[^s]` is fragile for a hard “must be 1 page” gate. Prefer `pdfinfo`, `pdftoppm`, or `pypdf` page length.
- **Title filter fields as raw regex** without per-pattern validation errors (see security Medium).
- **`track.py`** — unclosed `open()` in `load()` (ResourceWarning in tests). Use a context manager.
- **Apply kit / `--data` attestation** — see security High items.

### Suggestions

- Align `package.json` version (`0.1.0`) with plugin `1.0.0`
- Guard missing argv in `to_pdf.py` / `build_cv.js`
- Simplify no-op ternary in `check_cv.py` (`text if caps else text`)
- Consider a stable-shape test for `doctor.py --json` (`CLAUDE:` fix strings)

### What's done well

- Clear product boundary and hard rules encoded in scripts, not only prose
- Purposeful tests (eligibility, scoring, discovery, configure perms, apply-kit unsafe URL partial coverage, skill zip freshness)
- `npm test`: 41 tests OK (2 skipped without local `docx`)

---

## Suggested fix order

1. Word-bound home match + India/Indiana regression test  
2. Attest `--data` before writes  
3. Allowlist apply URL hosts  
4. Constrain `configure.py` settings path  
5. Non-zero exit on poller board failures  
6. Harden `check_cv` page count and `track.py` file handle  

---

## Verification at review time

- Tests: `npm test` — OK (skipped=2)  
- Diff-based Security Review / Bugbot: no branch diff on clean `main`  
- Manual PoCs: arbitrary HTTPS apply kit; `poll_boards` write to non–Job Finder dir; `configure.py` merge into arbitrary settings JSON  
