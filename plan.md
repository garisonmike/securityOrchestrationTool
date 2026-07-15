# Security Orchestration Tool — Rewrite Plan

Priority: testing & error-handling consistency. Scope: full rewrite, not an incremental patch.

## 0. Evidence base — why a rewrite, not a patch list

These are verified against your actual code and the run you pasted, not hypothetical:

1. **Report generation crashes on a completely ordinary path.** `templates/report.html.j2` line 117
   and `report.md.j2` line 84 both do `{% for key, result in privesc.findings.items() %}`, guarded
   only by `{% if privesc %}` — not by `findings` existing. When PrivEsc is skipped (`main.py` sets
   `session_findings["privesc"] = {"status": "skipped", "reason": "..."}` at three separate call
   sites — lines 439, 442, 445), there is no `findings` key at all. Jinja's attribute-then-getitem
   fallback returns `Undefined`, and calling `.items()` on it raises
   `UndefinedError: 'dict object' has no attribute 'findings'` (reproduced directly against the
   templates, not just inferred) — exactly the error in your pasted run.
   The identical unguarded pattern repeats for `log_analysis.matches.*` (both templates,
   `| length` filters on lines ~135-137 / ~101-103) — **and this path is actually the more common
   trigger, not a secondary case.** Rendering the templates directly against
   `log_analysis={"status": "skipped", "reason": "No shell access obtained", ...}` (the exact dict
   `main.py` line 471 builds) raises the same `UndefinedError`, this time on `matches` —
   **even with PrivEsc set to `{}` (module not selected at all).** Since Log Correlation only
   avoids "skipped" when PrivEsc is selected *and* SSH fully connects, selecting Log Correlation
   without also getting a working SSH login crashes the report every time. This should be treated
   as two independent regression cases in Phase 5, not one.
2. **nmap's own diagnostic text gets stored as scan data.** In noisy mode, raw nmap stdout (including
   NSE script help/error text like *"Couldn't determine the underlying framework... try increasing
   httpspider.maxpagecount"*) is written straight into the `backend` and `active_probes` tech-stack
   fields, which then feed nuclei's tag selection and get quoted verbatim in the report.
3. **The active-probe false-positive filter doesn't work — confirmed, with the precise mechanism
   corrected.** `recon.py`'s `noisy_fingerprint` (line 186) checks
   `'<html' not in resp.text[:50].lower()` to decide whether a 200 response is a "real" file. This is
   *not* simply "`<!DOCTYPE html>` never contains `<html`" — a short/modern doctype immediately
   followed by `<html>` often does land inside the first 50 characters, and the filter would catch
   that case correctly. The bug is the **fixed 50-character window** combined with realistic
   doctype length: DVWA (a PHP 4/XHTML-era app) serves a long
   `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "...">` declaration, which alone
   exceeds 50 characters and pushes the actual `<html` tag out of the checked window — reproduced
   directly: a realistic DVWA-style doctype yields `'<html' not in window` → `True`, i.e. the page
   is misclassified as "not HTML." This is exactly why your run reported "Found CHANGELOG.md /
   README.txt / .env / package.json" when the target was just serving its normal DVWA page for every
   path. **Implication for Phase 2's test spec:** the regression test needs a fixture with a
   realistic (long) doctype/head, not a minimal `<!DOCTYPE html><html>` toy string — a toy fixture
   would pass today's filter and silently fail to pin the real-world failure mode.
4. **Documented CLI flags don't exist.** `argparse` is imported in `main.py` and never used. Every
   `--target` / `--modules` / `--output-format` example in the README is fiction — the tool is
   100% interactive-only.
5. **Documented `config.yaml` support doesn't exist either.** No `yaml` import, no dependency on
   PyYAML, no loader anywhere in the codebase.
6. **Zero tests, no CI, no packaging config** anywhere in the repository.
7. **Log correlation is gated on PrivEsc's SSH object by `main.py`, not by module design.**
   `main.py` line 465 imports both `analyze_logs` and `analyze_logs_from_ssh` from
   `log_analyzer.py`, but only ever calls `analyze_logs_from_ssh` (line 485) — `analyze_logs`
   (`log_analyzer.py` line 115, takes a plain `log_path`, zero SSH dependency) is imported and never
   invoked. So "Log Correlation silently disables itself the instant PrivEsc is skipped" is
   confirmed as *current behavior*, but the root cause is an orchestration-wiring decision in
   `main.py`, not a structural limitation of `log_analyzer.py` — the decoupled path already exists.
   That's good news for effort, but it means Phase 4 owes an explicit product decision (does log
   correlation get a path to run independently of PrivEsc, e.g. `--log-source`? — spelled out in
   Phase 4 below), not just a mechanical port.

**Root cause behind #1–#3 and #7:** there is no typed contract for what a module's output looks
like. Every consumer (the nuclei tag selector, the report template, `main.py`'s console printer)
makes its own private assumption about a dict's shape, and those assumptions silently diverge the
moment a code path other than "everything succeeded" runs. Patching each symptom individually
would leave this exact class of bug free to reappear with the next new code path — which is the
argument for a full rewrite around typed models, not a bugfix pass.

## 0.1 Additional findings — verified against source, not in the original evidence base

These were found by reading `main.py`, `modules/*.py`, `templates/*.j2`, `README.md`,
`CONTRIBUTING.md`, `CHANGELOG.md`, and the one real report artifact already sitting in
`reports/report_localhost_8080_dvwa_vulnerabilities_sqli_.md`. Several are confirmed by that
captured report directly, not just by reading code.

8. **`analyze_logs_from_ssh` and `analyze_logs` don't agree on field names, and it's a live bug,
   not just a design smell.** `analyze_logs_from_ssh` returns `target` (`log_analyzer.py` line 30);
   `analyze_logs` returns `log_file` (line 123). Both templates reference
   `log_analysis.log_file` (`report.html.j2` line 130, `report.md.j2` line 97) — silently blank
   every time the only path `main.py` actually exercises (the SSH one) runs, because that key never
   exists there. Not a crash by itself (bare interpolation of `Undefined` renders empty), but a real
   correctness bug the original evidence base didn't list. This is direct input for why
   `LogFindings` needs one normalized field name across both variants, not two independently-shaped
   dicts merged by convention.

9. **Dead redaction code — a security-relevant bug, and it's not hypothetical.** `main.py` defines
   `redact_sensitive_data()` (lines 25-38, explicitly commented `# Issue #29: Redact sensitive data
   from output (session cookies, credentials)`) and it is called **nowhere** in the codebase
   (verified by grep across every `.py` file). Meanwhile the "Standard Findings" loop in both
   templates dumps every `recon` key except `hierarchical_stack`, `searchsploit_results`,
   `opsec_level`, `target`, `profile` into a `<pre>`/code block — which includes `web_headers`
   (`dict(response.headers)`, captured at `recon.py` line 278). **This isn't a theoretical risk: the
   report already committed to this repo,
   `reports/report_localhost_8080_dvwa_vulnerabilities_sqli_.md`, contains an unredacted live
   `PHPSESSID` cookie value in its "Web Headers" section from a real run.** Given the tool's stated
   purpose is producing shareable reports, this needs to land in Phase 1 (a redaction step on the
   `Report` model, or the render layer) or Phase 5 — right now it's an orphaned function nobody
   wired up, sitting next to a real example of the leak it was written to prevent.

10. **`CONTRIBUTING.md` documents an entire fictional test/tooling suite.** Beyond the README's
    CLI/config fiction, `CONTRIBUTING.md` references `tests/unit/`, `tests/integration/`,
    `conftest.py`, pytest markers, `black`/`flake8`/`mypy`/`bandit`/`safety`/pre-commit, and coverage
    gates (`pip install pytest black flake8 mypy pre-commit bandit safety`, line 99; `pytest
    --cov=modules --cov-report=html`, line 440) — none of which exist in the repo (confirmed: no
    `tests/`, no `.github/`, no `pyproject.toml`/`setup.py`/`setup.cfg`). This plan's Phase 0
    toolchain is deliberately leaner (pytest + pytest-cov + stdlib mock, no linters/security
    scanners), which is defensible, but it directly contradicts already-"documented" tooling.
    `bandit`/`safety` in particular — static analysis on a tool that shells out to
    nmap/gobuster/ssh/searchsploit — seem genuinely worth having; decide before Phase 0 starts
    whether to absorb them into CI or rewrite `CONTRIBUTING.md` to match the leaner reality (or
    both).

11. **`CHANGELOG.md` overclaims features that the code contradicts.** The `[1.0.0]` entry's
    "Security" section claims "Integrated sensitive data redaction capabilities" and "Implemented
    comprehensive input validation and sanitization" as *shipped* — see item 9 above for why the
    redaction claim is false, and the only "validation" in `main.py` is a non-empty-string check on
    the target field (line 64). This is a third documentation-vs-reality gap alongside README
    (CLI/config) and CONTRIBUTING (test tooling); worth folding into the same reconciliation
    decision rather than treating as a one-off.

12. **Internal inconsistency: "five pydantic models" vs. six named models.** Phase 1's exit bullet
    says "the five pydantic models"; Section 4's target-structure comment lists `ScanConfig`,
    `ReconFindings`, `FuzzerFindings`, `PrivescFindings`, `LogFindings`, `Report` — six. Minor, but
    in a plan whose thesis is "no more silent shape mismatches," the count and names should be
    locked before writing code. (Fixed below.)

13. **`config` vs `configuration` key duplication — confirmed, and the first key is already 100%
    dead code today, not just a future risk.** `main.py` line 197 seeds
    `session_findings["config"] = config`; line 511 later writes
    `session_findings["configuration"] = config`; `report_gen.py` line 22 reads
    `findings.get("configuration", {})`. Grepped across the whole repo: `session_findings["config"]`
    (the line-197 key) is never read anywhere — it's already an orphaned duplicate in the current
    codebase, not a hypothetical divergence risk. `Report`'s config field needs to be nailed down
    explicitly in Phase 1 so a third copy can't appear during the port.

14. **No non-interactive story for missing tools.** `check_and_install_missing_tools()`
    unconditionally calls `questionary.confirm(...)` to ask about `sudo apt-get install` (line 148),
    with no check for whether the process is running non-interactively. Phase 4's exit criterion
    requires the CLI to run "non-interactively, in CI, without touching a real network," but there's
    no spec for what happens when a required tool is simply absent on that path — fail fast with
    `ToolNotFoundError`? Auto-skip the module and mark it in the `Report`? This needs one sentence in
    Phase 4 or it'll get improvised mid-implementation.

15. **`PrivescFindings`'s three states are more specific than "sometimes missing a field" —
    confirmed exactly which code paths produce which shape.** `run_privesc()` itself (`privesc.py`
    line 241-246) *always* initializes `"findings": {}` at the top, and every one of its exception
    branches (auth failure, `SSHException`, `EOFError`, socket error, generic exception) returns
    that dict with `findings` present, just empty. The crash is caused exclusively by the three
    pre-connection "skip" branches hard-coded directly in `main.py` (lines 439, 442, 445), which
    bypass `run_privesc()` entirely and construct a raw `{"status": "skipped", "reason": ...}` with
    no `findings` key at all. So `PrivescFindings` needs to model three genuinely distinct shapes —
    success (populated `findings`), connection-error (empty `findings`, already how the code
    behaves), and user-skipped (no attempt made) — and the "skipped" variant should get an explicit
    `findings: Optional[...] = None` rather than the field simply being absent, which is precisely
    the class of fix Phase 1 is meant to guarantee.

## 1. Goals

- [ ] Every module's output is a typed, validated model — no bare dicts crossing a module boundary.
- [ ] Every fallible operation returns a `Result`, never a status-string dict or a swallowed exception.
- [ ] Every branch of scan logic (tag selection, filters, gating conditions) has a test that never
      touches a real network or spawns a real subprocess.
- [ ] The CLI is scriptable — every flag the README already promises actually works — and the
      interactive prompt flow is a thin wrapper over the same entry point, so the two can't drift.
- [ ] The five existing capabilities (recon, fuzzer, privesc, log correlation, report) are preserved
      1:1. This is an architecture rewrite, not a feature expansion.
- [ ] `README.md`, `CONTRIBUTING.md`, and `CHANGELOG.md` are reconciled with what actually ships —
      no flag, config schema, tooling command, or "already implemented" claim in the docs that the
      code doesn't back up (Section 0.1, items 10-11).
- [ ] Sensitive values (session cookies, credentials) never reach a generated report unredacted —
      the direct regression test for Section 0.1 item 9, which is already reproduced in this repo's
      own `reports/` folder.

## 2. Non-goals (explicitly out of scope for this plan)

- Concurrency / async execution of modules — parallelizing an as-yet-untested codebase compounds
  risk; revisit once Phase 4 is stable.
- New scan capabilities (cloud/container scanning from the README roadmap).
- Plugin marketplace / dynamic module loading — the module interface from this plan gives you this
  cheaply later, but building discovery machinery now is scope creep against your stated priority.
- GUI/dashboard.

## 3. Technology choices, and why

| Choice | Rationale | Alternative considered & rejected |
|---|---|---|
| **Pydantic v2** for `Config`/`Findings`/`Report` models | Runtime validation at exactly the boundary where the evidence shows failures happen (data in, data out) | Dataclasses + manual validation — rejected: hand-rolled validation per module is the same "inconsistent per-module" pattern currently causing bugs |
| **Hand-rolled `Result[T]`** (~30 lines, no dependency) for expected failures | Tool-missing / target-down / auth-failed are routine control flow, not exceptions | "Exceptions everywhere" — rejected: makes tests noisier and encourages the broad `except: pass` pattern already in the codebase |
| Small typed exception hierarchy, reserved for programmer errors only (bad config, invalid type) | Those should fail loudly, not be swallowed | — |
| **stdlib `argparse`**, not click/typer | Zero new dependency; this tool already shells out to nmap/gobuster/ssh — every added third-party package is attack surface in a security tool | click/typer — rejected on dependency-minimalism grounds, not on merit |
| **pytest + pytest-cov + `unittest.mock`** (stdlib) | No live network/tool calls in tests, ever — adapters take an injectable "runner" defaulting to the real call | — |
| **GitHub Actions CI** | Makes the README's existing (currently false) CI/CD claim true | — |

Net new dependency: **pydantic only.** Everything else is stdlib or already in `requirements.txt`.

## 4. Target structure

```
security_orchestrator/
  core/
    models.py        # Six models, not five: ScanConfig, ReconFindings, FuzzerFindings,
                      # PrivescFindings, LogFindings, Report — each with explicit
                      # success/skipped/error variants (see Section 0.1 items 8, 12, 15)
    result.py         # Result[T]
    exceptions.py     # ConfigError, ToolNotFoundError — programmer/setup errors only
    redact.py          # Redaction pass over Report before it reaches the render layer
                      # (replaces the orphaned main.py:redact_sensitive_data — Section 0.1 item 9)
  adapters/
    http.py, nmap.py, gobuster.py, nuclei.py, ssh.py, searchsploit.py, wkhtmltopdf.py
    fakes.py          # Fake* counterparts, used only by tests
  modules/
    recon.py, fuzzer.py, privesc.py, log_analyzer.py  # log_analyzer.py exposes one function
                      # taking an injected "log source", not two divergent entry points
  report/
    generator.py       # calls core/redact.py before template.render()
    templates/        # existing .j2 files, now rendered against model_dump() of typed Report
  orchestrator.py      # sequencing + gating logic (e.g. "log analysis needs an open ssh session")
  cli.py               # argparse wiring + interactive prompts, both calling orchestrator.run()
tests/
  unit/                # one file per adapter/module
  fixtures/            # canned tool outputs captured from this session's real run
pyproject.toml
.github/workflows/ci.yml
```

## 5. Phases

Each phase has entry criteria, deliverables, and an exit criterion you can check by running
something — not a subjective "looks done."

### PHASE-0 — Harness
- Deliverables: `pyproject.toml`, pytest config, empty package skeleton, `.github/workflows/ci.yml`
  running `pytest` on push.
- [ ] Exit: `pytest` is green in CI on a fresh clone, zero manual setup steps.

### PHASE-1 — Core contracts
- Deliverables: `Result[T]`, exception hierarchy, and the **six** pydantic models — `ScanConfig`,
  `ReconFindings`, `FuzzerFindings`, `PrivescFindings`, `LogFindings`, `Report` (the plan previously
  undercounted this as "five" — see Section 0.1 item 12) — built from the real shapes observed this
  session, including their "skipped"/"error" variants, so e.g. `PrivescFindings` has an explicit
  optional `findings` field with a documented default, never a key that's sometimes just absent
  (the three concrete shapes `run_privesc()` and `main.py` currently produce are enumerated in
  Section 0.1 item 15). `LogFindings` normalizes the `target`/`log_file` naming split between
  `analyze_logs` and `analyze_logs_from_ssh` (Section 0.1 item 8) into one field.
- Decide and implement where redaction lives: a `redact()` step on `Report` (or on the models that
  feed it) in `core/redact.py`, replacing the orphaned `main.py:redact_sensitive_data` — this is not
  optional cleanup, see the live unredacted cookie in this repo's own `reports/` folder
  (Section 0.1 item 9).
- Tests: valid input constructs correctly; missing required fields raise a clear `ValidationError`;
  skipped/error variants are representable without inventing data that was never collected; redaction
  strips session cookies/credentials from a `Report` built from a fixture containing a real-shaped
  `Set-Cookie` header.
- [ ] Exit: every model round-trips through `model_dump()` / `model_validate()` in tests. You can read
  `ReconFindings` and know every field that exists in all three of its states without opening `recon.py`.
  A `Report` built from a fixture with a `PHPSESSID` cookie never contains that cookie value after
  `redact()`.

### PHASE-2 — Adapters
Build in this order: `http` → `nmap` → `gobuster` → `nuclei` → `ssh` → `searchsploit` → `wkhtmltopdf`.
Each adapter is one class; constructor takes an injectable runner (defaults to the real
subprocess/paramiko/requests call); one public method returns a `Result`.

Mandatory test matrix per adapter:
- [ ] tool succeeds, output parses cleanly
- [ ] tool binary missing (`shutil.which` → `None`) → `Result.err(...)`, nothing escapes uncaught
- [ ] tool times out
- [ ] tool returns non-zero exit or malformed/unparseable output
- [ ] (`http` adapter only) response body starts with a **realistic, long** doctype (e.g. an XHTML
  1.0 Transitional declaration like DVWA actually serves), not a minimal `<!DOCTYPE html><html>`
  toy string — a short-doctype fixture would pass today's buggy filter too and fail to pin the real
  failure mode (see the corrected mechanism in Section 0, item 3) — regression test for bug #3

- [ ] Exit: all cases above pass for every adapter. A shared pytest fixture monkeypatches
  `subprocess.run`/`socket.socket` to fail the test immediately if called outside the injectable-runner
  path — so an accidental live call is a loud test failure, not a silent real scan.

### PHASE-3 — Modules
Rebuilt against Phase 2's adapters.
- **Recon**: adapter returns only parsed, structured data — closes off the path that let nmap's help
  text land in a `backend` field (bug #2). Add the DVWA-level detection and searchsploit filtering
  logic as their own tested units.
- **Fuzzer**: nuclei tag-selection gets one test per tech-stack keyword branch (currently only
  observable by reading console output).
- **Privesc**: rate-limit detection and default-credential brute-force tested against a fake SSH
  adapter simulating dropped connections, exponential delay, and each of the eight credential outcomes.
  Model the three genuinely distinct result shapes confirmed in Section 0.1 item 15 (success,
  connection-error with empty findings, user-skipped with no findings attempt) as explicit
  `PrivescFindings` variants rather than re-deriving them from `run_privesc`'s current dict shape.
- **Log analyzer**: accepts "a way to fetch log content" as an injected dependency instead of a live
  `paramiko` session directly — this also resolves the PrivEsc hard-coupling (bug #7), as a side
  effect of the typed rewrite rather than as separate new scope. Note this is largely a wiring fix,
  not new module logic: `analyze_logs(log_path)` already exists and is already SSH-free
  (Section 0.1 item 8) — `main.py` just never calls it. Collapse `analyze_logs` /
  `analyze_logs_from_ssh`'s divergent `log_file`/`target` fields into `LogFindings`'s one field as
  part of this work.
- [ ] Exit: each module has tests covering every status its model can represent. This is the direct
  regression test for bugs #1 and #2 — a "skipped" model can no longer be silently missing a field a
  "success" model has, because the model itself defines what's optional. Include the
  privesc-not-selected-but-log-correlation-selected case explicitly — Section 0, item 1 shows this
  is the more commonly hit crash trigger, not an edge case.

### PHASE-4 — Orchestrator + CLI
- Orchestrator: one function, sequences modules, owns gating rules as an explicit, named condition
  (e.g. `skip_reason = "no ssh session established"`), not an implicit side effect of call order.
- **Product decision, needed before implementation (Section 0, item 7):** should log correlation be
  reachable independently of PrivEsc — e.g. a `--log-source <path>` flag or separate credentials —
  now that `analyze_logs()` proves the module itself has no SSH dependency? If the decision is "no,"
  say so explicitly as a policy in the orchestrator's gating condition; if "yes," it's a small addition
  now that the typed rewrite has already done the hard part. Either way, write down which one — don't
  let it default silently.
- **Non-interactive missing-tool policy, needed before implementation (Section 0.1 item 14):**
  `check_and_install_missing_tools()` currently always prompts via `questionary.confirm(...)`, with
  no non-interactive branch. Decide: fail fast with `ToolNotFoundError`, or auto-skip the affected
  module and record it in the `Report`? This has to be resolved for the CLI's non-interactive exit
  criterion below to be meaningful in CI, not improvised into whichever thing happens to make CI pass.
- CLI: argparse wiring for every flag the README promises; interactive prompt flow calls the
  identical `orchestrator.run(config)` entry point.
- Tests: argument-parsing tests (valid/invalid combinations); one end-to-end test using all fake
  adapters, running the full pipeline against fixture data, asserting on the final `Report` object;
  a test asserting the chosen missing-tool policy fires correctly with no tty/stdin available.
- [ ] Exit: `python -m security_orchestrator --target <t> --modules recon,fuzzer --output-format markdown`
  actually runs non-interactively, in CI, without touching a real network, and without hanging on a
  missing-tool prompt.

### PHASE-5 — Report generation
- Templates render against `model_dump()` of the typed `Report`, not raw findings dicts.
- Tests: render each template against a "fully successful," a "fully skipped," and a "mixed" report;
  assert rendering never raises and contains the expected section headers. Include **both**
  independently-crashing shapes confirmed in Section 0, item 1 as separate cases — not one
  combined "skipped" fixture — since either alone is sufficient to raise `UndefinedError` today:
  (a) `PrivescFindings` in its user-skipped state, `LogFindings` absent/not-executed; (b)
  `PrivescFindings` absent/not-executed, `LogFindings` in its skipped state (this is the path that
  fires whenever Log Correlation is selected without a fully successful SSH login — the more common
  of the two in practice). Also render a `Report` built from a fixture containing a `Set-Cookie`
  header and assert the rendered output never contains the raw cookie value (regression test for
  Section 0.1 item 9).
- [ ] Exit: rendering doesn't raise for any valid `Report` instance — the direct regression test for
  the exact crash in your pasted run, covering both trigger paths above. No rendered report contains
  an unredacted session cookie or credential value.

## 6. Coverage gate

- `pytest-cov` target: ≥90% on `core/` and `adapters/` (near-pure logic, should approach 100%),
  ≥80% on `modules/` (some inherent I/O glue not worth chasing to 100%).
- CI fails the build if coverage drops below gate, or if any test opens a real socket/subprocess
  outside the injectable-runner path (Phase 2 fixture).

## 7. Migration approach

Not a big-bang cutover. The new `security_orchestrator/` package is built alongside the existing flat
`modules/`, ported one phase at a time in the order above. The old `main.py`/`modules/` are deleted
only once PHASE-4's exit criterion passes end-to-end. You have a runnable tool at every point in the
process — never a multi-week window with nothing working.

## 8. Validation of this plan

- **Phase ordering is load-bearing, not arbitrary**: Phase 2 needs Phase 1's models to type its
  `Result`; Phase 3 needs Phase 2's adapters to inject. Reordering creates rework, so this is close to
  the only viable sequence, not one of several equally-good ones.
- **Every exit criterion is checkable by running a command**, matching your stated priority —
  testing/error-handling consistency is a property of the plan's structure, not just the resulting code.
- **Each of the concrete bugs found maps to a named regression test in a named phase** — not just
  three anymore. Bug #1 (privesc-skipped crash) and its independently-triggering sibling
  (log-analysis-skipped crash, Section 0 item 1) → Phase 5; bug #2's root cause → Phase 3; bug #3 →
  Phase 2's http adapter, with a realistic-doctype fixture, not a toy one; the redaction gap
  (Section 0.1 item 9) → Phase 1/5; the `LogFindings` field-name split (item 8) → Phase 1/3; the
  five-vs-six model count (item 12) → Phase 1. If Phase 5 ships without *both* skipped-render test
  cases, or Phase 1 ships redaction as an afterthought instead of a tested step, the plan has failed
  at the one thing you asked for — that's a falsifiable check, not a vibe.
- **Alternative rejected**: patch the bugs in place, incrementally. Rejected because they share
  one root cause (no typed contracts) that patching can't fix without becoming this rewrite anyway,
  and because you'd already decided on a full rewrite before this plan was written.
- **Risk — one new dependency (pydantic) in a security tool**: mitigated by it being among the most
  widely audited Python packages in existence (it underpins FastAPI and a large share of the Python
  security tooling ecosystem), and by confining it to `core/models.py` rather than spreading it
  through business logic.
- **Honest sizing**: five phases of real work, not a single-session rewrite. Phase 2 is the largest
  (six or seven adapters, four to five test cases each). Treat each phase as its own session, the same
  way you've been working through numbered features on the Flutter app.
- **This plan's evidence base has been checked directly against the repository, not taken on
  faith.** Every bug in Section 0 and every item in Section 0.1 was confirmed by reading the actual
  source (`main.py`, `modules/*.py`, `templates/*.j2`, `README.md`, `CONTRIBUTING.md`,
  `CHANGELOG.md`) rather than re-described from memory of the pasted run. Several were reproduced
  directly rather than inferred: the exact `UndefinedError` traceback (both trigger paths), the
  `<html`-filter bypass with a realistic doctype, and the `analyze_logs`/`analyze_logs_from_ssh`
  field-name split. One finding (the unredacted cookie, item 9) isn't inferred at all — it's sitting
  in this repo's own `reports/report_localhost_8080_dvwa_vulnerabilities_sqli_.md` from a prior run.
  No claims in the original evidence base turned out to be wrong on inspection; three (items 3, 7,
  and the bug count) needed the mechanism or wording corrected for precision, and seven new findings
  (items 8-15) surfaced from the fuller read.
