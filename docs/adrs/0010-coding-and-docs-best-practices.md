# 10. Coding and documentation best practices

Date: 2026-08-29

## Status

Accepted

## Context

This repository is edited by people and by coding agents. A change is easiest
to review, and least likely to be questioned, when it reads like the code and
docs already in the tree. The failure mode of generated output is not that it
is wrong — it is that it diverges from the house style: fully typed where the
codebase annotates sparingly, wrapped to 88 columns where the codebase runs
long, documented where the codebase leaves a comment, tidied where the
codebase left a `TODO`. A reader spots that difference immediately, and it
costs them trust in the change.

This ADR records the best practices that are actually established in this
codebase — `scitt_emulator/*.py`, `tests/*.py`, `docs/*.md`, `README.md`, and
the commit history — so that any contributor has an explicit standard to
follow instead of a generic "Python style guide".

Two caveats about the standard. It is not uniform: roughly half the modules
carry a license header, imports are grouped but not alphabetised, and type
hints are partial. And one file is an outlier: `scitt_emulator/policy_engine.py`
(~2900 lines) is a long-running experiment with staged code,
`# TODO package deno`-style notes, a mermaid diagram in its module docstring,
and commits named `working`. It is the exception. The convention is set by
the majority of modules, and by the docs, which are the most consistent
surface in the repository.

## Decision

Contributions to this repository follow the best practices below. When a rule
says to match the file under edit, match the file under edit.

### Code

**Structure.** A module is a flat list, in order: license header (where the
files it resembles carry one), imports, module constants, small exception
classes, then functions and classes. Keep this ordering.

**License header.** Copy it from the file being edited rather than
re-inventing it. The tree contains `Copyright (c) Microsoft Corporation.`,
`Copyright (c) Microsoft Corporation. All rights reserved.`, and
`Copyright (c) SCITT Authors` variants. Top-level modules (`scitt.py`,
`server.py`, `client.py`, `cli.py`) all carry one; several helper modules do
not. Do not add a header to a file that has none, and do not normalise the
wording.

**Imports.** Stdlib first, then third-party, then `scitt_emulator.*`, with
blank lines between the groups. Do not alphabetise within a group — the
existing imports are not sorted (`server.py` imports `os`, `json`, `Path`,
`BytesIO`, `random` in that order).

**Constants.** Module-level `SCREAMING_SNAKE` names near the top, each with a
one-line comment that says what it is for and, where relevant, cites the
spec (`# temporary receipt header labels, see draft-birkholz-scitt-receipts`).
Keep a constant's exact string value even when it looks odd; names like
`COSE_Headers_Service_Id` are IANA labels held verbatim.

**Types.** Small `class XError(Exception): pass` classes for domain failures,
defined at the top of the module (`ClaimInvalidError`, `EntryNotFoundError`).
Add `__init__`/`__str__` only when the exception carries structured data
(`ClaimOperationError` in `client.py`). Use `@dataclass` for plain data holders
and an `@abstractmethod` ABC for an extension point.

**Functions.** `snake_case` names. Annotate parameters; annotate returns when
it is informative and leave them off otherwise — the codebase is deliberately
partial about this. Prefer a plain function over a method unless the object
is a real state holder. Prefer `pathlib` over `os.path` for file work.

**Plugin hooks.** Functions whose behaviour can be extended load their
overridable pieces as keyword-only arguments defaulting to `None`, then fall
back to `importlib.metadata.entry_points()` groups registered in `setup.py`.
Follow the existing shape: `verify_statement(msg, *, key_loaders=None)` and
`verification_key_to_object(vk, *, key_transforms=None)` are the templates.
Reuse those helpers instead of inventing a new loading mechanism.

**Comments.** Sentence case. A short "what/why" comment above a step
(`# Submit claim`, `# Store receipt`, `# Sign`), a spec URL when the behaviour
comes from a draft, and a full quoted block when the spec text is load-bearing
(`create_statement.py`). Leave `# TODO` markers where work is deferred; the
tree is full of them and that is normal here. Do not delete a commented-out
line that already exists.

**Errors and output.** Raise domain exceptions with f-string messages and
`!r` for values (`raise EntryNotFoundError(f"Entry {entry_id} not found")`),
and chain with `raise ... from error`. Use `print()` for operator/CLI-visible
status lines (`print(f"A COSE signed Claim was written to: {claim_path}")`);
this is how the tools report progress, not a debugging leftover.

**Match the codebase's prevailing conventions, including where they are not
maximalist.** Lines longer than 88 characters are common, type hints are
incomplete, imports are unsorted, and at least one function is misspelled
(`preform_verification_key_transforms`). None of these are to be fixed as part
of a feature change. Running a formatter over a file being edited makes the
diff look unlike the repository.

### Server, client, and CLI patterns

A Flask route lives inside a `create_flask_app(config)` factory, with errors
returned through a `make_error(code, msg, status_code)` helper that produces
`{"type": "urn:ietf:params:scitt:error:{code}", "detail": msg}`. Follow that
shape for new endpoints.

The command-line surface is built with the module `cli(fn)` convention: each
command module exposes `def cli(fn)` where `fn` is an argparse parser or a
subparser factory, wires arguments with `parser.set_defaults(func=lambda
args: ...)`, and `cli.py` composes them. New commands follow this pattern;
do not introduce a different argument-parsing approach.

Client work goes through an `HttpClient` wrapper class that centralises
retries (honouring `Retry-After`) and status handling, with retry defaults as
module constants.

### Docs

Markdown, with a single `#` level-1 title, `##`/`###` sections below, and a
`- References` bullet list near the top of a doc that cites external
material, as `docs/registration_policies.md` and `docs/oidc.md` do.

Tutorial/runbook docs are the house style: numbered or sequential steps,
`sh`, `console`, `output`, and `json` fenced code blocks, a `$`
shell prompt inside console blocks, real terminal output shown verbatim
(including tracebacks), `**Note:**` italic callouts for asides, and prose
between steps that says what is happening and why.
`docs/registration_policies.md` is the model.

Code samples in docs are load-bearing: `tests/test_docs.py` parses
`docs/registration_policies.md` with myst_parser, extracts each `**filename**`
marker followed by a fenced block, writes them to disk, and runs them. Any doc
code sample should be written so it can survive that treatment.

**ADRs.** The format is fixed by the existing series: `# N. Title`, a
`Date: YYYY-MM-DD` line, then `## Status`, `## Context`, `## Decision`, `##
Consequences`, with reference links at the foot. Context is evidence-based —
quote the spec, cite `grep` results and file reads. Decisions are concrete and
name the files they change. Consequences are bullet lists of what the decision
costs and buys. New ADRs copy that shape exactly.

**README.** `README.md` is a plain, practical guide: short intro, numbered
steps with commands, minimal prose, links to the IETF drafts that govern the
formats. When adding a feature, extend it in that voice rather than writing a
marketing paragraph.

### Commits

The commit history is `subject: predicate` in lowercase
(`create statement: Return URN of signed statement`), occasionally with a
nested scope (`token: issue: Fix verify_statement call`), and occasionally a
bare phrase (`Client`, `working`). Write a commit that names the area and the
behaviour change in that shape. Do not retrofit conventional-commit tags onto
the history.

### When in doubt

Mirror the file under edit. Its header, import order, comment density,
naming, and conventions are the local truth; the rules above are
generalisations of it. If the surrounding code contradicts a rule, the
surrounding code wins.

## Consequences

* Contributions should read as unremarkable parts of the tree, reducing review
  friction and preserving trust.
* The practices deliberately include the codebase's own non-maximalist
  choices — partial type hints, unsorted imports, `TODO`s, long lines.
  Following them means a contribution will not "tidy" the codebase as a side
  effect, and will not be penalised for leaving the occasional `TODO` or long
  line.
* `policy_engine.py` is called out as an outlier so contributors weight the
  dominant style rather than the most visible file.
* This ADR records the conventions at a point in time. If the codebase style
  shifts (for example, if a formatter is adopted), this ADR should be updated
  to match rather than forcing the code back to an older norm.
