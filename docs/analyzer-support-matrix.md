# Python analyzer pilot support matrix

This document is the version-controlled support contract for the `python-stdlib`
language pack, version `1.0`. It describes detection coverage, not a guarantee that
a repository is secure. Anything not explicitly listed as **pilot-supported** is
unsupported or experimental and must not be represented as covered.

## Support status definitions

- **Pilot-supported**: accepted for a limited customer pilot, with deterministic
  behavior covered by the current regression suite. Findings still require analyst
  validation.
- **Experimental**: available for evaluation, but not part of the pilot support
  commitment. Precision, recall, and compatibility may change.
- **Unsupported**: not analyzed; absence of a finding provides no assurance.

The pack as a whole continues to report `coverage.status: experimental`. Individual
pilot-supported rules below have a narrower commitment; that label does not promote
the whole language pack to general availability.

## Python syntax

| Input | Status | Scope |
| --- | --- | --- |
| Python 3 source accepted by the CPython 3.13 parser | Pilot-supported | UTF-8 `.py` files whose syntax `ast.parse` accepts in the pinned Python 3.13 analyzer image. This includes syntax compatible with Python 3.13, but does not certify behavior on every earlier runtime. |
| Python 3.14+ syntax | Unsupported | May produce a parse failure until the analyzer runtime and tests are upgraded. |
| Python 2 syntax | Unsupported | No Python 2 grammar or compatibility parsing. |
| Non-UTF-8 source, including encoding-cookie files not actually encoded as UTF-8 | Unsupported | Counted as a parse failure; no finding is produced for that file. |
| Files without the exact lowercase `.py` suffix | Unsupported | Counted under `unsupported_files`; notebooks, stubs (`.pyi`), templates, generated archives, and uppercase suffix variants are not parsed. |

A successful parse means only that the three call patterns below were inspected. It
does not mean all statements, data flows, dependencies, or vulnerabilities in that
file were analyzed.

## Framework and library coverage

The analyzer does not resolve imports, inspect lockfiles, or determine installed
package versions. Consequently, no third-party framework or library version is
certified. The only supported surface is the literal call shape shown below.

| Framework/library | Versions | Status | Recognized surface |
| --- | --- | --- | --- |
| Python standard library | CPython 3.13 parser/runtime | Pilot-supported | Directly spelled `subprocess.run`, `subprocess.call`, `subprocess.Popen`, and `os.system` calls for PY001. |
| Requests | No version certified | Pilot-supported pattern only | Attribute chains ending in `requests.get`, `requests.post`, `requests.put`, or `requests.delete`, with literal `verify=False`, for PY002. |
| HTTPX | No version certified | Experimental pattern only | Attribute chains ending in `httpx.get` or `httpx.post`, with literal `verify=False`, for PY002. Client methods and other verbs are not covered. |
| PyYAML | No version certified | Experimental pattern only | Attribute chains ending in `yaml.load`, with a `Loader` name ending in `UnsafeLoader` or `FullLoader`, for PY003. |
| Django, Flask, FastAPI, Pyramid, Tornado, and other web frameworks | None | Unsupported | No framework-aware routing, request-source, template, ORM, authentication, or configuration analysis. Calls matching a rule may still be found incidentally. |

“Pattern only” is intentional: aliases, wrappers, monkey patches, and unrelated
objects with matching attribute names can cause missed findings or false positives.

## Enabled rules

All and only the following rule IDs are emitted by pack version `1.0`.

| Rule ID | Category | Detection | CWE | Pilot status |
| --- | --- | --- | --- | --- |
| `PY001` | Command execution / injection | `os.system(...)`, or a listed `subprocess` call with literal `shell=True` | CWE-78 | **Pilot-supported** |
| `PY002` | Transport security | A listed Requests/HTTPX function with literal `verify=False` | CWE-295 | **Pilot-supported** for the Requests call shapes; **experimental** for HTTPX |
| `PY003` | Unsafe deserialization | `yaml.load(..., Loader=...)` where the loader name ends in `UnsafeLoader` or `FullLoader` | CWE-502 | **Experimental** |

Rules only emit `needs_validation` findings. Severity, confidence, CWE, ASVS mapping,
and remediation are triage metadata rather than proof of exploitability. There is no
interprocedural or data-flow analysis.

## Known blind spots and unsupported constructs

- Import aliases (`import subprocess as sp`), imported functions (`from os import
  system`), assignments, wrappers, decorators, factories, dynamic attribute access,
  and reflection are not resolved.
- Keyword values must be literal AST constants. Variables, environment/configuration
  values, `**kwargs`, and expressions that evaluate to `True` or `False` are missed.
- PY001 does not report subprocess calls without `shell=True`, even when an argument
  invokes a shell explicitly; it also does not trace untrusted command data.
- PY002 does not cover sessions/clients, `requests.request`, HTTPX verbs other than
  GET/POST, TLS context configuration, warning suppression, or verification disabled
  outside the call.
- PY003 does not cover omitted/default loaders, positional loader arguments,
  `CLoader` variants, constructors registered on a safe loader, other serializers,
  or attacker control of the input.
- Scope and name binding are not resolved. A local object named `requests`, `yaml`,
  `os`, or `subprocess` can match even when it is not the expected library.
- Comments, strings, configuration files, dependency metadata, native extensions,
  vendored binaries, notebooks, templates, and every non-Python language are not
  security-analyzed.
- Syntax or decoding failures are counted but otherwise skipped. Analysts must review
  coverage counters before interpreting an empty findings list.
- Symlink-based repository layouts cannot be submitted because archive links are
  forbidden. Ignored files and repository history are not available in an exported
  source archive unless the submitter includes them as ordinary files.

## Archive and repository constraints

Repository imports inherit the validation contract in `backend/core/archive.py`:

| Constraint | Accepted limit/behavior |
| --- | --- |
| Container formats | Valid ZIP or TAR archives recognized by Python's standard libraries. Other formats are rejected. |
| Compressed upload size | At most 250 MiB when the uploaded stream exposes its size. The API upload path does. |
| Extracted regular-file bytes | At most 1 GiB in total. |
| Archive entries | At most 50,000 entries, including directories and non-regular TAR entries. |
| Individual regular file | At most 10 MiB. |
| Path depth | At most 20 path components. |
| Paths | Relative POSIX paths only. NULs, backslashes, parent traversal, absolute paths, and a colon in the first component are rejected. |
| Links and special files | ZIP symbolic links and TAR symbolic links, hard links, devices, and FIFOs are rejected. Other non-file TAR entries count toward the entry limit but are omitted from the file manifest and extraction. |
| Repository model | One archive snapshot only: no Git history, branches, submodule checkout, Git LFS resolution, dependency installation, build, macro/template expansion, or network retrieval. |

Archive acceptance is not analysis coverage. Regular files within the archive that
are not supported UTF-8 `.py` inputs increase `unsupported_files` or
`parse_failures`; they are not inspected by a rule.

## Analyst acceptance for the pilot

Before relying on a scan, an analyst must confirm the pack/version is
`python-stdlib`/`1.0`, review all three coverage counters, record unsupported or
failed files, validate every finding against source context, and document manual
review for relevant blind spots. See the [analyst workflow](analyst-workflow.md).
