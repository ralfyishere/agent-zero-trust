# Coverage and known limitations

`azt safety` is separate from the corpus score. It parses the explicit
[AZT-FS-001 Compose JSON subset](packs/AZT-FS-001/v1/README.md) and compares
selected bind access. Inventoried agent formats do not thereby become supported
runtime configurations. Adapter/evaluator regressions are offline tests;
container evidence is indexed separately in [evidence](evidence/README.md). It
tests the selected directory/canary, not arbitrary child secrets or every channel. Existing benign
fixtures and the known-miss ledger below are unchanged.

This ledger describes what the current scanner tests, without claiming that
its corpus represents every attack. Regenerate the checks with:

```sh
python3 test_azt.py
python3 -m unittest discover -s tests -v
```

An inventoried file is not necessarily structurally analyzed. The report's
`scope.inspected[].analyses` records the analyses actually run.
[Format coverage](docs/supported-agent-files.md) distinguishes these cases.

## Fixture-backed detections

| Surface | Rules and evidence |
| --- | --- |
| Hidden and agent-directed instructions | `stealth.html_comment_imperative`, `inject.instruction_override`, `inject.concealment`, `inject.agent_directed`, `exec.always_run`: malicious-markdown corpus |
| Hidden Unicode | `stealth.hidden_unicode`: hidden-text corpus |
| Download and execution | `net.pipe_shell`: malicious-markdown, suspicious-install and hook-trap corpus |
| Data sent through a shell pipe | `exfil.pipe_out`: suspicious-install corpus |
| Credential shapes | `secret.token_shape`, `secret.private_key`: synthetic hidden-text corpus |
| MCP declarations | `mcp.server`: mcp-injection corpus; configuration path regression tests |
| Claude hooks and permissions | `hooks.claude`: hook-trap corpus; `perm.auto_approve`: unit tests |
| VS Code folder-open tasks | `auto.vscode_folderopen`: hook-trap corpus |
| Package lifecycle scripts | `pkg.lifecycle`: suspicious-install corpus |
| Selected CI checkout pattern | `ci.prt_checkout`: textual workflow unit tests |
| Escaping symlinks | `fs.symlink_escape`: file/directory link regressions; all encountered symlinks make inspection incomplete |

The rule definitions in `azt.py` include additional patterns. Presence of a
rule is not proof of comprehensive coverage for that attack class. The benign
corpus is retained and checked for zero MEDIUM-or-higher findings.

## Known misses

- **Natural-language social engineering.** The fixture in
  `corpus/misses/social-engineering.md` asks for sensitive diagnostic material
  without a recognized trigger shape. The corpus asserts no HIGH detection.
- **Instructions split across files.** The two `split-instructions` fixtures
  each appear innocuous alone. AZT does not reconstruct cross-file intent.
- **DNS execution inside a Markdown table.** A table-wrapped DNS TXT command
  piped to a shell can evade `net.dns_exec`. That rule is suppressed on
  table-looking lines because its broad pipe pattern also matches benign
  table separators. The separate pipe-to-shell and outbound-data rules do
  not use this table suppression. This is an unresolved detection limitation.
- **Selected formats receive text analysis only.** Devcontainer lifecycle
  fields and GitHub workflow semantics are not comprehensively parsed.
  Malformed YAML or JSON in a format without a JSON structural scanner is
  not guaranteed to be recognized as invalid configuration.
- **Content outside the inspected scope.** Runtime downloads, binary/image
  meaning, unsupported file extensions, ignored dependency trees and changes
  after inspection are not semantically analyzed. Hashed-only files have
  content binding without content analysis.

Known misses are not success cases or proof that an attack will work against
a particular agent. If a change catches a corpus miss, preserve its history,
move it into detection coverage and update the ledger and assertions together.

## Intake and admission regressions

The separate intake suite covers target wildcard suppression, explicit scoped
exceptions, stale exception hashes, malformed and ambiguous policy paths,
HMAC forgery, expiry/future dates, workspace replay, changed content and scope,
policy/threshold/engine changes, unsafe state paths, hook setup and re-admission.

It also tests malformed supported configurations, invalid encodings, work
limits, FIFOs, symlink handling, read failures, structural failures and JSON
output. These verify the intake boundary. They do not establish runtime
filesystem, network or descendant-process isolation.

## Scope and resource limits

Current limits are 1,000,000 bytes per file, 32,000,000 bytes read per scan,
10,000 directory entries, 64 directory/JSON nesting levels, 4,096 characters
per analyzed line and 10,000 findings. Exceeding relevant limits makes the scan
incomplete, not clean. The scan report lists effective limits and exclusions.

Built-in dependency/VCS/build directories are deliberate scope exclusions,
not exhaustive descriptions of what an agent may later access. External policy
may explicitly exclude an exact file or directory with a reason; such content
is outside analysis and content binding. Symlinks are never followed.
Unsupported extensions are ordinarily hashed only, and do not by themselves
make inspection incomplete. UTF-8 is required for analyzed text.

Scanning is sequential, not an atomic filesystem snapshot. Descriptor-relative
opens and repeated admission reads reduce particular races; they do not freeze
a hostile concurrent writer. Keep the tree quiescent during intake.

## Runtime evidence

FS-001 has a recorded synthetic Docker/Linux result for two configuration inputs
with three phases each, including legitimate-task and cleanup checks. See the
[exact accepted record](evidence/fs001-0.1.9/README.md). This is one selected
filesystem case, not six attack classes or a live-agent evaluation.

The separate intake ContainmentBench still has eight runtime scenarios not run.
Doctor tests validate prerequisite reporting for a deferred general runtime
proposal, including mocked Linux branches; they do not add execution evidence.
There is no universal safety percentage. See [runtime status](docs/runtime.md).
