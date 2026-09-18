# Captured-source research — optional and experimental

Review selected captured material without treating its instructions or claimed
roles as permission. The existing offline scanner remains the main product.
The [published 0.1.15 release](https://github.com/ralfyishere/agent-zero-trust/releases/tag/v0.1.15)
provides a local capture adapter and an optional fixed reference-worker experiment.
The unreleased **0.1.16 source candidate** adds the paging/preparation changes
identified below. Neither profile fetches websites or runs
a model, repository program, plugin, or live coding agent.

## Start without Docker

Install into an environment **outside** the selected inputs. Installation downloads
the published package; review/export operate offline. Use an explicitly reviewed
AZT checkout for the inert example files, not a target-selected installer.

```sh
# Use absolute paths; these examples deliberately accommodate spaces.
AZT_SOURCE="/absolute/path/to/reviewed AZT checkout"
AZT_ENV="/absolute/path/to/tools/azt research"
AZT_REPORTS="/absolute/path/to/private reports"
python3 -m venv "$AZT_ENV"
"$AZT_ENV/bin/python" -m pip --isolated install --index-url https://pypi.org/simple --no-deps agent-zero-trust==0.1.15
mkdir -m 700 "$AZT_REPORTS"
cd "$AZT_REPORTS"
"$AZT_ENV/bin/python" -I -m azt research review \
  --manifest "$AZT_SOURCE/examples/protected-research/sources.json" \
  --root "captures=$AZT_SOURCE/examples/protected-research/captures" \
  --output review.json
"$AZT_ENV/bin/python" -I -m azt research export \
  --input review.json --format html --output review.html
"$AZT_ENV/bin/python" -I -m azt research case \
  --input review.json --output pending-case.json
```

Open `review.html` locally. The limited diagnostic request has no finding. The
broad request names shell history and environment variables: MEDIUM review is
appropriate; it does not prove those materials contain credentials. The saved
peer message's claimed owner/system role grants no authority. Guidance comes
from AZT's maintained catalog, not from the suspect instruction.

To evaluate unreleased 0.1.16, install its locally built, reviewed wheel instead
of the published-package command above:
`"$AZT_ENV/bin/python" -m pip --isolated install --no-index --no-deps /absolute/path/to/agent_zero_trust-0.1.16-py3-none-any.whl`.
See [build verification](publication.md). A source merge is not publication.

`research review` exits **0 for completed inspection within its declared scope,
2 for incomplete/invalid work**. It is informational even when findings exist.
Nested scan records preserve the chosen `--fail-on` threshold and normal scan
0/1/2 meaning. Comparison and export do not issue admission. Existing commands
and scan thresholds are unchanged.

## Inputs and identities

The operator selects a registration file outside all input roots and supplies
explicit `--root ID=/absolute/path` mappings. Duplicate IDs, overlapping roots or
registrations, unsafe/encoded paths, symlinks, hardlinks and special files are
rejected. Nothing discovers your home directory or retrieves credential paths
mentioned by a source.

Each entry contains `id`, `kind`, `root`, relative `path`, and `method`:

| Kind | Method | Inspected material |
|---|---|---|
| `markdown` | `operator-supplied-text` | UTF-8 `.md`/`.mdc` |
| `text` | `operator-supplied-text` | UTF-8 `.txt` |
| `message` | `saved-message` | JSON object: schema `azt.saved-message.v1`, string `role`, string `content` |
| `repository` | `repository-snapshot` | Existing safe intake; relative directory or `.` |

Optional `sha256` binds captured file bytes (repository: existing input-manifest
digest). `origin` and `captured_at` may be unknown/null. They and message roles
are **claims**, hashed rather than copied into exports. A URL, role, timestamp
or matching digest does not authenticate a source. Hashes are not anonymization.

The [bundled registration schema](../azt_resources/research-sources-v1.schema.json)
is descriptive; stdlib validators enforce semantic/path relationships too. No
remote schema is loaded. Standalone documents are isolated text captures, not a
reconstructed conversation; repository registrations retain existing explicit
one-hop relationships, exclusions and unresolved support. No cross-registration
links are followed. No HTML/browser/PDF/OCR/JavaScript conversion is provided.

Standalone locations refer to logical `captured.md` text (message: lines in its
decoded `content`, not JSON serialization lines). The outer source record retains
the registered path and original byte hash; runtime mission document descriptors
map opaque channel IDs back to that registration and logical path.

Bounds: 64 KiB registration, 16 registrations including at most two repositories,
128 retained text documents, **64 KiB per document in the 0.1.16 candidate**
(published 0.1.15: 8 KiB), 1 MiB retained/attempted capture budget, 4 MiB
report/export. Saved JSON messages additionally allow at most 6 × 64 KiB + 512
serialized bytes for escaping; decoded UTF-8 content must still fit 64 KiB.
Repository intake also retains its existing
10,000-entry/32 MiB total-read budget **per repository**; at most two such scans
occur. JSON uses existing nesting/item/string bounds. Unsupported or oversized
sources are partial/omitted, never silently clean; other selected sources can
still be inspected. Read bytes are frozen before their analysis and mission use;
this does not claim an atomic whole-filesystem snapshot.

Candidate paging happens **after full admitted-byte inspection**, not before
detection. A `read` selects a registered source/hash and deterministic page index;
each result binds parent hash, segment hash/ID, zero-based half-open UTF-8 byte
offsets and one-based inclusive lines. Pages are at most 8 KiB and split only at
codepoint boundaries. They do not erase existing detector windows or join sources.
The worker checks every segment and the reconstructed parent digest. A complete
review needs all pages and checks, not just the first response. Replays consume
budgets and cannot substitute a different page under an old request ID.

## Optional protected reference worker

Requires native Linux, Docker Engine 25+, cgroup v2 with CPU/memory/swap/PID
controls, built-in seccomp, and an explicitly prepared **Docker Official Python
linux/amd64 image**. No implicit pull, daemon startup, permission change or
uncontained fallback exists. Docker Desktop on macOS is not this tested profile.

```sh
# IMAGE is the verified, already-present immutable sha256:<image-ID>.
"$AZT_ENV/bin/python" -I -m azt research run \
  --manifest "$AZT_SOURCE/examples/protected-research/sources.json" \
  --root "captures=$AZT_SOURCE/examples/protected-research/captures" \
  --image "$IMAGE" --output "$AZT_REPORTS/protected run"
```

The output must be a **new directory** outside the inputs. It is reserved before
launch and retained on failure: `inspection.json`, bounded `events.jsonl`, runtime
control/lease records, and, on completed collection, `report.json`, `summary.txt`
and `review.html`. Missing final output is incomplete, not evidence that nothing
happened. Export/case commands consume `inspection.json`, not arbitrary worker
or runtime logs. Keep the directory private; paths and hashes can be sensitive.
Delete a completed run's exact directory under your normal local retention rules;
there is no shared history, automatic upload, telemetry or standing memory.

```text
Operator registration + policy          Trusted controller / evaluator
           |                                       |
Safe intake -> frozen source bytes -> mission broker + private audit
                                           | launch-owned bounded pipes
                             Docker boundary: fixed unprivileged worker
                                           |
                       read IDs / checks / observation proposals / review
                                           X no shell, HTTP, upload or delegation
Separate-session host lease supervisor -> exact container removal on
controller-channel loss or finite monotonic deadline
```

The broker checks every request against the current mission/run, source hash,
lease/state and cumulative budget. Unknown operations, role/authority fields,
unknown sources, invalid evidence references and conflicting replay IDs fail.
Identical replay returns its prior bounded response without repeating effects;
denials and retries consume the candidate's 640-call/8 MiB channel budget
(0.1.15: 512 calls). The bounded maximum document/byte combination can need up to
256 page reads plus 128 checks and 128 observation proposals; 640 leaves finite
denial/control headroom, without raising response, storage or worker resources.
A fresh controller
creates new random mission/run identities and never resumes old authorization.
`read` returns frozen registered text; `check` returns the existing scan result;
`observe` accepts a bounded source-linked proposal, not factual truth; `review`
requires all registered text to have been read/checked and inspection complete.

The worker is deterministic bundled code, not an agent that must resist
persuasion. Test workers deliberately propose forbidden actions even for benign
text. A scanner finding is **not** needed for the broker to reject an upload.
Saved fake-boss messages and purported subordinate requests remain data.

Docker provides OS isolation; AZT adds registration, frozen mission handling,
the constrained protocol, lifecycle supervision and separate review evidence.
UID/GID 65532, no capabilities, no-new-privileges, network `none`, read-only root
and bundled worker, 8 MiB scratch, 4 MiB tmp, 1 MiB shm, 128 MiB memory+swap,
0.5 CPU, 16 PIDs, bounded files/FDs/output and finite lease are required.
No original target, controller store, host home, Docker socket, credentials or
shared cache is mounted. Sources arrive only through the controller channel.

The candidate broker starts in `preparing`, with **no worker authority** and a
separate cumulative 60-second preparation budget. Backend commands consume that
budget; audit failure, expiry or cancellation cannot activate the mission.
After preparation and supervisor readiness, the trusted controller activates the
broker against the supervisor's existing absolute deadline. There is no activation
or renewal operation in the worker protocol. Readiness/start overhead consumes
the maximum active lease; it does not silently create a second lease. Cleanup
retains its own bounded deadline even when preparation or authority has expired.

The independent supervisor is armed **before** start and has a maximum 30-second
lease (normal profile 20 seconds), followed by a bounded 5-second removal call.
Controller pipe loss initiates removal immediately. The harness tests an
eight-second controller-stop observation bound. This is not a universal timing
guarantee on a stalled or compromised host/daemon. Host kernel, Docker daemon,
approved image, supervisor, controller, evaluator, policy store and operator are
trusted. Killing/compromising that supervisor or host is outside this profile.

The candidate channel/policy are v2; use matching bundled worker/controller
versions. Existing `research-review.v1` exports remain readable with explicitly
recognized v1/v2 capture settings. No old event stream is reclassified as a new
activation or paging result. Snapshot-gate users must explicitly re-admit changed
engine inputs; research review never refreshes admission.

### Maintainer integration selection

After this workflow revision is merged, select a reviewed branch and its exact
full commit using the existing Actions workflow:

```sh
gh workflow run research.yml --repo ralfyishere/agent-zero-trust \
  --ref REVIEWED_BRANCH -f source_sha=FULL_REVIEWED_COMMIT
```

Only the named repository's maintainer can pass the workflow's actor/repository/
source selection checks. An incorrect SHA is not tested as if it were correct.
The [workflow](../.github/workflows/research.yml) is nonpublishing, has a 15-minute
ceiling, and runs only standard ephemeral Linux resources and synthetic fixtures.
It explicitly resolves then pulls one approved Official Python image by digest
using an empty registry configuration. The product itself never pulls an image.
Before that revision reaches main, the selected `feat/research-reliability`
bootstrap branch uses an explicitly marked `[azt-research-once]` push; ordinary
PR pushes do not run it. This temporary route exists because GitHub requires
`workflow_dispatch` on the default branch. Every selected run still needs operator
authorization/budget. A marker or actor name is not an independent permission
system, and a rerun is a new test decision. Never run these workers on a personal
host or route around an unavailable required control.

## Evidence and limits

[AZT-RESEARCH-001](../packs/AZT-RESEARCH-001/v1/README.md) distinguishes policy
tests, real backend tests and live-model tests (none). Required control failure,
audit failure, invalid worker output, cleanup failure or missing output cannot
produce a completed protected review. Audit is written before broker data release;
worker claims cannot append controller execution records. Observation is limited
to broker events and selected probes, not every syscall or covert channel.

The [final evidence index](../evidence/protected-research/README.md) records ten
passed native-Linux cases at the exact candidate source, including public-CLI
completion, controller death and paused-controller lease expiry. These results
do not establish a live-model or general hostile-program profile.

The [0.1.16 reliability evidence](../evidence/research-reliability/README.md)
separately records the v2 pack: 13 passed cases, including delayed preparation,
larger source paging and the unchanged stop/resource assertions. Its first failed
attempt remains visible. The exact tested source and new artifacts are recorded;
later documentation is not a new runtime experiment.

Raw controller records are not signed and are not independently authenticated.
The worker cannot access their store in this profile; the trusted host operator
can. Exported/redacted reports are derivatives, not original source bytes.
Pending cases never modify policy, detector rules, model weights or other missions.

Hidden/multimodal instructions, arbitrary multi-step persuasion, false consensus,
misleading human advice, reward/test gaming, poisoned updates and false attribution
are not comprehensively detected. Tool changes are not dynamically loaded.
Aggregate actions face cumulative call/byte limits; delayed work is bounded by
the lease. Historical FS-001 results remain a separate filesystem experiment.

## Next collector boundary — not implemented

Any later live-web profile needs an operator-approved source registry, site/rate
rules, bounded request semantics and decompression, validation of **every** redirect
and connection address, DNS-change handling, poisoned-metadata treatment and data
egress controls. A domain allowlist alone is not sufficient. SSRF, rebinding,
authenticated browsing and permitted-endpoint exfiltration remain future tests.
No captured-source command silently turns into live fetching. Live models also
need a separate explicit credential/egress/budget decision and behavior tests.

| Broader threat | Implemented check or explicit gap |
|---|---|
| Retrieval poisoning / fake owner or peer approval | Captured wording inspected; T2 rejects deliberately forbidden proposals regardless of detection; not a persuasion benchmark |
| Persistent poisoned summaries / false consensus | T4/T5 fresh mission and non-authoritative cases; no general consensus or factual-truth detector |
| Aggregate requests / delayed jobs | T4/T7 cumulative budgets; T6 finite lease/descendant stop; only the fixed protocol |
| Tool changes / poisoned updates | No dynamic tool loading; trusted installed code/image remains a supply-chain assumption |
| Hidden/multimodal instructions / multi-step persuasion | Existing text detectors only; media unsupported; live-model behavior not tested |
| SSRF / redirect / DNS rebinding | No network operation in broker; live collector requires separate implementation/testing |
| Authenticated browsing / permitted-endpoint exfiltration | No browser/account/model endpoint; not an implemented live-web protection |
| Misleading human advice / false attribution / test gaming | Maintained recommendations, claimed-origin labeling, evaluator outside worker; no general truth or intent proof |

Contribute a minimal synthetic source/registration or a finite reviewed test
worker plus legitimate control and external evaluator assertion. Never submit
real keys, environment dumps, shell history or private customer logs. Cases that
informed implementation are development cases, not held-out or third-party audits.
