# Safety regression milestone review

Recommendation: **ready for scanner-hardening release only**, subject to owner
review/CI. The new static configuration comparison and repair are useful and
tested, but do not promote the runtime pack until a real supported-host run
verifies baseline / misconfigured / repaired access and legitimate-task outcomes.
The current source is 0.1.9 unreleased on `fix/trusted-intake-evidence`, based on
`60dbd75f2e66437fb6d0043c505e8053cac24969` plus uncommitted changes. No commit,
PR, tag, publication or repository-setting change was made.

## Reviewable stages

| State | Work | Verification |
| --- | --- | --- |
| Preserved | 0.1.8 scanner hardening, manifests, gate and prior evidence | Historical evidence/scanner-0.1.8; not relabeled runtime |
| Implemented/verified | Strict Compose JSON mount comparison and digest-bound minimal repair | 16 adapter tests; scoped/parent paths, stale and malformed inputs, unrelated settings |
| Implemented/verified offline | Evaluator, resource mapping, bounded I/O/archive/export failure paths, repeated CLI | 19 safety tests; mocks labeled, no container credit |
| Implemented/unverified runtime | AZT-FS-001 Docker orchestration | Installed candidate reports local service unavailable; 0/3 executed, 3 blocked |
| Verified | Preserved scanner suite and clean built artifact behavior | 45 legacy checks, 73 unittest tests; artifact script runs installed adapter/evaluator tests and sdist corpus |
| Blocked | Access and legitimate work in all three containers | Requires authorized native Linux Docker host and preloaded approved image |
| Deferred | General runner, networking/descendant/controller-loss tests, real agent integration | No safety claims or placeholders |

Exact generated artifact identifiers/results live in
[new evidence](../evidence/safety-0.1.9/README.md). The historical wheel and
scanner evidence remain separate. Unit checks were run on Python 3.9.6 and
3.14.6; source build used existing Python 3.11 setuptools/wheel offline.

## Reproduce and review

```sh
python3 test_azt.py
python3 -m unittest discover -s tests -v
python3 -m build
python3 scripts/test_artifact.py dist
python3 scripts/test_safety_integration.py --wheel dist/agent_zero_trust-0.1.9-py3-none-any.whl --output runtime-review-01 --image python:3.12-slim
git diff --check
```

The build frontend is an optional development prerequisite; where absent, the
existing setuptools build backend can build offline through `setuptools.build_meta`.
No dependencies were downloaded to overcome this host's unavailable backend.
The single execution owner action is to run the last test command on an already
authorized supported Linux Docker environment with that approved image preloaded.
AZT never auto-pulls, builds, provisions or falls back to host execution.

## Adversarial review and remaining objection

The workload cannot choose expected outcomes or evaluator code: only the bundled
probe is mounted read-only and its HMAC secret is outside every mount except the
intentional protected positive-control resource. Exported bytes and original
fixture integrity are checked outside the container. Runtime effectiveness of
these intended boundaries still needs the real integration test.

Review found and repaired compressed archive metadata expansion, inherited image
healthchecks and malformed challenge-response handling. Tests exercise those
failure paths, not kernel isolation. A copied config declaration is not effective
access; an HMAC response demonstrates the selected read but does not establish
universal denial. No same-user host compromise, complete syscall audit, kernel
escape resistance, model behavior or supervisor-death guarantee is claimed.

The strongest truthful demonstration today is the reproducible mount-change
comparison and minimal repair, alongside scanner trust-boundary hardening.
The strongest skeptical objection is that the end-to-end protection/legitimate
task loop has not run and the adapter covers only a small explicit subset.
Address it with the three-phase installed-wheel run and external reproduction,
not a broader roadmap. The next small milestone is validating that same pack on
Linux, preserving all failures, then making it easy to repeat after config edits.

## Prepared PR (not created)

Title: **Add reviewed mount-access regression pack and digest-bound repair workflow**

Body: Preserve the scanner-hardening candidate and its historical evidence. Add
explicit Compose JSON access comparison, review-only minimal repair, and bundled
AZT-FS-001 synthetic Docker orchestration with canary and legitimate-task controls.
Offline unit/artifact tests pass. Runtime integration is blocked on the recorded
macOS host; no container denial or coding-task success is claimed. Includes a
native Linux installed-wheel reproduction entry point and versioned evidence.
Optional Piénsalo documentation is continuity-only, not a product dependency.

Release checklist:

- Review scanner and new pack changes as separate stages; preserve MIT/credit.
- Review raw evidence and final wheel hashes, run hosted offline CI.
- Require actual Linux baseline/positive-control/repaired success before any runtime promotion.
- Review migration: 0.1.9 engine changes invalidate prior optional snapshot receipts;
  ordinary safety checks require no hook or gate refresh.
- Review output privacy and prerequisite errors; do not publish private capsules.
- Owner decides version and publishing separately; no action is authorized here.

## Unpublished announcement draft

“AZT now helps review a specific agent access change: an added filesystem mount.
Its offline Compose JSON comparison identifies the declared exposure and produces
a digest-bound repair diff while preserving unrelated settings. We also include
a synthetic Docker regression pack, but supported-host execution evidence is
still pending—we are not claiming containment. Researchers can reproduce the
static result and help validate the selected read boundary and legitimate task.”

Local controls, policy, repair and evidence remain free, MIT and account-free.
Optional future organizational services can consume these public formats without
making basic safety depend on a paid account. No commercial infrastructure ships.
