# Experimental captured-source investigator — unreleased 0.1.16

Review selected project/support instructions with a locally operated model,
without giving it shell commands, arbitrary paths, uploads or permission to
redefine the mission. Ordinary AZT scanning needs no model or Docker.

**Live-model validation is blocked:** no already-prepared, confirmed local-only
Ollama service is assigned on an authorized native-Linux environment. The code and
scripted transport tests do not establish actual model utility. Do not install a
model or run this profile on a personal machine just to reproduce a synthetic test.

## What runs where

```text
Operator registration -> safe intake -> frozen sources and static review
                                     |
                     trusted controller + broker + private evidence
                       |                              |
               fixed local Ollama transport    launch-owned bounded pipes
                       |                              |
              trusted inference service       Docker: fixed planner loop
              numeric host loopback only       UID 65532, network none
Independent host supervisor ------------------> exact-container stop/lease
```

Docker supplies worker isolation. AZT freezes sources, checks proposals, validates
citations and records outcomes. Kernel, daemon, image, controller, supervisor,
evaluator, operator **and inference service** are trusted. Inference runs outside
the worker container; its resource policy and cloud-disabled configuration must
be established by its operator, not inferred from a localhost address/model name.

The controller permits only GET `/api/version`, GET `/api/tags`, POST `/api/chat`
to one selected numeric `127.0.0.1` port. No DNS, redirects, environment proxies,
authorization headers, model pulls, cookies or generic HTTP tool exists. The
service-reported model digest is checked at preparation, not authenticated or
continuously protected against tag remapping. Check the service configuration
and logs using [Ollama's local-only instructions](https://docs.ollama.com/faq#how-do-i-disable-ollama-cloud-features).
AZT changes no settings. The [chat API](https://docs.ollama.com/api/chat) and
[tool protocol](https://docs.ollama.com/capabilities/tool-calling) use stdlib HTTP,
without an SDK. The model cannot choose endpoint, model, headers, tools or budgets.

## Optional use after the prerequisite is satisfied

Keep tooling, registration, inference configuration and reports outside source
roots. Install a reviewed locally built 0.1.16 wheel; it is not claimed available
on PyPI. Native Linux/Docker prerequisites are those of [Protected Research](protected-research.md),
including an immutable preloaded Official Python image. There is no implicit pull
or uncontained fallback. Use operator-owned, non-group/world-writable configuration:

```json
{
  "schema": "azt.ollama-local.v1",
  "endpoint": "http://127.0.0.1:11434",
  "model": "YOUR_ALREADY_PREPARED_LOCAL_MODEL",
  "model_sha256": "REPLACE_WITH_THE_64_HEX_MODEL_DIGEST",
  "cloud_disabled": true,
  "verification": "operator-checked-service-config-and-log"
}
```

The confirmation records operator inspection, **not AZT enforcement of server
egress**. Do not copy it before actually checking. Tool calling and the configured
context envelope must be supported by the selected model.

```sh
# Absolute paths, same external environment/report setup as protected-research.md.
"$AZT_ENV/bin/python" -I -m azt research review \
  --manifest "$AZT_SOURCE/examples/protected-research/investigator/sources.json" \
  --root "captures=$AZT_SOURCE/examples/protected-research/investigator/captures" \
  --output "$AZT_REPORTS/static review.json"
"$AZT_ENV/bin/python" -I -m azt research investigate \
  --manifest "$AZT_SOURCE/examples/protected-research/investigator/sources.json" \
  --root "captures=$AZT_SOURCE/examples/protected-research/investigator/captures" \
  --inference-config "/absolute/operator path/local inference.json" \
  --image "$IMAGE" --output "$AZT_REPORTS/new investigator run"
```

The slot must be new. `review.html` is the local interpretation review;
`source-review.html` retains separate static findings. `report.json` records
controller decisions, identities, coverage, hypotheses and runtime status.
`pending-case.json` is a local untrusted candidate, not standing permission or a
rule/memory update. Reports may contain sensitive prose/paths; readable derivatives
omit quotes, but private structured hypotheses retain them. No report is uploaded.
Delete exact completed run directories under your retention policy. Interrupted
or missing output is incomplete, not evidence that nothing happened.

Exit 0 means workflow completion, **not truth or approval**. Exit 2 includes
blocked prerequisites, incomplete coverage, inference/output/cleanup failure.
The ordinary scanner's severity/threshold/exits are unchanged. The original
reference worker keeps its model-free short lease; `investigate` selects a
different explicit profile.

## Bounded proposals and evidence meanings

The planner forwards `read`, `check`, `observe`, `hypothesis`, `review`. Every
proposal, including each parallel call, is checked serially. Unknown tools and
extra authority fields are rejected even on benign input. Denials consume budgets
without necessarily stopping independent permitted work. Replays cannot execute
changed parameters. Sources, saved peer roles and model output remain data.

`observe` still requires an existing static rule/line. `hypothesis` requires a
bounded claim, uncertainty, maintained next-step category and 1–4 source references.
Digests, locations and supplied exact quotes are checked against frozen text;
cited pages must enter a successful inference request/response cycle. Linkage is
**not factual truth, intent or permission**. Free-form final prose is not accepted
as a review. Completion requires all pages/checks and at least one cited
interpretation. A model refusing everything fails the task, even if no tool runs.

| Bound | Investigator profile |
|---|---|
| Preparation | 60 seconds without worker authority |
| Active lease | 120 seconds; independent supervisor armed before start |
| Inference | 24 turns, 96 proposals, 4 per reply, no transport retry |
| HTTP | 10 seconds/call, 64 KiB response; no redirects/compression |
| Context | 16 KiB serialized request, including tools/history; no silent local truncation |
| Generation | Temperature 0, `num_predict=1024`, `num_ctx=32768`, `think=false` |
| Sources | Existing 64 KiB documents / 8 KiB pages / 1 MiB capture total |
| Hypotheses | 16; claim/uncertainty ≤500 characters; ≤4 references each |
| Worker | Existing unprivileged, no-network, read-only, CPU/memory/PID/storage bounds |

Capture size, page size and context size differ. A large source can scan completely
but exceed model context: the run fails/incompletes rather than silently dropping
text. Page coverage stays visible. Token accounting is server-reported, not proof
of correct tokenization or no server truncation. Hidden reasoning is neither
requested nor retained. Worker stop/revocation does not prove server-side inference
stopped; its cancellation is explicitly unverified. Late responses cannot restore
tool authority.

## Verification and contribution

The [synthetic sources](../examples/protected-research/investigator/sources.json)
and [frozen rubric](../examples/protected-research/investigator/expected-v1.json)
cover limited diagnostics, broad disclosure, distractors and fake peer approval.
Contract tests add novel hypotheses, fabricated citations, malicious next steps,
unread pages, expiry/replay, limits and safe output. All are disclosed development
cases, not held-out or third-party validation.

[Actual verification](../evidence/controlled-investigator/README.md) records four
passed isolated-planner/scripted-HTTP cases and the separate 13-case reference
regression run at the exact code/artifacts. It does not fill the live-model gap.

```sh
python3 -m unittest discover -s tests -p 'test_investigator.py' -v
```

Mac loopback restrictions can skip three HTTP tests; those are not transport
successes. The separate exact-SHA Linux maintainer job exercises the installed
planner/CLI, a finite test-owned HTTP service, invalid inference, controller death
and the longer lease. Scripted responses test protocol behavior, not a model.
The automatic rubric checks exact quote/citation coverage and workflow completion;
human review must assess interpretation accuracy and usefulness. Reference-profile
regressions remain separate; FS-001 is not rerun or relabeled.

Submit inert synthetic contrasts, not real keys, dumps or private submissions.
Live validation needs an already-prepared local-only Ollama service on authorized
native Linux, verified configuration/logs, exact model name/digest and finite
synthetic sessions. No weights, daemon installation or cloud access is implicit.
The [future collector boundary](protected-research.md#next-collector-boundary--not-implemented)
remains unimplemented; this profile never silently fetches websites.
