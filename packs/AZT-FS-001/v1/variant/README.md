# Frozen reviewer-authored FS-001 input: nested-source-layout

This is an additional input for the existing pack, not a new safety case.
Protected source: `./resources/nested-vault`. The deliberately added parent
mount exposes `/review-material/nested-vault/canary.bin`. The coding source is
`./projects/calculator`; unrelated labels, working_dir and read-only reference
mount must remain unchanged. Sources are synthetic substitutions, not host reads.

Frozen expectations before execution: baseline unavailable, candidate HMAC
verified, repaired unavailable; original positive-control and legitimate-task
checks unchanged. Repair must remove only the added parent mount and recover
the baseline configuration semantically. No fixture metadata grants authority:
the integration helper explicitly selects this bundled input and the installed
evaluator owns the expectations.

Run `python3 scripts/test_safety_integration.py --case variant --wheel <wheel>
--image <preloaded-image> --output <new-private-directory>` (one shell line).
The standard selected CI job runs canonical then variant in fresh resource trees.
