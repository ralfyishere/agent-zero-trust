# AZT-RESEARCH-001/v2 — reliability candidate

This revision retains all ten [v1 assertions](../v1/expectations.json) and adds
three [frozen development cases](expectations.json): large paged captures,
delayed preparation followed by a useful real run, and expired preparation with
no launch. The latter is a controller precondition, **not an OS denial**.
No live model participates. Existing runtime limits, matched synthetic controls
and external cleanup requirements are unchanged.

Install the reviewed wheel in an environment outside the test inputs. On the
supported disposable native-Linux host with an explicitly prepared immutable
Official Python image, use the existing entry point:

```sh
"$AZT_ENV/bin/python" -I scripts/test_research_integration.py \
  --image "$AZT_RESEARCH_IMAGE" --output /absolute/new/private/evidence
```

Or select the [maintainer workflow](../../../docs/protected-research.md#maintainer-integration-selection).
The script never pulls an image. Do not run its adversarial workers directly on
a host. Docker, host/kernel, supervisor, controller and evaluator remain trusted.
Source/code/worker/evaluator hashes, artifact identities and selected outcomes
must accompany a claimed result; these expectations alone establish no result.

The paging fixture is authored by the maintainer implementation process, freezes
its inputs before evaluation and is not independent or held-out validation.
The legacy evidence remains evidence for its exact original version only.
