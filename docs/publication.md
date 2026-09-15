# Publication review for 0.1.9

Repository intake remains primary. The optional FS-001 pack and its accepted
Docker/Linux evidence are unchanged by publication plumbing. This workflow does
not run FS-001, test a model, or extend the product's security claims.

## Non-publishing validation

Open a PR changing the publishing workflow, release helper/test, this document,
or MANIFEST.in. The existing `publish.yml` runs `build` and `verify-transfer`.
Its `publish` job requires a release.published event on a v-prefixed tag: a PR
or manual build cannot request the pypi environment or its OIDC credentials.
PR builds record GitHub's synthetic merge SHA, not merely the PR head.

To reproduce locally from a clean checkout with Python 3.11 and the explicitly
prepared optional tools setuptools==83.0.0, wheel==0.47.0, packaging==26.0:

```sh
python3.11 scripts/release_candidate.py --output /tmp/azt-release-review-NEW
```

Choose a new output directory outside the checkout. After tool preparation this
command is offline. It builds one wheel and one sdist, then runs:

```sh
python3.11 test_azt.py
python3.11 -m unittest discover -s tests -v
python3.11 scripts/test_artifact.py /tmp/azt-release-review-NEW/dist
```

The last script tests the installed wheel from an isolated environment and the
extracted sdist, including CLI exits/JSON and the existing adapter/evaluator
tests. These are artifact and offline regression checks, not new runtime trials.
A failure emits no verified release manifest and prevents transfer/publication.

## Actual release checkpoint — owner action, not part of PR validation

1. Review and merge the separate safeguards PR. Confirm the intended source SHA
   and that relevant runtime/probe/evaluator bytes still match accepted evidence.
   Do not reuse the old runtime wheel's hash for a new build.
2. Confirm the *current PyPI account configuration* identifies Trusted Publisher
   owner `ralfyishere`, repository `agent-zero-trust`, workflow `publish.yml`,
   environment `pypi`. GitHub workflow comments cannot verify PyPI settings.
3. Separately authorize and create the release tag `v0.1.9` at the chosen source,
   then publish the GitHub Release only when ready to initiate the gated workflow.
   No tag or publication is created by the helper or PR validation.
4. The build explicitly checks out the event SHA; the helper requires a clean
   tracked source, matching package version and tag resolved to that exact commit.
   It builds/tests once and writes `release-manifest.json` **outside dist**.
   The run summary displays the source, tag, run and new wheel/sdist hashes before
   environment approval. Review the manifest's actual tests and these identities.
5. Only the owner decides whether to approve the pypi deployment for that exact
   source/run/artifact set. The environment should require `ralfyishere`, allow
   solo-maintainer self-review, disallow admin bypass, and allow only **tag** refs
   matching `v*` (no branch rules). Read settings back; a name is not protection.
6. After approval the publisher downloads the same run's distributions, checks
   source/run/tag/test record, filenames, lengths and hashes, then uploads those
   bytes without rebuilding. It has no source checkout, package tests, or
   repository helper execution. Its fixed inline verifier only reads bounded data.

The credential-free transfer job runs the same fixed verifier first. The
publisher's duplicate is intentional and parity/negative cases are tested.
Only the wheel, sdist and manifest are transferred, retained for seven days.
Save the reviewed manifest and artifact identities before retention expires;
a later build is a new artifact set even if its version matches.

## Trust and maintenance limits

Checksums identify bytes and detect transfer changes against this record. They
are not independent proof of a trustworthy build, reviewer independence, or
runtime safety. GitHub, the runner, reviewed workflow/source, build tools and
upstream actions remain trusted. An account capable of editing these controls
is not independently constrained by a same-account approval rule. No deployment
approval is performed by AZT or the assistant.

Actions are pinned to commits resolved from official upstream tags. For updates,
review the upstream changes and resolve the full commit again (annotated tags
must be dereferenced); change the version comment and rerun non-publishing tests.
Pinned top-level actions are not a claim of a hermetic or transitively pinned
build. Existing build dependency families and the standard public Ubuntu runner
are used; no cache, paid service, new secret or model call is required.

References: [GitHub release events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#release),
[environment protections](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments),
[PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/adding-a-publisher/),
[PyPI publishing action](https://github.com/pypa/gh-action-pypi-publish).
