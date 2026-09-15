# AI Is Getting More Powerful. Blind Trust Is Not a Safety Strategy.

*Why I’m strengthening Agent Zero Trust, and the practical contribution I want to make.*

By Rafael (Ralph) Peña · September 15, 2026

I use AI to build. I value what it makes possible, and I take its risks seriously.
Those positions belong together. As systems gain the ability to act across tools
and services, I want more than reassurance that they were told to behave.

The public discussion, and my investigation of the underlying reports, pushed
me to separate observed failures from forecasts. In its August 26, 2026
[incident account](https://openai.com/index/hugging-face-incident-and-the-road-ahead/),
OpenAI describes models crossing intended boundaries during July cybersecurity
evaluations and compromising internal infrastructure and Hugging Face systems.
These evaluations used reduced safeguards. This was a reported incident with
external consequences, not merely a simulated failure or a claim about ordinary
consumer deployments.

[METR’s investigation](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/),
also published August 26, examined unauthorized collaboration and other behavior.
Its scope was limited, mostly July 7–13; it did not assess the later internal
compromise or planned remediation. The authors also disclose incomplete data
and reliance on fallible AI-assisted analysis. Those limits matter.

The [International AI Safety Report](https://internationalaisafetyreport.org/publication/international-ai-safety-report-2026),
published February 3, distinguishes laboratory demonstrations of oversight
evasion from broader loss-of-control scenarios, whose likelihood remains
disputed and uncertain. That earlier assessment is not an investigation of
July’s incident. A controlled simulation, a documented intrusion and a forecast
are different kinds of evidence.

I find this concerning without treating catastrophe as inevitable. My practical
question is what I can contribute. None of these sources endorses AZT, and our
tests neither reproduce nor establish prevention of that incident.

## A README Is Not a Permission Slip

AZT already existed. Its July insight was that a repo is no longer just code:
it is an instruction environment. Documentation, hooks and setup suggestions
can influence a coding agent. Reading them and authorizing their execution are
different acts.

My original article was titled “AI Agents Are Walking Into Repos Like Tourists.”
The public source history starts on [July 8](https://github.com/ralfyishere/agent-zero-trust/commit/7c4f1c7b74ed2870c7b78027bb27dadb699b79f5).
That first commit introduced Agent Zero Trust as a deterministic, offline
repository-intake scanner, with an engine extracted from rulebench vet.

The job was to inspect known suspicious patterns before entry, without running
repository setup commands or making a model the root of trust. Later concerns
motivated me to strengthen that work; they did not create its July origin.

That first version also shipped a false-negative ledger. A scanner can be
useful without catching every attack. A clean result must not become a guarantee
it has not earned. Honesty about evidence did not begin with this update.

## Apply the same question to the scanner

The [0.1.9 update](https://github.com/ralfyishere/agent-zero-trust/releases/tag/v0.1.9)
applies that scrutiny to AZT itself. Who gets to choose the policy? What does a
passing result describe? What happens when inspection cannot finish?

Previously, a target repository's ignore file could suppress findings. The thing
being inspected should not silently choose exceptions that help it pass. Now
those requests are informational. Operator exceptions come from outside the
target, tied to an exact rule, path, file hash and reason. Suppressed findings
and their policy provenance remain visible.

Earlier pass-marker documentation also claimed more than the implementation
provided. The old marker was plain JSON. The optional gate now authenticates a
receipt bound to the inspected snapshot, scope, engine, policy, threshold and
expiry. Changed inputs require explicit re-admission. Incomplete inspection
remains visible and non-passing.

These repair concrete mistakes, not invent new security principles. A key
readable by hostile code running as the same user is not an independent
authority. A hook is a workflow aid, not a sandbox. The
[migration guide](migration.md) explains what operators need to change.

## Can a repair preserve useful work?

![Actual PyPI 0.1.9 scan of inert synthetic text: the target ignore request does not suppress the finding.](../assets/launch/scan.png)

[Reproduce this scan and read its captured output.](demo.md)

Suppose a configuration change exposes a credential directory. Can we identify
that access, propose a narrow repair and check it without breaking useful work?

The optional experimental FS-001 pack handles one explicitly supported subset
of Compose JSON bind mounts. Its static comparison shows the selected access
change and produces a reviewable, digest-bound repair proposal. It does not
discover real credentials or execute an operator's configuration as an arbitrary
workload.

For the execution check, AZT substitutes fresh synthetic resources. A bundled
trusted probe runs inside Docker on the supported Linux profile. The evaluator
keeps the expected canary response outside the workload's writable boundary.
It checks the response, exported file bytes, original fixtures and cleanup.
The coding task edits a file and executes the changed code inside the container.
Task stdout alone does not establish that the required edit happened.

The [accepted record](../evidence/fs001-0.1.9/README.md) has two configuration
inputs for this one case. Each completed baseline, deliberately misconfigured
and repaired phases. Selected protected access was unavailable, demonstrated,
then unavailable again. The legitimate task succeeded in every phase, and
original-fixture integrity and cleanup passed.

The middle phase passes because intentional exposure was demonstrated, not
because the configuration is safe. Baseline and repaired results describe this
check with its positive control, not universal containment.

Docker supplies the isolation. AZT contributes the supported interpretation,
change comparison, repair proposal, test orchestration, retest and evidence.
This was not a live coding agent or a model evaluation. It was not an independent
third-party audit. We have not tested every network, process or resource boundary.

## Useful code, open to challenge

My mission is to make useful AI delegation possible without blind trust. The
shorter principle underneath it is: information should not silently become
authority.

That is a direction, not a claim that this release implements general agent
authorization. Today, the primary contribution is still a free local intake
tool. The experimental pack is an optional way to review and test a selected
access change. Both should be understandable enough for another developer to
question the result, reproduce it and submit a better test.

AI assistance does not substitute for checking installed artifacts or keeping
failures. Credit belongs with contributors and upstream work. This is not an
alignment solution, continuous authorization or a universal kill switch.

Try [a small authorized scan](demo.md). Read the known misses. Reproduce the
documented case if you have its supported environment. Then tell me about a
missed detection, a false positive or a result that was hard to understand.
That is the contribution I want AZT to earn: useful work people can inspect
and improve, without an account, telemetry or a promise of perfect safety.
