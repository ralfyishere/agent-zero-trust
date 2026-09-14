# Threat model

AZT's current purpose is repository intake before a developer gives a coding
agent access to unfamiliar content. Its output supports review; it does not
turn that repository into a safe execution environment.

An attacker may control repository files, configuration, names, symlinks,
ignore requests and instructions. The attacker may attempt to conceal findings,
supply malformed inputs, forge admission state or change the tree after a scan.
The scanner treats that content as data and does not execute repository setup
scripts, hooks or fixture commands.

## Trusted components and authority

For static intake, the operator, Python runtime, AZT installation and host
filesystem/kernel are trusted. The operator chooses the root, threshold and
any explicit external policy. A command-line flag is not evidence of a human
approval: an already-running agent can invoke the same command.

Target `.azt-ignore` content is visible as a request and has no suppression
authority. Trusted exceptions must name an exact rule, canonical relative path,
reviewed content hash and reason. They cannot use wildcards. Explicit exclusions
remove exact paths from scope and remain visible. Built-in dependency/VCS/build
exclusions are also part of the declared scope.

Policy is required to reside outside the workspace and meet file ownership,
link and write-permission checks. These checks reject several accidental or
target-file substitutions. They do not isolate policy from arbitrary code
running as the same operator. Do not pass authority through repository text.

## What intake establishes

The report records a bounded inventory, pattern and selected configuration
analyses, a content manifest, policy provenance and incomplete-inspection reasons.
Complete means complete within that declared scope, not complete understanding
of repository intent. Unsupported content can be hashed without being analyzed.

Regular inputs are opened relative to directory descriptors without following
symlinks. Special files are rejected; byte, entry, depth, line and finding limits
bound work. Files changed during reads are reported. Admission repeats the scan
and compares reports before issuing evidence.

These measures do not create an atomic filesystem snapshot. A hostile writer
can race checks, and files may change immediately afterward. Intake should run
on a quiescent tree. Nothing prevents later code from reading a secret, opening
a socket, modifying a file or creating descendants.

Raw excerpts and arbitrary config commands are omitted from findings. Reports
still contain paths and operator-supplied reasons; protect exports accordingly.

## Four different receipt properties

| Property | Current mechanism and assumption |
| --- | --- |
| Content binding | SHA-256 manifest plus workspace identity, scope, scanner source/version, policy and threshold bindings |
| Authenticated issuance | HMAC-SHA256 over the receipt using a random private issuer key |
| Freshness | Authenticated issue/expiry times checked against the trusted host clock; maximum lifetime 24 hours |
| Authority isolation | Not established against same-user hostile code; external private state is a workflow safeguard |

The HMAC key and receipts reside in an operator-owned mode-0700 directory
outside the workspace; private state files require mode 0600. A hash alone
is not a signature. HMAC verifies possession of the secret key; it is not
publicly verifiable signing or independent human authorization.

The host clock is trusted. Receipt deletion, replacement by an actor with the
key, host compromise and post-check changes are outside the authenticity claim.
This is not an append-only audit log and does not establish event completeness.

## Optional hook and edit lifecycle

The hook calls the local scanner to compare the current tree against the
admitted snapshot. The generated configuration covers Bash, Write, Edit and
NotebookEdit. Local installation and command behavior are tested; live coding-agent
application integration is not verified. The hook cannot constrain tools outside
its matcher, external processes or an application that does not honor it.

Install and admit from an operator terminal before starting the agent.
An ordinary in-scope edit invalidates the receipt. Review the changed tree and
re-admit from that terminal using the same state directory, policy and threshold.
A receipt describes an admitted snapshot; it does not approve all future changes.

The generated command maps failures to the blocking exit code and gives gate
inspection a shorter deadline than its configured hook timeout. Other user-level
settings can disable hooks; the current installer rejects known project/local
`disableAllHooks` settings but cannot establish the application's entire effective
configuration. Same-user code can change the hook, policy or key.

Legacy plain-JSON pass markers are rejected. Earlier claims of a signed legacy
marker were incorrect; [SECURITY.md](../SECURITY.md) records the correction.

## Outside current claims

Natural-language manipulation, split instructions, unknown patterns, dynamically
fetched content and unsupported-format semantics remain limitations. AZT does
not solve prompt injection, alignment or general agent safety. It does not replace
a dedicated secrets scanner or inspect all installed agent tools.

No runtime launcher is implemented. Network denial, filesystem isolation,
resource limits, descendant shutdown, credential brokering and cross-session
isolation are not delivered protections. [Runtime design and acceptance](runtime.md)
names the additional trusted kernel/backend/supervisor components and tests
required before making those claims.

Related projects have separate roles: rules-with-receipts addresses operating
discipline, rulebench behavioral testing, and agent-failure-modes failure taxonomy.
Rules or semantic judgments must never become the root of execution authority.
