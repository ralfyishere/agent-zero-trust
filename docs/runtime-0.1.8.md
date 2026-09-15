# Historical 0.1.8 runtime proposal — superseded for the bounded pack

This records the previous unreleased milestone, not current backend selection.
See [current runtime status](runtime.md). The bubblewrap proposal below was
never a launcher or runtime evidence; the next bounded pack uses Docker.

The offline scanner works independently. AZT does **not** ship a workload
launcher or claim an execution boundary in this milestone. `azt doctor --json`
reports prerequisites and exits 2: unsupported platform, missing dependency,
missing control, or integration unverified. Even all prerequisites present is
not proof of containment. It executes no discovered binaries, queries no
container daemon, and reports no backend version it has not observed.

The development host was macOS (Darwin). Linux namespace and cgroup integration
could not be exercised there. A Docker client was present; no Linux host was
provided or provisioned and no unrelated daemon state was inspected. The runtime
tests exercise diagnostic branches, including mocked Linux prerequisites. They
are **not** isolation tests. There are zero completed runtime boundary trials.

## Backend decision and current sources

The next implementation targets Linux with bubblewrap for namespace isolation
and systemd/cgroup v2 for resource and session lifecycle control. Bubblewrap
creates an initially empty mount namespace and supports separate process and
network namespaces. Its upstream maintainers explicitly make the caller
responsible for choosing a secure policy. Merely launching bubblewrap is not a
complete security design. [Upstream security model](https://github.com/containers/bubblewrap)

The [bubblewrap option reference](https://github.com/containers/bubblewrap/blob/main/bwrap.xml)
documents explicit namespace options, environment clearing, a new session, and
parent-death handling. The eventual profile must require needed namespaces;
`--unshare-all` includes optional `-try` behavior and alone does not establish
every required namespace. These are reviewed interfaces, not an AZT-tested
launch recipe.

The [Linux cgroup v2 documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
defines CPU, memory and process controls and delegation. Doctor only reads the
root controller names: it does not establish that the current user can create a
delegated cgroup or enforce a limit. A usable supervisor and actual effective
limits need integration tests.

Existing [Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing) and
the [Anthropic engineering description](https://www.anthropic.com/engineering/claude-code-sandboxing)
were reviewed as integration references. Their Bash-tool and proxy policy are
different from this proposed offline whole-workload profile. AZT has no working
Claude Code integration in this milestone. Docker's documented
[resource controls](https://docs.docker.com/engine/containers/resource_constraints/)
are another maintained option; adding daemon/image lifecycle is unnecessary for
the first selected local profile. No comparative safety ranking is claimed.

## Ordered implementation and acceptance backlog

1. Provide an isolated Linux test host with pinned tool versions, usable user
   namespaces and delegated cgroup v2 CPU, memory and pids controllers. Record
   platform/kernel/backend versions; fail if required controls cannot be set and
   read back. Do not relax the caller's sandbox to obtain them.
2. Build the launch profile using argument lists. Copy a bounded input manifest
   into a disposable workspace, reject special files and escaping links, expose
   only approved read-only runtime dependencies, clear environment and inherited
   file descriptors, and exclude home directories and host sockets. Show which
   workspace inputs were copied; workspace secrets remain exposed to that task.
3. Enforce separate mount, process, IPC and network namespaces and a new session.
   Enforce CPU, memory, process, wall-clock, output and writable-storage limits.
   Any missing required control must fail before workload execution.
4. Keep operator policy, receipts and the supervisor outside all writable mounts.
   Implement external stop and test descendant termination. Kill the controller
   with SIGKILL and independently check cleanup; a Python finally block cannot
   establish that property. Test evidence-store failure during termination.
5. Run finite synthetic attempts against host secrets, original workspace,
   supervisor state, privileged sockets, cross-session writable paths and
   resource limits. For direct-socket denial, first establish that a test-owned
   listener is reachable outside the sandbox. Record attempts separately from
   independently observed outcomes. No public destinations or model spend.
6. Prove a benign deterministic task completes and exports a bounded reviewable
   diff. Do not apply it automatically. Publish raw results with denominators,
   elapsed time, configuration, failed cases and skips. Only then expose `run`,
   `inspect` and `kill` as supported experimental commands with a runnable demo.

## Capability and evidence matrix

| Capability | State | Evidence |
| --- | --- | --- |
| Offline prerequisite report | Implemented/tested | `python3 -m unittest discover -s tests -p test_runtime.py -v` |
| Linux prerequisite branches | Implemented/tested with mocks | Diagnostic tests only; no kernel claim |
| Whole-workload runtime profile | Planned, integration blocked | No runtime launch or boundary trial |
| Network/filesystem/descendant isolation | Unsupported in AZT | Backend interfaces reviewed only |
| Limits, stop, controller-death cleanup | Unsupported in AZT | Acceptance backlog above |
| Runtime session receipts and result diff | Planned | No success-shaped placeholder commands |
| Cloud agents, credentials, model-call budgets | Unsupported | Separate broker design and authorized testing required |

The future trusted computing base is the operator, host/kernel, backend,
supervisor and protected policy/evidence store. Compromise of those components
is outside this proposed profile. Same-user files outside a workload are only
isolated if the actual execution boundary denies access; relocation alone does
not protect authority. Timing and hardware side channels remain outside the
proposed test scope.

Future child authority must be no broader than the parent's, with shared
budgets, revocation and expiry inherited rather than reset. OS process limits
do not enforce separately billed model-call budgets. Irreversible operations
need approval bound to exact arguments, target state and expiry, issued outside
the worker. A future credential broker must retain long-lived credentials and
respect provider-specific revocation limits. Semantic analysis may flag risk,
but cannot grant privileges. Local controls must keep enforcing policy if an
optional organization service goes offline; externally granted authority must
expire under local rules. These are design requirements, not shipped features.

Essential local policy, enforcement, stop, inspection, evidence export and the
public benchmark remain usable without an account. Future organization services
may distribute policy or collect optional exports; no service is required for
the standalone scanner, and no account, telemetry or paid safety limit is added.
