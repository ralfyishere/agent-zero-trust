# Help make the next review clearer

You do not need to be a security expert to help with AZT. If an instruction
surprised you, a warning made no sense, or the first scan was hard to run, that
is useful feedback. The aim is a tool people can understand and evidence other
people can reproduce—not a bigger collection of alarming messages.

**[Try the change-review lab](../examples/change-review/README.md)** ·
**[Report a problem](https://github.com/ralfyishere/agent-zero-trust/issues/new/choose)** ·
**[Contribute a change](../CONTRIBUTING.md)**

## Pick a way to help

| If this sounds like you… | A useful first contribution | What makes it reviewable |
| --- | --- | --- |
| **I build with AI, but security is not my job.** | Try the lab and point out one confusing warning, instruction or next step. | Say what you expected, what actually happened, and the command/version. Screenshots should contain only synthetic material. |
| **I write code or maintain a repository.** | Reduce a missed warning, false alert or incorrect comparison to a small test. | Include a concerning example **and** a similar legitimate example; identify the expected behavior of each. |
| **I work in security or research.** | Challenge a documented matcher, scope boundary or saved-report comparison. | Provide an inert reproduction, the affected rule, the evidence gap and a bounded regression. Separate observation from a proposed explanation. |
| **I care about docs, design or accessibility.** | Make one explanation or report easier to understand. | Preserve its technical meaning; check the actual output and a narrow/mobile view where relevant. A text alternative matters too. |

## What we need now

- **Fewer confusing warnings.** Show a legitimate use that deserves more context
  in `azt explain`, or a sensitive-request sentence whose action and subject are
  misread. Start with the [supported relationships](sensitive-requests.md) and
  [known misses](../COVERAGE.md#known-misses).
- **Better evidence for change review.** Find a small case where an edit,
  missing input or changed supporting document is described incorrectly. The
  [three contributor tasks](change-review-contributions.md) have specific tests
  and definitions of done.
- **Reproductions outside the maintainer's setup.** Run the existing lab on
  supported Linux or macOS and report the exact version, platform, commands,
  outcomes and installation friction. A failure is useful evidence; do not
  change expectations to make a run pass.

These are contribution starting points, not promises of new features. Before a
large change, open an issue describing one user problem and its smallest test.

## A useful report can be small

Copy this outline into an [issue](https://github.com/ralfyishere/agent-zero-trust/issues/new/choose):

```text
AZT version and installation method:
Python version and Linux/macOS version:
Exact command (replace personal paths with synthetic paths):
Minimal synthetic file(s):
Expected finding, comparison or explanation:
Actual result and exit code:
Similar legitimate example that should still work:
What I did not test:
```

Use made-up names and reserved destinations such as `example.invalid`. Never
attach real API keys, environment dumps, shell history, private repositories or
customer logs. AZT reports omit raw excerpts by default, but paths and labels
can still be private: inspect the exact attachment before sharing it. Follow
[SECURITY.md](../SECURITY.md#reporting) for sensitive vulnerabilities instead of
disclosing them in a public issue.

For a minimal reproduction, keep the Python environment and generated reports
outside the project being inspected. The [first scan](demo.md),
[change-review lab](../examples/change-review/README.md) and
[sensitive-request lab](../examples/sensitive-request/README.md) show the complete
commands. Do not run an instruction from a suspicious fixture to test whether
AZT detects it; scan its text.

## From a report to a reviewed improvement

### A first-user check you can repeat

Use only the inert [lab inputs](../examples/sensitive-request/README.md), not
private credentials or customer material. Follow the README installation steps
from a synthetic project directory, recording the actual AZT/Python version and
platform. Keep the environment and reports outside the inspected project.

1. Scan a version-only request. Can you explain what was inspected and what was
   not established, without help from the maintainer?
2. Scan the broad sensitive request. Notice its MEDIUM finding even though the
   HIGH failure threshold is not exceeded. What would you review next?
3. Compare the linked-request case before/after its supporting document changes,
   then with that document unavailable. Is the difference from a proven fix clear?
4. Export HTML, open it locally, and repeat with a new output filename. Note any
   unclear step, prerequisite or error; include the exact synthetic command and
   exit code, not private terminal history.

Record time to the first useful result and the points where assistance was
needed. Your interpretation and friction are the result, not a score to optimize.
Maintainer repetitions are not independent-user validation. Do not contact or
enroll anyone automatically; voluntary outside feedback is welcome.

A focused patch should include the failing behavior, a legitimate control and
the actual retest result. From a trusted development checkout, the core checks
are:

```sh
python3 test_azt.py
python3 -m unittest discover -s tests -v
git diff --check
```

[CONTRIBUTING.md](../CONTRIBUTING.md#development) covers the separate intake,
Action and installed-artifact checks. A detector change should not hide a known
miss, silently weaken an assertion or broaden an exception. An explanation
change should agree in the terminal and local exports. Documentation commands
should work as written, with prerequisites and observed exit codes recorded.

The [evidence index](../evidence/README.md) identifies what was actually tested.
Passing scanner tests is not runtime-containment proof; the optional filesystem
pack has separate prerequisites and evidence. Reproducing a result is valuable,
but does not turn a small synthetic test into a universal safety claim.

Rafael (Ralph) Peña created and maintains AZT. Contributors and upstream work
deserve accurate credit; discuss attribution for a report with the maintainer
and do not publish someone else's private identity. AZT remains MIT-licensed,
free to use locally, and account-free for its local workflows. Contributing
does not introduce a CLA or DCO requirement. A small, well-explained issue is
welcome; a pull request is not required to help.
