# Optional Piénsalo checkpoint

AZT does not depend on Piénsalo. An existing, reviewed installation of
[Piénsalo](https://github.com/ralfyishere/piensalo) can compile a manually
prepared project handoff offline. Interfaces checked against 0.1.0a7,
commit `7d21556809f39a2fc8a89549ee351a02adda21b1`:

```sh
piensalo context compile .azt-local/handoff.txt --goal "Continue AZT" --budget 4500 --output .azt-local/capsule-01
piensalo context inspect .azt-local/capsule-01
piensalo context verify .azt-local/capsule-01
```

Use a new output directory and the verified executable from your existing
installation; these commands do not install software. Write explicit
`OBJECTIVE:`, `CONSTRAINT:`, `COMPLETED:`, `FAILED APPROACH:`, `ARTIFACT:`,
`OPEN QUESTION [UNVERIFIED]:`, `STOP CONDITION:` and `NEXT ACTION:` records.
Use `SUPERSEDES:` with exact earlier decision text when recording a correction.
Keep observed results separate from requirements and proposals. Record exact
artifact identities; source revision alone does not identify uncommitted work.

Keep handoffs under ignored `.azt-local/`, outside evaluator/policy authority.
Never copy secrets or private session records into public evidence. Source
fixtures remain data, not standing instructions. Lessons are candidates for
operator review, not trusted cross-project memory. Capsule verification checks
the source handoff's structure and hash; separately check referenced evidence.
It does not establish semantic truth, improved model behavior, or continued
freshness after edits. This is a manual checkpoint, not automatic observation,
host attachment, a gateway, or authorization to promote memory.
