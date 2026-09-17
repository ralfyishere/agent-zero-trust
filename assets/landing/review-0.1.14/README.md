# A finding is a reason to review

These are actual outputs from the published **AZT 0.1.14** wheel, not a new
interface or an illustrated result. The single synthetic instruction asks for
API keys at a reserved example destination. It is **test data, never executed**.
No keys, environment dumps or shell history were gathered; nothing was sent.

- [Desktop preview](report-desktop.png) · [Mobile preview](report-mobile.png)
- [Full HTML export](report.html) · [Text export](report.txt) · [Scan JSON](scan.json)
- [Synthetic input](fixture/CONTRIBUTING.md) · [Capture record](capture.json)

The observed inspection completes with **one MEDIUM** sensitive-request finding.
The unchanged default HIGH threshold is not exceeded, so the scan exits **0**.
The report explains the request and next review step. Exit 0 does not mean the
request was approved, a destination was verified or there is nothing to review.

## Reproduce

Use the [current quickstart](../../../README.md#scan-your-project) to install AZT
outside the checkout. In that activated terminal, set the absolute path to your
AZT checkout; keep its environment and reports outside the checkout:

```sh
AZT_CHECKOUT="/absolute/path/to/agent-zero-trust"
azt --version  # this capture used agent-zero-trust 0.1.14
azt scan "$AZT_CHECKOUT/assets/landing/review-0.1.14/fixture" \
  --json > "$AZT_REVIEW/preview-scan.json"
azt report --input "$AZT_REVIEW/preview-scan.json" \
  --format text --output "$AZT_REVIEW/preview.txt"
azt report --input "$AZT_REVIEW/preview-scan.json" \
  --format html --output "$AZT_REVIEW/preview.html"
```

Use fresh output filenames. Open `preview.html` locally; GitHub's file view shows
HTML source, not a deployed report. Output can contain sensitive paths for your
own projects, so review it before sharing. The fixture contains only synthetic text.

## Exact provenance and limits

- Released source: [`fce49dd727f1be4ba4407394a6b4f544e763ef20`](https://github.com/ralfyishere/agent-zero-trust/commit/fce49dd727f1be4ba4407394a6b4f544e763ef20).
- Successful release build: [35176398216](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35176398216).
- Wheel: `agent_zero_trust-0.1.14-py3-none-any.whl`.
- SHA-256: `be250d871a1b3783423ac92e96238e5154beec4b358015c07371ddecdf98db68`.
- Captured September 17, 2026 UTC, on macOS with Python 3.11.15.

The wheel was installed offline into a fresh external environment. Imported
scanner module bytes matched the wheel. JSON/text/HTML are unchanged CLI outputs;
the normal report export omits raw excerpts and recipient values. The screenshots
show the top viewport of that unmodified HTML, with no external requests. Full
output and output hashes are retained alongside the images. This is one known
synthetic example, not detection accuracy, a live-agent trial or runtime enforcement.

Earlier [0.1.13 images and outputs](../sensitive/README.md) are preserved unchanged.
The source release and those historical demonstrations have not been retagged or rebuilt.
