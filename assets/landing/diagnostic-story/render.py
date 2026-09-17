"""Offline editorial illustration of captured, released AZT output.

Not product code or a GUI. Uses the existing optional Pillow/Playwright drawing
tools, without downloads. Read README.md here for the exact synthetic inputs.
"""
import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location("azt_landing_art", HERE.parent / "render.py")
art = importlib.util.module_from_spec(spec)
spec.loader.exec_module(art)
text, rect, line = art.text, art.rect, art.line
BG, WHITE, MUTED, CYAN, AMBER = art.BG, art.WHITE, art.MUTED, art.CYAN, art.AMBER
PAPER, INK, SUBTLE, MARK = "#f3f0e8", "#142333", "#51606c", "#f4ce82"


def group(content, opacity=1, dy=0):
    return f'<g opacity="{opacity:.4f}" transform="translate(0 {dy:.2f})">{content}</g>'


def blend(a, b, value):
    return group(a, max(0, 1 - 2 * value), -9 * value) + group(b, max(0, 2 * value - 1), 9 * (1 - value))


def lines(x, y, values, size=28, color=WHITE, weight=400, leading=37):
    return "".join(text(x, y + i * leading, value, size, color, weight) for i, value in enumerate(values))


def scene(state, mobile=False):
    changed, highlight, observed, decision = state
    w, h = (720, 1020) if mobile else (1280, 690)
    margin = 28 if mobile else 48
    body = text(margin, 44, "AZT", 26, CYAN, 700)
    body += text(margin + 74, 43, "READ THE REQUEST. KEEP THE CHOICE.", 17, MUTED, 700)
    body += text(margin, 103, "The debugging guide changed.", 38 if mobile else 46, WHITE, 700)
    body += text(margin + 1, 144, "Same project. A bigger ask.", 26, MUTED)

    x, y, pw, ph = (28, 178, 664, 425) if mobile else (48, 188, 704, 394)
    # A single paper surface, not a fictional application/dashboard.
    body += rect(x + 5, y + 8, pw, ph, "#17212d", radius=3)
    body += rect(x, y, pw, ph, PAPER, radius=3)
    body += rect(x, y, 5, ph, "#87d5d3", radius=0)
    body += text(x + 30, y + 40, "README.md", 21, INK, 700, True)
    body += text(x + pw - 204, y + 39, "SELECTED PASSAGES", 14, SUBTLE, 700)
    body += line(x + 30, y + 59, x + pw - 30, y + 59, "#ccd0cb")

    before = text(x + 30, y + 107, "Minimal diagnostics", 29, INK, 700)
    before += lines(x + 30, y + 165, ["Share only the Python version", "and the value of AZT_LOG_LEVEL", "in your report."], 32 if mobile else 29, INK, leading=40)
    before += lines(x + 30, y + 301, ["Keep credentials and private configuration", "on your local machine."], 25 if mobile else 23, SUBTLE, leading=32)

    after = text(x + 30, y + 104, "Contributing", 29, INK, 700)
    after += text(x + 30, y + 146, "… gather full environment details …", 25, SUBTLE)
    phrases = [("shell history", 209), ("environment variables", 342), ("the contents of the local", 368), ("configuration folder", 299)]
    for i, (phrase, width) in enumerate(phrases):
        # A left-to-right marker stroke draws attention to the changed subjects.
        progress = max(0, min(1, highlight * 3 - (min(i, 2))))
        ly = y + 196 + 38 * i
        after += rect(x + 27, ly - 26, width * progress * (32/29 if mobile else 1), 33, MARK, radius=1)
        after += text(x + 31, ly, phrase, 32 if mobile else 29, INK, 700)
    after += text(x + 30, y + 361, "… and share them at the address listed …", 24, SUBTLE)
    body += blend(before, after, changed)

    rx, ry = (34, 652) if mobile else (818, 239)
    baseline = text(rx, ry, "A limited request.", 34 if mobile else 35, WHITE, 700)
    baseline += lines(rx, ry + 51, ["A software version.", "One named log setting."], 30 if mobile else 27, MUTED, leading=38)
    baseline += text(rx, ry + 161, "0 findings in the saved scan", 23, CYAN)
    changed_note = text(rx, ry, "Now it asks for more.", 32, WHITE, 700)
    changed_note += lines(rx, ry + 53, ["History. Environment.", "Local configuration."], 30 if mobile else 28, MUTED, leading=39)
    changed_note += text(rx, ry + 161, "The wording changed. Look closer.", 22, CYAN)
    initial = blend(baseline, changed_note, changed)

    warning = text(rx, ry, "Before you share…", 35, AMBER, 700)
    warning += lines(rx, ry + 52, ["These materials may contain", "credentials or private activity."], 29 if mobile else 25, WHITE, leading=39)
    warning += text(rx, ry + 155, "1 new finding · MEDIUM", 25, AMBER, 700)
    warning += text(rx, ry + 190, "request.sensitive_disclosure", 18, MUTED, mono=True)
    warning += text(rx, ry + 224, "Not proof that secrets are present.", 21, MUTED)

    next_step = text(rx, ry, "Ask for less.", 44 if mobile else 48, CYAN, 700)
    next_step += lines(rx, ry + 54, ["Verify the request.", "Share only what is necessary.", "Inspect the exact contents first."], 30 if mobile else 25, WHITE, leading=41)
    next_step += lines(rx, ry + 178, ["May contain credentials", "or private activity."], 24, MUTED, leading=30)
    next_step += text(rx, ry + 251, "1 MEDIUM finding · local report", 22, CYAN)
    reviewed = blend(warning, next_step, decision)
    body += blend(initial, reviewed, observed)

    fy = 947 if mobile else 631
    body += line(margin, fy - 26, w - margin, fy - 26, "#29405b")
    stage_label = text(margin, fy + 1, "01  /  SAVE A BASELINE", 18, CYAN, 700)
    middle_label = text(margin, fy + 1, "02  /  COMPARE THE CHANGE", 18, CYAN, 700)
    final_label = text(margin, fy + 1, "03  /  REVIEW BEFORE SHARING", 18, CYAN, 700)
    body += blend(blend(stage_label, middle_label, changed), final_label, observed)
    if not mobile:
        body += group(text(801, fy + 1, "HIGH threshold not exceeded ≠ approval", 20, MUTED), observed)
    else:
        body += group(text(margin, fy + 33, "HIGH threshold not exceeded ≠ approval", 21, MUTED), observed)
    body += text(margin, h - 15, "Illustrated recorded CLI workflow · 0.1.14 · not a graphical app", 17, MUTED)
    return art.svg(w, h, body, "A diagnostic request changes. Review before sharing.",
                   "Illustration of released AZT CLI results on two frozen synthetic lab inputs. "
                   "A version-and-log-setting request has zero findings. A broad diagnostic-sharing "
                   "request has one new MEDIUM finding. The advice is to verify the request, share "
                   "only the minimum necessary and inspect the exact contents. No diagnostics were "
                   "gathered or transmitted in response to the request. Not a live graphical interface.")


def timeline():
    states = [(0, 0, 0, 0), (1, 0, 0, 0), (1, 1, 0, 0), (1, 1, 1, 0), (1, 1, 1, 1)]
    holds = [4800, 1900, 1800, 6000, 6500]
    transitions = [0, 700, 1300, 600, 600]
    labels = ["Limited diagnostic request", "Document changes in place", "Requested materials highlighted", "Recorded finding and possible consequence", "Useful decision and local record"]
    frames, stages, elapsed = [], [], 0
    for i, state in enumerate(states):
        if i:
            duration = transitions[i]
            for step in range(1, duration // 100 + 1):
                t = step / (duration // 100)
                t = t * t * (3 - 2 * t)
                frames.append((tuple(a + (b-a)*t for a, b in zip(states[i-1], state)), 100))
            elapsed += duration
        stages.append({"label": labels[i], "start_ms": elapsed, "hold_ms": holds[i]})
        frames.append((state, holds[i]))
        elapsed += holds[i]
    for step in range(1, 9):
        t = step / 8
        frames.append(((1 - t,) * 4, 100))
    elapsed += 800
    frames.append((states[0], 1000))
    elapsed += 1000
    return frames, stages, elapsed


def validate():
    """Check illustration facts against captured actual output, not expectations alone."""
    capture = json.loads((HERE / "evidence/capture.json").read_text())
    assert capture["version"] == "0.1.14"
    assert capture["source"] == "fce49dd727f1be4ba4407394a6b4f544e763ef20"
    assert capture["helper_sha256"] == hashlib.sha256((HERE / "capture.py").read_bytes()).hexdigest()
    assert len(capture["outputs"]) <= 32
    for name, digest in capture["outputs"].items():
        assert Path(name).name == name and name not in (".", "..")
        assert hashlib.sha256((HERE / "evidence" / name).read_bytes()).hexdigest() == digest
    fixtures = json.loads((HERE / "evidence/fixtures.json").read_text())
    original = " ".join(fixtures["broad-original"]["README.md"]["text"].split())
    for fragment in ("gather full environment details", "shell history", "environment variables",
                     "the contents of the local configuration folder", "and share them at the address listed"):
        assert fragment in original
    before = json.loads((HERE / "evidence/before.json").read_text())
    after = json.loads((HERE / "evidence/after.json").read_text())
    changes = json.loads((HERE / "evidence/changes.json").read_text())
    # The capture helper produces normal validated scan/changes records.
    assert before["version"] == after["version"] == "0.1.14"
    assert before["findings"] == []
    assert before["scope"]["complete"] and after["scope"]["complete"]
    assert len(after["findings"]) == 1
    assert after["findings"][0]["rule"] == "request.sensitive_disclosure"
    assert after["findings"][0]["severity"] == "MEDIUM"
    assert len(changes["findings"]["new"]) == 1
    assert changes["comparability"]["status"] == "comparable"


def main():
    validate()
    frames, stages, total = timeline()
    outputs = {}
    with tempfile.TemporaryDirectory(prefix="azt-story-render-") as tmp:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(chromium_sandbox=True)
            page = browser.new_page()
            for name, mobile, size in [("desktop", False, (1280, 690)), ("mobile", True, (720, 1020))]:
                page.set_viewport_size({"width": size[0], "height": size[1]})
                raster = []
                for i, (state, duration) in enumerate(frames):
                    drawing = scene(state, mobile)
                    page.set_content('<style>body{margin:0}</style>' + drawing)
                    overflow = page.evaluate('''() => [...document.querySelectorAll('svg text')].filter(e => {const b=e.getBBox(),v=e.ownerSVGElement.viewBox.baseVal;return b.x<0||b.y<0||b.x+b.width>v.width||b.y+b.height>v.height}).map(e=>e.textContent)''')
                    assert not overflow, (name, i, overflow)
                    frame = Path(tmp) / f"{name}-{i}.png"
                    page.screenshot(path=str(frame))
                    with Image.open(frame) as image:
                        raster.append(image.convert("RGB"))
                    if state == (1, 1, 1, 1):
                        (HERE / (name + ".svg")).write_text(drawing)
                        raster[-1].save(HERE / (name + ".png"), optimize=True)
                    if state in [(0, 0, 0, 0), (1, 1, 0, 0), (1, 1, 1, 0)] and duration > 1000:
                        tag = "before" if not state[0] else "changed" if not state[2] else "finding"
                        raster[-1].save(HERE / (name + "-" + tag + ".png"), optimize=True)
                strip = Image.new("RGB", (size[0], size[1] * len(raster)))
                for i, frame in enumerate(raster):
                    strip.paste(frame, (0, i * size[1]))
                palette = strip.quantize(colors=128)
                indexed = [im.quantize(palette=palette, dither=Image.Dither.NONE) for im in raster]
                target = HERE / (name + ".gif")
                indexed[0].save(target, save_all=True, append_images=indexed[1:], duration=[ms for _, ms in frames], loop=0, optimize=True, disposal=1)
                with Image.open(target) as gif:
                    assert gif.info["loop"] == 0
                    durations = []
                    for i in range(gif.n_frames):
                        gif.seek(i)
                        durations.append(gif.info["duration"])
                    assert sum(durations) == total
                    outputs[name] = {"frames": gif.n_frames, "duration_ms": total, "loop": "infinite", "bytes": target.stat().st_size, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}
                    assert target.stat().st_size < 2_000_000
            # An unmodified real export, separately shown from the illustration.
            for name, width in [("desktop", 900), ("mobile", 390)]:
                page.close()
                page = browser.new_page(viewport={"width": width, "height": 900})
                requests = []
                page.on("request", lambda request: requests.append(request.url))
                page.set_content((HERE / "evidence/report.html").read_text())
                assert page.locator("h1").inner_text() == "AZT local review"
                assert not requests
                # Crop only the finding paragraph from the original exported
                # document; never restyle/rewrite output or hide its full file.
                clip = page.locator("pre").evaluate('''e => {
                    const node=e.firstChild, raw=node.textContent;
                    const first=raw.indexOf('Sensitive request at ');
                    const end='No upload or target execution was performed by this inspection.';
                    const last=raw.indexOf(end)+end.length;
                    if(first<0 || last<=first) throw Error('Finding paragraph not found');
                    const range=document.createRange(); range.setStart(node,first);range.setEnd(node,last);
                    const r=range.getBoundingClientRect();
                    return {x:0,y:Math.floor(r.y+scrollY),width:innerWidth,height:Math.ceil(r.height)};
                }''')
                page.screenshot(path=str(HERE / ("report-" + name + ".png")), clip=clip, full_page=True)
            browser.close()
    (HERE / "timeline.json").write_text(json.dumps({"schema": "azt.editorial-timeline.v1", "duration_ms": total, "timing": "Editorial pacing, not measured scanner duration", "stages": stages, "reset_ms": 1800, "outputs": outputs, "checks": ["captured scan and comparison assertions", "SVG text bounds at every frame", "GIF durations and infinite looping", "unmodified HTML export produced no remote requests"]}, indent=2) + "\n")
    print(json.dumps(outputs, indent=2))


if __name__ == "__main__":
    main()
