"""Optional offline editorial drawing, using existing AZT art helpers.

Pillow and an already-installed Playwright Chromium are asset-development tools,
not AZT dependencies. No download or target instruction execution is performed.
"""

import base64
import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("azt_landing_art", HERE.parent / "render.py")
art = importlib.util.module_from_spec(spec)
spec.loader.exec_module(art)
text, rect, line, svg = art.text, art.rect, art.line, art.svg
BG, PANEL, EDGE, WHITE, MUTED, CYAN, AMBER = art.BG, art.PANEL, art.EDGE, art.WHITE, art.MUTED, art.CYAN, art.AMBER
STEPS = ["Read the request", "See the consequence", "Review before sharing", "Keep a local record"]


def validate_capture():
    capture = json.loads((HERE / "capture.json").read_text())
    for case in ("broad", "limited"):
        data = (HERE / (case + "-scan.json")).read_bytes()
        assert hashlib.sha256(data).hexdigest() == capture["cases"][case]["scan_sha256"]
        scan = json.loads(data)
        assert scan["scope"]["complete"] and scan["threshold"] == "high"
    assert capture["cases"]["broad"]["findings"] == 1
    assert capture["cases"]["limited"]["findings"] == 0
    assert hashlib.sha256((HERE / "report.html").read_bytes()).hexdigest() == capture["report_html_sha256"]
    assert "This request asks you to share tokens." in (HERE / "report.txt").read_text()
    assert "verify the intended recipient" in (HERE / "explanation.txt").read_text()


def scene(stage, mobile=False, transition=1):
    w, h = (720, 1100) if mobile else (1280, 760)
    body = text(32, 43, "AZT / REVIEW BEFORE SHARING", 19 if mobile else 20, CYAN, 700)
    body += text(32, 104, "Helpful request. Sensitive access.", 36 if mobile else 44, WHITE, 700)
    body += text(34, 145, "What is this asking you to disclose?", 26, MUTED)
    x, y, pw, ph = (24, 177, 672, 285) if mobile else (32, 181, 584, 338)
    body += rect(x, y, pw, ph, PANEL, EDGE)
    body += text(x + 24, y + 40, "CONTRIBUTING.md", 24, WHITE, 700, True)
    body += text(x + 24, y + 73, "Synthetic instruction · never executed", 19, MUTED)
    body += line(x + 24, y + 92, x + pw - 24, y + 92)
    body += rect(x + 16, y + 115, pw - 32, 54, "#49382c" if stage >= 1 else "#1a2a3f", radius=6)
    body += text(x + 28, y + 151, "Upload your API keys", 31 if mobile else 30, AMBER if stage >= 1 else WHITE, 700)
    body += text(x + 28, y + 196, "to [example destination].", 27, MUTED)
    body += text(x + 25, y + 243, "URL omitted from this illustration.", 20, MUTED)
    if not mobile:
        body += text(x + 25, y + 296, "No keys collected. No destination contacted.", 20, CYAN)
    x2, y2, p2w, p2h = (24, 480, 672, 342) if mobile else (640, 181, 608, 338)
    body += rect(x2, y2, p2w, p2h, PANEL, CYAN if stage else EDGE)
    body += text(x2 + 24, y2 + 40, STEPS[stage].upper(), 23, CYAN, 700)
    if stage == 0:
        lines = ["A contribution guide can ask", "for more access than a task needs.", "AZT inspects the wording", "without following the request."]
        for i, value in enumerate(lines):
            body += text(x2 + 25, y2 + 101 + 43*i, value, 27, WHITE if i < 2 else MUTED)
    else:
        content = text(x2 + 25, y2 + 93, "1 finding · MEDIUM", 29, AMBER, 700)
        content += text(x2 + 25, y2 + 130, "request.sensitive_disclosure", 21, MUTED, mono=True)
        if stage == 1:
            lines = ["This asks you to share API keys.", "They can grant access to services.", "Recipient mentioned ≠ verified."]
        elif stage == 2:
            lines = ["Verify the request and recipient.", "Share only what is necessary.", "Inspect the exact contents first."]
        else:
            lines = ["Save a local HTML / text / JSON review.", "Retain the finding and source identity.", "Nothing is uploaded by AZT."]
        for i, value in enumerate(lines):
            content += text(x2 + 25, y2 + 190 + i*44, value, 25 if stage == 3 else 27, WHITE if i == 0 else MUTED)
        body += '<g opacity="' + str(transition) + '">' + content + '</g>'
    by = 842 if mobile else 539
    bw = 672 if mobile else 1216
    body += rect(24 if mobile else 32, by, bw, 104, "#122637", EDGE)
    bx = 48 if mobile else 56
    body += text(bx, by + 33, "A LIMITED CONTROL", 17, CYAN, 700)
    body += text(bx, by + 66, "“Send only the Python version. Do not include API keys…”", 21 if mobile else 24, WHITE)
    body += text(bx, by + 93, "Same installed scanner: 0 sensitive-request findings.", 17 if mobile else 19, MUTED)
    fy = 979 if mobile else 680
    body += text(32, fy, "Default HIGH threshold: exit 0 ≠ no findings or approval.", 21 if mobile else 23, AMBER)
    body += text(32, fy + 35, "Illustrated recorded CLI workflow · AZT 0.1.13 · not a graphical app", 18 if mobile else 20, MUTED)
    body += text(32, fy + 66, "Bounded English review. No upload, target execution or automatic repair.", 17 if mobile else 19, MUTED)
    return svg(w, h, body, "Review a sensitive request before sharing", "Illustration of actual AZT 0.1.13 CLI output. A synthetic API-key upload request yields one MEDIUM sensitive-disclosure finding. A version-only control yields none. Default HIGH threshold returns exit 0 for both, not approval. No target instructions were executed.")


def main():
    validate_capture()
    # Four persistent states with short opacity transitions and readable holds.
    timeline = [(0, 1, 3800)]
    for stage in (1, 2, 3):
        timeline.extend((stage, alpha, 100) for alpha in (0.25, 0.5, 0.75))
        timeline.append((stage, 1, 5100))
    timeline.append((0, 1, 2500))  # explicit readable reset, not a new measurement
    durations = [entry[2] for entry in timeline]
    with tempfile.TemporaryDirectory(prefix="azt-sensitive-art-") as temporary:
        temporary = Path(temporary)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(chromium_sandbox=True)
            page = browser.new_page()
            for mobile in (False, True):
                name = "mobile" if mobile else "desktop"
                width, height = (720, 1100) if mobile else (1280, 760)
                page.set_viewport_size({"width": width, "height": height})
                frames = []
                for i, (stage, alpha, _) in enumerate(timeline):
                    drawing = scene(stage, mobile, alpha)
                    page.set_content('<style>body{margin:0}</style>' + drawing)
                    overflowing = page.evaluate("""() => [...document.querySelectorAll('svg text')].filter(e => {const b=e.getBBox(),v=e.ownerSVGElement.viewBox.baseVal; return b.x<0||b.y<0||b.x+b.width>v.width||b.y+b.height>v.height}).map(e=>e.textContent)""")
                    assert not overflowing, (name, stage, overflowing)
                    frame = temporary / (name + str(i) + ".png")
                    page.screenshot(path=str(frame))
                    with Image.open(frame) as image:
                        frames.append(image.convert("RGB"))
                    if stage == 2 and alpha == 1:
                        (HERE / (name + ".svg")).write_text(drawing)
                        frames[-1].save(HERE / (name + ".png"), optimize=True)
                # One shared palette prevents color flicker during opacity transitions.
                palette = frames[4].quantize(colors=96)
                frames = [frame.quantize(palette=palette, dither=Image.Dither.NONE) for frame in frames]
                frames[0].save(HERE / (name + ".gif"), save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True, disposal=1)
                with Image.open(HERE / (name + ".gif")) as image:
                    assert image.info["loop"] == 0
                    actual = []
                    for i in range(image.n_frames):
                        image.seek(i)
                        actual.append(image.info["duration"])
                    assert sum(actual) == sum(durations)
                assert (HERE / (name + ".gif")).stat().st_size < 1_000_000
            # These are actual, unmodified HTML exports. Screenshots show the top
            # viewport; complete text/JSON and identities remain in report.html.
            for name, width, height in [("desktop", 1120, 455), ("mobile", 390, 915)]:
                page.set_viewport_size({"width": width, "height": height})
                requests = []
                page.on("request", lambda request: requests.append(request.url))
                page.set_content((HERE / "report.html").read_text())
                assert page.locator("h1").inner_text() == "AZT local review"
                assert not requests
                page.screenshot(path=str(HERE / ("report-" + name + ".png")))
            # Browser playback over a full loop plus reset, not just frame counting.
            # The actual report sets a restrictive CSP. Use a fresh document so
            # its policy does not correctly block this separate data-image test.
            page.close()
            page = browser.new_page()
            page.set_viewport_size({"width": 1280, "height": 760})
            encoded = base64.b64encode((HERE / "desktop.gif").read_bytes()).decode()
            page.set_content('<style>body{margin:0}</style><img alt="Illustrated sensitive-request review" src="data:image/gif;base64,' + encoded + '">')
            page.locator("img").evaluate("e => e.decode()")
            assert page.locator("img").evaluate("e => e.naturalWidth") == 1280
            page.screenshot(path=str(temporary / "playback-start.png"))
            page.wait_for_timeout(35000)
            page.screenshot(path=str(temporary / "playback-35s.png"))
            assert (temporary / "playback-start.png").read_bytes() != (temporary / "playback-35s.png").read_bytes()
            # Static media selection preserves a reduced-motion option without
            # trying to override GitHub's own animated-image preferences/controls.
            page.emulate_media(reduced_motion="reduce")
            still = base64.b64encode((HERE / "desktop.png").read_bytes()).decode()
            page.set_content('<picture><source media="(prefers-reduced-motion: reduce)" srcset="data:image/png;base64,' + still + '"><img src="data:image/gif;base64,' + encoded + '"></picture>')
            assert page.locator("img").evaluate("e => e.currentSrc").startswith("data:image/png")
            browser.close()
    (HERE / "timeline.json").write_text(json.dumps({"schema": "azt.editorial-timeline.v1", "duration_ms": sum(durations), "loop": "infinite", "stages": [{"stage": stage, "opacity": alpha, "duration_ms": duration} for stage, alpha, duration in timeline], "timing": "Editorial pacing, not measured scanner time", "checks": ["SVG text bounds", "desktop and mobile renders", "browser playback differs at 35 seconds after a complete loop", "reduced-motion picture selects static PNG", "actual report HTML produced no remote requests"]}, indent=2) + "\n")
    print("Rendered connected desktop/mobile GIFs + stills + actual report screenshots; bounds, capture identity, 35-second playback and reduced-motion checks passed.")


if __name__ == "__main__":
    main()
