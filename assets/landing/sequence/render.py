"""Render a connected illustration from existing recorded AZT CLI evidence.

Optional, offline editorial tooling only. No target execution, new measurement,
download, product dependency or implementation of a graphical AZT interface.
"""

import importlib.util
import json
import tempfile
import textwrap
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("azt_landing_art", HERE.parent / "render.py")
ART = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ART)  # Reviewed local drawing helpers + evidence assertions.
text, rect, line = ART.text, ART.rect, ART.line
BG, PANEL, EDGE = ART.BG, ART.PANEL, ART.EDGE
WHITE, MUTED, CYAN, AMBER, BLUE = ART.WHITE, ART.MUTED, ART.CYAN, ART.AMBER, ART.BLUE

EXPLANATION = "This instruction asks your agent to download and run a remote script."
NEXT_STEP = "Review the source before using it."
SOURCE = "0296facec2565668386c3c0d5dbacb734e6241e3"
STAGES = ["Baseline saved", "Instruction changed", "Two findings", "Guidance", "Local export"]
HOLD_MS = [2800, 2200, 3500, 3700, 6000]
TRANSITION_MS = 600
TRANSITION_FRAMES = 6
RESET_HOLD_MS = 800


def group(content, opacity=1):
    return '<g opacity="%.4f">%s</g>' % (opacity, content)


def replacement_opacity(progress):
    """Fade outgoing words out before incoming words, avoiding doubled text."""
    return max(0, 1 - 2 * progress), max(0, 2 * progress - 1)


def wrapped(x, y, content, width, size, color=WHITE, weight=400, mono=False, spacing=None):
    rows = textwrap.wrap(content, width, break_long_words=False, break_on_hyphens=False)
    assert " ".join(rows) == content
    return "".join(text(x, y + index * (spacing or size * 1.35), row, size, color, weight, mono)
                   for index, row in enumerate(rows))


def scene(state, mobile=False):
    changed, findings, guidance, exported = state
    before_opacity, after_opacity = replacement_opacity(changed)
    placeholder_opacity, findings_opacity = replacement_opacity(findings)
    width, height = (720, 940) if mobile else (1280, 620)
    body = text(30, 39, "AZT", 26, CYAN, 700)
    body += text(97, 39, "Illustrated recorded CLI workflow", 19, MUTED)
    if mobile:
        body += text(30, 91, "One instruction changes.", 38, WHITE, 700)
        card_x, card_y, card_w, card_h = 24, 123, 672, 209
        result_x, result_y, result_w, result_h = 24, 351, 672, 278
        guidance_x, guidance_y, guidance_w = 24, 648, 672
        export_x, export_y, export_w, export_h = 24, 799, 672, 72
    else:
        body += text(32, 91, "One instruction. One reviewable change.", 38, WHITE, 700)
        card_x, card_y, card_w, card_h = 32, 129, 578, 267
        result_x, result_y, result_w, result_h = 636, 129, 612, 267
        guidance_x, guidance_y, guidance_w = 32, 415, 578
        export_x, export_y, export_w, export_h = 636, 415, 612, 123

    body += rect(card_x, card_y, card_w, card_h, PANEL, EDGE)
    body += text(card_x + 23, card_y + 40, "AGENTS.md", 24, WHITE, 700, True)
    body += text(card_x + card_w - 136, card_y + 37, "INSTRUCTION", 14, MUTED, 700)
    body += line(card_x + 23, card_y + 58, card_x + card_w - 23, card_y + 58)
    code_y = card_y + 99
    code_size = 27 if mobile else 24
    wrap = 37 if mobile else 36
    body += group(rect(card_x + 12, code_y - 29, card_w - 24, 89, "#203247", radius=5), changed)
    body += group(wrapped(card_x + 24, code_y, ART.BEFORE, wrap, code_size, spacing=37), before_opacity)
    body += group(wrapped(card_x + 24, code_y, ART.AFTER, wrap, code_size, spacing=37), after_opacity)
    body += group(text(card_x + 24, card_y + card_h - 23, "Baseline instruction", 21, MUTED), before_opacity)
    body += group(text(card_x + 24, card_y + card_h - 23, "Changed instruction · saved scans compared", 21, CYAN), after_opacity)

    body += rect(result_x, result_y, result_w, result_h, PANEL, EDGE)
    body += text(result_x + 24, result_y + 36, "REVIEW", 18, MUTED, 700)
    placeholder = text(result_x + 24, result_y + 99, "Scan → compare → explain → export", 25, MUTED)
    placeholder += text(result_x + 24, result_y + 143, "A local review, not automatic approval.", 21, MUTED)
    body += group(placeholder, placeholder_opacity)
    result = text(result_x + 24, result_y + 82, "2 findings to review", 32, AMBER, 700)
    result += wrapped(result_x + 24, result_y + 126, EXPLANATION, 43 if mobile else 37,
                      28 if mobile else 27, WHITE, 400, spacing=36)
    ids_y = result_y + result_h - 49
    result += text(result_x + 24, ids_y, "net.pipe_shell · HIGH", 19, MUTED, mono=True)
    result += text(result_x + 24, ids_y + 28, "net.fetch_unknown · MEDIUM", 19, MUTED, mono=True)
    body += group(result, findings_opacity)

    guidance_h = 132 if mobile else 123
    body += rect(guidance_x, guidance_y, guidance_w, guidance_h, PANEL, EDGE)
    body += text(guidance_x + 24, guidance_y + 32, "NEXT STEP", 17, MUTED, 700)
    guide = text(guidance_x + 24, guidance_y + 74, NEXT_STEP, 29 if mobile else 27, WHITE, 700)
    guide += text(guidance_x + 24, guidance_y + 109, "A documented installer may be legitimate.", 22 if mobile else 20, MUTED)
    body += group(guide, guidance)

    body += rect(export_x, export_y, export_w, export_h, PANEL, EDGE)
    if mobile:
        body += text(export_x + 24, export_y + 28, "LOCAL HTML REVIEW", 15, MUTED, 700)
        export = text(export_x + 24, export_y + 57, "review.html", 26, CYAN, 700, True)
        export += text(export_x + 279, export_y + 54, "Kept locally. No upload.", 22, WHITE)
    else:
        body += text(export_x + 24, export_y + 32, "LOCAL HTML REVIEW", 17, MUTED, 700)
        export = text(export_x + 24, export_y + 75, "review.html", 28, CYAN, 700, True)
        export += text(export_x + 259, export_y + 74, "Kept locally. No upload.", 21, WHITE)
        export += text(export_x + 24, export_y + 106, "A readable record to review and share deliberately.", 19, MUTED)
    body += group(export, exported)

    if mobile:
        body += text(30, 903, "Synthetic input. No target execution. Not a live GUI.", 21, MUTED)
        body += text(30, 932, "Recorded 0.1.11 candidate · source " + SOURCE[:12], 18, MUTED)
    else:
        body += text(34, 576, "Synthetic input. No target execution. Not a live GUI.", 20, MUTED)
        body += text(34, 607, "Recorded 0.1.11 candidate · source " + SOURCE[:12], 17, MUTED)
        body += text(916, 576, "Offline. Deterministic. Local.", 20, CYAN)
    return ART.svg(width, height, body, "AZT: a connected illustration of recorded change review",
                   "Illustrated recorded CLI workflow, not a shipped graphical interface or live measurement. "
                   "The exact synthetic AGENTS.md instruction changes in place. Two findings appear, then "
                   + EXPLANATION + " " + NEXT_STEP + " A local HTML review is illustrated. No target execution.")


def timeline():
    states = [(0, 0, 0, 0), (1, 0, 0, 0), (1, 1, 0, 0), (1, 1, 1, 0), (1, 1, 1, 1)]
    frames, stages = [], []
    elapsed = 0
    for index, state in enumerate(states):
        if index:
            previous = states[index - 1]
            stages.append({"name": "Transition to " + STAGES[index].lower(), "start_ms": elapsed, "duration_ms": TRANSITION_MS})
            for step in range(1, TRANSITION_FRAMES + 1):
                fraction = step / TRANSITION_FRAMES
                # Smoothstep easing, with labels and card coordinates stationary.
                fraction = fraction * fraction * (3 - 2 * fraction)
                interpolated = tuple(a + (b - a) * fraction for a, b in zip(previous, state))
                frames.append((interpolated, TRANSITION_MS // TRANSITION_FRAMES))
            elapsed += TRANSITION_MS
        stages.append({"name": STAGES[index], "start_ms": elapsed, "duration_ms": HOLD_MS[index]})
        frames.append((state, HOLD_MS[index]))
        elapsed += HOLD_MS[index]
    stages.append({"name": "Readable reset to original instruction", "start_ms": elapsed, "duration_ms": TRANSITION_MS})
    for step in range(1, TRANSITION_FRAMES + 1):
        fraction = step / TRANSITION_FRAMES
        fraction = fraction * fraction * (3 - 2 * fraction)
        frames.append(((1 - fraction,) * 4, TRANSITION_MS // TRANSITION_FRAMES))
    elapsed += TRANSITION_MS
    stages.append({"name": "Original instruction before replay", "start_ms": elapsed, "duration_ms": RESET_HOLD_MS})
    frames.append((states[0], RESET_HOLD_MS))
    elapsed += RESET_HOLD_MS
    assert elapsed == 22000
    return frames, stages, elapsed


def assert_sources():
    # Reuse the historical fixture hash, outcomes and exact rule assertions.
    ART.validate_sources()
    recorded_guidance = ART.GUIDANCE["net.pipe_shell"]
    assert recorded_guidance["next_step"] == "Inspect the source and publisher; prefer a reviewed, pinned local artifact."
    assert recorded_guidance["context_example"] == "A documented installer may legitimately fetch code."
    before = textwrap.wrap(ART.BEFORE, 36)
    after = textwrap.wrap(ART.AFTER, 36)
    assert " ".join(before) == ART.CASES["baseline"]["AGENTS.md"].strip()
    assert " ".join(after) == ART.CASES["concerning"]["AGENTS.md"].strip()
    assert SOURCE in (ART.ROOT / "evidence/change-review/README.md").read_text()


def main():
    assert_sources()
    frames, stages, total_ms = timeline()
    outputs = {}
    with tempfile.TemporaryDirectory(prefix="azt-connected-demo-") as temporary:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(chromium_sandbox=True)
            page = browser.new_page()
            for name, mobile, size in [("desktop", False, (1280, 620)), ("mobile", True, (720, 940))]:
                page.set_viewport_size({"width": size[0], "height": size[1]})
                raster = []
                static_svg = scene((1, 1, 1, 1), mobile)
                (HERE / (name + ".svg")).write_text(static_svg)
                for index, (state, duration) in enumerate(frames + [((1, 1, 1, 1), 0)]):
                    page.set_content('<style>body{margin:0}</style>' + scene(state, mobile))
                    overflowing = page.evaluate("""() => {
                        const v = document.querySelector('svg').viewBox.baseVal;
                        return [...document.querySelectorAll('text')].filter(e => {
                            const b = e.getBBox(); return b.x < 0 || b.y < 0 || b.x+b.width > v.width || b.y+b.height > v.height;
                        }).map(e => e.textContent);
                    }""")
                    assert not overflowing, (name, index, overflowing)
                    target = Path(temporary) / (name + "-" + str(index) + ".png")
                    page.screenshot(path=str(target))
                    with Image.open(target) as image:
                        if duration:
                            raster.append(image.convert("RGB"))
                        else:
                            image.convert("RGB").save(HERE / (name + ".png"), optimize=True)
                # One shared palette avoids color pumping across opacity changes.
                contact = Image.new("RGB", (size[0], size[1] * len(raster)))
                for index, image in enumerate(raster):
                    contact.paste(image, (0, index * size[1]))
                palette = contact.quantize(colors=96)
                indexed = [image.quantize(palette=palette, dither=Image.Dither.NONE) for image in raster]
                indexed[0].save(HERE / (name + ".gif"), save_all=True, append_images=indexed[1:],
                                duration=[duration for _, duration in frames], loop=0, optimize=True, disposal=1)
                with Image.open(HERE / (name + ".gif")) as image:
                    assert image.info["loop"] == 0
                    durations = []
                    for index in range(image.n_frames):
                        image.seek(index)
                        durations.append(image.info["duration"])
                    assert sum(durations) == total_ms
                    assert image.n_frames >= 25
                    outputs[name] = {"width": size[0], "height": size[1], "gif_frames": image.n_frames,
                                     "gif_duration_ms": sum(durations), "gif_loop": 0,
                                     "gif_bytes": (HERE / (name + ".gif")).stat().st_size,
                                     "png_bytes": (HERE / (name + ".png")).stat().st_size}
                    assert outputs[name]["gif_bytes"] < 1_500_000
            browser.close()
    record = {"kind": "editorial-animation-timeline", "source": SOURCE,
              "captured_version": "0.1.11 candidate", "total_ms": total_ms,
              "timing": "Editorial pacing, not measured operation duration", "stages": stages,
              "observations": {"concerning_new": 2, "benign_new": 0, "incomplete_unresolved": 2},
              "checks": {"recorded_fixture_and_outcomes": "passed", "svg_text_bounds": "passed",
                         "exact_instruction_wrapping": "passed", "gif_duration_and_loop": "passed"},
              "outputs": outputs}
    (HERE / "timeline.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
