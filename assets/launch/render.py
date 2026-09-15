"""Optional local editorial renderer. No downloads; never part of AZT execution."""
import html
import json
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
BG, PANEL, BLUE, CYAN, WHITE, MUTED = '#090e17', '#111d2d', '#2979ff', '#56e0ee', '#f6f9ff', '#b4c4d9'

def text(x, y, content, size=26, color=WHITE, weight=400, mono=False):
    family = 'monospace' if mono else 'Arial, Helvetica, sans-serif'
    return f'<text x="{x}" y="{y}" fill="{color}" font-size="{size}" font-weight="{weight}" font-family="{family}">{html.escape(content)}</text>'

def rect(x, y, w, h, fill=PANEL, stroke='none', radius=12):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="{fill}" stroke="{stroke}"/>'

def svg(content):
    return '<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="640" viewBox="0 0 1280 640">'+rect(0,0,1280,640,BG,radius=0)+content+'</svg>'

hero = rect(48,48,6,45,CYAN, radius=0)+text(76,80,'AGENT ZERO TRUST',28,CYAN,700)
hero += text(64,176,'Inspect before',66,WHITE,700)+text(64,250,'you delegate.',66,WHITE,700)
hero += text(66,313,'Offline repository intake',29,MUTED)+text(66,354,'for AI coding agents.',29,MUTED)
hero += rect(66,415,450,66,BLUE)+text(91,457,'Delegate work. Retain control.',25,WHITE,700)
hero += text(66,565,'OPEN SOURCE  /  LOCAL FIRST  /  MIT',19,MUTED,mono=True)
hero += rect(707,123,509,366,PANEL,'#2a405c')
hero += text(735,164,'REPOSITORY INPUTS',19,CYAN,700,True)
for i,label in enumerate(['README.md','agent instructions','hooks + setup','MCP configuration']):
    hero += text(736,222+i*48,'> '+label,24,WHITE,mono=True)
hero += '<path d="M685 101 V510" stroke="#56e0ee" stroke-width="2" stroke-dasharray="7 8"/>'
hero += text(708,544,'READING IS NOT AUTHORIZATION',20,CYAN,700,True)
(ROOT/'hero.svg').write_text(svg(hero))

record = json.loads((ROOT.parent.parent/'evidence/fs001-0.1.9/34915008373.json').read_text())
for case in ['canonical','variant']:
    result = record['export']['records'][case+'/evidence.json']['execution']
    assert result['status'] == 'passed' and result['counts']['outcomes']['passed'] == 3
    for trial in result['trials']:
        checks = trial['independent_checks']
        assert checks['legitimate_task_completed'] and checks['original_project_unchanged']
        assert checks['access_expectation_met'] and checks['positive_control_confirmed']
        assert trial['cleanup'] == 'removed' and all(trial['stages'].values())
assert record['export']['cleanup']['status'] == 'verified_absent'
card = text(56,68,'AZT-FS-001  /  RECORDED SYNTHETIC TEST',25,CYAN,700)
card += text(56,130,'One access change. A repair. A retest.',42,WHITE,700)
card += text(56,178,'Two configuration inputs for one case. Three phases per input.',24,MUTED)
for i,(title,result,color) in enumerate([('BASELINE','Access unavailable',CYAN),('MISCONFIGURED','Exposure demonstrated','#ffbc69'),('REPAIRED','Access unavailable',CYAN)]):
    x=56+i*396
    card += rect(x,220,376,232,PANEL,'#2a405c')+text(x+24,264,title,22,color,700)
    card += text(x+24,315,result,25,WHITE,700)+text(x+24,365,'Legitimate task: verified',23,MUTED)
    card += text(x+24,406,'Integrity + cleanup: passed',21,MUTED)
card += text(56,504,'Intentional exposure is a positive control, not a safe configuration.',24,'#ffbc69')
card += text(56,548,'Docker/Linux isolation. Bundled trusted probe. No live coding agent.',23,MUTED)
card += text(56,594,'Source 94a802bbe8b5  /  run 34915008373  /  selected filesystem read only',20,MUTED,mono=True)
(ROOT/'fs001.svg').write_text(svg(card))
frames = json.loads((ROOT/'scan-frames.json').read_text())
for i,frame in enumerate(frames['frames']):
    body = text(48,62,'AZT / PUBLIC PYPI 0.1.9 / CAPTURED SCAN',23,CYAN,700)
    body += rect(40,96,1200,463,PANEL,'#2a405c')+text(66,139,frame['title'],20,MUTED,700)
    body += text(66,207,frame['command'],29,CYAN,mono=True)
    for j,line in enumerate(frame['lines']):
        body += text(66,278+j*52,line,22,'#ffbc69' if 'HIGH' in line else WHITE,mono=True)
    body += text(66,525,frame['footer'],23,MUTED)
    body += text(48,605,'Synthetic input / selected actual output / edited pacing / no target execution',21,MUTED)
    (ROOT/f'scan-{i+1}.svg').write_text(svg(body))

with sync_playwright() as p:
    browser = p.chromium.launch(chromium_sandbox=True)
    page = browser.new_page(viewport={'width':1280,'height':640},device_scale_factor=1)
    for path in [ROOT/'hero.svg', ROOT/'fs001.svg']+[ROOT/f'scan-{i}.svg' for i in range(1,5)]:
        page.goto(path.as_uri()); page.screenshot(path=str(path.with_suffix('.png')))
    browser.close()
for path in ROOT.glob('*.png'):
    with Image.open(path) as im:
        im.save(path,optimize=True)
with Image.open(ROOT/'scan-3.png') as im:
    im.save(ROOT/'scan.png',optimize=True)
images=[Image.open(ROOT/f'scan-{i}.png').convert('P',palette=Image.Palette.ADAPTIVE,colors=96) for i in range(1,5)]
images[0].save(ROOT/'scan.gif',save_all=True,append_images=images[1:],duration=[6000]*4,loop=0,optimize=True)
assert (ROOT/'hero.png').stat().st_size < 1000000
print('Rendered hero, evidence card, four real-output frames and 24-second GIF. Inspect before publication.')
