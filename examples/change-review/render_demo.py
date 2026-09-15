"""Optional editorial renderer from captured lab output; not an AZT dependency.

Uses the same navy/cyan palette as assets/launch. No network or downloads.
Pass a completed lab directory and a new output directory. With --raster,
the already available Playwright browser and Pillow render a paced GIF/PNG.
"""
import argparse
import html
import json
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('lab',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--raster',action='store_true');args=parser.parse_args()
    record=json.loads((args.lab/'results.json').read_text())
    assert record['passed']==record['planned']==4
    transcript=(args.lab/'transcript.txt').read_text()
    args.output.mkdir(mode=0o700)
    def text(x,y,value,size=18,color='#f6f9ff'):
        return f'<text x="{x}" y="{y}" font-family="Arial, sans-serif" font-size="{size}" fill="{color}">{html.escape(value)}</text>'
    def frame(selected=None):
        body='<rect width="440" height="820" fill="#090e17"/>'
        body+=text(24,38,'AGENT ZERO TRUST',20,'#56e0ee')+text(24,78,'What changed?',32)
        body+=text(24,111,'0.1.11 candidate / captured CLI output',17,'#b4c4d9')
        for i,case in enumerate(record['cases']):
            section=transcript.split('CASE: '+case['case']+'\n',1)[1].split('CASE:',1)[0]
            labels=[line for line in section.splitlines() if line.startswith(('Meaningful delta:', 'Comparability:', 'Findings new:', 'Findings unresolved:'))]
            assert len(labels)==4
            y=137+i*145
            color='#56e0ee' if selected is None or selected==i else '#314154'
            body+=f'<rect x="16" y="{y}" width="408" height="133" rx="12" fill="#111d2d" stroke="{color}"/>'
            body+=text(32,y+28,case['case'].upper(),18,color)
            for j,label in enumerate(labels):body+=text(32,y+52+j*21,label,17)
        body+=text(24,757,'Offline. Synthetic. No target execution.',17,'#b4c4d9')
        body+=text(24,785,'Not an approval or proof of a fix.',17,'#b4c4d9')
        return '<svg xmlns="http://www.w3.org/2000/svg" width="440" height="820" viewBox="0 0 440 820">'+body+'</svg>'
    (args.output/'demo.svg').write_text(frame())
    if args.raster:
        from playwright.sync_api import sync_playwright
        from PIL import Image
        with sync_playwright() as p:
            browser=p.chromium.launch(chromium_sandbox=True)
            page=browser.new_page(viewport={'width':440,'height':820})
            for i in range(4):
                page.set_content('<style>body{margin:0}</style>'+frame(i));page.screenshot(path=str(args.output/f'frame-{i}.png'))
            page.set_content('<style>body{margin:0}</style>'+frame());page.screenshot(path=str(args.output/'demo.png'))
            browser.close()
        images=[Image.open(args.output/f'frame-{i}.png').convert('P',palette=Image.Palette.ADAPTIVE,colors=96) for i in range(4)]
        images[0].save(args.output/'demo.gif',save_all=True,append_images=images[1:],duration=3500,loop=0,optimize=True)
    print('Rendered selected actual output; editorial pacing is not measured execution time.')


if __name__=='__main__':main()
