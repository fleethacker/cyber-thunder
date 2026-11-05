"""Bundle the presentation and its assets into an offline HTML file and ZIP."""
import argparse
import base64
import json
import mimetypes
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def data_uri(path, media_type=None):
    media_type = media_type or mimetypes.guess_type(str(path))[0] or 'application/octet-stream'
    return 'data:' + media_type + ';base64,' + base64.b64encode(path.read_bytes()).decode('ascii')


def export(output):
    source = ROOT / 'dist'
    output.mkdir(parents=True, exist_ok=True)
    html = (source / 'index.html').read_text(encoding='utf-8')
    fonts = (source / 'assets/fonts.css').read_text(encoding='utf-8')
    css = (source / 'style.css').read_text(encoding='utf-8')
    script = (source / 'app.js').read_text(encoding='utf-8')
    for path in (source / 'assets').glob('*.woff2'):
        fonts = fonts.replace('url(' + path.name + ')', 'url(' + data_uri(path, 'font/ttf') + ')')
    html = html.replace('<link rel="stylesheet" href="assets/fonts.css">', '<style>' + fonts + '</style>')
    html = html.replace('<link rel="stylesheet" href="style.css">', '<style>' + css + '</style>')
    images = {'assets/' + path.name: data_uri(path) for path in sorted((source / 'assets').glob('*.jpg'))}
    for name in images:
        html = html.replace('src="' + name + '"', 'data-embedded-src="' + name + '"')
        script = script.replace("'" + name + "'", 'EMBEDDED_ASSETS[' + json.dumps(name) + ']')
    script = script.replace("byId('image-dialog-img').src = src;", "byId('image-dialog-img').src = EMBEDDED_ASSETS[src] || src;")
    initialize = "document.querySelectorAll('[data-embedded-src]').forEach(img => { img.src = EMBEDDED_ASSETS[img.dataset.embeddedSrc]; });\n"
    script = "'use strict';\nconst EMBEDDED_ASSETS = " + json.dumps(images) + ';\n' + initialize + script
    html = html.replace('<script src="app.js" defer></script>', '')
    html = html.replace('</body>', '<script>' + script + '</script>\n</body>')
    html = html.replace('href="assets/bolt.svg"', 'href="' + data_uri(source / 'assets/bolt.svg') + '"')
    html = html.replace('href="assets/capture-provenance.json" class="mono" target="_blank" rel="noopener"',
                        'href="' + data_uri(source / 'assets/capture-provenance.json', 'application/json') +
                        '" class="mono" download="capture-provenance.json"')
    licenses = '\n\n'.join(path.read_text(encoding='utf-8') for path in sorted((source / 'assets/font-licenses').glob('*.txt')))
    html = html.replace('</html>', '<!-- Bundled font licenses\n' + licenses.replace('--', '—') + '\n-->\n</html>')
    html = '\n'.join(line.rstrip() for line in html.splitlines()) + '\n'
    standalone = output / 'cyber-thunder-demo.html'
    standalone.write_text(html, encoding='utf-8')
    package = output / 'cyber-thunder-demo.zip'
    with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.write(standalone, 'index.html')
        archive.write(source / 'assets/capture-provenance.json', 'screenshots/capture-provenance.json')
        for path in sorted((source / 'assets').glob('*.jpg')):
            archive.write(path, ('screenshots/' if path.name.startswith('app-') else 'artwork/') + path.name)
        archive.writestr('START-HERE.txt',
            'CYBER THUNDER / FLEETHACKER DEMO\n\n'
            'Open index.html in a modern browser. All artwork, screenshots, fonts and interactions are embedded.\n'
            'No server or network connection is needed.\n\n'
            'Start briefing: seven slides; arrow keys navigate and Escape closes.\n'
            'Explore the app: five screenshot steps with zoom.\n'
            'Take the conn: approve, deny, verify or trigger rollback in a browser-only simulation.\n\n'
            'The local-app link requires the demo network and an authorized sign-in.\n'
            'Original screenshots and provenance are included in screenshots/.\n')
    print('Exported:', standalone)
    print('Packaged:', package)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-directory', type=Path, default=ROOT.parents[1])
    export(parser.parse_args().output_directory.resolve())
