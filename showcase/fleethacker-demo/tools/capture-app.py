"""Capture the running application without making state-changing API requests."""
import json
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'dist' / 'assets'
BASE = 'http://127.0.0.1:8781'
PAGES = [
    ('assets', '/assets', 'Assets'),
    ('findings', '/findings', 'Findings'),
    ('decisions', '/', 'Decisions'),
    ('audit', '/audit', 'Audit trail'),
    ('reports', '/reports', 'Reports'),
    ('commander', '/commander', 'Commander view'),
    ('mission', '/mission', 'Mission'),
]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1600, 'height': 1060}, device_scale_factor=1)
    context.add_init_script("""
        localStorage.setItem('ct.actor', 'Demo operator');
        localStorage.setItem('ct.dec.state', JSON.stringify(['proposed']));
        localStorage.setItem('ct.dec.sev', JSON.stringify([]));
    """)
    blocked = []
    def read_only(route):
        if route.request.method in ('GET', 'HEAD', 'OPTIONS'):
            route.continue_()
        else:
            blocked.append(route.request.method + ' ' + route.request.url)
            route.abort()
    context.route('**/api/**', read_only)
    page = context.new_page()
    page.set_default_timeout(90000)
    records = []
    for name, path, title in PAGES:
        page.goto(BASE + '/#' + path, wait_until='domcontentloaded')
        page.get_by_text(title, exact=True).last.wait_for()
        page.wait_for_function("""() => {
            const m = document.querySelector('main');
            return m && m.innerText.length > 120 &&
              !/Loading the decision queue|Loading findings|Reading the audit chain|Loading assets|Loading reports|Loading mission|Loading\\.\\.\\./.test(m.innerText);
        }""")
        if name == 'decisions':
            page.locator('[id^="proposal-"]').first.wait_for()
        if name == 'commander':
            page.get_by_text('Open CAT I', exact=True).wait_for()
        if name == 'assets':
            page.get_by_text('Local Kubernetes cluster', exact=True).first.wait_for()
        if name == 'findings':
            page.locator('tbody tr').first.wait_for()
        if name == 'reports':
            page.get_by_text('Report history', exact=True).wait_for()
        if name == 'audit':
            page.get_by_role('button', name='Verify chain', exact=True).click()
            page.get_by_text('Chain verified', exact=True).last.wait_for()
        page.evaluate('document.fonts.ready')
        page.wait_for_timeout(700)
        page.mouse.move(1520, 1020)
        destination = ASSETS / ('app-' + name + '.jpg')
        page.screenshot(path=str(destination), type='jpeg', quality=92, animations='disabled')
        text = page.locator('main').inner_text()
        records.append({'name': name, 'route': path, 'asset': destination.name,
                        'captured_at': datetime.now(timezone.utc).isoformat(),
                        'viewport': {'width': 1600, 'height': 1060},
                        'source_commit': 'd374cfe8db7b9e1905435dc9429b473013e528f6'})
        (ROOT / 'tools' / ('capture-' + name + '.txt')).write_text(text, encoding='utf-8')
        print('CAPTURED', name, destination.stat().st_size, flush=True)
    (ASSETS / 'capture-provenance.json').write_text(json.dumps({'screenshots': records,
        'method': 'Playwright Chromium, deployed application, read-only API access',
        'blocked_mutations': blocked}, indent=2), encoding='utf-8')
    assert not blocked, blocked
    browser.close()
