import json
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parent
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width':1440,'height':1000}, reduced_motion='reduce')
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto('http://127.0.0.1:8790/', wait_until='networkidle')
    page.evaluate('document.fonts.ready')
    expect(page).to_have_title('Cyber Thunder — Keep the Watch')
    assert page.locator('h1').count() == 1
    for index in range(5):
        tab = page.locator('[data-step]').nth(index)
        tab.click()
        expect(tab).to_have_attribute('aria-selected','true')
        page.wait_for_function('document.getElementById("tour-image").complete && document.getElementById("tour-image").naturalWidth > 0')
    page.locator('[data-step]').first.click()
    page.locator('[data-step]').first.focus()
    page.keyboard.press('ArrowRight')
    expect(page.locator('[data-step]').nth(1)).to_be_focused()
    expect(page.locator('#tour-route')).to_have_text('FINDINGS')
    page.locator('#tour-zoom').click()
    expect(page.locator('#image-dialog')).to_be_visible()
    page.keyboard.press('Escape')
    expect(page.locator('#image-dialog')).not_to_be_visible()
    page.locator('#sim-approve').click()
    expect(page.locator('#sim-status')).to_contain_text('Approved.')
    page.locator('#sim-pass').click()
    expect(page.locator('#sim-status')).to_contain_text('Verified.')
    page.locator('#sim-reset').click()
    page.locator('#sim-deny').click()
    expect(page.locator('#sim-status')).to_contain_text('Denied.')
    expect(page.locator('#verify-options')).not_to_be_visible()
    page.locator('#sim-reset').click()
    page.locator('#sim-approve').click()
    page.locator('#sim-fail').click()
    expect(page.locator('#sim-status')).to_contain_text('Before-state restored automatically.')
    page.locator('#sim-reset').click()
    page.locator('[data-brief]').first.click()
    expect(page.locator('#brief-dialog')).to_be_visible()
    expect(page.locator('#brief-prev')).to_be_disabled()
    for index in range(1,7):
        page.keyboard.press('ArrowRight')
        expect(page.locator('#brief-progress')).to_have_text(f'{index+1:02d} / 07')
    expect(page.locator('#brief-next')).to_have_text('Restart ↺')
    page.locator('#brief-next').click()
    expect(page.locator('#brief-progress')).to_have_text('01 / 07')
    page.keyboard.press('End')
    expect(page.locator('#brief-progress')).to_have_text('07 / 07')
    page.keyboard.press('Escape')
    expect(page.locator('#brief-dialog')).not_to_be_visible()
    page.locator('[data-step]').first.click()
    page.evaluate('window.scrollTo(0,0)')
    page.screenshot(path=str(ROOT/'qa-desktop.png'),full_page=True)
    page.screenshot(path=str(ROOT/'qa-hero.png'))
    dimensions=[]
    for width in (390,768,1440):
        page.set_viewport_size({'width':width,'height':900})
        page.evaluate('window.scrollTo(0,0)')
        box=page.evaluate('({width:innerWidth,scroll:document.documentElement.scrollWidth})')
        assert box['scroll'] <= box['width'],box
        assert page.locator('img').evaluate_all('(imgs)=>imgs.every(img=>img.complete && img.naturalWidth>0)'), 'Broken image'
        dimensions.append(box)
        if width==390:
            page.screenshot(path=str(ROOT/'qa-mobile.png'),full_page=True)
            page.locator('[data-brief]').first.click()
            expect(page.locator('#brief-next')).to_be_in_viewport()
            page.keyboard.press('Escape')
    assert not errors, errors
    result={'status':'passed','checks':['five screenshot tabs','accessible keyboard tabs','image lightbox','approve and verify','deny without changes','failed verification and rollback','seven-slide keyboard briefing','mobile briefing controls','local screenshot and font assets','responsive width and image loading'],'viewports':dimensions,'page_errors':errors}
    (ROOT/'qa-results.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))
    browser.close()
