# Cyber Thunder FLEETHACKER demo

An interactive pitch for the Autonomous Cyber Defender prototype: **Close the gap. Keep the watch.**

Open [the standalone HTML](../cyber-thunder-demo.html) directly in a browser. It embeds the screenshots,
fonts, styling and interactions, so the presentation works without a server or network connection.
[Preview the design](../cyber-thunder-demo-preview.png).

The demo includes a five-step application tour, screenshot zoom, an operator approval/denial simulation,
successful verification and automatic rollback outcomes, a seven-slide judge's briefing, and a proposed
30/60/90-day evaluation plan. The simulation changes only browser state. It does not call the application
or execute remediation. The local-app link requires access to the demo network and an authorized sign-in.

## Edit and preview

The editable page is in `dist/`. These are buildless source files, intentionally checked in with seven
original application screenshots, local fonts and their licenses. From the repository root:

```bash
python3 -m http.server 8790 --bind 127.0.0.1 --directory showcase/fleethacker-demo/dist
```

Open <http://127.0.0.1:8790>. Select **Start briefing** for presentation mode. Left and right arrow keys
navigate the slides; Escape closes the briefing. The workflow tabs also support arrow-key navigation.

After changing `dist/` or its assets, regenerate the standalone HTML and offline ZIP from the repository
root:

```bash
python3 showcase/fleethacker-demo/tools/export-demo.py
```

The export embeds each image once, including the supplied CyberThunder branding, and includes the original
screenshots and artwork in the ZIP. ZIP archives remain local build outputs.

## Screenshot provenance

The screenshots were taken with Playwright from the isolated deployment at application commit
`d374cfe8db7b9e1905435dc9429b473013e528f6` on November 5, 2026. They are recorded evidence, not live metrics.
The range includes simulated assets. See [capture-provenance.json](dist/assets/capture-provenance.json)
for timestamps and viewport details.

`tools/capture-app.py` captures the seven screens through the local application endpoint at port 8781.
It permits only read-only API methods and records blocked mutation attempts. Before recapturing another
deployment, update the endpoint and source commit to match it. Use only an authorized isolated range.

## Browser checks

The browser tools require Playwright and its Chromium browser in a development environment; they do not
add a dependency to the application. With the preview server above running:

```bash
python3 showcase/fleethacker-demo/tools/check-demo.py
```

The checks exercise the screenshot tabs, keyboard navigation, image zoom, approval, denial, verification,
rollback and briefing, and check image loading and overflow at desktop, tablet and mobile widths. Local
screenshots and check results are ignored by Git.
