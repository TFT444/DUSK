#!/usr/bin/env python3
# ruff: noqa: E501
"""Generate the DUSK README hero and compact workflow strip."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SOURCE_ARCH = ROOT / "dusk-agent-harness" / "docs" / "architecture.svg"


def _logo_uri() -> str:
    match = re.search(r'href="(data:image/png;base64,[^"]+)"', SOURCE_ARCH.read_text())
    if match is None:
        raise RuntimeError("embedded DUSK logo not found in architecture.svg")
    return match.group(1)


def hero() -> str:
    logo = _logo_uri()
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="330" viewBox="0 0 1200 330" role="img" aria-labelledby="title desc">
<title id="title">DUSK behavioral security for AI agents</title><desc id="desc">DUSK detects abnormal agent actions before they become infrastructure impact.</desc>
<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#f4f6f9"/></linearGradient><radialGradient id="glow"><stop offset="0" stop-color="#d8dee8" stop-opacity=".55"/><stop offset="1" stop-color="#d8dee8" stop-opacity="0"/></radialGradient><style>text{{font-family:Inter,Arial,sans-serif;fill:#111827}}.k{{font-size:12px;font-weight:800;letter-spacing:1.8px}}.b{{font-size:17px;fill:#475467}}</style></defs>
<rect width="1200" height="330" rx="24" fill="url(#bg)"/><circle cx="1080" cy="38" r="230" fill="url(#glow)"/><circle cx="112" cy="335" r="180" fill="url(#glow)"/>
<path d="M0 1H1200M0 329H1200" stroke="#d8dee8"/><rect x="0" y="0" width="10" height="330" rx="5" fill="#111827"/>
<image href="{logo}" x="54" y="42" width="246" height="79" preserveAspectRatio="xMinYMid meet"/>
<text x="58" y="158" class="k">BEHAVIOURAL AI SECURITY FOR AGENTIC SYSTEMS</text>
<text x="58" y="218" font-size="45" font-weight="880">Security for what AI agents do next.</text>
<text x="58" y="275" class="b">Detect abnormal actions before they become infrastructure impact. Explain every decision before execution.</text>
</svg>'''


def workflow() -> str:
    return """<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="190" viewBox="0 0 1200 190" role="img" aria-labelledby="title desc">
<title id="title">How DUSK works in five steps</title><desc id="desc">Agent, structured action, behavioral analysis with SIE, explainable verdict, and conditional target execution.</desc>
<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0 10 5 0 10Z" fill="#98a2b3"/></marker><style>text{font-family:Inter,Arial,sans-serif;fill:#111827}.k{font-size:11px;font-weight:800;letter-spacing:1.2px}.s{font-size:10px;fill:#667085}.n{fill:#fff;stroke:#d8dee8;stroke-width:1.3}.f{fill:none;stroke:#98a2b3;stroke-width:1.8;stroke-dasharray:6 5;marker-end:url(#a);animation:m 1.4s linear infinite}@keyframes m{to{stroke-dashoffset:-22}}</style></defs>
<rect width="1200" height="190" rx="18" fill="#fff" stroke="#d8dee8"/><text x="30" y="34" class="k">HOW DUSK WORKS</text><text x="1170" y="34" text-anchor="end" class="s">inline behavioral control for proposed agent actions</text>
<path d="M210 106H263M430 106H483M650 106H703M870 106H923" class="f"/>
<g><circle cx="55" cy="106" r="19" fill="#111827"/><text x="55" y="111" text-anchor="middle" style="fill:#fff;font-size:12px;font-weight:800">1</text><rect x="82" y="70" width="128" height="72" rx="12" class="n"/><text x="146" y="101" text-anchor="middle" class="k">AGENT</text><text x="146" y="122" text-anchor="middle" class="s">proposes a tool action</text></g>
<g><circle cx="275" cy="106" r="19" fill="#111827"/><text x="275" y="111" text-anchor="middle" style="fill:#fff;font-size:12px;font-weight:800">2</text><rect x="302" y="70" width="128" height="72" rx="12" class="n"/><text x="366" y="101" text-anchor="middle" class="k">STRUCTURE</text><text x="366" y="122" text-anchor="middle" class="s">normalize AgentAction</text></g>
<g><circle cx="495" cy="106" r="19" fill="#111827"/><text x="495" y="111" text-anchor="middle" style="fill:#fff;font-size:12px;font-weight:800">3</text><rect x="522" y="64" width="128" height="84" rx="12" fill="#f8fafc" stroke="#111827" stroke-width="1.5"/><text x="586" y="96" text-anchor="middle" class="k">ANALYSE</text><text x="586" y="117" text-anchor="middle" class="s">baseline + SIE signals</text><text x="586" y="134" text-anchor="middle" class="s">risk + evidence</text></g>
<g><circle cx="715" cy="106" r="19" fill="#111827"/><text x="715" y="111" text-anchor="middle" style="fill:#fff;font-size:12px;font-weight:800">4</text><rect x="742" y="70" width="128" height="72" rx="12" class="n"/><text x="806" y="101" text-anchor="middle" class="k">VERDICT</text><text x="806" y="122" text-anchor="middle" class="s">allow / flag / block</text></g>
<g><circle cx="935" cy="106" r="19" fill="#16834b"/><text x="935" y="111" text-anchor="middle" style="fill:#fff;font-size:12px;font-weight:800">5</text><rect x="962" y="70" width="208" height="72" rx="12" fill="#f5fbf7" stroke="#9bcfaf"/><text x="1066" y="99" text-anchor="middle" class="k" style="fill:#12693d">EXECUTE CONDITIONALLY</text><text x="1066" y="121" text-anchor="middle" class="s">target called only when policy permits</text></g>
</svg>"""


def main() -> None:
    assets = {"dusk-hero-banner.svg": hero(), "dusk-workflow-strip.svg": workflow()}
    for name, content in assets.items():
        out = DOCS / name
        out.write_text(content, encoding="utf-8", newline="\n")
        print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
