#!/usr/bin/env python3
# ruff: noqa: E501
"""Generate the branded DUSK decision-evidence demo SVG."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "dusk-attack-demo.svg"
SOURCE_ARCH = ROOT / "dusk-agent-harness" / "docs" / "architecture.svg"


def _logo_uri() -> str:
    match = re.search(r'href="(data:image/png;base64,[^"]+)"', SOURCE_ARCH.read_text())
    if match is None:
        raise RuntimeError("embedded DUSK logo not found in architecture.svg")
    return match.group(1)


def build() -> str:
    logo = _logo_uri()
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="620" viewBox="0 0 1200 620" role="img" aria-labelledby="title desc">
<title id="title">DUSK action decision evidence</title>
<desc id="desc">A professional comparison of a routine action allowed by DUSK and an anomalous firewall action flagged before execution.</desc>
<defs>
  <filter id="shadow" x="-10%" y="-15%" width="120%" height="140%"><feDropShadow dx="0" dy="5" stdDeviation="9" flood-color="#111827" flood-opacity=".08"/></filter>
  <style>text{{font-family:Inter,Arial,sans-serif;fill:#111827}}.k{{font-size:11px;font-weight:800;letter-spacing:1.4px}}.h{{font-size:18px;font-weight:800}}.b{{font-size:13px}}.s{{font-size:11px;fill:#667085}}.white{{fill:#fff}}.footer{{fill:#d0d5dd}}.line{{stroke:#e1e6ed}}@keyframes scan{{0%{{transform:translateX(-45px);opacity:0}}20%,75%{{opacity:1}}100%{{transform:translateX(945px);opacity:0}}}}.scan{{animation:scan 4.8s ease-in-out infinite}}</style>
</defs>
<rect width="1200" height="620" fill="#fff"/>
<image href="{logo}" x="25" y="18" width="244" height="79" preserveAspectRatio="xMinYMid meet"/>
<text x="1170" y="42" text-anchor="end" class="k" fill="#667085">LIVE DECISION EVIDENCE</text>
<text x="1170" y="72" text-anchor="end" font-size="28" font-weight="850">Every verdict explains what changed and why it matters.</text>
<line x1="28" y1="112" x2="1172" y2="112" class="line"/>

<rect x="28" y="139" width="1144" height="392" rx="18" fill="#fff" stroke="#d8dee8" stroke-width="1.4" filter="url(#shadow)"/>
<rect x="28" y="139" width="1144" height="54" rx="18" fill="#f8fafc"/><rect x="28" y="176" width="1144" height="17" fill="#f8fafc"/>
<text x="54" y="172" class="k">SCENARIO</text><text x="198" y="172" class="k">PROPOSED ACTION</text><text x="494" y="172" class="k">BEHAVIOURAL EVIDENCE</text><text x="850" y="172" class="k">RISK</text><text x="944" y="172" class="k">VERDICT</text><text x="1082" y="172" class="k">APPLIED</text>

<!-- clean row -->
<line x1="28" y1="346" x2="1172" y2="346" class="line"/>
<circle cx="74" cy="265" r="17" fill="#eaf7ef"/><path d="m66 265 6 6 11-13" fill="none" stroke="#16834b" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
<text x="100" y="258" class="h">Routine</text><text x="100" y="279" class="s">known-good behavior</text>
<text x="198" y="249" class="b" font-weight="800">route_change</text><text x="198" y="273" class="b">rt-corp-default</text><text x="198" y="298" class="s">port 443 / allow</text>
<rect x="494" y="227" width="302" height="82" rx="11" fill="#f7faf8" stroke="#c9e3d2"/><text x="513" y="250" class="b">Action type seen before</text><text x="513" y="273" class="b">Target class established</text><text x="513" y="296" class="b">No new privileged values</text>
<text x="850" y="263" font-size="25" font-weight="850" fill="#16834b">0.00</text><text x="850" y="286" class="s">low</text>
<rect x="944" y="242" width="105" height="42" rx="21" fill="#eaf7ef"/><text x="996" y="269" text-anchor="middle" class="k" fill="#16834b">ALLOW</text>
<circle cx="1110" cy="263" r="18" fill="#eaf7ef"/><path d="m1102 263 6 6 11-13" fill="none" stroke="#16834b" stroke-width="3"/>

<!-- attack row -->
<circle cx="74" cy="429" r="17" fill="#fdeceb"/><path d="M74 419v12m0 6v.1" stroke="#c73b3b" stroke-width="3" stroke-linecap="round"/>
<text x="100" y="422" class="h">Poisoned</text><text x="100" y="443" class="s">prompt-injected action</text>
<text x="198" y="413" class="b" font-weight="800">firewall_rule_change</text><text x="198" y="437" class="b">fw-corp-restricted</text><text x="198" y="462" class="s">0.0.0.0/0 / allow</text>
<rect x="494" y="391" width="302" height="92" rx="11" fill="#fff8f7" stroke="#e9b7b1"/><text x="513" y="414" class="b">New action and target class</text><text x="513" y="437" class="b">Sensitive values introduced</text><text x="513" y="460" class="b">SIE confirms semantic novelty</text><rect x="513" y="470" width="246" height="4" rx="2" fill="#f1d1ce"/><rect x="513" y="470" width="197" height="4" rx="2" fill="#c73b3b"/>
<text x="850" y="428" font-size="25" font-weight="850" fill="#c73b3b">0.80</text><text x="850" y="451" class="s">high</text>
<rect x="930" y="406" width="133" height="46" rx="23" fill="#fdeceb"/><text x="996" y="435" text-anchor="middle" class="k" fill="#c73b3b">WOULD-BLOCK</text>
<circle cx="1110" cy="429" r="18" fill="#fdeceb"/><path d="m1102 421 16 16m0-16-16 16" stroke="#c73b3b" stroke-width="3" stroke-linecap="round"/>

<!-- animated inspection beam -->
<g class="scan"><rect x="190" y="199" width="2" height="322" fill="#111827" opacity=".2"/><circle cx="191" cy="514" r="4" fill="#111827"/></g>

<rect x="28" y="558" width="1144" height="42" rx="11" fill="#111827"/><text x="52" y="584" class="k white">MEASURED RESULT</text><text x="244" y="584" class="b footer">precision 1.00</text><text x="405" y="584" class="b footer">recall 1.00</text><text x="548" y="584" class="b footer">false-positive rate 0.00</text><text x="1148" y="584" text-anchor="end" class="b" style="fill:#8de0ad" font-weight="800">The risky action is visible before it becomes impact.</text>
</svg>'''


def main() -> None:
    OUT.write_text(build(), encoding="utf-8", newline="\n")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
